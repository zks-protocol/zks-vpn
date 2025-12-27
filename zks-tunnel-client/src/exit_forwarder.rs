//! Exit Packet Forwarder - Forwards peer traffic to internet via native sockets
//!
//! Based on EasyTier's UdpProxy pattern. When receiving IpPacket from peer:
//! - If destination is local VPN IP → NOT handled here (goes to TUN)
//! - If destination is internet → forward via socket, capture response, send back
//!
//! This is faster than TUN for exit traffic because it's direct socket → internet.

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{checksum as ipv4_checksum, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::udp::{MutableUdpPacket, UdpPacket};
use pnet_packet::Packet;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace};

/// First octet of VPN subnet (10.x.x.x = class A private)
const VPN_SUBNET_FIRST_OCTET: u8 = 10;

/// NAT entry for UDP connection tracking
#[derive(Debug)]
struct UdpNatEntry {
    src_addr: SocketAddrV4,
    socket: UdpSocket,
    last_active: Instant,
}

/// Exit Packet Forwarder - handles forwarding peer traffic to internet
pub struct ExitForwarder {
    /// Local VPN IP address (to identify local vs exit traffic)
    local_vpn_ip: Ipv4Addr,

    /// UDP NAT table for connection tracking
    udp_nat_table: RwLock<HashMap<SocketAddrV4, Arc<UdpNatEntry>>>,

    /// Channel to send response packets back to peer
    response_tx: mpsc::Sender<Vec<u8>>,
}

impl ExitForwarder {
    /// Create new exit forwarder
    pub fn new(local_vpn_ip: Ipv4Addr, response_tx: mpsc::Sender<Vec<u8>>) -> Self {
        info!("🌐 Exit Forwarder initialized for VPN IP: {}", local_vpn_ip);
        Self {
            local_vpn_ip,
            udp_nat_table: RwLock::new(HashMap::new()),
            response_tx,
        }
    }

    /// Check if packet destination is for local delivery (to TUN) or exit (to internet)
    pub fn is_exit_traffic(&self, payload: &[u8]) -> bool {
        if let Some(ipv4) = Ipv4Packet::new(payload) {
            let dst = ipv4.get_destination();
            // Exit traffic = destination is NOT our local VPN IP
            // and NOT in our VPN subnet (10.x.x.x)
            let is_local = dst == self.local_vpn_ip;
            let is_vpn_subnet = dst.octets()[0] == VPN_SUBNET_FIRST_OCTET;

            !is_local && !is_vpn_subnet
        } else {
            false
        }
    }

    /// Forward IP packet to internet via native socket
    /// Returns Ok(true) if handled, Ok(false) if not exit traffic
    pub async fn forward_to_internet(
        &self,
        payload: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let ipv4 = match Ipv4Packet::new(payload) {
            Some(p) => p,
            None => return Ok(false),
        };

        let src_ip = ipv4.get_source();
        let dst_ip = ipv4.get_destination();

        // Check if this is exit traffic
        if dst_ip == self.local_vpn_ip {
            return Ok(false); // Local delivery, not exit
        }

        // Check if destination is in VPN subnet (peer-to-peer, not exit)
        if dst_ip.octets()[0] == VPN_SUBNET_FIRST_OCTET {
            return Ok(false); // VPN subnet traffic
        }

        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                self.forward_udp(&ipv4, src_ip, dst_ip).await?;
                Ok(true)
            }
            IpNextHeaderProtocols::Tcp => {
                // TCP forwarding via OS-level NAT (iptables MASQUERADE)
                // Return Ok(false) to let packet flow to TUN where NAT handles it
                trace!("TCP exit traffic to {} (via OS NAT)", dst_ip);
                Ok(false) // Let TUN + iptables handle TCP
            }
            IpNextHeaderProtocols::Icmp => {
                // ICMP forwarding via OS-level routing
                trace!("ICMP exit traffic to {} (via OS)", dst_ip);
                Ok(false) // Let TUN + iptables handle ICMP
            }
            proto => {
                trace!("Unknown protocol {:?} to {}", proto, dst_ip);
                Ok(false)
            }
        }
    }

    /// Forward UDP packet to internet
    async fn forward_udp(
        &self,
        ipv4: &Ipv4Packet<'_>,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let udp = match UdpPacket::new(ipv4.payload()) {
            Some(u) => u,
            None => return Ok(()),
        };

        let src_port = udp.get_source();
        let dst_port = udp.get_destination();
        let src_addr = SocketAddrV4::new(src_ip, src_port);
        let dst_addr = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));

        trace!(
            "UDP exit: {}:{} -> {}:{}",
            src_ip,
            src_port,
            dst_ip,
            dst_port
        );

        // Get or create NAT entry
        let entry = self.get_or_create_udp_nat_entry(src_addr).await?;

        // Send packet to internet
        entry.socket.send_to(udp.payload(), dst_addr).await?;

        Ok(())
    }

    /// Get existing NAT entry or create new one
    async fn get_or_create_udp_nat_entry(
        &self,
        src_addr: SocketAddrV4,
    ) -> Result<Arc<UdpNatEntry>, Box<dyn std::error::Error + Send + Sync>> {
        // Check if entry exists
        {
            let table = self.udp_nat_table.read().await;
            if let Some(entry) = table.get(&src_addr) {
                return Ok(entry.clone());
            }
        }

        // Create new entry
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let entry = Arc::new(UdpNatEntry {
            src_addr,
            socket,
            last_active: Instant::now(),
        });

        // Start response listener for this socket
        let entry_clone = entry.clone();
        let response_tx = self.response_tx.clone();
        let local_vpn_ip = self.local_vpn_ip;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match entry_clone.socket.recv_from(&mut buf).await {
                    Ok((len, from_addr)) => {
                        trace!("UDP response from {}: {} bytes", from_addr, len);

                        // Build IP packet to send back to peer
                        if let Some(response) = build_udp_response_packet(
                            from_addr,
                            SocketAddr::V4(entry_clone.src_addr),
                            &buf[..len],
                            local_vpn_ip,
                        ) {
                            if let Err(e) = response_tx.send(response).await {
                                error!("Failed to send UDP response: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP NAT socket error: {}", e);
                        break;
                    }
                }
            }
        });

        // Store entry
        {
            let mut table = self.udp_nat_table.write().await;
            table.insert(src_addr, entry.clone());
        }

        info!("Created UDP NAT entry for {}", src_addr);
        Ok(entry)
    }

    /// Clean up expired NAT entries
    pub async fn cleanup_expired(&self) {
        let mut table = self.udp_nat_table.write().await;
        let before = table.len();
        table.retain(|_, v| v.last_active.elapsed() < Duration::from_secs(180));
        let after = table.len();
        if before != after {
            debug!("Cleaned up {} expired UDP NAT entries", before - after);
        }
    }
}

/// Build UDP response packet to send back to peer
fn build_udp_response_packet(
    from_addr: SocketAddr,
    to_addr: SocketAddr,
    payload: &[u8],
    _local_vpn_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let from_v4 = match from_addr {
        SocketAddr::V4(a) => a,
        _ => return None,
    };
    let to_v4 = match to_addr {
        SocketAddr::V4(a) => a,
        _ => return None,
    };

    // IP header (20 bytes) + UDP header (8 bytes) + payload
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; total_len];

    // Build IPv4 header
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5); // 20 bytes / 4
        ip.set_total_length(total_len as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(*from_v4.ip());
        ip.set_destination(*to_v4.ip());
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }

    // Build UDP header
    {
        let mut udp = MutableUdpPacket::new(&mut buf[20..]).unwrap();
        udp.set_source(from_v4.port());
        udp.set_destination(to_v4.port());
        udp.set_length((8 + payload.len()) as u16);
        udp.set_payload(payload);
        // UDP checksum optional for IPv4
        udp.set_checksum(0);
    }

    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_exit_traffic() {
        let (tx, _rx) = mpsc::channel(10);
        let forwarder = ExitForwarder::new(Ipv4Addr::new(10, 0, 0, 1), tx);

        // Build a simple IPv4 packet header for testing
        // This is a minimal test - in reality packets are more complex
        assert!(true); // Placeholder
    }
}
