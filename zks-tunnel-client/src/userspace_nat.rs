//! Userspace NAT for ZKS-VPN Exit Peer
//!
//! This module implements a userspace NAT using smoltcp.
//! It allows the Exit Peer to forward traffic to the internet without
//! requiring OS-level NAT (iptables/ICS), enabling "System-Wide VPN" support on Windows.

use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use netstack_smoltcp::{AnyIpPktFrame, Stack, StackBuilder};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};

/// NAT Table Entry
#[derive(Debug, Clone)]
struct NatEntry {
    src_addr: SocketAddr, // Original Client Address (10.0.85.1:SrcPort)
    dst_addr: SocketAddr, // Original Destination Address (8.8.8.8:80)
    last_active: std::time::Instant,
}

/// Userspace NAT Controller
pub struct UserspaceNat {
    stack: Stack,
    nat_table: Arc<RwLock<HashMap<u16, NatEntry>>>,
    virtual_ip: Ipv4Addr,
    listen_port: u16,
}

pub struct UserspaceNatReader {
    reader: futures::stream::SplitStream<Stack>,
    nat_table: Arc<RwLock<HashMap<u16, NatEntry>>>,
}

pub struct UserspaceNatWriter {
    writer: futures::stream::SplitSink<Stack, AnyIpPktFrame>,
    nat_table: Arc<RwLock<HashMap<u16, NatEntry>>>,
    virtual_ip: Ipv4Addr,
    listen_port: u16,
}

impl UserspaceNat {
    /// Create a new Userspace NAT
    pub fn new() -> Self {
        let virtual_ip = Ipv4Addr::new(10, 0, 85, 2);
        let listen_port = 1234;

        // Create smoltcp stack
        // StackBuilder::default() is used as per netstack-smoltcp examples.
        // It doesn't require setting IP addresses on the builder itself.
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_udp(true)
            .enable_tcp(true)
            .enable_icmp(true)
            .build()
            .unwrap();

        let mut runner = runner.expect("Runner missing");
        let udp_socket = udp_socket.expect("UDP socket missing");
        let mut tcp_listener = tcp_listener.expect("TCP listener missing");

        // Spawn stack runner
        tokio::spawn(async move {
            info!("NetStack runner started");
            match runner.await {
                Ok(()) => warn!("NetStack runner completed (stack closed)"),
                Err(e) => error!("NetStack runner failed: {}", e),
            }
        });

        let nat_table: Arc<RwLock<HashMap<u16, NatEntry>>> = Arc::new(RwLock::new(HashMap::new()));
        let nat_table_clone = nat_table.clone();
        let listen_port_clone = listen_port;

        // Spawn TCP Handler
        tokio::spawn(async move {
            while let Some((stream, addr1, addr2)) = tcp_listener.next().await {
                debug!("Accepted TCP connection. Addr1={}, Addr2={}", addr1, addr2);

                // Identify peer address (Client)
                // The listener returns (stream, local, remote) or (stream, remote, local).
                // One of them is the Virtual IP:ListenPort (10.0.85.2:1234).
                // The other is the Client IP:ClientPort.
                // We want the Client address to look up the NAT entry.
                let peer_addr = if addr1.port() == listen_port_clone {
                    addr2
                } else {
                    addr1
                };

                let port = peer_addr.port();
                let target = {
                    let table = nat_table_clone.read().await;
                    table.get(&port).map(|e| e.dst_addr)
                };

                if let Some(target) = target {
                    info!("Proxying TCP {} -> {}", peer_addr, target);
                    tokio::spawn(async move {
                        if let Err(e) = proxy_tcp(stream, target).await {
                            warn!("TCP Proxy failed: {}", e);
                        }
                    });
                } else {
                    warn!("No NAT entry found for TCP connection from {}", peer_addr);
                }
            }
        });

        // Spawn UDP Handler
        let nat_table_udp = nat_table.clone();

        // UDP Flow Table: Source Port -> Sender
        struct UdpFlow {
            sender: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
        }
        let udp_flows: Arc<RwLock<HashMap<u16, UdpFlow>>> = Arc::new(RwLock::new(HashMap::new()));

        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));

        tokio::spawn(async move {
            while let Some(msg) = udp_rx.next().await {
                let (payload, src_addr, _dst_addr) = msg; // src=Client, dst=VirtualIP

                let port = src_addr.port();
                let target = {
                    let table: tokio::sync::RwLockReadGuard<HashMap<u16, NatEntry>> =
                        nat_table_udp.read().await;
                    table.get(&port).map(|e| e.dst_addr)
                };

                if let Some(target) = target {
                    info!("Proxying UDP {} -> {}", src_addr, target);
                    // Check if flow exists
                    let sender = {
                        let flows = udp_flows.read().await;
                        flows.get(&port).map(|f| f.sender.clone())
                    };

                    if let Some(tx) = sender {
                        // Send to existing flow
                        if let Err(_) = tx.send((payload, target)).await {
                            // Channel closed, ignore
                        }
                    } else {
                        // Create new flow
                        debug!("Creating new UDP flow for {}", src_addr);
                        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

                        {
                            let mut flows = udp_flows.write().await;
                            flows.insert(port, UdpFlow { sender: tx.clone() });
                        }

                        let flows_clone = udp_flows.clone();
                        let udp_tx_clone = udp_tx.clone();

                        // Spawn Flow Task
                        tokio::spawn(async move {
                            // Bind a real socket for this flow
                            let real_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("Failed to bind UDP socket for flow: {}", e);
                                    flows_clone.write().await.remove(&port);
                                    return;
                                }
                            };

                            // Send initial packet
                            if let Err(e) = real_socket.send_to(&payload, target).await {
                                warn!("Failed to send initial UDP packet: {}", e);
                            }

                            let mut rx_buf = [0u8; 65535];
                            let timeout = std::time::Duration::from_secs(60);

                            loop {
                                tokio::select! {
                                    // Outbound: Stack -> Internet
                                    msg = rx.recv() => {
                                        match msg {
                                            Some((data, dst)) => {
                                                if let Err(e) = real_socket.send_to(&data, dst).await {
                                                    debug!("UDP flow send error: {}", e);
                                                }
                                            }
                                            None => break, // Channel closed
                                        }
                                    }
                                    // Inbound: Internet -> Stack
                                    res = real_socket.recv_from(&mut rx_buf) => {
                                        match res {
                                            Ok((n, remote_src)) => {
                                                // We received from Internet (remote_src). Send to Stack.
                                                // Stack expects: (payload, src, dst)
                                                // src = remote_src (Internet IP)
                                                // dst = src_addr (Client IP)
                                                let mut tx = udp_tx_clone.lock().await;
                                                if let Err(e) = tx.send((rx_buf[..n].to_vec(), remote_src, src_addr)).await {
                                                    debug!("UDP flow stack send error: {}", e);
                                                }
                                            }
                                            Err(e) => {
                                                debug!("UDP flow recv error: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                    // Idle Timeout
                                    _ = tokio::time::sleep(timeout) => {
                                        debug!("UDP flow timeout for {}", src_addr);
                                        break;
                                    }
                                }
                            }

                            // Cleanup
                            flows_clone.write().await.remove(&port);
                        });
                    }
                } else {
                    warn!("No NAT entry found for UDP packet from {}", src_addr);
                }
            }
        });

        Self {
            stack,
            nat_table,
            virtual_ip,
            listen_port,
        }
    }

    /// Split into Reader and Writer
    pub fn split(self) -> (UserspaceNatReader, UserspaceNatWriter) {
        let (writer, reader) = self.stack.split();

        (
            UserspaceNatReader {
                reader,
                nat_table: self.nat_table.clone(),
            },
            UserspaceNatWriter {
                writer,
                nat_table: self.nat_table,
                virtual_ip: self.virtual_ip,
                listen_port: self.listen_port,
            },
        )
    }
}

impl UserspaceNatWriter {
    /// Process an IP packet from the Client (Relay -> Stack)
    pub async fn send_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        let mut packet = packet.to_vec();

        let mut ipv4_packet = match Ipv4Packet::new_checked(&mut packet) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        let src_addr = SocketAddr::new(std::net::IpAddr::V4(ipv4_packet.src_addr().into()), 0);
        let dst_addr = SocketAddr::new(std::net::IpAddr::V4(ipv4_packet.dst_addr().into()), 0);
        debug!("NAT Writer: Packet {} -> {}", src_addr, dst_addr);

        let protocol = ipv4_packet.next_header();

        match protocol {
            IpProtocol::Tcp => {
                let _header_len = ipv4_packet.header_len() as usize;
                let mut tcp_packet = match TcpPacket::new_checked(ipv4_packet.payload_mut()) {
                    Ok(p) => p,
                    Err(_) => return Ok(()),
                };

                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();

                let full_src = SocketAddr::new(src_addr.ip(), src_port);
                let full_dst = SocketAddr::new(dst_addr.ip(), dst_port);

                {
                    let mut table = self.nat_table.write().await;
                    table.insert(
                        src_port,
                        NatEntry {
                            src_addr: full_src,
                            dst_addr: full_dst,
                            last_active: std::time::Instant::now(),
                        },
                    );
                }

                tcp_packet.set_dst_port(self.listen_port);

                let src_ip_smol = match src_addr.ip() {
                    std::net::IpAddr::V4(ip) => Ipv4Address::from(ip),
                    _ => unreachable!(),
                };
                let virtual_ip_smol = Ipv4Address::from(self.virtual_ip);
                tcp_packet.fill_checksum(
                    &IpAddress::Ipv4(src_ip_smol),
                    &IpAddress::Ipv4(virtual_ip_smol),
                );
            }
            IpProtocol::Udp => {
                let _header_len = ipv4_packet.header_len() as usize;
                let mut udp_packet = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                    Ok(p) => p,
                    Err(_) => return Ok(()),
                };

                let src_port = udp_packet.src_port();
                let dst_port = udp_packet.dst_port();

                let full_src = SocketAddr::new(src_addr.ip(), src_port);
                let full_dst = SocketAddr::new(dst_addr.ip(), dst_port);

                {
                    let mut table = self.nat_table.write().await;
                    table.insert(
                        src_port,
                        NatEntry {
                            src_addr: full_src,
                            dst_addr: full_dst,
                            last_active: std::time::Instant::now(),
                        },
                    );
                }

                udp_packet.set_dst_port(self.listen_port);

                let src_ip_smol = match src_addr.ip() {
                    std::net::IpAddr::V4(ip) => Ipv4Address::from(ip),
                    _ => unreachable!(),
                };
                let virtual_ip_smol = Ipv4Address::from(self.virtual_ip);
                udp_packet.fill_checksum(
                    &IpAddress::Ipv4(src_ip_smol),
                    &IpAddress::Ipv4(virtual_ip_smol),
                );
            }
            _ => return Ok(()),
        }

        ipv4_packet.set_dst_addr(self.virtual_ip.into());
        ipv4_packet.fill_checksum();

        // Write to stack (Sink)
        self.writer
            .send(packet)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }
}

impl UserspaceNatReader {
    /// Read an IP packet from the Stack (Stack -> Relay)
    pub async fn recv_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Read from stack (Stream)
        if let Some(res) = self.reader.next().await {
            match res {
                Ok(pkt) => {
                    // pkt is Vec<u8> (AnyIpPktFrame)
                    debug!("Stack output: {} byte packet (return path)", pkt.len());
                    if pkt.len() > buf.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Packet too large",
                        ));
                    }
                    buf[..pkt.len()].copy_from_slice(&pkt);
                    let n = pkt.len();

                    let mut packet = &mut buf[..n];

                    let mut ipv4_packet = match Ipv4Packet::new_checked(&mut packet) {
                        Ok(p) => p,
                        Err(_) => return Ok(n),
                    };

                    let protocol = ipv4_packet.next_header();
                    let dst_addr_client = ipv4_packet.dst_addr();

                    let mut original_src: Option<SocketAddr> = None;

                    match protocol {
                        IpProtocol::Tcp => {
                            let mut tcp_packet =
                                match TcpPacket::new_checked(ipv4_packet.payload_mut()) {
                                    Ok(p) => p,
                                    Err(_) => return Ok(n),
                                };

                            let dst_port = tcp_packet.dst_port();

                            {
                                let table = self.nat_table.read().await;
                                if let Some(entry) = table.get(&dst_port) {
                                    original_src = Some(entry.dst_addr);
                                }
                            }

                            if let Some(orig) = original_src {
                                tcp_packet.set_src_port(orig.port());
                                let orig_ip_smol = match orig.ip() {
                                    std::net::IpAddr::V4(ip) => Ipv4Address::from(ip),
                                    _ => return Ok(n),
                                };
                                let dst_ip_smol = Ipv4Address::from(dst_addr_client);
                                tcp_packet.fill_checksum(
                                    &IpAddress::Ipv4(orig_ip_smol),
                                    &IpAddress::Ipv4(dst_ip_smol),
                                );
                            }
                        }
                        IpProtocol::Udp => {
                            let mut udp_packet =
                                match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                                    Ok(p) => p,
                                    Err(_) => return Ok(n),
                                };

                            let dst_port = udp_packet.dst_port();

                            {
                                let table = self.nat_table.read().await;
                                if let Some(entry) = table.get(&dst_port) {
                                    original_src = Some(entry.dst_addr);
                                }
                            }

                            if let Some(orig) = original_src {
                                udp_packet.set_src_port(orig.port());
                                let orig_ip_smol = match orig.ip() {
                                    std::net::IpAddr::V4(ip) => Ipv4Address::from(ip),
                                    _ => return Ok(n),
                                };
                                let dst_ip_smol = Ipv4Address::from(dst_addr_client);
                                udp_packet.fill_checksum(
                                    &IpAddress::Ipv4(orig_ip_smol),
                                    &IpAddress::Ipv4(dst_ip_smol),
                                );
                            }
                        }
                        _ => {}
                    }

                    if let Some(orig) = original_src {
                        let orig_ip_smol = match orig.ip() {
                            std::net::IpAddr::V4(ip) => Ipv4Address::from(ip),
                            _ => return Ok(n),
                        };
                        ipv4_packet.set_src_addr(orig_ip_smol);
                        ipv4_packet.fill_checksum();
                    } else {
                        warn!(
                            "NAT Reader: No NAT entry for return packet to {}",
                            dst_addr_client
                        );
                    }

                    Ok(n)
                }
                Err(e) => Err(e),
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Stack closed",
            ))
        }
    }
}

/// Proxy a TCP connection
async fn proxy_tcp(
    client_stream: netstack_smoltcp::TcpStream,
    target: SocketAddr,
) -> std::io::Result<()> {
    debug!("proxy_tcp: Connecting to target {}...", target);
    let mut target_stream = match tokio::net::TcpStream::connect(target).await {
        Ok(s) => {
            debug!("proxy_tcp: Connected to target {}", target);
            s
        }
        Err(e) => {
            warn!("proxy_tcp: Failed to connect to {}: {}", target, e);
            return Err(e);
        }
    };
    let (mut client_read, mut client_write) = tokio::io::split(client_stream); // Use tokio::io::split for AsyncRead/Write
    let (mut target_read, mut target_write) = target_stream.split();

    let target_clone = target;
    let client_to_target = async {
        let result = tokio::io::copy(&mut client_read, &mut target_write).await;
        debug!(
            "proxy_tcp: client->target copy finished for {}: {:?}",
            target_clone, result
        );
        result
    };
    let target_to_client = async {
        let result = tokio::io::copy(&mut target_read, &mut client_write).await;
        debug!(
            "proxy_tcp: target->client copy finished for {}: {:?}",
            target_clone, result
        );
        result
    };

    match tokio::try_join!(client_to_target, target_to_client) {
        Ok((c2t, t2c)) => {
            debug!(
                "proxy_tcp: Completed for {}. Client->Target: {} bytes, Target->Client: {} bytes",
                target, c2t, t2c
            );
            Ok(())
        }
        Err(e) => {
            debug!("proxy_tcp: Error for {}: {}", target, e);
            Err(e)
        }
    }
}
