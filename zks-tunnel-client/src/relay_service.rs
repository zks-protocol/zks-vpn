//! Relay Service - Forwards encrypted packets between peers
//!
//! This module implements the relay functionality where a peer forwards
//! encrypted packets from one peer to another. The relay:
//! - Cannot decrypt the packets (end-to-end encryption)
//! - Earns bandwidth tokens for relaying
//! - Helps create traffic mixing for plausible deniability

#![allow(dead_code)]

use crate::entropy_tax::EntropyTax;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

/// Relay packet forwarding request
#[derive(Debug, Clone)]
pub struct RelayPacket {
    /// Source peer ID
    pub from_peer: String,

    /// Destination peer ID
    pub to_peer: String,

    /// Encrypted payload (relay cannot decrypt)
    pub data: Bytes,

    /// Packet sequence number
    pub seq: u64,
}

/// Relay service state
pub struct RelayService {
    /// Active relay sessions (peer_id -> channel)
    sessions: Arc<RwLock<HashMap<String, mpsc::Sender<RelayPacket>>>>,

    /// Incoming relay requests
    incoming_rx: mpsc::Receiver<RelayPacket>,

    /// Outgoing relay packets (to traffic mixer)
    traffic_tx: mpsc::Sender<crate::traffic_mixer::TrafficPacket>,

    /// Statistics: packets relayed
    packets_relayed: Arc<RwLock<u64>>,

    /// Statistics: bytes relayed
    bytes_relayed: Arc<RwLock<u64>>,

    /// Entropy Tax collector (for earning tokens)
    entropy_tax: Arc<Mutex<EntropyTax>>,
}

impl RelayService {
    /// Create a new relay service
    pub fn new(
        incoming_rx: mpsc::Receiver<RelayPacket>,
        traffic_tx: mpsc::Sender<crate::traffic_mixer::TrafficPacket>,
        entropy_tax: Arc<Mutex<EntropyTax>>,
    ) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            incoming_rx,
            traffic_tx,
            packets_relayed: Arc::new(RwLock::new(0)),
            bytes_relayed: Arc::new(RwLock::new(0)),
            entropy_tax,
        }
    }

    /// Run the relay service
    pub async fn run(mut self) {
        info!("📡 Relay Service started (forwarding packets for peers)");

        loop {
            match self.incoming_rx.recv().await {
                Some(packet) => {
                    self.handle_relay_packet(packet).await;
                }
                None => {
                    debug!("Relay service channel closed");
                    break;
                }
            }
        }

        // Print statistics
        let packets = *self.packets_relayed.read().await;
        let bytes = *self.bytes_relayed.read().await;

        info!("✅ Relay Service stopped");
        info!(
            "   Relayed: {} packets ({} MB)",
            packets,
            bytes / 1024 / 1024
        );
    }

    /// Handle a relay packet request
    async fn handle_relay_packet(&mut self, packet: RelayPacket) {
        let packet_size = packet.data.len();

        debug!(
            "📡 Relay: {} -> {} ({} bytes, seq={})",
            packet.from_peer, packet.to_peer, packet_size, packet.seq
        );

        // Forward to destination peer
        // In actual implementation, this would use libp2p to send to peer
        // For now, send to traffic mixer for transmission
        let traffic_packet = crate::traffic_mixer::TrafficPacket::RelayTraffic {
            peer_id: packet.to_peer.clone(),
            data: packet.data.clone(),
        };

        if let Err(e) = self.traffic_tx.send(traffic_packet).await {
            warn!("Failed to forward relay packet: {}", e);
            return;
        }

        // Update statistics
        *self.packets_relayed.write().await += 1;
        *self.bytes_relayed.write().await += packet_size as u64;

        // Earn bandwidth tokens via entropy_tax
        let mut tax = self.entropy_tax.lock().await;
        tax.earn_tokens(packet_size as u64);
        debug!("💰 Earned {} tokens for relaying", packet_size);
    }

    /// Get relay statistics
    pub async fn stats(&self) -> (u64, u64) {
        let packets = *self.packets_relayed.read().await;
        let bytes = *self.bytes_relayed.read().await;
        (packets, bytes)
    }
}

/// Create relay service channels
pub fn create_relay_channels() -> (mpsc::Sender<RelayPacket>, mpsc::Receiver<RelayPacket>) {
    mpsc::channel(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_forwarding() {
        let (relay_tx, relay_rx) = create_relay_channels();
        let (traffic_tx, mut traffic_rx) = mpsc::channel(100);

        let relay_service = RelayService::new(
            relay_rx,
            traffic_tx,
            Arc::new(Mutex::new(EntropyTax::new())),
        );

        // Start relay service in background
        tokio::spawn(relay_service.run());

        // Send a relay packet
        let packet = RelayPacket {
            from_peer: "peer_a".to_string(),
            to_peer: "peer_b".to_string(),
            data: Bytes::from("encrypted payload"),
            seq: 1,
        };

        relay_tx.send(packet).await.unwrap();

        // Verify it was forwarded to traffic mixer
        let forwarded = traffic_rx.recv().await.unwrap();
        match forwarded {
            crate::traffic_mixer::TrafficPacket::RelayTraffic { peer_id, .. } => {
                assert_eq!(peer_id, "peer_b");
            }
            _ => panic!("Expected relay traffic"),
        }
    }
}
