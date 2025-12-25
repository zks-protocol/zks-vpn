//! Exit Service - Provides internet gateway for swarm peers
//!
//! This module implements the exit node functionality where a peer:
//! - Accepts ZKS encrypted tunnels from other peers
//! - Decrypts and forwards traffic to the internet
//! - Encrypts responses and sends back to peers
//! - Earns bandwidth tokens for providing exit service
//!
//! Security: Exit node sees destination but not source (peer's real IP)
//! Privacy: All users relay for others, creating plausible deniability

#![allow(dead_code)]

use crate::entropy_tax::EntropyTax;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

/// Exit session represents a tunnel from a peer
#[derive(Debug, Clone)]
pub struct ExitSession {
    /// Session ID (unique per tunnel)
    pub session_id: String,

    /// Peer ID who created the tunnel
    pub peer_id: String,

    /// Session encryption keys (ZKS tunnel)
    pub tunnel_key: Vec<u8>,
}

/// Exit traffic packet
#[derive(Debug, Clone)]
pub struct ExitPacket {
    /// Session ID
    pub session_id: String,

    /// Encrypted payload from peer
    pub encrypted_data: Bytes,

    /// Sequence number
    pub seq: u64,
}

/// Exit service state
pub struct ExitService {
    /// Active exit sessions (session_id -> session)
    sessions: Arc<RwLock<HashMap<String, ExitSession>>>,

    /// Incoming exit requests (from peers)
    incoming_rx: mpsc::Receiver<ExitPacket>,

    /// Outgoing exit traffic (to traffic mixer)
    traffic_tx: mpsc::Sender<crate::traffic_mixer::TrafficPacket>,

    /// Statistics: packets forwarded
    packets_forwarded: Arc<RwLock<u64>>,

    /// Statistics: bytes forwarded
    bytes_forwarded: Arc<RwLock<u64>>,

    /// Exit policy (optional port filtering)
    policy: ExitPolicy,

    /// Entropy Tax collector (for earning tokens)
    entropy_tax: Arc<Mutex<EntropyTax>>,
}

/// Exit node policy (safety configuration)
#[derive(Debug, Clone)]
pub struct ExitPolicy {
    /// Blocked ports (e.g., SMTP=25, RPC=135, SMB=445)
    pub blocked_ports: Vec<u16>,

    /// Maximum bandwidth (Mbps)
    pub max_bandwidth_mbps: u32,

    /// Enable port filtering
    pub enable_port_filtering: bool,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        Self {
            // Block common abuse ports by default
            blocked_ports: vec![
                25,   // SMTP (email spam)
                135,  // RPC
                139,  // NetBIOS
                445,  // SMB
                1433, // MSSQL
                3389, // RDP
            ],
            max_bandwidth_mbps: 100,
            enable_port_filtering: true,
        }
    }
}

impl ExitService {
    /// Create a new exit service
    pub fn new(
        incoming_rx: mpsc::Receiver<ExitPacket>,
        traffic_tx: mpsc::Sender<crate::traffic_mixer::TrafficPacket>,
        policy: ExitPolicy,
        entropy_tax: Arc<Mutex<EntropyTax>>,
    ) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            incoming_rx,
            traffic_tx,
            packets_forwarded: Arc::new(RwLock::new(0)),
            bytes_forwarded: Arc::new(RwLock::new(0)),
            policy,
            entropy_tax,
        }
    }

    /// Run the exit service
    pub async fn run(mut self) {
        info!("🌍 Exit Service started (providing internet gateway)");
        info!(
            "   Port filtering: {}",
            if self.policy.enable_port_filtering {
                "enabled"
            } else {
                "disabled"
            }
        );
        info!("   Blocked ports: {:?}", self.policy.blocked_ports);

        loop {
            match self.incoming_rx.recv().await {
                Some(packet) => {
                    self.handle_exit_packet(packet).await;
                }
                None => {
                    debug!("Exit service channel closed");
                    break;
                }
            }
        }

        // Print statistics
        let packets = *self.packets_forwarded.read().await;
        let bytes = *self.bytes_forwarded.read().await;

        info!("✅ Exit Service stopped");
        info!(
            "   Forwarded: {} packets ({} MB)",
            packets,
            bytes / 1024 / 1024
        );
    }

    /// Handle an exit packet request
    async fn handle_exit_packet(&mut self, packet: ExitPacket) {
        let packet_size = packet.encrypted_data.len();

        debug!(
            "🌍 Exit: session={} ({} bytes, seq={})",
            packet.session_id, packet_size, packet.seq
        );

        // TODO: Decrypt ZKS tunnel and extract destination
        // TODO: Check exit policy (port filtering)
        // TODO: Forward to internet via TCP/UDP
        // TODO: Encrypt response and send back

        // For now, just forward to traffic mixer
        let traffic_packet = crate::traffic_mixer::TrafficPacket::ExitTraffic {
            session_id: packet.session_id.clone(),
            data: packet.encrypted_data.clone(),
        };

        if let Err(e) = self.traffic_tx.send(traffic_packet).await {
            warn!("Failed to forward exit packet: {}", e);
            return;
        }

        // Update statistics
        *self.packets_forwarded.write().await += 1;
        *self.bytes_forwarded.write().await += packet_size as u64;

        // Earn bandwidth tokens via entropy_tax
        let mut tax = self.entropy_tax.lock().await;
        tax.earn_tokens(packet_size as u64);
        debug!("💰 Earned {} tokens for exit service", packet_size);
    }

    /// Create a new exit session
    #[allow(dead_code)]
    pub async fn create_session(&mut self, session: ExitSession) -> Result<(), String> {
        let session_id = session.session_id.clone();
        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);
        info!("🌍 Created exit session: {}", session_id);
        Ok(())
    }

    /// Remove an exit session
    #[allow(dead_code)]
    pub async fn remove_session(&mut self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
        info!("🌍 Removed exit session: {}", session_id);
    }

    /// Get exit statistics
    #[allow(dead_code)]
    pub async fn stats(&self) -> (u64, u64) {
        let packets = *self.packets_forwarded.read().await;
        let bytes = *self.bytes_forwarded.read().await;
        (packets, bytes)
    }
}

/// Create exit service channels
pub fn create_exit_channels() -> (mpsc::Sender<ExitPacket>, mpsc::Receiver<ExitPacket>) {
    mpsc::channel(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_exit_forwarding() {
        let (exit_tx, exit_rx) = create_exit_channels();
        let (traffic_tx, mut traffic_rx) = mpsc::channel(100);

        let exit_service = ExitService::new(
            exit_rx,
            traffic_tx,
            ExitPolicy::default(),
            Arc::new(Mutex::new(EntropyTax::new())),
        );

        // Start exit service in background
        tokio::spawn(exit_service.run());

        // Send an exit packet
        let packet = ExitPacket {
            session_id: "session1".to_string(),
            encrypted_data: Bytes::from("encrypted tunnel data"),
            seq: 1,
        };

        exit_tx.send(packet).await.unwrap();

        // Verify it was forwarded to traffic mixer
        let forwarded = traffic_rx.recv().await.unwrap();
        match forwarded {
            crate::traffic_mixer::TrafficPacket::ExitTraffic { session_id, .. } => {
                assert_eq!(session_id, "session1");
            }
            _ => panic!("Expected exit traffic"),
        }
    }
}
