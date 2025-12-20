//! ZKS Entry Node - UDP Relay for Multi-Hop VPN
//!
//! The Entry Node (VPS1) acts as the first hop in the Faisal Swarm topology:
//! - Accepts UDP connections from Clients
//! - Forwards encrypted packets to the Exit Node (VPS2)
//! - Maintains triple-blind privacy: knows Client IP but not destination
//!
//! Usage:
//!   zks-vpn --mode entry-node --exit-node 213.35.103.204:51820

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Entry Node configuration
pub struct EntryNodeConfig {
    /// Address to listen on (e.g., 0.0.0.0:51820)
    pub listen_addr: SocketAddr,
    /// Exit Node address (VPS2)
    pub exit_node_addr: SocketAddr,
}

/// Client session tracking
struct ClientSession {
    /// Client's socket address
    addr: SocketAddr,
    /// Last activity timestamp
    last_seen: std::time::Instant,
}

/// Entry Node state
struct EntryNodeState {
    /// Map of client sessions (indexed by client addr)
    clients: HashMap<SocketAddr, ClientSession>,
}

impl EntryNodeState {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    fn register_client(&mut self, addr: SocketAddr) {
        self.clients.insert(
            addr,
            ClientSession {
                addr,
                last_seen: std::time::Instant::now(),
            },
        );
    }

    fn update_client(&mut self, addr: &SocketAddr) {
        if let Some(session) = self.clients.get_mut(addr) {
            session.last_seen = std::time::Instant::now();
        }
    }

    fn get_active_client(&self) -> Option<SocketAddr> {
        // For now, return the most recently active client
        // In future, support multiple clients with proper session management
        self.clients
            .values()
            .max_by_key(|s| s.last_seen)
            .map(|s| s.addr)
    }

    fn cleanup_stale(&mut self, timeout_secs: u64) {
        let now = std::time::Instant::now();
        self.clients
            .retain(|_, session| now.duration_since(session.last_seen).as_secs() < timeout_secs);
    }
}

/// Run the Entry Node
///
/// This is the core relay loop:
/// 1. Listen on UDP port for client packets
/// 2. Forward to Exit Node
/// 3. Receive responses from Exit Node
/// 4. Forward back to Client
pub async fn run_entry_node(
    config: EntryNodeConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║       ZKS Entry Node - Faisal Swarm First Hop               ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  Listen:    {:45} ║", config.listen_addr.to_string());
    info!("║  Exit Node: {:45} ║", config.exit_node_addr.to_string());
    info!("╚══════════════════════════════════════════════════════════════╝");

    // Bind UDP socket
    let socket = Arc::new(UdpSocket::bind(config.listen_addr).await?);
    info!("✅ UDP socket bound to {}", config.listen_addr);

    // State for tracking clients
    let state = Arc::new(RwLock::new(EntryNodeState::new()));

    // Buffer for receiving packets
    let mut buf = vec![0u8; 65535];

    info!("⏳ Waiting for connections...");
    info!("   Clients will connect via UDP, packets forwarded to Exit Node");

    // Cleanup task for stale sessions
    let state_cleanup = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut state = state_cleanup.write().await;
            let before = state.clients.len();
            state.cleanup_stale(300); // 5 minute timeout
            let after = state.clients.len();
            if before != after {
                info!("Cleaned up {} stale sessions", before - after);
            }
        }
    });

    // Main relay loop
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let data = &buf[..len];

                // Determine source: Client or Exit Node?
                if addr == config.exit_node_addr {
                    // Packet from Exit Node -> Forward to Client
                    debug!("← Exit → Client: {} bytes", len);

                    let state_read = state.read().await;
                    if let Some(client_addr) = state_read.get_active_client() {
                        if let Err(e) = socket.send_to(data, client_addr).await {
                            warn!("Failed to send to client {}: {}", client_addr, e);
                        }
                    } else {
                        debug!("No active client to forward response to");
                    }
                } else {
                    // Packet from Client -> Forward to Exit Node
                    debug!("→ Client → Exit: {} bytes from {}", len, addr);

                    // Register/update client session
                    {
                        let mut state_write = state.write().await;
                        if !state_write.clients.contains_key(&addr) {
                            info!("New client connected: {}", addr);
                            state_write.register_client(addr);
                        } else {
                            state_write.update_client(&addr);
                        }
                    }

                    // Forward to Exit Node
                    if let Err(e) = socket.send_to(data, config.exit_node_addr).await {
                        error!("Failed to forward to Exit Node: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("UDP recv error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_node_state() {
        let mut state = EntryNodeState::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        state.register_client(addr);
        assert!(state.clients.contains_key(&addr));

        let active = state.get_active_client();
        assert_eq!(active, Some(addr));
    }
}
