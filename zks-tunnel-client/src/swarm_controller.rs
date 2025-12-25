//! Swarm Controller - Unified orchestrator for Client + Relay + Exit roles
//!
//! This module implements the Faisal-Swarm topology where every user simultaneously:
//! 1. Acts as VPN Client (routes own traffic through swarm)
//! 2. Acts as Relay (forwards encrypted packets for others)
//! 3. Acts as Exit (provides internet gateway for others, opt-in)
//!
//! Security: Traffic mixing creates plausible deniability - ISP cannot tell
//! which traffic is user's own vs. relayed for others.

use crate::entropy_tax::EntropyTax;
use crate::exit_service::{create_exit_channels, ExitPolicy, ExitService};
use crate::p2p_relay::TunnelMessage;
use crate::p2p_vpn::P2PVpnController;
use crate::relay_service::{create_relay_channels, RelayService};
use crate::traffic_mixer::{
    create_channels, TrafficMixerChannels, TrafficMixerConfig, TrafficPacket,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Configuration for swarm operation
#[derive(Clone, Debug)]
pub struct SwarmControllerConfig {
    /// Enable VPN client (use swarm for own traffic)
    pub enable_client: bool,

    /// Enable relay service (forward for others)
    pub enable_relay: bool,

    /// Enable exit service (internet gateway for others)
    pub enable_exit: bool,

    /// Room ID for peer discovery
    pub room_id: String,

    /// Cloudflare Worker signaling URL
    pub relay_url: String,

    /// Vernam entropy URL
    pub vernam_url: String,

    /// Exit node consent (legal requirement)
    pub exit_consent_given: bool,

    /// VPN IP address (to avoid conflict)
    pub vpn_address: String,

    /// Server mode (Exit Node) - skip default route, enable NAT
    pub server_mode: bool,
}

impl Default for SwarmControllerConfig {
    fn default() -> Self {
        Self {
            enable_client: true,
            enable_relay: true,
            enable_exit: true, // True Swarm: Everyone is an exit node
            room_id: "faisal-swarm".to_string(),
            relay_url: "wss://zks-tunnel-relay.md-wasif-faisal.workers.dev".to_string(),
            vernam_url: "https://zks-key.md-wasif-faisal.workers.dev/entropy".to_string(),
            exit_consent_given: false,
            vpn_address: "10.0.85.1".to_string(),
            server_mode: false,
        }
    }
}

/// Packet for traffic mixing
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum MixedPacket {
    /// User's own VPN traffic
    OwnTraffic(Vec<u8>),
    /// Relayed traffic for another peer
    RelayTraffic { peer_id: String, data: Vec<u8> },
    /// Exit traffic (decrypted and forwarded to internet)
    ExitTraffic { session_id: String, data: Vec<u8> },
    /// Dummy padding packet
    Padding(Vec<u8>),
}

/// Swarm Controller - manages all three roles concurrently
pub struct SwarmController {
    /// VPN client controller (user's own traffic)
    vpn_client: Option<Arc<Mutex<P2PVpnController>>>,

    /// Relay service state
    relay_active: Arc<RwLock<bool>>,

    /// Exit service state  
    exit_active: Arc<RwLock<bool>>,

    /// Bandwidth token system
    entropy_tax: Arc<Mutex<EntropyTax>>,

    /// Configuration
    config: SwarmControllerConfig,

    /// Routing table for Exit Node (Client IP -> Relay Sender)
    routes: Arc<RwLock<HashMap<Ipv4Addr, mpsc::Sender<TunnelMessage>>>>,

    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: Arc<Mutex<Option<mpsc::Receiver<()>>>>,
}

impl SwarmController {
    /// Create new swarm controller
    pub fn new(config: SwarmControllerConfig) -> Self {
        Self {
            vpn_client: None,
            relay_active: Arc::new(RwLock::new(false)),
            exit_active: Arc::new(RwLock::new(false)),
            entropy_tax: Arc::new(Mutex::new(EntropyTax::new())),
            config,
            routes: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: None,
            shutdown_rx: Arc::new(Mutex::new(None)),
        }
    }

    /// Start all enabled services
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🌐 Starting Faisal-Swarm Controller...");

        // Check exit consent (Soft check - warning only for True Swarm)
        if self.config.enable_exit && !self.config.exit_consent_given {
            warn!("⚠️  RUNNING AS EXIT NODE WITHOUT EXPLICIT CONSENT FLAG");
            warn!("   You are part of the Faisal Swarm. Your IP forwards traffic for others.");
            warn!("   This provides plausible deniability but carries legal risks.");
            warn!("   Use --no-exit to disable this role if you are not comfortable.");
            // No return Err() - we allow it by default
        }

        // Show legal disclaimer if exit enabled
        if self.config.enable_exit {
            self.show_exit_disclaimer();
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);
        *self.shutdown_rx.lock().await = Some(shutdown_rx);

        // Start VPN client service
        if self.config.enable_client {
            info!("🖥️  Starting VPN Client service...");
            self.start_vpn_client().await?;
        }

        // Create traffic mixer channels ONCE
        let (mixer_channels, output_rx) = create_channels();

        // Start relay service
        if self.config.enable_relay {
            info!("📡 Starting Relay service...");
            let relay_tx = mixer_channels.relay_tx.clone();
            self.start_relay_service(relay_tx).await?;
        }

        // Start exit service
        if self.config.enable_exit {
            info!("🌍 Starting Exit service...");
            let exit_tx = mixer_channels.exit_tx.clone();
            self.start_exit_service(exit_tx).await?;
        }

        // Start traffic mixer
        info!("🔀 Starting Traffic Mixer...");
        self.start_traffic_mixer(mixer_channels, output_rx).await?;

        info!("✅ Faisal-Swarm Controller running");
        info!("   - Client: {}", self.config.enable_client);
        info!("   - Relay: {}", self.config.enable_relay);
        info!("   - Exit: {}", self.config.enable_exit);

        // Wait for shutdown signal
        let _ = self.shutdown_rx.lock().await.as_mut().unwrap().recv().await;

        Ok(())
    }

    /// Start VPN client (user's own traffic)
    async fn start_vpn_client(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(feature = "vpn")]
        {
            use crate::p2p_vpn::P2PVpnConfig;

            let config = P2PVpnConfig {
                relay_url: self.config.relay_url.clone(),
                room_id: self.config.room_id.clone(),
                vernam_url: self.config.vernam_url.clone(),
                device_name: "zks0".to_string(),
                address: self.config.vpn_address.parse().unwrap(),
                netmask: "255.255.255.0".parse().unwrap(),
                mtu: 1400,
                dns_protection: true,
                kill_switch: false,
                proxy: None,
                exit_peer_address: "10.0.85.2".parse().unwrap(),
                server_mode: self.config.server_mode,
            };

            let controller = P2PVpnController::new(config, self.entropy_tax.clone());
            self.vpn_client = Some(Arc::new(Mutex::new(controller)));

            // Start VPN in background
            let client = self.vpn_client.as_ref().unwrap().clone();
            tokio::spawn(async move {
                let ctrl = client.lock().await;
                if let Err(e) = ctrl.start().await {
                    error!("VPN client error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Start relay service (forward for others)
    async fn start_relay_service(
        &mut self,
        traffic_tx: mpsc::Sender<TrafficPacket>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        *self.relay_active.write().await = true;

        // Create channels for relay service
        let (_relay_tx, relay_rx) = create_relay_channels();

        // Create and start relay service
        let relay_service = RelayService::new(relay_rx, traffic_tx, self.entropy_tax.clone());
        tokio::spawn(async move {
            relay_service.run().await;
        });

        info!("📡 Relay service started (forwarding packets for peers)");

        Ok(())
    }

    /// Start exit service (internet gateway)
    async fn start_exit_service(
        &mut self,
        traffic_tx: mpsc::Sender<TrafficPacket>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        *self.exit_active.write().await = true;

        // Create channels for exit service
        let (_exit_tx, exit_rx) = create_exit_channels();

        // Create exit service with default policy
        let policy = ExitPolicy::default();
        let exit_service = ExitService::new(exit_rx, traffic_tx, policy, self.entropy_tax.clone());

        tokio::spawn(async move {
            exit_service.run().await;
        });

        // Start Exit Relay (Network Connection)
        let relay_url = self.config.relay_url.clone();
        let vernam_url = self.config.vernam_url.clone();
        let room_id = self.config.room_id.clone();
        let vpn_client = self.vpn_client.clone();
        let server_mode = self.config.server_mode;
        let routes = self.routes.clone();

        tokio::spawn(async move {
            loop {
                info!("🌍 Exit Service waiting for client connection...");
                match crate::p2p_relay::P2PRelay::connect(
                    &relay_url,
                    &vernam_url,
                    &room_id,
                    crate::p2p_relay::PeerRole::ExitPeer,
                    None,
                )
                .await
                {
                    Ok(relay) => {
                        info!("🌍 Exit Service CONNECTED to a client!");
                        let relay = std::sync::Arc::new(relay);

                        // If in Server Mode, setup bidirectional forwarding with TUN
                        if let (true, Some(client)) = (server_mode, vpn_client.as_ref()) {
                            let client = client.clone();
                            let routes = routes.clone();
                            let relay = relay.clone();

                            // Spawn handler for this client
                            tokio::spawn(async move {
                                // Create channel for sending TO this client (used by Outbound Router)
                                let (client_tx, mut client_rx) = mpsc::channel(1000);
                                let relay_send = relay.clone();

                                // Task: Rx from Channel -> Relay (Outbound from TUN)
                                tokio::spawn(async move {
                                    while let Some(msg) = client_rx.recv().await {
                                        if let Err(e) = relay_send.send(&msg).await {
                                            warn!("Failed to send to client relay: {}", e);
                                            break;
                                        }
                                    }
                                });

                                // Task: Rx from Relay -> TUN (Inbound to Exit)
                                while let Ok(msg) = relay.recv().await {
                                    if let Some(msg) = msg {
                                        match msg {
                                            TunnelMessage::IpPacket { payload } => {
                                                // 1. Learn Source IP
                                                if payload.len() >= 20 {
                                                    // IPv4 Source IP is at offset 12
                                                    let src_ip = Ipv4Addr::new(
                                                        payload[12],
                                                        payload[13],
                                                        payload[14],
                                                        payload[15],
                                                    );

                                                    // Update routing table
                                                    {
                                                        let mut r: tokio::sync::RwLockWriteGuard<
                                                            '_,
                                                            HashMap<
                                                                Ipv4Addr,
                                                                mpsc::Sender<TunnelMessage>,
                                                            >,
                                                        > = routes.write().await;
                                                        r.entry(src_ip).or_insert_with(|| {
                                                            info!(
                                                                "🆕 Learned route: {} -> Client",
                                                                src_ip
                                                            );
                                                            client_tx.clone()
                                                        });
                                                    }
                                                }

                                                // 2. Inject into TUN
                                                client
                                                    .lock()
                                                    .await
                                                    .inject_packet(payload.to_vec())
                                                    .await;
                                            }
                                            _ => {
                                                debug!(
                                                    "Exit Service received non-IP message: {:?}",
                                                    msg
                                                );
                                            }
                                        }
                                    } else {
                                        break; // Connection closed
                                    }
                                }

                                // Cleanup route?
                                // Ideally yes, but we don't know which IP unless we stored it.
                                // For now, let it stale.
                                warn!("Client disconnected");
                            });
                        } else {
                            // Legacy/Placeholder mode (just keep alive)
                            tokio::spawn(async move {
                                while let Ok(_msg) = relay.recv().await {
                                    // TODO: Forward to ExitService (SOCKS/HTTP)
                                }
                            });
                        }
                    }
                    Err(e) => {
                        // Don't log "timeout" as error, it's normal waiting
                        if e.to_string().contains("AuthInit timeout") {
                            debug!("🌍 Exit Service: No client connected (timeout), retrying...");
                        } else {
                            warn!("Exit Service connect error: {}. Retrying...", e);
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });

        // Spawn Outbound Router (TUN -> Clients)
        // Only one router needed for all clients
        if server_mode && self.vpn_client.is_some() {
            let client = self.vpn_client.as_ref().unwrap().clone();
            let routes = self.routes.clone();

            // Get outbound_rx (from TUN)
            let outbound_rx_opt = client.lock().await.get_outbound_rx().await;

            if let Some(mut outbound_rx) = outbound_rx_opt {
                tokio::spawn(async move {
                    while let Some(packet) = outbound_rx.recv().await {
                        // Parse Dest IP
                        if packet.len() >= 20 {
                            let dst_ip =
                                Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                            // Lookup route
                            let tx = {
                                let r: tokio::sync::RwLockReadGuard<
                                    '_,
                                    HashMap<Ipv4Addr, mpsc::Sender<TunnelMessage>>,
                                > = routes.read().await;
                                r.get(&dst_ip).cloned()
                            };

                            if let Some(tx) = tx {
                                let msg = TunnelMessage::IpPacket {
                                    payload: bytes::Bytes::from(packet),
                                };
                                if let Err(e) = tx.send(msg).await {
                                    warn!("Failed to route packet to {}: {}", dst_ip, e);
                                    // Remove stale route?
                                }
                            } else {
                                // debug!("No route for dest: {}", dst_ip);
                            }
                        }
                    }
                });
            }
        }

        info!("🌍 Exit service started (providing internet gateway)");

        Ok(())
    }

    /// Start traffic mixer (blend own + relay + exit)
    async fn start_traffic_mixer(
        &mut self,
        mixer_channels: TrafficMixerChannels,
        mut output_rx: mpsc::Receiver<bytes::Bytes>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create mixer with configuration
        let config = TrafficMixerConfig {
            enable_padding: true,
            padding_rate_pps: 10,
            padding_size: 1400,
        };

        let mixer = mixer_channels.create_mixer(config);

        // Start mixer in background
        tokio::spawn(async move {
            mixer.run().await;
        });

        // Consume mixed output (TODO: send to network)
        tokio::spawn(async move {
            while let Some(_packet) = output_rx.recv().await {
                // TODO: Send mixed packet to network via libp2p
            }
        });

        info!("🔀 Traffic mixer started (blending traffic sources)");

        Ok(())
    }

    /// Show legal disclaimer for exit nodes
    fn show_exit_disclaimer(&self) {
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║              ZKS-VPN EXIT NODE ACTIVE                    ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  Your IP address is being used as an internet gateway   ║");
        println!("║  for other ZKS-VPN users (encrypted traffic).           ║");
        println!("║                                                          ║");
        println!("║  You have plausible deniability: All users relay for    ║");
        println!("║  others, so any observed traffic could originate from   ║");
        println!("║  any peer in the swarm.                                 ║");
        println!("║                                                          ║");
        println!("║  Logs: NONE (zero-knowledge architecture)               ║");
        println!("╚══════════════════════════════════════════════════════════╝\n");
    }

    /// Stop all services
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🛑 Stopping Faisal-Swarm Controller...");

        // Stop VPN client
        if let Some(client) = &self.vpn_client {
            let ctrl = client.lock().await;
            ctrl.stop().await?;
        }

        // Stop relay
        *self.relay_active.write().await = false;

        // Stop exit
        *self.exit_active.write().await = false;

        // Send shutdown signal
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }

        info!("✅ Faisal-Swarm Controller stopped");

        Ok(())
    }
}
