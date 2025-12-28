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
            server_mode: false, // Role-based routing handled by p2p_vpn.rs
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

    /// Shared P2PRelay connection for SIGNALING ONLY (key exchange, peer discovery)
    signaling_relay: Option<Arc<crate::p2p_relay::P2PRelay>>,
    
    /// LibP2P transport for DIRECT DATA TRANSFER (DCUtR, 85% success)
    libp2p_transport: Option<crate::libp2p_transport::LibP2PTransport>,
    
    /// LibP2P swarm for DCUtR connections
    libp2p_swarm: Option<libp2p::Swarm<crate::libp2p_transport::TransportBehaviour>>,
    
    /// Data stream for VPN packets (via libp2p direct connection)
    data_stream: Option<libp2p::Stream>,

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
            signaling_relay: None,
            libp2p_transport: None,
            libp2p_swarm: None,
            data_stream: None,
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

        // ========== PHASE 1: SIGNALING (WebSocket) ==========
        // Establish P2P Relay for signaling only (key exchange, peer discovery)
        info!("📡 Phase 1: Establishing WebSocket signaling connection...");
        let signaling = crate::p2p_relay::P2PRelay::connect(
            &self.config.relay_url,
            &self.config.vernam_url,
            &self.config.room_id,
            crate::p2p_relay::PeerRole::Swarm,
            None,
        )
        .await?;
        self.signaling_relay = Some(signaling.clone());
        info!("✅ WebSocket signaling established (for key exchange only)");

        // ========== PHASE 2: LIBP2P TRANSPORT (DCUtR) ==========
        // Initialize libp2p transport for direct data transfer
        info!("🚀 Phase 2: Initializing LibP2P DCUtR transport...");
        match crate::libp2p_transport::LibP2PTransport::new(None).await {
            Ok((transport, swarm)) => {
                self.libp2p_transport = Some(transport);
                self.libp2p_swarm = Some(swarm);
                info!("✅ LibP2P transport initialized (QUIC 85% + TCP 70% hole-punch)");
            }
            Err(e) => {
                warn!("⚠️ LibP2P transport failed: {}. Falling back to WebSocket relay.", e);
                // Continue with WebSocket-only mode
            }
        }

        // Start VPN client service
        println!(
            "🔥 DEBUG: Checking enable_client: {}",
            self.config.enable_client
        );
        if self.config.enable_client {
            info!("🖥️  Starting VPN Client service...");
            self.start_vpn_client().await?;
            
            // Wire up incoming DCUtR packets to VPN interface
            if let Some(transport) = &self.libp2p_transport {
                if let Some(mut incoming_rx) = transport.take_incoming_rx().await {
                    if let Some(vpn_client) = self.vpn_client.clone() {
                        info!("🔌 Wiring up incoming DCUtR packets to VPN interface...");
                        tokio::spawn(async move {
                            while let Some(packet) = incoming_rx.recv().await {
                                // Inject into TUN interface
                                vpn_client.lock().await.inject_packet(packet).await;
                            }
                            warn!("⚠️ Incoming DCUtR packet stream closed");
                        });
                    }
                }
            }
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
        
        // ========== PHASE 3: DCUtR PEER INFO EXCHANGE ==========
        // After services are running, exchange peer info for direct P2P
        if let (Some(transport), Some(_swarm), Some(relay)) = (
            self.libp2p_transport.as_ref(),
            self.libp2p_swarm.as_ref(),
            self.signaling_relay.as_ref(),
        ) {
            info!("🔗 Phase 3: Exchanging PeerInfo for DCUtR hole-punch...");
            
            // Get our libp2p PeerId and addresses
            let our_peer_id = transport.local_peer_id().to_string();
            
            // Get listen addresses from swarm
            let our_addrs: Vec<String> = if let Some(swarm) = self.libp2p_swarm.as_ref() {
                // Get all listeners and external addresses
                let mut addrs: Vec<String> = swarm.listeners()
                    .map(|a| a.to_string())
                    .collect();
                
                // Also add any discovered external addresses (from identify protocol)
                for addr in swarm.external_addresses() {
                    addrs.push(addr.to_string());
                }
                
                info!("📍 Our listen addresses: {:?}", addrs);
                addrs
            } else {
                warn!("⚠️ No swarm available, using empty addresses");
                vec![]
            };
            
            // Send our PeerInfo to the remote peer
            if let Err(e) = relay.send_peer_info(our_peer_id.clone(), our_addrs).await {
                warn!("Failed to send PeerInfo: {}", e);
            }
            
            // Wait for remote peer's PeerInfo (10 second timeout)
            if let Some((remote_peer_id, remote_addrs)) = relay.wait_for_peer_info(10).await {
                info!("📍 Remote peer info received:");
                info!("   Peer ID: {}", remote_peer_id);
                info!("   Addresses: {:?}", remote_addrs);
                
                // Parse peer ID and multiaddrs for DCUtR attempt
                if let Ok(peer_id) = remote_peer_id.parse::<libp2p::PeerId>() {
                    let multiaddrs: Vec<libp2p::Multiaddr> = remote_addrs
                        .iter()
                        .filter_map(|addr| addr.parse().ok())
                        .collect();
                    
                    if !multiaddrs.is_empty() {
                        // Attempt DCUtR connection
                        match self.attempt_dcutr_connection(peer_id, multiaddrs).await {
                            Ok(true) => {
                                info!("🎉 DCUtR SUCCESS! Using direct P2P connection");
                                info!("   Expected latency improvement: 3-5x faster");
                            }
                            Ok(false) => {
                                info!("📡 DCUtR failed, using WebSocket relay (still functional)");
                            }
                            Err(e) => {
                                warn!("DCUtR connection error: {}", e);
                            }
                        }
                    } else {
                        info!("📡 No valid addresses for DCUtR, using WebSocket relay");
                    }
                } else {
                    warn!("Failed to parse remote peer ID: {}", remote_peer_id);
                }
            } else {
                info!("📡 No PeerInfo received, using WebSocket relay");
            }
        }
        
        if self.libp2p_transport.is_some() && self.data_stream.is_some() {
            info!("   - Transport: LibP2P DCUtR (Direct P2P, low latency ⚡)");
        } else if self.libp2p_transport.is_some() {
            info!("   - Transport: WebSocket Relay (fallback, higher latency)");
        } else {
            info!("   - Transport: WebSocket Relay only");
        }

        // Wait for shutdown signal
        let _ = self.shutdown_rx.lock().await.as_mut().unwrap().recv().await;

        Ok(())
    }

    /// Attempt DCUtR direct connection to a peer
    /// Returns true if direct connection established, false if should use WebSocket fallback
    #[allow(dead_code)]
    pub async fn attempt_dcutr_connection(
        &mut self,
        peer_id: libp2p::PeerId,
        peer_addrs: Vec<libp2p::Multiaddr>,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        use crate::libp2p_transport::TransportState;
        
        info!("🎯 Attempting DCUtR hole-punch to peer: {}", peer_id);
        
        // Check if we have libp2p transport
        let transport = self.libp2p_transport.as_mut();
        let swarm = self.libp2p_swarm.as_mut();
        
        match (transport, swarm) {
            (Some(transport), Some(swarm)) => {
                // Attempt DCUtR connection
                match transport.connect_to_peer(swarm, peer_id, peer_addrs).await {
                    Ok(()) => {
                        let state = transport.state().await;
                        match state {
                            TransportState::DirectConnected => {
                                info!("✅ DCUtR SUCCESS! Direct P2P connection established");
                                info!("   Expected latency: ~30-50ms (vs ~120-350ms via relay)");
                                
                                // Open VPN data stream
                                match transport.open_vpn_stream().await {
                                    Ok(stream) => {
                                        // Inject stream into signaling relay for use by P2PVpnController
                                        if let Some(relay) = &self.signaling_relay {
                                            let mut ds = relay.data_stream.lock().await;
                                            *ds = Some(stream); // P2PRelay will now use this stream!
                                            info!("✅ DCUtR stream injected into P2PRelay data path");
                                        }
                                        
                                        // Also keep a reference if needed (though P2PRelay takes ownership effectively)
                                        // self.data_stream = Some(stream); // Cannot clone stream easily
                                        
                                        info!("✅ VPN data stream opened (direct libp2p)");
                                        Ok(true)
                                    }
                                    Err(e) => {
                                        warn!("⚠️ Failed to open data stream: {}", e);
                                        Ok(false)
                                    }
                                }
                            }
                            TransportState::RelayConnected => {
                                info!("📡 Connected via libp2p relay (DCUtR failed, 15% case)");
                                info!("   Still better than Cloudflare WebSocket");
                                
                                // Open VPN data stream via libp2p relay
                                match transport.open_vpn_stream().await {
                                    Ok(stream) => {
                                        // Inject stream into signaling relay
                                        if let Some(relay) = &self.signaling_relay {
                                            let mut ds = relay.data_stream.lock().await;
                                            *ds = Some(stream);
                                            info!("✅ Relayed stream injected into P2PRelay data path");
                                        }
                                        
                                        info!("✅ VPN data stream opened (via libp2p relay)");
                                        Ok(true)
                                    }
                                    Err(e) => {
                                        warn!("⚠️ Failed to open data stream: {}", e);
                                        Ok(false)
                                    }
                                }
                            }
                            _ => {
                                warn!("❌ DCUtR connection failed, using WebSocket fallback");
                                Ok(false)
                            }
                        }
                    }
                    Err(e) => {
                        warn!("❌ DCUtR connection error: {}", e);
                        Ok(false)
                    }
                }
            }
            _ => {
                debug!("LibP2P transport not available, using WebSocket");
                Ok(false)
            }
        }
    }

    /// Get the data stream for direct P2P communication (if available)
    #[allow(dead_code)]
    pub fn data_stream(&mut self) -> Option<&mut libp2p::Stream> {
        self.data_stream.as_mut()
    }

    /// Check if using direct P2P connection
    #[allow(dead_code)]
    pub fn is_direct_p2p(&self) -> bool {
        self.data_stream.is_some()
    }

    /// Start VPN client (user's own traffic)
    async fn start_vpn_client(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("🔥 DEBUG: start_vpn_client ENTERED");

        #[cfg(feature = "vpn")]
        {
            println!("🔥 DEBUG: VPN FEATURE ENABLED");
            eprintln!("🔥 DEBUG: start_vpn_client CALLED (stderr)");
            println!("🔥 DEBUG: start_vpn_client CALLED (stdout)");
            // panic!("🔥 TEST PANIC: start_vpn_client called!");

            use crate::p2p_vpn::P2PVpnConfig;

            let config = P2PVpnConfig {
                relay_url: self.config.relay_url.clone(),
                room_id: self.config.room_id.clone(),
                vernam_url: self.config.vernam_url.clone(),
                device_name: "zks0".to_string(),
                address: self.config.vpn_address.parse().unwrap(),
                netmask: "255.255.0.0".parse().unwrap(),
                mtu: 1400,
                dns_protection: true,
                kill_switch: false,
                proxy: None,
                exit_peer_address: "10.0.85.2".parse().unwrap(),
                server_mode: self.config.server_mode,
                role: crate::p2p_relay::PeerRole::Swarm,
            };

            let controller = P2PVpnController::new(config, self.entropy_tax.clone());

            // CRITICAL FIX: Pass signaling relay to VPN client for key exchange
            // Data transfer will use libp2p DCUtR (direct P2P) when available
            if let Some(relay) = &self.signaling_relay {
                info!("🔗 Passing signaling relay to VPN client (for key exchange)");
                controller.set_shared_relay(relay.clone()).await;
            } else {
                warn!("⚠️ No signaling relay available - VPN client will create its own connection");
            }

            self.vpn_client = Some(Arc::new(Mutex::new(controller)));

            // Start VPN in background
            let client = self.vpn_client.as_ref().unwrap().clone();
            tokio::spawn(async move {
                println!("🔥 DEBUG: VPN client background task STARTED");
                println!("🔥 DEBUG: Acquiring VPN client lock...");
                let ctrl = client.lock().await;
                println!("🔥 DEBUG: VPN client lock acquired, calling start()...");
                if let Err(e) = ctrl.start().await {
                    eprintln!("🔥 DEBUG: VPN client error: {}", e);
                    error!("VPN client error: {}", e);
                } else {
                    println!("🔥 DEBUG: VPN client start() completed successfully");
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

        // Use the signaling relay connection for key exchange
        let relay = self
            .signaling_relay
            .as_ref()
            .ok_or("Signaling relay not initialized")?
            .clone();

        let vpn_client = self.vpn_client.clone();
        let server_mode = self.config.server_mode;
        let routes = self.routes.clone();
        let entropy_tax = self.entropy_tax.clone();

        tokio::spawn(async move {
            info!("🌍 Exit Service starting with shared relay connection...");

            // If in Server Mode, setup bidirectional forwarding with TUN
            if let (true, Some(client)) = (server_mode, vpn_client.as_ref()) {
                let client = client.clone();
                let routes = routes.clone();
                let entropy_tax_handler = entropy_tax.clone();

                // Create channel for sending TO clients (used by Outbound Router)
                let (client_tx, mut client_rx) = mpsc::channel(1000);
                let relay_send = relay.clone();
                let entropy_tax_send = entropy_tax_handler.clone();

                // Task: Rx from Channel -> Relay (Outbound from TUN)
                let _outbound_task = tokio::spawn(async move {
                    while let Some(msg) = client_rx.recv().await {
                        let msg_len = if let TunnelMessage::IpPacket { payload } = &msg {
                            payload.len()
                        } else {
                            0
                        };

                        if let Err(e) = relay_send.send(&msg).await {
                            warn!("Failed to send to relay: {}", e);
                            break;
                        }

                        if msg_len > 0 {
                            entropy_tax_send.lock().await.earn_tokens(msg_len as u64);
                        }
                    }
                });

                // Task: Rx from Relay -> TUN (Inbound to Exit)
                loop {
                    match relay.recv().await {
                        Ok(Some(msg)) => {
                            match msg {
                                TunnelMessage::IpPacket { payload } => {
                                    // 1. Learn Source IP
                                    if payload.len() >= 20 {
                                        let src_ip = Ipv4Addr::new(
                                            payload[12],
                                            payload[13],
                                            payload[14],
                                            payload[15],
                                        );

                                        // Update routing table
                                        {
                                            let mut r = routes.write().await;
                                            r.entry(src_ip).or_insert_with(|| {
                                                info!("🆕 Learned route: {} -> Client", src_ip);
                                                client_tx.clone()
                                            });
                                        }
                                    }

                                    // 2. Inject into TUN
                                    let payload_len = payload.len();
                                    client.lock().await.inject_packet(payload.to_vec()).await;

                                    // 3. Earn tokens
                                    entropy_tax_handler
                                        .lock()
                                        .await
                                        .earn_tokens(payload_len as u64);
                                }
                                _ => {
                                    debug!("Exit Service received non-IP message: {:?}", msg);
                                }
                            }
                        }
                        Ok(None) => {
                            warn!("Exit Service: Connection closed");
                            break;
                        }
                        Err(e) => {
                            warn!("Exit Service recv error: {}", e);
                            break;
                        }
                    }
                }
            } else {
                // Legacy/Placeholder mode (just keep alive)
                loop {
                    match relay.recv().await {
                        Ok(Some(_msg)) => {
                            // TODO: Forward to ExitService (SOCKS/HTTP)
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }

            warn!("Exit Service stopped");
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
        mut output_rx: mpsc::Receiver<crate::traffic_mixer::TrafficPacket>,
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
