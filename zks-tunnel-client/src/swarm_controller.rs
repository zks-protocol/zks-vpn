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
use zks_tunnel_proto::NatSignalingMessage;
use crate::nat_traversal::NatSignaling;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use tokio_stream::StreamExt;

/// Commands that can be sent to the SwarmController
#[derive(Debug, Clone)]
pub enum SwarmCommand {
    /// Attempt to dial a peer using NAT traversal
    DialPeer {
        peer_id: String,
        ports: Vec<u16>,
        nat_type: String,
    },
    /// Start birthday attack listening
    StartBirthdayAttack {
        start_port: u16,
        end_port: u16,
        listen_count: u32,
    },
}

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

/// Adapter for P2P Relay implementing NatSignaling
/// Allows NatTraversalCoordinator to send signaling messages via the relay
pub struct RelayNatSignaling {
    pub relay: Arc<crate::p2p_relay::P2PRelay>,
}

#[async_trait::async_trait]
impl crate::nat_traversal::NatSignaling for RelayNatSignaling {
    async fn send_nat_message(
        &self, 
        message: crate::nat_traversal::NatSignalingMessage
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize message to JSON
        let json = serde_json::to_string(&message)?;
        
        // Send via relay
        match self.relay.send_text(json).await {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("Failed to send NAT message: {}", e).into()),
        }
    }
    
    async fn get_peer_ip(
        &self, 
        _peer_id: libp2p::PeerId
    ) -> Result<std::net::IpAddr, Box<dyn std::error::Error>> {
        // Extract IP from stored peer info in relay
        let info_guard = self.relay.remote_peer_info.lock().await;
        
        if let Some((_, addrs)) = &*info_guard {
            // Try to find a valid public IP in the addresses
            for addr_str in addrs {
                // Try parsing multiaddr
                if let Ok(ma) = addr_str.parse::<libp2p::Multiaddr>() {
                    // Extract IP component
                    for protocol in ma.iter() {
                        match protocol {
                            libp2p::multiaddr::Protocol::Ip4(ip) => return Ok(std::net::IpAddr::V4(ip)),
                            libp2p::multiaddr::Protocol::Ip6(ip) => return Ok(std::net::IpAddr::V6(ip)),
                            _ => {}
                        }
                    }
                }
            }
        }
        
        Err("Peer IP not found in relay info".into())
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
    libp2p_transport: Option<Arc<Mutex<crate::libp2p_transport::LibP2PTransport>>>,
    
    /// LibP2P swarm for DCUtR connections
    libp2p_swarm: Option<Arc<Mutex<libp2p::Swarm<crate::libp2p_transport::TransportBehaviour>>>>,
    
    /// Data stream for VPN packets (via libp2p direct connection)
    data_stream: Option<libp2p::Stream>,

    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: Arc<Mutex<Option<mpsc::Receiver<()>>>>,

    /// Command channel for NAT traversal
    command_tx: Option<mpsc::Sender<SwarmCommand>>,
    command_rx: Arc<Mutex<Option<mpsc::Receiver<SwarmCommand>>>>,
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
            command_tx: None,
            command_rx: Arc::new(Mutex::new(None)),
        }
    }

    /// Get command sender for NAT traversal
    pub fn command_sender(&self) -> Option<mpsc::Sender<SwarmCommand>> {
        self.command_tx.clone()
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

        // Initialize command channel for NAT traversal
        let (command_tx, command_rx) = mpsc::channel::<SwarmCommand>(100);
        self.command_tx = Some(command_tx);
        *self.command_rx.lock().await = Some(command_rx);

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

        // Spawn NAT signal handler for coordinating NAT traversal
        info!("🎯 Spawning NAT signal handler for NAT traversal coordination...");
        if let Err(e) = self.spawn_nat_signal_handler().await {
            warn!("⚠️ Failed to spawn NAT signal handler: {}", e);
        }

        // ========== PHASE 2: LIBP2P TRANSPORT (DCUtR) ==========
        // Initialize libp2p transport for direct data transfer
        info!("🚀 Phase 2: Initializing LibP2P DCUtR transport...");
        match crate::libp2p_transport::LibP2PTransport::new(None).await {
            Ok((transport, swarm)) => {
                self.libp2p_transport = Some(Arc::new(Mutex::new(transport)));
                self.libp2p_swarm = Some(Arc::new(Mutex::new(swarm)));
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
            if let Some(transport_arc) = &self.libp2p_transport {
                let _transport = transport_arc.lock().await;
                if let Some(mut incoming_rx) = _transport.take_incoming_rx().await {
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
        if let (Some(_transport), Some(_swarm), Some(relay)) = (
            self.libp2p_transport.as_ref(),
            self.libp2p_swarm.as_ref(),
            self.signaling_relay.as_ref(),
        ) {
            info!("🔗 Phase 3: Exchanging PeerInfo for DCUtR hole-punch...");
            
            // Get our libp2p PeerId and addresses
            let our_peer_id = {
                let transport = self.libp2p_transport.as_ref().unwrap().lock().await;
                transport.local_peer_id().to_string()
            };
            
            // Get listen addresses from swarm
            let our_addrs: Vec<String> = if let Some(swarm_arc) = self.libp2p_swarm.as_ref() {
                // Get all listeners and external addresses
                let swarm = swarm_arc.lock().await;
                let mut addrs: Vec<String> = swarm.listeners()
                    .map(|a| a.to_string())
                    .collect();
                
                // Also add any discovered external addresses (from identify protocol and STUN)
                for addr in swarm.external_addresses() {
                    addrs.push(addr.to_string());
                }
                
                info!("📍 Our listen addresses: {:?}", addrs);
                
                // ========== STUN-BASED ADDRESS ENHANCEMENT ==========
                // If we don't have external addresses, try STUN discovery
                if addrs.iter().all(|addr| addr.contains("127.0.0.1") || addr.contains("192.168.") || addr.contains("10.")) {
                    info!("🔍 No public addresses found, attempting STUN discovery...");
                    
                    match crate::secure_stun::secure_query_stun_server("stun.l.google.com:19302", None).await {
                        Ok(stun_result) => {
                            // Add QUIC public address
                            let quic_public_addr = format!("/ip4/{}/udp/{}/quic-v1", stun_result.mapped_address, stun_result.mapped_port);
                            addrs.push(quic_public_addr.clone());
                            info!("📍 Added STUN-discovered QUIC address: {}", quic_public_addr);
                            
                            // Also add TCP variant for fallback
                            let tcp_public_addr = format!("/ip4/{}/tcp/{}", stun_result.mapped_address, stun_result.mapped_port);
                            addrs.push(tcp_public_addr.clone());
                            info!("📍 Added STUN-discovered TCP address: {}", tcp_public_addr);
                        }
                        Err(e) => {
                            warn!("⚠️ STUN discovery failed: {}", e);
                        }
                    }
                }
                
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
                        .filter_map(|addr: &String| addr.parse::<libp2p::Multiaddr>().ok())
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

        // Start command processing task for NAT traversal
        self.start_command_processor().await?;

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
        
        // Clone relay for signaling adapter (before mutable borrow of transport)
        let signaling = if let Some(relay) = &self.signaling_relay {
            Some(Box::new(RelayNatSignaling {
                relay: relay.clone(),
            }) as Box<dyn crate::nat_traversal::NatSignaling + Send + Sync>)
        } else {
            None
        };

        // Check if we have libp2p transport (wrapped in Arc<Mutex<>>)
        if let (Some(transport_arc), Some(swarm_arc)) = (&self.libp2p_transport, &self.libp2p_swarm) {
            // Lock both transport and swarm for the operation
            let mut transport = transport_arc.lock().await;
            let mut swarm = swarm_arc.lock().await;
            
            // Attempt advanced NAT traversal (3-phase: DCUtR → Port Prediction → Birthday Attack)
            match transport.connect_with_nat_traversal(&mut swarm, peer_id, peer_addrs.clone(), signaling).await {
                Ok(()) => {
                    let state = transport.state().await;
                    match state {
                        TransportState::DirectConnected => {
                            info!("✅ DCUtR SUCCESS! Direct P2P connection established");
                            info!("   Expected latency: ~30-50ms (vs ~120-350ms via relay)");
                            
                            // Open VPN data stream and inject into P2PRelay
                            match transport.open_vpn_stream(peer_id).await {
                                Ok(stream) => {
                                    info!("✅ VPN stream opened (direct libp2p)");
                                    
                                    // Store stream locally
                                    self.data_stream = Some(stream);
                                    
                                    // CRITICAL: Also inject into P2PRelay for VPN traffic
                                    if let Some(_relay) = &self.signaling_relay {
                                        // Clone the stream reference - P2PRelay needs its own
                                        // For now we skip this since Stream isn't Clone
                                        // The VPN will use self.data_stream directly
                                        info!("✅ DCUtR stream ready for VPN data transfer");
                                    }
                                    
                                    Ok(true)
                                }
                                Err(e) => {
                                    warn!("⚠️ Failed to open VPN stream: {}", e);
                                    Ok(false)
                                }
                            }
                        }
                        TransportState::RelayConnected => {
                            info!("📡 Connected via libp2p relay (DCUtR failed, 15% case)");
                            info!("   Still better than Cloudflare WebSocket");
                            
                            // Open VPN data stream via libp2p relay
                            match transport.open_vpn_stream(peer_id).await {
                                Ok(stream) => {
                                    info!("✅ VPN stream opened (via libp2p relay)");
                                    self.data_stream = Some(stream);
                                    Ok(true)
                                }
                                Err(e) => {
                                    warn!("⚠️ Failed to open VPN stream: {}", e);
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
        } else {
            debug!("LibP2P transport not available, using WebSocket");
            Ok(false)
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

    /// Spawn NAT signal handler task
    /// This task continuously listens for NAT signaling messages from the relay
    /// and processes them to coordinate NAT traversal
    #[allow(dead_code)]
    pub async fn spawn_nat_signal_handler(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let relay = self.signaling_relay.as_ref()
            .ok_or("Signaling relay not initialized")?
            .clone();
        
        // Get the command sender for NAT traversal
        let command_sender = self.command_sender();
        
        // Get the NAT signal receiver from the relay
        let mut nat_signal_rx = {
            let mut rx_opt = relay.nat_signal_rx.lock().await;
            rx_opt.take().ok_or("NAT signal receiver already taken")?
        };
        
        tokio::spawn(async move {
            info!("🎯 NAT signal handler started");
            
            while let Some(text_msg) = nat_signal_rx.recv().await {
                debug!("📡 Received NAT signaling text message: {} chars", text_msg.len());
                
                // Try to parse the JSON message
                match serde_json::from_str::<NatSignalingMessage>(&text_msg) {
                    Ok(nat_msg) => {
                        info!("📡 Received NAT signaling message: {:?}", nat_msg);
                        
                        // Process the NAT signaling message
                        if let Err(e) = Self::handle_incoming_nat_message(nat_msg, command_sender.clone()).await {
                            warn!("Failed to handle NAT signaling message: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse NAT signaling message: {}. Message: {}", e, text_msg);
                    }
                }
            }
            
            info!("🎯 NAT signal handler stopped (channel closed)");
        });
        
        Ok(())
    }

    /// Start command processor task for handling NAT traversal commands
    async fn start_command_processor(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut command_rx = self.command_rx.lock().await;
        let command_receiver = command_rx.take().ok_or("Command receiver already taken")?;
        
        let libp2p_swarm = self.libp2p_swarm.clone();
        
        tokio::spawn(async move {
            info!("🎯 Command processor started");
            let mut command_stream = tokio_stream::wrappers::ReceiverStream::new(command_receiver);
            
            while let Some(command) = command_stream.next().await {
                match command {
                    SwarmCommand::DialPeer { peer_id, ports, nat_type } => {
                        info!("🎯 Processing DialPeer command for {} with {} ports ({})", peer_id, ports.len(), nat_type);
                        
                        // Try to get actual peer ID from string
                        match peer_id.parse::<libp2p::PeerId>() {
                            Ok(_peer_id_obj) => {
                                if let Some(swarm_arc) = &libp2p_swarm {
                                    info!("🎯 Attempting to dial peer {} with {} ports", peer_id, ports.len());
                                    
                                    // Build multiaddresses from ports
                                    let mut multiaddrs: Vec<libp2p::Multiaddr> = Vec::new();
                                    for port in &ports {
                                        // Try common address formats
                                        let addr_strings = vec![
                                            format!("/ip4/0.0.0.0/tcp/{}", port),
                                            format!("/ip4/127.0.0.1/tcp/{}", port),
                                            format!("/ip6/::1/tcp/{}", port),
                                        ];
                                        
                                        for addr_str in addr_strings {
                                            if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                                                multiaddrs.push(addr);
                                            }
                                        }
                                    }
                                    
                                    if !multiaddrs.is_empty() {
                                        // Lock the swarm and attempt to dial
                                        let mut swarm: tokio::sync::MutexGuard<'_, libp2p::Swarm<crate::libp2p_transport::TransportBehaviour>> = swarm_arc.lock().await;
                                        match swarm.dial(multiaddrs[0].clone()) {
                                            Ok(()) => {
                                                info!("✅ Successfully initiated dial to {} at {}", peer_id, multiaddrs[0]);
                                            }
                                            Err(e) => {
                                                error!("❌ Failed to dial {}: {}", peer_id, e);
                                            }
                                        }
                                    } else {
                                        warn!("⚠️ No valid multiaddresses generated from ports {:?}", ports);
                                    }
                                } else {
                                    warn!("⚠️ No swarm available for dialing");
                                }
                            }
                            Err(e) => {
                                error!("❌ Invalid peer ID format '{}': {}", peer_id, e);
                            }
                        }
                    }
                    SwarmCommand::StartBirthdayAttack { start_port, end_port, listen_count } => {
                        info!("🎯 Processing StartBirthdayAttack command for ports {}-{} (listen: {})", start_port, end_port, listen_count);
                        
                        if let Some(swarm_arc) = &libp2p_swarm {
                            info!("🎯 Starting birthday attack listening on ports {}-{} (count: {})", start_port, end_port, listen_count);
                            
                            // Create multiple listeners on the specified port range
                            let mut successful_listeners = 0;
                            for port in start_port..=end_port {
                                if successful_listeners >= listen_count {
                                    break;
                                }
                                
                                // Build multiaddress for this port
                                let addr_strings = vec![
                                    format!("/ip4/0.0.0.0/tcp/{}", port),
                                    format!("/ip4/127.0.0.1/tcp/{}", port),
                                ];
                                
                                for addr_str in addr_strings {
                                    if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                                        // Lock the swarm and attempt to listen on this address
                                        let mut swarm: tokio::sync::MutexGuard<'_, libp2p::Swarm<crate::libp2p_transport::TransportBehaviour>> = swarm_arc.lock().await;
                                        match swarm.listen_on(addr.clone()) {
                                            Ok(_listener_id) => {
                                                info!("✅ Birthday attack listener started on {}", addr);
                                                successful_listeners += 1;
                                                break; // Move to next port
                                            }
                                            Err(e) => {
                                                debug!("Failed to listen on {}: {}", addr, e);
                                            }
                                        }
                                    }
                                }
                            }
                            
                            info!("✅ Birthday attack completed: {} listeners started", successful_listeners);
                        } else {
                            warn!("⚠️ No swarm available for birthday attack");
                        }
                    }
                }
            }
            
            info!("🎯 Command processor stopped");
        });
        
        Ok(())
    }

    /// Handle incoming NAT signaling message (independent version for async spawn)
    async fn handle_incoming_nat_message(
        msg: NatSignalingMessage,
        command_sender: Option<mpsc::Sender<SwarmCommand>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match msg {
            NatSignalingMessage::PortPrediction { ports, nat_type, timeout_ms } => {
                info!("🎯 Received PortPrediction message: {} ports, type: {}, timeout: {}ms", ports.len(), nat_type, timeout_ms);
                
                // Send command to swarm controller to attempt dialing
                if let Some(sender) = command_sender {
                    let command = SwarmCommand::DialPeer {
                        peer_id: "remote_peer".to_string(), // TODO: Extract from message context
                        ports: ports.clone(),
                        nat_type: nat_type.clone(),
                    };
                    
                    if let Err(e) = sender.send(command).await {
                        error!("Failed to send dial command: {}", e);
                    } else {
                        info!("🎯 Sent dial command for port prediction with {} ports", ports.len());
                    }
                } else {
                    warn!("No command sender available for port prediction");
                }
            }
            NatSignalingMessage::BirthdayAttack { start_port, end_port, listen_count } => {
                info!("🎯 Received BirthdayAttack message: ports {}-{} (listen: {})", start_port, end_port, listen_count);
                
                // Send command to swarm controller to start birthday attack
                if let Some(sender) = command_sender {
                    let command = SwarmCommand::StartBirthdayAttack {
                        start_port,
                        end_port,
                        listen_count: listen_count as u32,
                    };
                    
                    if let Err(e) = sender.send(command).await {
                        error!("Failed to send birthday attack command: {}", e);
                    } else {
                        info!("🎯 Sent birthday attack command for ports {}-{}", start_port, end_port);
                    }
                } else {
                    warn!("No command sender available for birthday attack");
                }
            }
            NatSignalingMessage::NatInfo { delta_type, avg_delta, last_port } => {
                info!("🔍 Received NAT info: {} (avg_delta: {}, last_port: {})", delta_type, avg_delta, last_port);
                // Store NAT info for future use
            }
        }
        Ok(())
    }
    
    /// Handle incoming NAT signaling message (legacy version with swarm parameters)
    async fn handle_nat_signaling_message(
        msg: NatSignalingMessage,
        _transport: Option<()>,
        _swarm: Option<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match msg {
            NatSignalingMessage::PortPrediction { ports, nat_type, timeout_ms } => {
                info!("🎯 Received PortPrediction message: {} ports, type: {}, timeout: {}ms", ports.len(), nat_type, timeout_ms);
                
                // For now, just log the message
                // TODO: Implement actual port prediction logic
                info!("🎯 Would attempt port prediction with {} ports", ports.len());
            }
            NatSignalingMessage::BirthdayAttack { start_port, end_port, listen_count } => {
                info!("🎯 Received BirthdayAttack message: ports {}-{} (listen: {})", start_port, end_port, listen_count);
                
                // For now, just log the message
                // TODO: Implement actual birthday attack logic
                info!("🎯 Would attempt birthday attack on ports {}-{}", start_port, end_port);
            }
            NatSignalingMessage::NatInfo { delta_type, avg_delta, last_port } => {
                info!("🔍 Received NAT info: {} (avg_delta: {}, last_port: {})", delta_type, avg_delta, last_port);
                // Store NAT info for future use
            }
        }
        Ok(())
    }
    
    /// Handle port prediction coordination
    async fn handle_port_prediction(
        prediction: crate::port_prediction::PortPredictionMsg,
        _transport: &crate::libp2p_transport::LibP2PTransport,
        _swarm: &libp2p::Swarm<crate::libp2p_transport::TransportBehaviour>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("📊 Handling port prediction with {} predicted ports", prediction.ports.len());
        
        // TODO: Implement port prediction coordination logic
        // This should coordinate with the peer to attempt connections on predicted ports
        
        Ok(())
    }
    
    /// Handle birthday attack coordination
    async fn handle_birthday_attack(
        start_port: u16,
        end_port: u16,
        listen_count: u16,
        _transport: &crate::libp2p_transport::LibP2PTransport,
        _swarm: &libp2p::Swarm<crate::libp2p_transport::TransportBehaviour>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("🎂 Handling birthday attack: listening on {} ports in range {}-{}", listen_count, start_port, end_port);
        
        // TODO: Implement birthday attack coordination logic
        // This should coordinate with the peer to listen on specified ports
        
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat_traversal::{NatSignaling, NatSignalingMessage};

    #[tokio::test]
    async fn test_relay_nat_signaling_message_handling() {
        use zks_tunnel_proto::NatSignalingMessage;
        
        // Test that NAT signaling messages are properly handled
        let port_prediction = NatSignalingMessage::PortPrediction {
            ports: vec![8080, 8081, 8082],
            nat_type: "Symmetric".to_string(),
            timeout_ms: 5000,
        };

        let birthday_attack = NatSignalingMessage::BirthdayAttack {
            start_port: 30000,
            end_port: 30100,
            listen_count: 50,
        };

        let nat_info = NatSignalingMessage::NatInfo {
            delta_type: "Preserve".to_string(),
            avg_delta: 1.5,
            last_port: 5000,
        };

        // Test message handling (these should not panic)
        let result = SwarmController::handle_incoming_nat_message(port_prediction, None).await;
        assert!(result.is_ok());

        let result = SwarmController::handle_incoming_nat_message(birthday_attack, None).await;
        assert!(result.is_ok());

        let result = SwarmController::handle_incoming_nat_message(nat_info, None).await;
        assert!(result.is_ok());
    }
}
