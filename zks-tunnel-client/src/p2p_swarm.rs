//! P2P Swarm Module - libp2p Integration for Faisal Swarm
//!
//! This module implements the core P2P networking layer using libp2p with:
//! - DCUtR (Direct Connection Upgrade through Relay) for NAT hole-punching
//! - Relay client for fallback when hole-punch fails
//! - Identify protocol for peer discovery

#![allow(dead_code)]

#[cfg(feature = "swarm")]
use futures::StreamExt;
#[cfg(feature = "swarm")]
use libp2p::{
    dcutr, identify, kad, noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, StreamProtocol, Swarm, SwarmBuilder,
};
#[cfg(feature = "swarm")]
use std::time::Duration;
#[cfg(feature = "swarm")]
use tracing::{debug, info, warn};

/// Combined network behavior for ZKS Swarm
#[cfg(feature = "swarm")]
#[derive(NetworkBehaviour)]
pub struct SwarmBehaviour {
    /// Relay client for connecting through relay servers
    relay_client: relay::client::Behaviour,
    /// DCUtR for direct connection upgrade (hole-punching)
    dcutr: dcutr::Behaviour,
    /// Identify protocol for peer info exchange
    identify: identify::Behaviour,
    /// Kademlia DHT for decentralized peer discovery
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Ping for keepalive and latency measurement
    ping: libp2p::ping::Behaviour,
}

/// Configuration for the P2P swarm
#[cfg(feature = "swarm")]
#[derive(Clone)]
pub struct SwarmConfig {
    /// Relay server multiaddress (e.g., /ip4/1.2.3.4/tcp/4001/p2p/QmRelay)
    pub relay_addr: Option<Multiaddr>,
    /// Listen port for incoming connections
    pub listen_port: u16,
    /// Signaling server URL (Cloudflare Worker)
    pub signaling_url: String,
    /// Room ID for peer discovery
    pub room_id: String,
}

#[cfg(feature = "swarm")]
impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            relay_addr: None,
            listen_port: 0, // Random port
            signaling_url: "wss://zks-tunnel-relay.md-wasif-faisal.workers.dev".to_string(),
            room_id: "faisal-swarm".to_string(),
        }
    }
}

/// Create and configure a new libp2p swarm for ZKS
#[cfg(feature = "swarm")]
pub async fn create_swarm(
    config: SwarmConfig,
) -> Result<(Swarm<SwarmBehaviour>, SwarmConfig), Box<dyn std::error::Error + Send + Sync>> {
    info!("🌐 Initializing libp2p swarm...");

    // Build the swarm with tokio runtime
    // Uses QUIC (lower latency, better NAT) + TCP (firewall fallback) + DNS + Relay
    // Chain order from official libp2p DCUtR example:
    // with_tcp() -> with_quic() -> with_dns()? -> with_relay_client()
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        // TCP transport with Noise encryption (firewall-friendly fallback)
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        // QUIC transport (lower latency, better NAT hole-punch)
        .with_quic()
        // DNS resolution for hostname support
        .with_dns()?
        // Relay client for NAT traversal when direct connection fails
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|keypair, relay_client| {
            // Build identify config
            let identify_config = identify::Config::new("/zks/1.0.0".to_string(), keypair.public());

            // Build Kademlia config
            let kad_store = kad::store::MemoryStore::new(keypair.public().to_peer_id());
            let kad_config = kad::Config::new(StreamProtocol::new("/zks/kad/1.0.0"));

            SwarmBehaviour {
                relay_client,
                dcutr: dcutr::Behaviour::new(keypair.public().to_peer_id()),
                identify: identify::Behaviour::new(identify_config),
                kademlia: kad::Behaviour::with_config(
                    keypair.public().to_peer_id(),
                    kad_store,
                    kad_config,
                ),
                ping: libp2p::ping::Behaviour::default(),
            }
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Get our peer ID
    let local_peer_id = *swarm.local_peer_id();
    info!("📍 Local Peer ID: {}", local_peer_id);

    // Listen on QUIC (primary - lower latency)
    let quic_addr: Multiaddr =
        format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.listen_port).parse()?;
    swarm.listen_on(quic_addr)?;

    // Listen on TCP (fallback - firewall-friendly)
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port).parse()?;
    swarm.listen_on(tcp_addr)?;

    info!("📶 Transports: QUIC (primary) + TCP (fallback)");

    // If relay address provided, connect to it
    if let Some(relay_addr) = &config.relay_addr {
        info!("📡 Connecting to relay: {}", relay_addr);
        swarm.dial(relay_addr.clone())?;

        // Listen via relay for incoming connections
        let relay_listen = relay_addr
            .clone()
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        swarm.listen_on(relay_listen)?;
    }

    Ok((swarm, config))
}

/// Run the swarm event loop
#[cfg(feature = "swarm")]
pub async fn run_swarm_loop(
    mut swarm: Swarm<SwarmBehaviour>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("🔄 Starting swarm event loop...");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("✅ Listening on: {}", address);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                // Show transport type used (QUIC or TCP)
                let addr = endpoint.get_remote_address().to_string();
                let transport = if addr.contains("quic") {
                    "QUIC ⚡"
                } else {
                    "TCP 🔌"
                };
                info!(
                    "🤝 Connected to peer: {} via {} [{}]",
                    peer_id, transport, addr
                );
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!("🔌 Disconnected from peer: {} ({:?})", peer_id, cause);
            }
            SwarmEvent::Behaviour(SwarmBehaviourEvent::Dcutr(event)) => {
                info!("🎯 DCUtR event: {:?}", event);
            }
            SwarmEvent::Behaviour(SwarmBehaviourEvent::RelayClient(event)) => {
                info!("📡 Relay event: {:?}", event);
            }
            SwarmEvent::Behaviour(SwarmBehaviourEvent::Identify(event)) => {
                debug!("🔍 Identify event: {:?}", event);
            }
            SwarmEvent::Behaviour(SwarmBehaviourEvent::Ping(event)) => {
                debug!("🏓 Ping event: {:?}", event);
            }
            SwarmEvent::Behaviour(SwarmBehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed { result, .. },
            )) => {
                match result {
                    kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                        providers,
                        ..
                    })) => {
                        for peer_id in providers {
                            info!("🕸️ DHT found peer: {}", peer_id);
                            // Swarm will automatically try to connect if we dial or if they are in our routing table?
                            // No, we should explicitly dial them if we are not connected.
                            // But for now, just logging. Kademlia might auto-connect depending on config.
                            // Let's explicitly dial.
                            let _ = swarm.dial(peer_id);
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(SwarmBehaviourEvent::Kademlia(event)) => {
                debug!("🕸️ Kademlia event: {:?}", event);
            }
            _ => {}
        }
    }
}

/// Run the complete swarm with signaling integration
/// This connects to the CF Worker, discovers peers, and manages the swarm
#[cfg(feature = "swarm")]
pub async fn run_swarm_with_signaling(
    config: SwarmConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::signaling::SignalingClient;

    // Create the swarm
    let (mut swarm, config) = create_swarm(config).await?;
    let local_peer_id = *swarm.local_peer_id();

    // Wait briefly for listeners to be established
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Collect our listening addresses
    let listen_addrs: Vec<Multiaddr> = swarm.listeners().cloned().collect();
    info!("📍 Our addresses: {:?}", listen_addrs);

    // Connect to signaling server
    match SignalingClient::connect(
        &config.signaling_url,
        &config.room_id,
        &local_peer_id,
        listen_addrs,
    )
    .await
    {
        Ok(mut signaling) => {
            info!("✅ Connected to signaling server");

            // Get peers from signaling
            match signaling.get_peers().await {
                Ok(peers) => {
                    info!("📥 Discovered {} peers", peers.len());

                    // Dial each discovered peer
                    for peer in peers {
                        if peer.peer_id != local_peer_id.to_string() {
                            let addrs = SignalingClient::parse_addrs(&peer.addrs);
                            for addr in addrs {
                                info!("📞 Dialing peer {} at {}", peer.peer_id, addr);
                                if let Err(e) = swarm.dial(addr.clone()) {
                                    warn!("⚠️ Failed to dial {}: {}", addr, e);
                                }

                                // Add to Kademlia DHT (Hybrid Discovery)
                                if let Ok(pid) = peer.peer_id.parse::<libp2p::PeerId>() {
                                    swarm.behaviour_mut().kademlia.add_address(&pid, addr);
                                }
                            }
                        }
                    }

                    // Bootstrap Kademlia after adding initial peers
                    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                        warn!("⚠️ Failed to bootstrap Kademlia: {}", e);
                    } else {
                        info!("🚀 Kademlia DHT bootstrapping started...");
                    }

                    // Announce ourselves in the room (DHT Content Routing)
                    let room_key = kad::RecordKey::new(&config.room_id.as_bytes());
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .kademlia
                        .start_providing(room_key.clone())
                    {
                        warn!("⚠️ Failed to announce presence in DHT: {}", e);
                    } else {
                        info!("📢 Announced presence in room '{}' via DHT", config.room_id);
                    }

                    // Look for other peers in the room (Decentralized Discovery)
                    swarm.behaviour_mut().kademlia.get_providers(room_key);
                    info!("🔍 Searching DHT for peers in room '{}'...", config.room_id);
                }
                Err(e) => {
                    warn!("⚠️ Failed to get peers: {}", e);
                }
            }
        }
        Err(e) => {
            warn!(
                "⚠️ Signaling connection failed: {}. Running in standalone mode.",
                e
            );
        }
    }

    // Run the main event loop
    run_swarm_loop(swarm).await
}
