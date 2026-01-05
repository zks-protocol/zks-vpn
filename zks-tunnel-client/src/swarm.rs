//! Swarm Connection Module
//!
//! Implements a unified state machine for the ZKS Swarm protocol.
//! Replaces the scattered logic in p2p_relay.rs and signaling.rs.
//!
//! Architecture:
//! - Single `SwarmConnection` struct owns the WebSocket and all state
//! - Explicit `SwarmState` enum tracks connection progress
//! - Synchronous state transitions (no background tasks for handshake)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::{info, warn};
use url::Url;

use crate::entropy_tax::EntropyTax;
use crate::exit_service::{ExitPacket, ExitPolicy, ExitService};
use crate::key_exchange::KeyExchange;
use crate::p2p_relay::{PeerRole, WasifVernam};
use crate::relay_service::{RelayPacket, RelayService};
use crate::traffic_mixer::{TrafficMixer, TrafficMixerConfig, TrafficPacket};

use bytes::Bytes;
use tokio::sync::mpsc;

// ... existing code ...

/// Swarm Node Orchestrator
/// Manages the 3 concurrent roles: Client, Relay, Exit
pub struct SwarmNode {
    config: SwarmConfig,
    connection: SwarmConnection,

    // Services
    relay_service: Option<RelayService>,
    exit_service: Option<ExitService>,
    traffic_mixer: Option<TrafficMixer>,

    // Channels
    client_tx: Option<mpsc::Sender<crate::traffic_mixer::TrafficPacket>>,
    relay_tx: Option<mpsc::Sender<RelayPacket>>,
    exit_tx: Option<mpsc::Sender<ExitPacket>>,

    // State
    entropy_tax: Arc<Mutex<EntropyTax>>,
}

impl SwarmNode {
    pub fn new(config: SwarmConfig) -> Self {
        Self {
            config: config.clone(),
            connection: SwarmConnection::new(config),
            relay_service: None,
            exit_service: None,
            traffic_mixer: None,
            client_tx: None,
            relay_tx: None,
            exit_tx: None,
            entropy_tax: Arc::new(Mutex::new(EntropyTax::new())),
        }
    }

    pub async fn run(mut self) -> Result<(), String> {
        info!("🐝 SwarmNode starting...");

        // 1. Initialize Services & Channels
        let (mixer_channels, mut output_rx) = crate::traffic_mixer::create_channels();
        let (relay_tx, relay_rx) = crate::relay_service::create_relay_channels();
        let (exit_tx, exit_rx) = crate::exit_service::create_exit_channels();

        // Client channel (from SOCKS5 to Mixer)
        let (client_tx, _client_rx) = mpsc::channel(1000);
        self.client_tx = Some(client_tx);
        self.relay_tx = Some(relay_tx);
        self.exit_tx = Some(exit_tx);

        // 2. Create Services
        let relay_service = RelayService::new(
            relay_rx,
            mixer_channels.relay_tx.clone(),
            self.entropy_tax.clone(),
        );

        let exit_service = ExitService::new(
            exit_rx,
            mixer_channels.exit_tx.clone(),
            ExitPolicy::default(),
            self.entropy_tax.clone(),
        );

        // Mixer needs to be constructed with the channels we created
        // But TrafficMixer::new takes receivers.
        // create_channels returns (TrafficMixerChannels, output_rx)
        // TrafficMixerChannels has create_mixer method.
        let traffic_mixer = mixer_channels.create_mixer(TrafficMixerConfig::default());

        // 3. Connect to Swarm
        self.connection.connect().await?;

        // 4. Run Services concurrently
        let relay_handle = tokio::spawn(relay_service.run());
        let exit_handle = tokio::spawn(exit_service.run());
        let mixer_handle = tokio::spawn(traffic_mixer.run());

        // 5. Main Loop: Route traffic between Connection and Mixer/Services
        let my_peer_id = self.connection.my_peer_id().await;

        loop {
            tokio::select! {
                // 1. Outgoing Traffic (Mixed) -> Send to Swarm
                Some(packet) = output_rx.recv() => {
                    let (target, payload) = match packet {
                        TrafficPacket::ClientTraffic { target, data } => {
                            // Client traffic is usually TunnelMessage encoded
                            // Prefix with 0x01 (Direct)
                            let mut p = vec![0x01];
                            p.extend_from_slice(&data);
                            (target, p)
                        }
                        TrafficPacket::ExitTraffic { target, session_id: _, data } => {
                            // Exit traffic (response)
                            // Prefix with 0x01 (Direct)
                            // Note: We assume data is already in correct format (e.g. TunnelMessage)
                            // or the receiver knows how to handle it.
                            let mut p = vec![0x01];
                            p.extend_from_slice(&data);
                            (target, p)
                        }
                        TrafficPacket::RelayTraffic { peer_id, data } => {
                            // Relayed traffic. 'data' is the inner payload which already has the prefix.
                            (peer_id, data.to_vec())
                        }
                        TrafficPacket::Padding { size: _size } => {
                            // Padding - send to random peer or broadcast?
                            // For now, skip
                            continue;
                        }
                    };

                    if target.is_empty() { continue; }

                    // Construct SwarmMessage: [TargetLen(1) | Target | Payload]
                    let target_bytes = target.as_bytes();
                    if target_bytes.len() > 255 {
                        tracing::warn!("Target ID too long: {}", target);
                        continue;
                    }

                    let mut msg = Vec::with_capacity(1 + target_bytes.len() + payload.len());
                    msg.push(target_bytes.len() as u8);
                    msg.extend_from_slice(target_bytes);
                    msg.extend_from_slice(&payload);

                    if let Err(e) = self.connection.send_binary(&msg).await {
                        tracing::warn!("Failed to send packet to {}: {}", target, e);
                    }
                }

                // 2. Incoming Events from Connection
                event_res = self.connection.next_event() => {
                    match event_res {
                        Ok(SwarmEvent::PacketReceived(data)) => {
                            // Parse SwarmMessage
                            if data.len() < 1 { continue; }
                            let target_len = data[0] as usize;
                            if data.len() < 1 + target_len { continue; }

                            let target = String::from_utf8_lossy(&data[1..1+target_len]);
                            let payload = &data[1+target_len..];

                            if target == my_peer_id {
                                // It's for me!
                                if payload.is_empty() { continue; }
                                let msg_type = payload[0];
                                let msg_data = &payload[1..];

                                match msg_type {
                                    0x01 => { // Direct
                                        // Could be for ExitService or ClientService
                                        // We try to dispatch to both?
                                        // Or check if we are running ExitService?

                                        // If we have ExitService, try to parse as ExitPacket?
                                        // But ExitPacket is internal struct.
                                        // The wire format is likely TunnelMessage.

                                        // TODO: Proper dispatch based on content
                                        // For now, if we have ExitService, send there.
                                        // If we have ClientService (pending), send there.

                                        // Since we haven't implemented ClientService fully yet,
                                        // and ExitService expects ExitPacket (which we can't easily construct from raw bytes without parsing),
                                        // we'll just log for now.
                                        tracing::debug!("Received Direct message ({} bytes)", msg_data.len());
                                    }
                                    0x02 => { // Relay (Control?)
                                        // If we implement P2P relaying control messages
                                    }
                                    _ => {}
                                }
                            } else {
                                // Not for me. Am I a Relay?
                                if self.relay_service.is_some() {
                                    // Forward to RelayService
                                    // Construct RelayPacket
                                    let relay_packet = RelayPacket {
                                        from_peer: "unknown".to_string(), // We don't know sender from SwarmMessage
                                        to_peer: target.to_string(),
                                        data: Bytes::copy_from_slice(payload), // The whole payload (including prefix)
                                        seq: 0,
                                    };

                                    if let Some(tx) = &self.relay_tx {
                                        let _ = tx.send(relay_packet).await;
                                    }
                                }
                            }
                        }
                        Ok(SwarmEvent::PeerJoined(peer_id)) => {
                            tracing::info!("Peer joined: {}", peer_id);
                        }
                        Ok(SwarmEvent::None) => {}
                        Err(e) => {
                            tracing::error!("Connection error: {}", e);
                            // TODO: Reconnect logic
                            break;
                        }
                    }
                }
            }
        }

        // Cleanup
        let _ = tokio::join!(relay_handle, exit_handle, mixer_handle);

        Ok(())
    }
}

// Re-use existing message types where possible, or define new ones if needed
// For now, we'll redefine the essential ones to ensure cleanliness,
// and eventually replace the old ones.

#[derive(Debug)]
pub enum SwarmState {
    /// Initial state
    Disconnected,

    /// WebSocket connected, sent Join, waiting for Joined/Welcome
    Handshaking { sent_join: Instant },

    /// Authenticated, waiting for peers to join/exchange keys
    Peering {
        my_peer_id: String,
        // Track state of each peer we are connecting to
        peers: HashMap<String, PeerHandshakeState>,
        // Our key exchange keypair
        key_exchange: KeyExchange,
    },

    /// Fully connected, TUN device active, exchanging traffic
    Ready {
        my_peer_id: String,
        cipher: WasifVernam,
        // Keep track of peers for stats/maintenance
        peers: Vec<String>,
    },

    /// Failed state
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerHandshakeState {
    /// We know about them, haven't started exchange
    Discovered,
    /// Sent AuthInit, waiting for response
    SentAuthInit,
    /// Received AuthInit, sent response (or waiting to send)
    ReceivedAuthInit,
    /// Key exchange complete
    Completed { shared_secret: Zeroizing<[u8; 32]> },
}

#[derive(Clone, Debug)]
pub struct SwarmConfig {
    pub relay_url: String,
    pub room_id: String,
    pub role: PeerRole,
    // Add other config as needed
}

struct SwarmShared {
    state: SwarmState,
    config: SwarmConfig,
}

#[derive(Clone)]
pub struct SwarmConnection {
    shared: Arc<Mutex<SwarmShared>>,
    ws_writer: Arc<Mutex<Option<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>>,
    ws_reader: Arc<Mutex<Option<SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>>>>,
}

impl SwarmConnection {
    pub fn new(config: SwarmConfig) -> Self {
        Self {
            shared: Arc::new(Mutex::new(SwarmShared {
                state: SwarmState::Disconnected,
                config,
            })),
            ws_writer: Arc::new(Mutex::new(None)),
            ws_reader: Arc::new(Mutex::new(None)),
        }
    }
}

#[derive(Debug)]
pub enum SwarmEvent {
    None,
    PacketReceived(Vec<u8>),
    PeerJoined(String),
}

impl SwarmConnection {
    // ... existing new() ...

    /// Connect to the relay and perform handshake
    /// This is an async method that drives the state machine until Ready or Failed
    /// Connect to the relay and perform handshake
    /// This is an async method that drives the state machine until Ready or Failed
    /// Connect to the relay and perform handshake
    /// This is an async method that drives the state machine until Ready or Failed
    pub async fn connect(&self) -> Result<(), String> {
        info!("🚀 SwarmConnection: Starting connection sequence...");

        // 1. Connect WebSocket
        self.connect_websocket().await?;

        // 2. Drive state machine until Ready
        loop {
            let is_ready = {
                let guard = self.shared.lock().await;
                match &guard.state {
                    SwarmState::Ready { .. } => true,
                    SwarmState::Failed { reason } => return Err(reason.clone()),
                    _ => false,
                }
            };

            if is_ready {
                info!("✅ SwarmConnection: Ready!");
                return Ok(());
            }

            // Process next event
            let _event = self.step().await?;
        }
    }

    pub async fn next_event(&self) -> Result<SwarmEvent, String> {
        self.step().await
    }

    async fn connect_websocket(&self) -> Result<(), String> {
        let (relay_url, room_id) = {
            let guard = self.shared.lock().await;
            (guard.config.relay_url.clone(), guard.config.room_id.clone())
        };

        let url = Url::parse(&relay_url).map_err(|e| format!("Invalid URL: {}", e))?;

        // Construct room URL: /room/<room_id>?role=swarm
        let mut room_url = url.clone();
        if !room_url.path().starts_with("/room/") {
            room_url.set_path(&format!("/room/{}", room_id));
        }
        room_url.set_query(Some("role=swarm"));

        info!("Connecting to relay: {}", room_url);

        let (ws_stream, response) = connect_async(room_url.to_string())
            .await
            .map_err(|e| format!("WebSocket connection failed: {}", e))?;

        info!("WebSocket connected with status: {}", response.status());

        let (write, read) = ws_stream.split();
        *self.ws_writer.lock().await = Some(write);
        *self.ws_reader.lock().await = Some(read);

        // Send Join message immediately
        let my_peer_id = self.generate_peer_id();
        let join_msg = serde_json::json!({
            "type": "join",
            "peer_id": my_peer_id,
            "addrs": [],
            "room_id": room_id
        });

        self.send_json(&join_msg).await?;

        {
            let mut guard = self.shared.lock().await;
            guard.state = SwarmState::Handshaking {
                sent_join: Instant::now(),
            };
        }

        Ok(())
    }

    async fn step(&self) -> Result<SwarmEvent, String> {
        // Read next message from WebSocket
        let msg = {
            let mut reader_guard = self.ws_reader.lock().await;
            let reader = reader_guard.as_mut().ok_or("WebSocket not connected")?;

            match reader.next().await {
                Some(Ok(msg)) => msg,
                Some(Err(e)) => return Err(format!("WebSocket error: {}", e)),
                None => return Err("WebSocket closed".to_string()),
            }
        };

        match msg {
            Message::Text(text) => {
                self.handle_text_message(&text).await?;
                Ok(SwarmEvent::None)
            }
            Message::Binary(data) => self.handle_binary_message(data).await,
            Message::Close(_) => Err("Relay closed connection".to_string()),
            Message::Ping(_) | Message::Pong(_) => Ok(SwarmEvent::None),
            Message::Frame(_) => Ok(SwarmEvent::None),
        }
    }

    async fn handle_text_message(&self, text: &str) -> Result<(), String> {
        // Parse JSON
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {}", e))?;

        let msg_type = v["type"].as_str().unwrap_or("");

        let mut guard = self.shared.lock().await;

        match &mut guard.state {
            SwarmState::Handshaking { .. } => {
                if msg_type == "joined" || msg_type == "welcome" {
                    let your_id = v["your_id"]
                        .as_str()
                        .or_else(|| v["peer_id"].as_str()) // Fallback
                        .ok_or("Missing peer_id in joined message")?
                        .to_string();

                    info!("✅ Joined room as {}", your_id);

                    // Transition to Peering
                    guard.state = SwarmState::Peering {
                        my_peer_id: your_id,
                        peers: HashMap::new(),
                        key_exchange: KeyExchange::new(&guard.config.room_id),
                    };
                    return Ok(());
                }
            }
            SwarmState::Peering {
                my_peer_id,
                peers,
                key_exchange,
            } => {
                match msg_type {
                    "peer_joined" => {
                        let peer_id = v["peer"]["peer_id"]
                            .as_str()
                            .or_else(|| v["peer_id"].as_str())
                            .unwrap_or("");

                        if !peer_id.is_empty() && peer_id != *my_peer_id {
                            info!("New peer joined: {}", peer_id);
                            peers.insert(peer_id.to_string(), PeerHandshakeState::Discovered);

                            // Initiate Key Exchange if we are the "Master" (lexicographically lower ID)
                            if my_peer_id.as_str() < peer_id {
                                info!("Initiating key exchange with {}", peer_id);
                                let auth_init =
                                    key_exchange.create_auth_init().map_err(|e| e.to_string())?;
                                let msg = serde_json::json!({
                                    "type": "auth_init",
                                    "payload": auth_init,
                                    "target": peer_id
                                });
                                self.send_json(&msg).await?;
                                peers.insert(peer_id.to_string(), PeerHandshakeState::SentAuthInit);
                            }
                        }
                    }
                    "auth_init" => {
                        // Handle incoming AuthInit
                        info!("Received AuthInit");
                    }
                    _ => {}
                }

                // For Phase 1 testing, force transition to Ready
                let ready = true;

                if ready {
                    guard.state = SwarmState::Ready {
                        my_peer_id: my_peer_id.clone(),
                        cipher: WasifVernam::new([0u8; 32], vec![0u8; 32]), // Dummy
                        peers: peers.keys().cloned().collect(),
                    };
                    return Ok(());
                }
            }
            SwarmState::Ready { .. } => {
                if msg_type == "peer_joined" {
                    info!("Peer joined while Ready");
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn handle_binary_message(&self, data: Vec<u8>) -> Result<SwarmEvent, String> {
        let mut guard = self.shared.lock().await;
        match &mut guard.state {
            SwarmState::Ready { cipher, .. } => {
                // Decrypt
                match cipher.decrypt(&data) {
                    Ok(decrypted) => Ok(SwarmEvent::PacketReceived(decrypted)),
                    Err(e) => {
                        warn!("Decryption failed: {}", e);
                        Ok(SwarmEvent::None)
                    }
                }
            }
            _ => {
                warn!(
                    "Received {} bytes of binary data in non-Ready state",
                    data.len()
                );
                Ok(SwarmEvent::None)
            }
        }
    }

    pub async fn send_binary(&self, data: &[u8]) -> Result<(), String> {
        let encrypted = {
            let mut guard = self.shared.lock().await;
            match &mut guard.state {
                SwarmState::Ready { cipher, .. } => {
                    cipher.encrypt(data).map_err(|e| e.to_string())?
                }
                _ => return Err("Not connected or not ready".to_string()),
            }
        };

        let mut writer_guard = self.ws_writer.lock().await;
        if let Some(writer) = writer_guard.as_mut() {
            writer
                .send(Message::Binary(encrypted))
                .await
                .map_err(|e| format!("Failed to send binary: {}", e))?;
        }
        Ok(())
    }

    pub async fn my_peer_id(&self) -> String {
        let guard = self.shared.lock().await;
        match &guard.state {
            SwarmState::Peering { my_peer_id, .. } => my_peer_id.clone(),
            SwarmState::Ready { my_peer_id, .. } => my_peer_id.clone(),
            _ => String::new(),
        }
    }

    async fn send_json(&self, value: &serde_json::Value) -> Result<(), String> {
        let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
        let mut writer_guard = self.ws_writer.lock().await;
        if let Some(writer) = writer_guard.as_mut() {
            writer
                .send(Message::Text(text))
                .await
                .map_err(|e| format!("Failed to send JSON: {}", e))?;
        }
        Ok(())
    }

    fn generate_peer_id(&self) -> String {
        let mut rng = rand::thread_rng();
        let random_id: String = (0..8)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        format!("swarm-{}", random_id)
    }
}
