use crate::message_optimizer::MessagePriority;
/**
 * VpnRoom - ZKS-VPN Durable Object for P2P VPN Relay
 *
 * High-performance binary packet relay between Client and Exit Peer.
 * Uses WebSocket Hibernation for cost-efficient idle connections.
 *
 * Key features:
 * - Supports 2-peer VPN mode (Client + Exit Peer)
 * - Supports multi-peer Swarm mode (any number of peers)
 * - Zero-knowledge: Cannot decrypt ZKS-encrypted traffic
 * - Binary message relay for maximum throughput
 * - Automatic peer notification on join/leave
 */
use serde::{Deserialize, Serialize};
use worker::*;

/// Peer role in the VPN room
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum PeerRole {
    Client,
    ExitPeer,
    Swarm, // Multi-peer mesh mode
}

/// Peer session data stored with hibernated WebSocket
#[derive(Clone, Serialize, Deserialize)]
struct PeerSession {
    peer_id: String,
    role: PeerRole,
    addrs: Vec<String>, // Multiaddrs for P2P connectivity
    joined_at: u64,
    last_heartbeat: u64, // Last ping/pong timestamp for health monitoring
}

/// Inbound messages from clients (matches client's SignalingRequest)
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Join a room with peer info
    Join {
        peer_id: String,
        addrs: Vec<String>,
        #[allow(dead_code)]
        room_id: String,
    },
    /// Request list of peers
    GetPeers,
    /// Contribute entropy
    Entropy { entropy: String },
    /// Request hole-punch coordination
    HolePunch { target_peer_id: String },
    /// Simple ping
    Ping,
}

/// Outbound events to clients (matches client's SignalingResponse)
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerEvent {
    /// Acknowledgment of join (Swarm mode)
    Joined { your_id: String },
    /// List of peers in room (Swarm mode)
    Peers { peers: Vec<PeerInfo> },
    /// New peer joined (Swarm mode)
    PeerJoined { peer: PeerInfo },
    /// Peer left (Swarm mode)
    PeerLeft { peer_id: String },
    /// Swarm entropy
    SwarmEntropy { entropy: String },
    /// Hole-punch coordination
    PunchAt {
        timestamp_ms: u64,
        target_addrs: Vec<String>,
    },
    /// Error message
    Error { message: String },

    // Legacy VPN mode events (backwards compatible)
    #[serde(rename = "welcome")]
    Welcome {
        your_id: String,
        role: String,
        peer_connected: bool,
    },
    #[serde(rename = "peer_join")]
    LegacyPeerJoin { peer_id: String, role: String },
    #[serde(rename = "peer_leave")]
    LegacyPeerLeave { peer_id: String, role: String },
    #[serde(rename = "pong")]
    Pong,
}

/// Peer info for Swarm mode
#[derive(Clone, Serialize)]
struct PeerInfo {
    peer_id: String,
    addrs: Vec<String>,
    role: Option<String>,
}

#[durable_object]
pub struct VpnRoom {
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for VpnRoom {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let upgrade = req.headers().get("Upgrade")?;

        if upgrade.as_deref() != Some("websocket") {
            return Response::error("Expected WebSocket upgrade", 426);
        }

        // Parse query parameters
        let url = req.url()?;
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();

        // Get role (required)
        let role_str = params.get("role").map(|s| s.as_ref()).unwrap_or("client");
        let role = match role_str {
            "exit" | "exit-peer" | "exitpeer" => PeerRole::ExitPeer,
            "swarm" => PeerRole::Swarm,
            _ => PeerRole::Client,
        };

        // For VPN mode (Client/ExitPeer): check if role is already taken
        if role != PeerRole::Swarm {
            let websockets = self.state.get_websockets();
            for ws in &websockets {
                if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                    if session.role == role {
                        console_log!(
                            "[VpnRoom] ⚠️ Kicking old {:?} connection to allow new one",
                            role
                        );
                        let _ = ws.close(Some(1000), Some("New connection replaced this session"));
                    }
                }
            }
        }

        // Generate peer ID
        let peer_id = params
            .get("peerId")
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{:?}-{}", role, rand_id()));

        // Create WebSocket pair
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        // Accept with hibernation
        self.state.accept_web_socket(&server);

        // Prepare session (addrs will be filled in when Join message is received)
        let session = PeerSession {
            peer_id: peer_id.clone(),
            role,
            addrs: vec![],
            joined_at: Date::now().as_millis(),
            last_heartbeat: Date::now().as_millis(), // Initialize heartbeat
        };

        // Store session for hibernation recovery
        server.serialize_attachment(&session)?;

        if role == PeerRole::Swarm {
            // Swarm mode: Don't send welcome yet, wait for Join message
            console_log!("[VpnRoom] Swarm peer connected: {}", peer_id);
        } else {
            // VPN mode: Send legacy welcome immediately
            let join_msg = serde_json::to_string(&ServerEvent::LegacyPeerJoin {
                peer_id: peer_id.clone(),
                role: format!("{:?}", role),
            })
            .unwrap_or_default();
            self.broadcast_text(&join_msg, Some(&peer_id));

            let existing_roles: Vec<PeerRole> = self
                .get_all_sessions()
                .into_iter()
                .map(|s| s.role)
                .collect();
            let peer_connected = existing_roles.iter().any(|r| *r != role);

            let welcome = serde_json::to_string(&ServerEvent::Welcome {
                your_id: peer_id.clone(),
                role: format!("{:?}", role),
                peer_connected,
            })
            .unwrap_or_default();
            let _ = server.send_with_str(&welcome);

            console_log!("[VpnRoom] {:?} joined: {}", role, peer_id);
        }

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let mut session: PeerSession = match ws.deserialize_attachment::<PeerSession>() {
            Ok(Some(s)) => s,
            _ => return Ok(()),
        };

        // Update heartbeat on any message (cost optimization: passive heartbeat)
        session.last_heartbeat = Date::now().as_millis();
        ws.serialize_attachment(&session)?;

        match message {
            WebSocketIncomingMessage::Binary(data) => {
                // Relay binary ZKS-encrypted data to the OTHER peer only
                self.relay_to_peer(&data, &session);
            }
            WebSocketIncomingMessage::String(text) => {
                // Try to parse as ClientMessage
                if let Ok(msg) = serde_json::from_str::<ClientMessage>(&text) {
                    match msg {
                        ClientMessage::Join { peer_id, addrs, .. } => {
                            // Update session with peer info
                            session.peer_id = peer_id.clone();
                            session.addrs = addrs.clone();
                            ws.serialize_attachment(&session)?;

                            console_log!(
                                "[VpnRoom] Swarm Join: {} with {} addrs",
                                peer_id,
                                addrs.len()
                            );

                            // Send Joined acknowledgment
                            let joined = serde_json::to_string(&ServerEvent::Joined {
                                your_id: peer_id.clone(),
                            })
                            .unwrap_or_default();
                            let _ = ws.send_with_str(&joined);

                            // Notify other Swarm peers
                            let peer_info = PeerInfo {
                                peer_id: peer_id.clone(),
                                addrs,
                                role: Some("swarm".to_string()),
                            };
                            let notify =
                                serde_json::to_string(&ServerEvent::PeerJoined { peer: peer_info })
                                    .unwrap_or_default();
                            self.broadcast_to_swarm(&notify, Some(&session.peer_id));
                        }

                        ClientMessage::GetPeers => {
                            // Return all Swarm peers with their addresses
                            let peers: Vec<PeerInfo> = self
                                .get_all_sessions()
                                .into_iter()
                                .filter(|s| {
                                    s.role == PeerRole::Swarm && s.peer_id != session.peer_id
                                })
                                .map(|s| PeerInfo {
                                    peer_id: s.peer_id,
                                    addrs: s.addrs,
                                    role: Some("swarm".to_string()),
                                })
                                .collect();

                            console_log!(
                                "[VpnRoom] GetPeers: returning {} peers to {}",
                                peers.len(),
                                session.peer_id
                            );

                            let response = serde_json::to_string(&ServerEvent::Peers { peers })
                                .unwrap_or_default();
                            let _ = ws.send_with_str(&response);
                        }

                        ClientMessage::Entropy { entropy } => {
                            // Broadcast entropy to all Swarm peers
                            let response =
                                serde_json::to_string(&ServerEvent::SwarmEntropy { entropy })
                                    .unwrap_or_default();
                            self.broadcast_to_swarm(&response, Some(&session.peer_id));
                        }

                        ClientMessage::HolePunch { target_peer_id } => {
                            // Find target peer and get their addrs
                            if let Some(target) = self
                                .get_all_sessions()
                                .into_iter()
                                .find(|s| s.peer_id == target_peer_id)
                            {
                                let response = serde_json::to_string(&ServerEvent::PunchAt {
                                    timestamp_ms: Date::now().as_millis() + 500, // 500ms from now
                                    target_addrs: target.addrs,
                                })
                                .unwrap_or_default();
                                let _ = ws.send_with_str(&response);
                            } else {
                                let err = serde_json::to_string(&ServerEvent::Error {
                                    message: format!("Peer {} not found", target_peer_id),
                                })
                                .unwrap_or_default();
                                let _ = ws.send_with_str(&err);
                            }
                        }

                        ClientMessage::Ping => {
                            let pong =
                                serde_json::to_string(&ServerEvent::Pong).unwrap_or_default();
                            let _ = ws.send_with_str(&pong);
                        }
                    }
                } else if text == "ping" || text == "{\"type\":\"ping\"}" {
                    // Legacy ping handling
                    let pong = serde_json::to_string(&ServerEvent::Pong).unwrap_or_default();
                    let _ = ws.send_with_str(&pong);
                } else {
                    // Forward unrecognized text to other peer (VPN mode control messages)
                    self.relay_text_to_peer(&text, &session);
                }
            }
        }

        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
            console_log!("[VpnRoom] {:?} left: {}", session.role, session.peer_id);

            if session.role == PeerRole::Swarm {
                // Notify Swarm peers
                let leave_msg = serde_json::to_string(&ServerEvent::PeerLeft {
                    peer_id: session.peer_id.clone(),
                })
                .unwrap_or_default();
                self.broadcast_to_swarm(&leave_msg, None);
            } else {
                // Legacy VPN mode
                let leave_msg = serde_json::to_string(&ServerEvent::LegacyPeerLeave {
                    peer_id: session.peer_id,
                    role: format!("{:?}", session.role),
                })
                .unwrap_or_default();
                self.broadcast_text(&leave_msg, None);
            }
        }

        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, error: Error) -> Result<()> {
        console_error!("[VpnRoom] WebSocket error: {:?}", error);

        if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
            if session.role == PeerRole::Swarm {
                let leave_msg = serde_json::to_string(&ServerEvent::PeerLeft {
                    peer_id: session.peer_id.clone(),
                })
                .unwrap_or_default();
                self.broadcast_to_swarm(&leave_msg, None);
            } else {
                let leave_msg = serde_json::to_string(&ServerEvent::LegacyPeerLeave {
                    peer_id: session.peer_id,
                    role: format!("{:?}", session.role),
                })
                .unwrap_or_default();
                self.broadcast_text(&leave_msg, None);
            }
        }

        Ok(())
    }
}

impl VpnRoom {
    fn get_all_sessions(&self) -> Vec<PeerSession> {
        self.state
            .get_websockets()
            .into_iter()
            .filter_map(|ws| ws.deserialize_attachment::<PeerSession>().ok().flatten())
            .collect()
    }

    /// Send message with retry logic for robustness
    /// Retries up to 2 times with exponential backoff
    fn send_with_retry(&self, ws: &WebSocket, msg: &str) -> bool {
        const MAX_RETRIES: u32 = 2;

        for attempt in 0..=MAX_RETRIES {
            match ws.send_with_str(msg) {
                Ok(_) => return true,
                Err(e) if attempt < MAX_RETRIES => {
                    console_log!(
                        "[VpnRoom] Send retry {}/{}: {:?}",
                        attempt + 1,
                        MAX_RETRIES,
                        e
                    );
                    // Note: Can't use async sleep in sync context,
                    // but Cloudflare Workers will handle backpressure
                }
                Err(e) => {
                    console_error!(
                        "[VpnRoom] Send failed after {} retries: {:?}",
                        MAX_RETRIES,
                        e
                    );
                    return false;
                }
            }
        }
        false
    }

    /// Broadcast to all Swarm peers only
    fn broadcast_to_swarm(&self, text: &str, exclude_id: Option<&str>) {
        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if session.role == PeerRole::Swarm
                    && exclude_id.map(|id| id != session.peer_id).unwrap_or(true)
                {
                    let _ = ws.send_with_str(text);
                }
            }
        }
    }

    /// Relay binary data to the OTHER peer (VPN mode: point-to-point)
    fn relay_to_peer(&self, data: &[u8], sender: &PeerSession) {
        let target_role = match sender.role {
            PeerRole::Client => PeerRole::ExitPeer,
            PeerRole::ExitPeer => PeerRole::Client,
            PeerRole::Swarm => {
                // Swarm mode: Broadcast binary data to all other swarm peers
                // This enables a mesh where every peer receives every packet (encrypted)
                for ws in self.state.get_websockets() {
                    if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                        if session.role == PeerRole::Swarm && session.peer_id != sender.peer_id {
                            let _ = ws.send_with_bytes(data);
                        }
                    }
                }
                return;
            }
        };

        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if session.role == target_role {
                    if let Err(e) = ws.send_with_bytes(data) {
                        console_error!(
                            "[VpnRoom] Failed to send {} bytes to {:?}: {:?}",
                            data.len(),
                            target_role,
                            e
                        );
                    }
                    return;
                }
            }
        }
    }

    /// Relay text to the OTHER peer (VPN mode)
    fn relay_text_to_peer(&self, text: &str, sender: &PeerSession) {
        let target_role = match sender.role {
            PeerRole::Client => PeerRole::ExitPeer,
            PeerRole::ExitPeer => PeerRole::Client,
            PeerRole::Swarm => return,
        };

        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if session.role == target_role {
                    let _ = ws.send_with_str(text);
                    return;
                }
            }
        }
    }

    fn broadcast_text(&self, text: &str, exclude_id: Option<&str>) {
        // Determine message priority
        let priority = MessagePriority::from_message(text);

        let mut success_count = 0;
        let mut fail_count = 0;

        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if exclude_id.map(|id| id != session.peer_id).unwrap_or(true) {
                    // Critical messages: send immediately without retry (fastest path)
                    // Other messages: use retry logic for robustness
                    let sent = if priority.is_critical() {
                        ws.send_with_str(text).is_ok()
                    } else {
                        self.send_with_retry(&ws, text)
                    };

                    if sent {
                        success_count += 1;
                    } else {
                        fail_count += 1;
                        console_error!(
                            "[VpnRoom] Failed to broadcast {:?} message to {:?} ({})",
                            priority,
                            session.role,
                            session.peer_id
                        );
                    }
                }
            }
        }

        if fail_count > 0 {
            console_log!(
                "[VpnRoom] Broadcast {:?}: {} success, {} failed",
                priority,
                success_count,
                fail_count
            );
        }
    }
}

fn rand_id() -> String {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).unwrap_or_default();
    hex::encode(buf)
}
