/**
 * VpnRoom - ZKS-VPN Durable Object for P2P VPN Relay
 *
 * High-performance binary packet relay between Client and Exit Peer.
 * Uses WebSocket Hibernation for cost-efficient idle connections.
 *
 * Key features:
 * - Only 2 peers per room (Client + Exit Peer)
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
}

/// Peer session data stored with hibernated WebSocket
#[derive(Clone, Serialize, Deserialize)]
struct PeerSession {
    peer_id: String,
    role: PeerRole,
    joined_at: u64,
}

/// Outbound events to clients
#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerEvent {
    #[serde(rename = "welcome")]
    Welcome {
        your_id: String,
        role: String,
        peer_connected: bool,
    },
    #[serde(rename = "peer_join")]
    PeerJoin { peer_id: String, role: String },
    #[serde(rename = "peer_leave")]
    PeerLeave { peer_id: String, role: String },
    #[serde(rename = "error")]
    Error { message: String },
    #[serde(rename = "pong")]
    Pong,
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
            _ => PeerRole::Client,
        };

        // Check if role is already taken
        let existing_roles: Vec<PeerRole> = self
            .get_all_sessions()
            .into_iter()
            .map(|s| s.role)
            .collect();

        if existing_roles.contains(&role) {
            return Response::error(format!("{:?} already connected to this room", role), 409);
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

        // Prepare session
        let session = PeerSession {
            peer_id: peer_id.clone(),
            role,
            joined_at: Date::now().as_millis(),
        };

        // Store session for hibernation recovery
        server.serialize_attachment(&session)?;

        // Notify the other peer if connected
        let join_msg = serde_json::to_string(&ServerEvent::PeerJoin {
            peer_id: peer_id.clone(),
            role: format!("{:?}", role),
        })
        .unwrap_or_default();
        self.broadcast_text(&join_msg, Some(&peer_id));

        // Check if the other peer is connected
        let peer_connected = existing_roles.iter().any(|r| *r != role);

        // Send welcome
        let welcome = serde_json::to_string(&ServerEvent::Welcome {
            your_id: peer_id.clone(),
            role: format!("{:?}", role),
            peer_connected,
        })
        .unwrap_or_default();
        let _ = server.send_with_str(&welcome);

        console_log!("[VpnRoom] {:?} joined: {}", role, peer_id);

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let session: PeerSession = match ws.deserialize_attachment::<PeerSession>() {
            Ok(Some(s)) => s,
            _ => return Ok(()),
        };

        match message {
            WebSocketIncomingMessage::Binary(data) => {
                // Relay binary ZKS-encrypted data to the OTHER peer only
                // This is the core of the VPN relay - just forward encrypted blobs
                self.relay_to_peer(&data, &session);
            }
            WebSocketIncomingMessage::String(text) => {
                if text == "ping" {
                    let pong = serde_json::to_string(&ServerEvent::Pong).unwrap_or_default();
                    let _ = ws.send_with_str(&pong);
                } else {
                    // Forward text messages (control messages) to the other peer
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

            let leave_msg = serde_json::to_string(&ServerEvent::PeerLeave {
                peer_id: session.peer_id,
                role: format!("{:?}", session.role),
            })
            .unwrap_or_default();
            self.broadcast_text(&leave_msg, None);
        }

        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, error: Error) -> Result<()> {
        console_error!("[VpnRoom] WebSocket error: {:?}", error);

        if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
            let leave_msg = serde_json::to_string(&ServerEvent::PeerLeave {
                peer_id: session.peer_id,
                role: format!("{:?}", session.role),
            })
            .unwrap_or_default();
            self.broadcast_text(&leave_msg, None);
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

    /// Relay binary data to the OTHER peer (not broadcast, point-to-point)
    fn relay_to_peer(&self, data: &[u8], sender: &PeerSession) {
        let target_role = match sender.role {
            PeerRole::Client => PeerRole::ExitPeer,
            PeerRole::ExitPeer => PeerRole::Client,
        };

        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if session.role == target_role {
                    let _ = ws.send_with_bytes(data);
                    return; // Only one peer of each type
                }
            }
        }
    }

    /// Relay text to the OTHER peer
    fn relay_text_to_peer(&self, text: &str, sender: &PeerSession) {
        let target_role = match sender.role {
            PeerRole::Client => PeerRole::ExitPeer,
            PeerRole::ExitPeer => PeerRole::Client,
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
        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if exclude_id.map(|id| id != session.peer_id).unwrap_or(true) {
                    let _ = ws.send_with_str(text);
                }
            }
        }
    }
}

fn rand_id() -> String {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).unwrap_or_default();
    hex::encode(buf)
}
