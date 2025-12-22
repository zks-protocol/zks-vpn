/**
 * RelayRoom - Durable Object for WebSocket-based video relay
 * 
 * High-performance binary packet reflector for video streams.
 * Uses WebSocket Hibernation for cost-efficient idle connections.
 */

use serde::{Deserialize, Serialize};
use worker::*;

/// Peer session data stored with hibernated WebSocket
#[derive(Clone, Serialize, Deserialize)]
struct PeerSession {
    client_id: String,
    joined_at: u64,
}

/// Outbound events to clients
#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerEvent {
    #[serde(rename = "welcome")]
    Welcome { your_id: String, peers: Vec<String> },
    #[serde(rename = "peer_join")]
    PeerJoin { client_id: String },
    #[serde(rename = "peer_leave")]
    PeerLeave { client_id: String },
    #[serde(rename = "pong")]
    Pong,
}

#[durable_object]
pub struct RelayRoom {
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for RelayRoom {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let upgrade = req.headers().get("Upgrade")?;
        
        if upgrade.as_deref() != Some("websocket") {
            return Response::error("Expected WebSocket upgrade", 426);
        }

        // Parse client ID from query string
        let url = req.url()?;
        let client_id = url.query_pairs()
            .find(|(k, _)| k == "clientId")
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| format!("anon-{}", rand_id()));

        // Create WebSocket pair
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        // Accept with hibernation
        self.state.accept_web_socket(&server);

        // Prepare session
        let session = PeerSession {
            client_id: client_id.clone(),
            joined_at: Date::now().as_millis(),
        };

        // Store session for hibernation recovery
        server.serialize_attachment(&session)?;

        // Notify existing peers
        let join_msg = serde_json::to_string(&ServerEvent::PeerJoin { 
            client_id: client_id.clone() 
        }).unwrap_or_default();
        self.broadcast_text(&join_msg, Some(&client_id));

        // Send welcome with peer list
        let peer_ids: Vec<String> = self.get_all_peer_ids()
            .into_iter()
            .filter(|id| id != &client_id)
            .collect();
        
        let welcome = serde_json::to_string(&ServerEvent::Welcome {
            your_id: client_id.clone(),
            peers: peer_ids,
        }).unwrap_or_default();
        let _ = server.send_with_str(&welcome);

        console_log!("[RelayRoom] Peer joined: {}", client_id);

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // deserialize_attachment returns Result<Option<T>>
        let session: PeerSession = match ws.deserialize_attachment::<PeerSession>() {
            Ok(Some(s)) => s,
            _ => return Ok(()),
        };

        match message {
            WebSocketIncomingMessage::Binary(data) => {
                self.broadcast_binary(&data, Some(&session.client_id));
            }
            WebSocketIncomingMessage::String(text) => {
                if text == "ping" {
                    let pong = serde_json::to_string(&ServerEvent::Pong).unwrap_or_default();
                    let _ = ws.send_with_str(&pong);
                } else {
                    // Forward all other text messages (chat/actions) to other peers
                    self.broadcast_text(&text, Some(&session.client_id));
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
            console_log!("[RelayRoom] Peer left: {}", session.client_id);
            
            let leave_msg = serde_json::to_string(&ServerEvent::PeerLeave { 
                client_id: session.client_id 
            }).unwrap_or_default();
            self.broadcast_text(&leave_msg, None);
        }

        Ok(())
    }

    async fn websocket_error(
        &self,
        ws: WebSocket,
        error: Error,
    ) -> Result<()> {
        console_error!("[RelayRoom] WebSocket error: {:?}", error);
        
        if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
            let leave_msg = serde_json::to_string(&ServerEvent::PeerLeave { 
                client_id: session.client_id 
            }).unwrap_or_default();
            self.broadcast_text(&leave_msg, None);
        }

        Ok(())
    }
}

impl RelayRoom {
    fn get_all_peer_ids(&self) -> Vec<String> {
        self.state.get_websockets()
            .into_iter()
            .filter_map(|ws| {
                ws.deserialize_attachment::<PeerSession>().ok().flatten()
            })
            .map(|s| s.client_id)
            .collect()
    }

    fn broadcast_binary(&self, data: &[u8], exclude_id: Option<&str>) {
        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if exclude_id.map(|id| id != session.client_id).unwrap_or(true) {
                    let _ = ws.send_with_bytes(data);
                }
            }
        }
    }

    fn broadcast_text(&self, text: &str, exclude_id: Option<&str>) {
        for ws in self.state.get_websockets() {
            if let Ok(Some(session)) = ws.deserialize_attachment::<PeerSession>() {
                if exclude_id.map(|id| id != session.client_id).unwrap_or(true) {
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
