//! Signaling Client - WebSocket connection to Cloudflare Worker
//!
//! Connects to the CF Worker for:
//! - Room-based peer discovery
//! - Multiaddr exchange
//! - DCUtR hole-punch coordination
//! - Swarm entropy collection

#![allow(dead_code)]

#[cfg(feature = "swarm")]
use futures::{SinkExt, StreamExt};
#[cfg(feature = "swarm")]
use libp2p::{Multiaddr, PeerId};
#[cfg(feature = "swarm")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "swarm")]
use tokio_tungstenite::{connect_async, tungstenite::Message};
#[cfg(feature = "swarm")]
use tracing::{debug, info, warn};

/// Peer info from signaling server
#[cfg(feature = "swarm")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addrs: Vec<String>,
    pub role: Option<String>,
}

/// Messages sent to signaling server
#[cfg(feature = "swarm")]
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalingRequest {
    /// Join a room with our peer info
    Join {
        peer_id: String,
        addrs: Vec<String>,
        room_id: String,
    },
    /// Request list of peers in room
    GetPeers,
    /// Contribute entropy to swarm
    Entropy {
        entropy: String, // hex-encoded 32 bytes
    },
    /// Request hole-punch coordination
    HolePunch {
        target_peer_id: String,
    },
}

/// Messages received from signaling server
#[cfg(feature = "swarm")]
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalingResponse {
    /// Acknowledgment of join
    Joined {
        your_id: String,
    },
    /// List of peers in room
    Peers {
        peers: Vec<PeerInfo>,
    },
    /// New peer joined the room
    PeerJoined {
        peer: PeerInfo,
    },
    /// Peer left the room
    PeerLeft {
        peer_id: String,
    },
    /// Entropy from swarm
    SwarmEntropy {
        entropy: String, // hex-encoded
    },
    /// Hole-punch coordination
    PunchAt {
        timestamp_ms: u64,
        target_addrs: Vec<String>,
    },
    /// Error message
    Error {
        message: String,
    },
}

/// WebSocket signaling client
#[cfg(feature = "swarm")]
pub struct SignalingClient {
    write: futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    read: futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    room_id: String,
    local_peer_id: String,
}

#[cfg(feature = "swarm")]
impl SignalingClient {
    /// Connect to Cloudflare Worker signaling server
    pub async fn connect(
        worker_url: &str,
        room_id: &str,
        peer_id: &PeerId,
        addrs: Vec<Multiaddr>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Build WebSocket URL: wss://worker.dev/room/<room_id>
        let ws_url = format!("{}/room/{}?role=swarm", worker_url, room_id);
        info!("📡 Connecting to signaling: {}", ws_url);

        // Connect to WebSocket
        let (ws_stream, response) = connect_async(&ws_url).await?;
        info!("✅ Signaling connected (status: {})", response.status());

        let (mut write, read) = ws_stream.split();
        let local_peer_id = peer_id.to_string();

        // Send join message
        let join_msg = SignalingRequest::Join {
            peer_id: local_peer_id.clone(),
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
            room_id: room_id.to_string(),
        };

        let json = serde_json::to_string(&join_msg)?;
        write.send(Message::Text(json)).await?;
        debug!("📤 Sent join message");

        Ok(Self {
            write,
            read,
            room_id: room_id.to_string(),
            local_peer_id,
        })
    }

    /// Get list of peers in the room
    pub async fn get_peers(&mut self) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
        // Request peers
        let msg = SignalingRequest::GetPeers;
        let json = serde_json::to_string(&msg)?;
        self.write.send(Message::Text(json)).await?;

        // Wait for response
        while let Some(msg) = self.read.next().await {
            match msg? {
                Message::Text(text) => {
                    if let Ok(response) = serde_json::from_str::<SignalingResponse>(&text) {
                        match response {
                            SignalingResponse::Peers { peers } => {
                                info!("📥 Received {} peers from signaling", peers.len());
                                return Ok(peers);
                            }
                            SignalingResponse::Error { message } => {
                                warn!("⚠️ Signaling error: {}", message);
                            }
                            _ => {
                                debug!("📥 Other message: {:?}", response);
                            }
                        }
                    }
                }
                Message::Close(_) => {
                    warn!("📴 Signaling connection closed");
                    break;
                }
                _ => {}
            }
        }

        Ok(vec![])
    }

    /// Broadcast our entropy contribution
    pub async fn broadcast_entropy(&mut self, entropy: &[u8; 32]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = SignalingRequest::Entropy {
            entropy: hex::encode(entropy),
        };
        let json = serde_json::to_string(&msg)?;
        self.write.send(Message::Text(json)).await?;
        debug!("📤 Broadcast entropy");
        Ok(())
    }

    /// Parse multiaddr strings into Multiaddr objects
    pub fn parse_addrs(addrs: &[String]) -> Vec<Multiaddr> {
        addrs
            .iter()
            .filter_map(|s| s.parse::<Multiaddr>().ok())
            .collect()
    }

    /// Parse peer_id string into PeerId
    pub fn parse_peer_id(peer_id: &str) -> Option<PeerId> {
        peer_id.parse().ok()
    }
}

#[cfg(all(test, feature = "swarm"))]
mod tests {
    use super::*;

    #[test]
    fn test_signaling_request_serialization() {
        let join = SignalingRequest::Join {
            peer_id: "12D3KooWTest".to_string(),
            addrs: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            room_id: "test-room".to_string(),
        };

        let json = serde_json::to_string(&join).unwrap();
        assert!(json.contains("\"type\":\"join\""));
        assert!(json.contains("\"peer_id\":\"12D3KooWTest\""));
    }

    #[test]
    fn test_signaling_response_deserialization() {
        let json = r#"{"type":"peers","peers":[{"peer_id":"12D3KooWTest","addrs":["/ip4/1.2.3.4/tcp/4001"]}]}"#;
        let response: SignalingResponse = serde_json::from_str(json).unwrap();
        
        match response {
            SignalingResponse::Peers { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].peer_id, "12D3KooWTest");
            }
            _ => panic!("Expected Peers response"),
        }
    }
}
