//! Global Entropy Pool - Aggregates entropy from all connected peers
//!
//! Every peer in the ZKS network contributes random bytes (Entropy Tax).
//! When a session needs K_Remote, it samples N random contributors and XORs their entropy.
//!
//! Security Model:
//! - To predict K_Remote, an attacker must control ALL N selected peers
//! - Default N = 10, providing (1/total_peers)^10 attack probability
//!
//! Protocol:
//! - Peers send ENTROPY_CONTRIBUTE messages with random bytes
//! - Pool stores latest contribution from each peer
//! - ENTROPY_REQUEST returns XOR of N random peer contributions

use serde::{Deserialize, Serialize};
use worker::*;

/// Entropy contribution from a peer
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EntropyContribution {
    pub peer_id: String,
    pub entropy: Vec<u8>,
    pub timestamp: u64,
}

/// Outbound events from Entropy Pool
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum EntropyEvent {
    /// Entropy successfully generated
    #[serde(rename = "entropy_response")]
    EntropyResponse {
        request_id: String,
        entropy: Vec<u8>,
        contributors: usize,
    },
    /// Error generating entropy
    #[serde(rename = "entropy_error")]
    EntropyError { request_id: String, message: String },
    /// Contribution acknowledged
    #[serde(rename = "contribution_ack")]
    ContributionAck { bytes_received: usize },
}

/// Inbound requests to Entropy Pool
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum EntropyRequest {
    /// Contribute entropy to the pool
    #[serde(rename = "contribute")]
    Contribute { entropy: Vec<u8> },
    /// Request entropy (XOR of N peers)
    #[serde(rename = "request")]
    Request {
        request_id: String,
        size: usize,
        n: usize,
    },
}

/// Session data for connected entropy contributors
#[derive(Clone, Serialize, Deserialize)]
struct EntropySession {
    peer_id: String,
    connected_at: u64,
}

#[durable_object]
pub struct EntropyPool {
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for EntropyPool {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let upgrade = req.headers().get("Upgrade")?;

        if upgrade.as_deref() != Some("websocket") {
            // HTTP endpoint for one-shot entropy requests
            return self.handle_http_request(req).await;
        }

        // WebSocket for persistent entropy contribution
        let url = req.url()?;
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();

        let peer_id = params
            .get("peerId")
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("entropy-{}", rand_id()));

        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        self.state.accept_web_socket(&server);

        let session = EntropySession {
            peer_id: peer_id.clone(),
            connected_at: Date::now().as_millis(),
        };

        server.serialize_attachment(&session)?;

        console_log!("[EntropyPool] Peer connected: {}", peer_id);

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let session: EntropySession = match ws.deserialize_attachment::<EntropySession>() {
            Ok(Some(s)) => s,
            _ => return Ok(()),
        };

        match message {
            WebSocketIncomingMessage::Binary(data) => {
                // Binary data is treated as raw entropy contribution
                self.store_entropy(&session.peer_id, &data).await?;

                let ack = serde_json::to_string(&EntropyEvent::ContributionAck {
                    bytes_received: data.len(),
                })
                .unwrap_or_default();
                let _ = ws.send_with_str(&ack);
            }
            WebSocketIncomingMessage::String(text) => {
                // Parse JSON request
                if let Ok(request) = serde_json::from_str::<EntropyRequest>(&text) {
                    match request {
                        EntropyRequest::Contribute { entropy } => {
                            self.store_entropy(&session.peer_id, &entropy).await?;

                            let ack = serde_json::to_string(&EntropyEvent::ContributionAck {
                                bytes_received: entropy.len(),
                            })
                            .unwrap_or_default();
                            let _ = ws.send_with_str(&ack);
                        }
                        EntropyRequest::Request {
                            request_id,
                            size,
                            n,
                        } => {
                            let result = self.generate_entropy(size, n).await;
                            let response = match result {
                                Ok((entropy, contributors)) => {
                                    serde_json::to_string(&EntropyEvent::EntropyResponse {
                                        request_id,
                                        entropy,
                                        contributors,
                                    })
                                }
                                Err(e) => serde_json::to_string(&EntropyEvent::EntropyError {
                                    request_id,
                                    message: e.to_string(),
                                }),
                            };
                            let _ = ws.send_with_str(response.unwrap_or_default());
                        }
                    }
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
        if let Ok(Some(session)) = ws.deserialize_attachment::<EntropySession>() {
            console_log!("[EntropyPool] Peer disconnected: {}", session.peer_id);
            // Optionally remove their entropy contribution
            // For now, we keep it for a grace period
        }
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, error: Error) -> Result<()> {
        console_error!("[EntropyPool] WebSocket error: {:?}", error);
        Ok(())
    }
}

impl EntropyPool {
    /// Handle HTTP requests for one-shot entropy
    async fn handle_http_request(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();

        if path.ends_with("/entropy") {
            // GET /entropy?size=32&n=10
            let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
            let size = params
                .get("size")
                .and_then(|s| s.parse().ok())
                .unwrap_or(32);
            let n = params.get("n").and_then(|s| s.parse().ok()).unwrap_or(10);

            match self.generate_entropy(size, n).await {
                Ok((entropy, contributors)) => {
                    let response = serde_json::json!({
                        "entropy": hex::encode(&entropy),
                        "contributors": contributors,
                        "size": entropy.len(),
                    });
                    Response::from_json(&response)
                }
                Err(e) => Response::error(e.to_string(), 500),
            }
        } else if path.ends_with("/stats") {
            // GET /stats - return pool statistics
            let contributions = self.get_all_contributions().await?;
            let response = serde_json::json!({
                "total_contributors": contributions.len(),
                "total_entropy_bytes": contributions.iter().map(|c| c.entropy.len()).sum::<usize>(),
            });
            Response::from_json(&response)
        } else {
            Response::error("Not found", 404)
        }
    }

    /// Store entropy contribution from a peer
    async fn store_entropy(&self, peer_id: &str, entropy: &[u8]) -> Result<()> {
        let contribution = EntropyContribution {
            peer_id: peer_id.to_string(),
            entropy: entropy.to_vec(),
            timestamp: Date::now().as_millis(),
        };

        // Store in Durable Object storage
        let key = format!("entropy:{}", peer_id);
        self.state.storage().put(&key, &contribution).await?;

        console_log!(
            "[EntropyPool] Stored {} bytes from {}",
            entropy.len(),
            peer_id
        );

        Ok(())
    }

    /// Get all stored entropy contributions
    async fn get_all_contributions(&self) -> Result<Vec<EntropyContribution>> {
        let storage = self.state.storage();

        // Use list_with_options to filter by prefix
        let options = ListOptions::new().prefix("entropy:");
        let map = storage.list_with_options(options).await?;

        // The map is already a HashMap-like structure
        let mut contributions = Vec::new();

        // Get keys and iterate - keys() returns iterator of Result<JsValue, _>
        for key_js in map.keys().into_iter().flatten() {
            // Convert JsValue to String
            if let Some(key_str) = key_js.as_string() {
                if let Ok(Some(contribution)) = storage.get::<EntropyContribution>(&key_str).await {
                    contributions.push(contribution);
                }
            }
        }

        Ok(contributions)
    }

    /// Generate entropy by XORing N random peer contributions
    async fn generate_entropy(&self, size: usize, n: usize) -> Result<(Vec<u8>, usize)> {
        let contributions = self.get_all_contributions().await?;

        if contributions.is_empty() {
            // Fallback: use local RNG (degraded security)
            console_warn!("[EntropyPool] No contributions, falling back to local RNG");
            let mut result = vec![0u8; size];
            getrandom::getrandom(&mut result).unwrap_or_default();
            return Ok((result, 0));
        }

        // Select N random contributors (or all if less than N)
        let selected_count = std::cmp::min(n, contributions.len());
        let mut selected: Vec<_> = contributions.clone();

        // Shuffle using Fisher-Yates
        let mut rng_seed = [0u8; 8];
        getrandom::getrandom(&mut rng_seed).unwrap_or_default();
        let mut rng = u64::from_le_bytes(rng_seed);

        for i in (1..selected.len()).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (rng as usize) % (i + 1);
            selected.swap(i, j);
        }

        selected.truncate(selected_count);

        // XOR all selected contributions
        let mut result = vec![0u8; size];

        for contribution in &selected {
            for (i, byte) in result.iter_mut().enumerate() {
                // Cycle through contribution bytes
                if !contribution.entropy.is_empty() {
                    *byte ^= contribution.entropy[i % contribution.entropy.len()];
                }
            }
        }

        // Add local RNG as final XOR (defense in depth)
        let mut local_rng = vec![0u8; size];
        getrandom::getrandom(&mut local_rng).unwrap_or_default();
        for (i, byte) in result.iter_mut().enumerate() {
            *byte ^= local_rng[i];
        }

        console_log!(
            "[EntropyPool] Generated {} bytes from {} contributors",
            size,
            selected_count
        );

        Ok((result, selected_count))
    }
}

fn rand_id() -> String {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).unwrap_or_default();
    hex::encode(buf)
}
