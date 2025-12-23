//! ZKS-Tunnel Worker - Serverless VPN Gateway
//!
//! This Cloudflare Worker provides:
//! 1. WebSocket tunnel endpoint for ZKS-encrypted traffic
//! 2. TCP socket proxying via Cloudflare's connect() API
//! 3. Stream multiplexing for multiple concurrent connections
//!
//! Architecture:
//! [Client] --WebSocket(ZKS)--> [Worker] --TCP--> [Internet]

use futures::StreamExt;
use worker::*;

mod tunnel_session;
pub use tunnel_session::TunnelSession;

/// Entry point: Route requests to appropriate handlers
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let url = req.url()?;
    let path = url.path();

    // WebSocket tunnel endpoint
    if path.starts_with("/tunnel") {
        return handle_tunnel(req, env).await;
    }

    // Health check
    if path == "/health" || path == "/" {
        return Response::ok(
            serde_json::json!({
                "status": "ok",
                "service": "zks-tunnel",
                "version": "0.1.0",
                "capabilities": ["tcp", "websocket", "zks"]
            })
            .to_string(),
        );
    }

    // Entropy Tax endpoint
    if path.starts_with("/entropy") {
        return handle_entropy(req).await;
    }

    Response::error("Not Found. Use /tunnel for VPN connection.", 404)
}

/// Handle Entropy Tax requests
async fn handle_entropy(req: Request) -> Result<Response> {
    // 1. GET request: Fetch entropy (for Swarm Entropy)
    if req.method() == Method::Get && !req.headers().has("Upgrade")? {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap_or_default();
        let entropy_hex = hex::encode(&entropy);

        return Response::ok(
            serde_json::json!({
                "entropy": entropy_hex,
                "timestamp": Date::now().to_string()
            })
            .to_string(),
        );
    }

    // 2. WebSocket request: Contribute entropy (Entropy Tax)
    if req.headers().has("Upgrade")? {
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        server.accept()?;

        // We don't need to do anything with the contribution for now
        // just keep the connection open and ack messages
        wasm_bindgen_futures::spawn_local(async move {
            let mut event_stream = server.events().expect("could not open stream");
            while let Some(event) = event_stream.next().await {
                if let worker::WebsocketEvent::Message(msg) =
                    event.expect("received error in websocket")
                {
                    if let Some(text) = msg.text() {
                        let _ = server.send_with_str(&format!("ACK: {}", text));
                    }
                }
            }
        });

        return Response::from_websocket(pair.client);
    }

    Response::error("Method not allowed", 405)
}

/// Handle WebSocket tunnel upgrade
async fn handle_tunnel(req: Request, env: Env) -> Result<Response> {
    // Get or create Durable Object for this session
    let namespace = env.durable_object("TUNNEL_SESSION")?;

    // Generate unique session ID
    let session_id = generate_session_id();
    let id = namespace.id_from_name(&session_id)?;
    let stub = id.get_stub()?;

    // Forward to Durable Object
    stub.fetch_with_request(req).await
}

/// Generate random session ID
fn generate_session_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).unwrap_or_default();
    hex::encode(&buf)
}

/// Hex encoding helper
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for &byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }
}
// Deploy trigger 12/17/2025 12:37:57
