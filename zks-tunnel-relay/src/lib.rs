/**
 * ZKS-Tunnel Relay - P2P VPN Relay Worker v0.2.0
 *
 * Relays encrypted VPN traffic between Client and Exit Peer.
 * Uses ZKS double-key Vernam encryption for information-theoretic security.
 *
 * URL Pattern: wss://<worker>/room/<room_id>?role=<client|exit>
 *
 * Architecture:
 *   Client <--[ZKS Encrypted]--> Relay <--[ZKS Encrypted]--> Exit Peer
 *                                  |
 *                        (Cannot decrypt traffic)
 *
 * Swarm Entropy:
 *   All peers contribute entropy to the Global Entropy Pool.
 *   K_Remote = XOR(E_P1, E_P2, ..., E_PN) where N = 10 by default.
 */
use worker::*;

mod entropy_pool;
mod vpn_room;

pub use entropy_pool::EntropyPool;
pub use vpn_room::VpnRoom;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let url = req.url()?;
    let path = url.path();

    // Parse room ID from path: /room/<room_id>
    if path.starts_with("/room/") {
        let room_id = path.strip_prefix("/room/").unwrap_or("default");

        if room_id.is_empty() {
            return Response::error("Room ID required", 400);
        }

        // Get or create the Durable Object for this VPN room
        let namespace = env.durable_object("VPN_ROOM")?;
        let id = namespace.id_from_name(room_id)?;
        let stub = id.get_stub()?;

        // Forward the request to the Durable Object
        return stub.fetch_with_request(req).await;
    }

    // Entropy Pool endpoint: /entropy or /entropy/...
    if path.starts_with("/entropy") {
        // Use a single global entropy pool
        let namespace = env.durable_object("ENTROPY_POOL")?;
        let id = namespace.id_from_name("global")?;
        let stub = id.get_stub()?;

        return stub.fetch_with_request(req).await;
    }

    // Health check endpoint
    if path == "/health" || path == "/" {
        return Response::ok(
            serde_json::json!({
                "status": "ok",
                "service": "zks-tunnel-relay",
                "version": "0.2.0",
                "description": "ZKS-VPN P2P Relay with Swarm Entropy",
                "endpoints": {
                    "vpn_room": "/room/<room_id>?role=client|exit",
                    "entropy": "/entropy?size=32&n=10",
                    "entropy_ws": "wss://.../entropy (WebSocket for contributions)",
                    "health": "/health"
                }
            })
            .to_string(),
        );
    }

    Response::error("Not Found. Use /room/<room_id> or /entropy", 404)
}
