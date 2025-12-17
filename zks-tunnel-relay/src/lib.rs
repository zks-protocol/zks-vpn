/**
 * ZKS-Tunnel Relay - P2P VPN Relay Worker
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
 */
use worker::*;

mod vpn_room;

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

    // Health check endpoint
    if path == "/health" || path == "/" {
        return Response::ok(
            serde_json::json!({
                "status": "ok",
                "service": "zks-tunnel-relay",
                "version": "0.1.0",
                "description": "ZKS-VPN P2P Relay with double-key Vernam encryption",
                "endpoints": {
                    "vpn_room": "/room/<room_id>?role=client|exit",
                    "health": "/health"
                }
            })
            .to_string(),
        );
    }

    Response::error("Not Found. Use /room/<room_id>", 404)
}
