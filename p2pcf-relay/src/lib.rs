/**
 * p2pcf-relay - Video Relay Worker Entry Point
 * 
 * Routes incoming WebSocket connections to room-specific Durable Objects.
 * Each room is isolated in its own DO instance for scalability.
 * 
 * URL Pattern: wss://<worker>/room/<room_id>?clientId=<client_id>
 */

use worker::*;

mod relay_room;

pub use relay_room::RelayRoom;

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

        // Get or create the Durable Object for this room
        let namespace = env.durable_object("RELAY_ROOM")?;
        let id = namespace.id_from_name(room_id)?;
        let stub = id.get_stub()?;

        // Forward the request to the Durable Object
        return stub.fetch_with_request(req).await;
    }

    // Health check endpoint
    if path == "/health" || path == "/" {
        return Response::ok(serde_json::json!({
            "status": "ok",
            "service": "p2pcf-relay",
            "version": "0.1.0"
        }).to_string());
    }

    Response::error("Not Found. Use /room/<room_id>", 404)
}
