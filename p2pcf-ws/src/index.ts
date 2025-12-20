/**
 * P2PCF-WS Worker Entry Point
 * 
 * Routes WebSocket connections to the appropriate SignalingRoom
 * Durable Object based on room ID.
 * 
 * Endpoints:
 *   GET /ws/room/:roomId?clientId=xxx  - WebSocket upgrade for signaling
 *   GET /health                        - Health check
 *   GET /                              - Server info
 */

import { SignalingRoom } from "./SignalingRoom";

export interface Env {
    SIGNALING_ROOM: DurableObjectNamespace;
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // Health check
        if (url.pathname === "/health") {
            return new Response("OK", { status: 200 });
        }

        // WebSocket route: /ws/room/:roomId
        const wsMatch = url.pathname.match(/^\/ws\/room\/([^/]+)$/);
        if (wsMatch) {
            const roomId = decodeURIComponent(wsMatch[1]);

            // Get or create Durable Object for this room
            const roomObjectId = env.SIGNALING_ROOM.idFromName(roomId);
            const roomStub = env.SIGNALING_ROOM.get(roomObjectId);

            // Forward the WebSocket upgrade request to the Durable Object
            return roomStub.fetch(request);
        }

        // Root endpoint - server info
        if (url.pathname === "/" || url.pathname === "") {
            return new Response(JSON.stringify({
                name: "P2PCF-WS Signaling Server",
                version: "1.0.0",
                description: "WebSocket-based WebRTC signaling using Cloudflare Durable Objects",
                endpoints: {
                    websocket: "/ws/room/:roomId?clientId=yourId",
                    health: "/health",
                },
            }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }

        return new Response("Not Found", { status: 404 });
    },
};

// Export Durable Object class
export { SignalingRoom };
