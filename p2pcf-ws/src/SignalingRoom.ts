/**
 * SignalingRoom - Durable Object for WebSocket-based WebRTC signaling
 * 
 * Each room is a separate Durable Object instance that manages:
 * - WebSocket connections for all peers in the room
 * - Forwarding SDP offers/answers and ICE candidates
 * - Peer join/leave notifications
 * 
 * Uses WebSocket Hibernation for cost-efficient idle connections.
 */

import { DurableObject } from "cloudflare:workers";

interface PeerSession {
    clientId: string;
    joinedAt: number;
}

interface SignalMessage {
    type: "signal";
    targetId: string;
    signal: unknown;
}

interface BroadcastMessage {
    type: "broadcast";
    data: unknown;
}

type ClientMessage = SignalMessage | BroadcastMessage;

interface Env {
    SIGNALING_ROOM: DurableObjectNamespace;
}

export class SignalingRoom extends DurableObject {
    private sessions: Map<WebSocket, PeerSession> = new Map();

    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env);

        // Restore hibernated WebSocket sessions
        this.ctx.getWebSockets().forEach((ws) => {
            const attachment = ws.deserializeAttachment();
            if (attachment) {
                this.sessions.set(ws, attachment as PeerSession);
            }
        });

        // Auto ping/pong for keepalive (doesn't wake hibernated DO)
        this.ctx.setWebSocketAutoResponse(
            new WebSocketRequestResponsePair("ping", "pong")
        );
    }

    /**
     * Handle incoming HTTP requests (WebSocket upgrade)
     */
    async fetch(request: Request): Promise<Response> {
        const upgradeHeader = request.headers.get("Upgrade");

        if (upgradeHeader !== "websocket") {
            return new Response("Expected WebSocket upgrade", { status: 426 });
        }

        const url = new URL(request.url);
        const clientId = url.searchParams.get("clientId") || crypto.randomUUID();

        // Check if this clientId is already connected
        for (const [ws, session] of this.sessions) {
            if (session.clientId === clientId) {
                // Close existing connection
                ws.close(4000, "Duplicate connection");
                this.sessions.delete(ws);
                break;
            }
        }

        // Create WebSocket pair
        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair);

        // Accept the WebSocket with hibernation support
        this.ctx.acceptWebSocket(server);

        const session: PeerSession = {
            clientId,
            joinedAt: Date.now(),
        };

        // Serialize session for hibernation restoration
        server.serializeAttachment(session);
        this.sessions.set(server, session);

        // Notify all existing peers of new peer
        this.broadcast(
            { type: "peer_join", clientId, timestamp: Date.now() },
            server
        );

        // Send list of existing peers to the new peer
        const existingPeers = Array.from(this.sessions.values())
            .filter((s) => s.clientId !== clientId)
            .map((s) => s.clientId);

        server.send(JSON.stringify({
            type: "peers",
            peers: existingPeers,
            yourId: clientId,
        }));

        console.log(`[SignalingRoom] Peer joined: ${clientId}, total: ${this.sessions.size}`);

        return new Response(null, { status: 101, webSocket: client });
    }

    /**
     * Handle incoming WebSocket messages
     */
    async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
        const session = this.sessions.get(ws);
        if (!session) {
            console.error("[SignalingRoom] Message from unknown WebSocket");
            return;
        }

        try {
            const data: ClientMessage = JSON.parse(message as string);

            switch (data.type) {
                case "signal":
                    // Check if this is a broadcast signal (for relay mode)
                    if (data.targetId === "__broadcast__") {
                        // Broadcast to all except sender (relay mode for large rooms)
                        this.broadcast(
                            { type: "signal", fromId: session.clientId, signal: data.signal },
                            ws
                        );
                    } else {
                        // Forward signal (SDP/ICE) to specific peer
                        this.sendToPeer(data.targetId, {
                            type: "signal",
                            fromId: session.clientId,
                            signal: data.signal,
                        });
                    }
                    break;

                case "broadcast":
                    // Broadcast to all except sender
                    this.broadcast(
                        { type: "broadcast", fromId: session.clientId, data: data.data },
                        ws
                    );
                    break;

                default:
                    console.warn("[SignalingRoom] Unknown message type:", (data as { type: string }).type);
            }
        } catch (err) {
            console.error("[SignalingRoom] Failed to parse message:", err);
        }
    }

    /**
     * Handle WebSocket close
     */
    async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
        const session = this.sessions.get(ws);
        if (session) {
            console.log(`[SignalingRoom] Peer left: ${session.clientId}, reason: ${reason}`);

            // Notify all peers
            this.broadcast(
                { type: "peer_leave", clientId: session.clientId, timestamp: Date.now() },
                ws
            );

            this.sessions.delete(ws);
        }
    }

    /**
     * Handle WebSocket errors
     */
    async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
        console.error("[SignalingRoom] WebSocket error:", error);
        const session = this.sessions.get(ws);
        if (session) {
            this.sessions.delete(ws);
            this.broadcast({ type: "peer_leave", clientId: session.clientId, timestamp: Date.now() });
        }
    }

    /**
     * Broadcast message to all connected peers
     */
    private broadcast(data: object, exclude?: WebSocket): void {
        const message = JSON.stringify(data);
        this.sessions.forEach((_, ws) => {
            if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
                try {
                    ws.send(message);
                } catch (err) {
                    console.error("[SignalingRoom] Failed to send to peer:", err);
                }
            }
        });
    }

    /**
     * Send message to a specific peer by clientId
     */
    private sendToPeer(targetId: string, data: object): void {
        for (const [ws, session] of this.sessions) {
            if (session.clientId === targetId) {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify(data));
                }
                return;
            }
        }
        console.warn(`[SignalingRoom] Target peer not found: ${targetId}`);
    }
}
