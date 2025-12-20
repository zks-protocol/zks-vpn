/**
 * WebSocketTransport - WebSocket-based signaling transport for P2PCF-WS
 * 
 * This is the client-side transport that connects to the P2PCF-WS Durable Objects
 * signaling server via WebSocket.
 */

export interface SignalingTransport {
    start(): void;
    stop(): void;
    send(targetId: string, signal: unknown): void;
    broadcast(data: unknown): void;
    onPeerJoin(callback: (peerId: string) => void): void;
    onPeerLeave(callback: (peerId: string) => void): void;
    onSignal(callback: (fromId: string, signal: unknown) => void): void;
    onPeers(callback: (peers: string[], yourId: string) => void): void;
}

export interface WebSocketTransportOptions {
    workerUrl: string;
    roomId: string;
    clientId?: string;
    reconnectInterval?: number;
    maxReconnectAttempts?: number;
}

type MessageHandler = (data: unknown) => void;

export class WebSocketTransport implements SignalingTransport {
    private ws: WebSocket | null = null;
    private readonly workerUrl: string;
    private readonly roomId: string;
    private readonly clientId: string;
    private readonly reconnectInterval: number;
    private readonly maxReconnectAttempts: number;

    private reconnectAttempts = 0;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private isDestroyed = false;

    // Event handlers
    private peerJoinHandlers: Set<(peerId: string) => void> = new Set();
    private peerLeaveHandlers: Set<(peerId: string) => void> = new Set();
    private signalHandlers: Set<(fromId: string, signal: unknown) => void> = new Set();
    private peersHandlers: Set<(peers: string[], yourId: string) => void> = new Set();

    constructor(options: WebSocketTransportOptions) {
        this.workerUrl = options.workerUrl.replace(/^https?:\/\//, 'wss://');
        this.roomId = options.roomId;
        this.clientId = options.clientId || `user-${Math.random().toString(36).substring(2, 10)}`;
        this.reconnectInterval = options.reconnectInterval || 3000;
        this.maxReconnectAttempts = options.maxReconnectAttempts || 10;
    }

    start(): void {
        if (this.isDestroyed) return;
        this.connect();
    }

    stop(): void {
        this.isDestroyed = true;
        this.cleanup();
    }

    send(targetId: string, signal: unknown): void {
        if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'signal',
                targetId,
                signal,
            }));
        }
    }

    broadcast(data: unknown): void {
        if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'broadcast',
                data,
            }));
        }
    }

    onPeerJoin(callback: (peerId: string) => void): void {
        this.peerJoinHandlers.add(callback);
    }

    onPeerLeave(callback: (peerId: string) => void): void {
        this.peerLeaveHandlers.add(callback);
    }

    onSignal(callback: (fromId: string, signal: unknown) => void): void {
        this.signalHandlers.add(callback);
    }

    onPeers(callback: (peers: string[], yourId: string) => void): void {
        this.peersHandlers.add(callback);
    }

    private connect(): void {
        const url = `${this.workerUrl}/ws/room/${encodeURIComponent(this.roomId)}?clientId=${encodeURIComponent(this.clientId)}`;

        console.log(`[WebSocketTransport] Connecting to ${url}`);

        try {
            this.ws = new WebSocket(url);
            this.setupHandlers();
        } catch (err) {
            console.error('[WebSocketTransport] Failed to create WebSocket:', err);
            this.scheduleReconnect();
        }
    }

    private setupHandlers(): void {
        if (!this.ws) return;

        this.ws.onopen = () => {
            console.log('[WebSocketTransport] Connected');
            this.reconnectAttempts = 0;
        };

        this.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                this.handleMessage(msg);
            } catch (err) {
                console.error('[WebSocketTransport] Failed to parse message:', err);
            }
        };

        this.ws.onclose = (event) => {
            console.log(`[WebSocketTransport] Disconnected: ${event.code} ${event.reason}`);
            if (!this.isDestroyed) {
                this.scheduleReconnect();
            }
        };

        this.ws.onerror = (event) => {
            console.error('[WebSocketTransport] WebSocket error:', event);
        };
    }

    private handleMessage(msg: { type: string;[key: string]: unknown }): void {
        switch (msg.type) {
            case 'peers':
                this.peersHandlers.forEach((h) => h(msg.peers as string[], msg.yourId as string));
                break;
            case 'peer_join':
                this.peerJoinHandlers.forEach((h) => h(msg.clientId as string));
                break;
            case 'peer_leave':
                this.peerLeaveHandlers.forEach((h) => h(msg.clientId as string));
                break;
            case 'signal':
                this.signalHandlers.forEach((h) => h(msg.fromId as string, msg.signal));
                break;
            default:
                console.warn('[WebSocketTransport] Unknown message type:', msg.type);
        }
    }

    private scheduleReconnect(): void {
        if (this.isDestroyed) return;

        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('[WebSocketTransport] Max reconnect attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectInterval * Math.pow(1.5, this.reconnectAttempts - 1);

        console.log(`[WebSocketTransport] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

        this.reconnectTimer = setTimeout(() => {
            this.connect();
        }, delay);
    }

    private cleanup(): void {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }

        this.peerJoinHandlers.clear();
        this.peerLeaveHandlers.clear();
        this.signalHandlers.clear();
        this.peersHandlers.clear();
    }
}
