# P2PCF-WS

**WebSocket signaling for P2PCF using Cloudflare Durable Objects**

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare)](https://workers.cloudflare.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Drop-in WebSocket upgrade for [P2PCF](https://github.com/gfodor/p2pcf) - instant signaling, 15x fewer requests, works on free tier.

## Why?

The original P2PCF uses HTTP polling for signaling, which has limitations:

| Aspect | HTTP Polling | WebSocket (this) |
|--------|--------------|------------------|
| Latency | 1-5 seconds | **<50ms** |
| Requests/user | ~450 | **~30** |
| Users/day (free tier) | ~220 | **~3,000** |

## Quick Start

### 1. Deploy the Worker

```bash
git clone https://github.com/your-username/p2pcf-ws.git
cd p2pcf-ws
npm install
npx wrangler deploy
```

### 2. Connect from Client

```javascript
const ws = new WebSocket('wss://your-worker.workers.dev/ws/room/my-room?clientId=user123');

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  
  switch (msg.type) {
    case 'peers':
      console.log('Your ID:', msg.yourId);
      console.log('Existing peers:', msg.peers);
      break;
    case 'peer_join':
      console.log('New peer:', msg.clientId);
      break;
    case 'peer_leave':
      console.log('Peer left:', msg.clientId);
      break;
    case 'signal':
      // Handle WebRTC signaling (SDP/ICE)
      handleSignal(msg.fromId, msg.signal);
      break;
  }
};

// Send signal to peer
ws.send(JSON.stringify({
  type: 'signal',
  targetId: 'other-user-id',
  signal: { sdp: '...' }
}));
```

## Protocol

### Client → Server

| Message | Description |
|---------|-------------|
| `{ type: "signal", targetId, signal }` | Forward SDP/ICE to specific peer |
| `{ type: "broadcast", data }` | Send to all peers in room |

### Server → Client

| Message | Description |
|---------|-------------|
| `{ type: "peers", peers, yourId }` | Initial peer list on connect |
| `{ type: "peer_join", clientId, timestamp }` | New peer joined room |
| `{ type: "peer_leave", clientId, timestamp }` | Peer disconnected |
| `{ type: "signal", fromId, signal }` | Forwarded signal from peer |

## Architecture

```
┌─────────────┐     WebSocket     ┌──────────────────────┐
│   Client A  │ ◄───────────────► │  Cloudflare Worker   │
└─────────────┘                   │                      │
                                  │   ┌───────────────┐  │
┌─────────────┐     WebSocket     │   │ SignalingRoom │  │
│   Client B  │ ◄───────────────► │   │ Durable Object│  │
└─────────────┘                   │   └───────────────┘  │
                                  └──────────────────────┘
```

**Key features:**
- **Durable Objects**: Each room is a separate DO instance
- **WebSocket Hibernation**: Idle connections don't consume CPU
- **SQLite-backed**: Works on Cloudflare free tier

## Configuration

`wrangler.toml`:
```toml
name = "p2pcf-ws"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[[durable_objects.bindings]]
name = "SIGNALING_ROOM"
class_name = "SignalingRoom"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["SignalingRoom"]
```

## Integration with P2PCF

This project is designed to work alongside P2PCF:

1. **Fast matchmaking**: Use WebSocket for instant peer discovery
2. **WebRTC signaling**: Exchange SDP/ICE through the WebSocket
3. **Peer-to-peer data**: Use P2PCF's existing WebRTC DataChannel

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Server info |
| `GET /health` | Health check |
| `GET /ws/room/:roomId?clientId=xxx` | WebSocket upgrade |

## Development

```bash
# Install dependencies
npm install

# Run locally
npm run dev

# Deploy
npm run deploy

# View logs
npm run tail
```

## License

MIT © [Your Name]

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
