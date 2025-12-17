# ZKS-VPN Future Roadmap

## 1. ZKS Onion Routing (Multi-Hop)
**Goal**: True anonymity by chaining peers (Tor-like architecture).

### Architecture
```
User -> [Relay] -> Peer A -> [Relay] -> Peer B -> Internet
```
- **Peer A (Entry)**: Knows User IP, doesn't know Destination.
- **Peer B (Exit)**: Knows Destination, doesn't know User IP.

### Implementation Plan
- Add `--upstream-proxy` support to `exit-peer` mode.
- Allow `exit-peer` to route its outbound traffic through another `p2p-client` instance.

## 2. UDP Hole Punching (Direct P2P)
**Goal**: Bypass the Cloudflare Relay for maximum speed.
- Use the Relay only for signaling (exchanging IPs/Keys).
- Establish a direct UDP connection between Client and Exit Peer.
- **Benefit**: Zero relay latency, unlimited bandwidth (limited only by peers).

## 3. Public Swarm Discovery
**Goal**: Allow users to share bandwidth anonymously.
- **DHT (Distributed Hash Table)**: Store active Room IDs.
- **Incentives**: Earn credits for running an Exit Peer (ZKS Token?).
- **Reputation System**: Verify honest peers.

## 4. Obfuscation (Stealth Mode)
**Goal**: Hide ZKS traffic from Deep Packet Inspection (DPI).
- Wrap WebSocket traffic in "fake" HTML or video stream headers.
- Make VPN traffic look like watching YouTube.

## 5. System-Wide Routing (TUN Interface)
**Goal**: Finish the `vpn` mode integration with `tun-rs`.
- Currently, `p2p-client` provides SOCKS5.
- Next step: Connect SOCKS5 to a virtual network card so *all* apps work without configuration.
