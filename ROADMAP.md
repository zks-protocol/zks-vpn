# ZKS-VPN Future Roadmap

## 1. ZKS Triple-Blind Architecture (Priority #1)
**Goal**: The "Ultimate Security Model" where no single node knows the full path.
**Status**: **Feasible & High Priority**.

### Why Rust makes this "Blazing Fast":
- **Zero-Cost Abstractions**: We can swap "TCP Socket" for "ZKS Socket" with 0% CPU overhead.
- **XOR Encryption**: The Vernam cipher is the fastest encryption possible (faster than AES).
- **Async I/O**: Rust's Tokio engine handles thousands of concurrent chains without slowing down.

### Architecture
```
User -> [Relay] -> VPS 1 -> [Relay] -> VPS 2 -> Internet
```
- **VPS 1**: Acts as an Exit for User, but a Client for VPS 2.
- **No Bottleneck**: Cloudflare scales infinitely. VPS 1 and VPS 2 use full datacenter bandwidth.

### Implementation Plan
- [ ] Refactor `exit-peer` to support "Upstream ZKS Proxy".
- [ ] Add `--chain-to <room-id>` flag.

## 2. UDP Hole Punching (Direct P2P)
**Goal**: Bypass the Cloudflare Relay for maximum speed.
- Use the Relay only for signaling (exchanging IPs/Keys).
- Establish a direct UDP connection between Client and Exit Peer.
- **Benefit**: Zero relay latency, unlimited bandwidth (limited only by peers).

## 3. Constant Rate Padding (Anti-Timing Analysis)
**Goal**: Defeat Global Timing Analysis by making traffic look like a flat line.
- **Mechanism**: Send data at a fixed rate (e.g., 50 Mbps). If no data, send dummy packets.
- **Rust Implementation**: Use `tokio::time::interval` to enforce strict packet timing.
- **Trade-off**: Wastes bandwidth (but we have unlimited Oracle bandwidth).

## 4. ZKS Remote Browser (Anti-User Error)
**Goal**: Prevent users from de-anonymizing themselves (cookies, fingerprinting).
- **Architecture**: Run a headless Chromium instance on the Exit Peer.
- **Protocol**: Stream video/pixels to the Client (like Stadia/GeForce Now).
- **Result**: The "Browser" is 100% isolated from the User's PC. No cookies or malware can cross the gap.

## 5. ZKS Browser Control Protocol (ZBCP)
**Goal**: A custom protocol to control a remote browser with minimal bandwidth.
- **Concept**: Instead of streaming video (heavy), we stream *commands* and *state*.
- **Protocol**: JSON-based WebSocket protocol.
    - Client -> Server: `{ "cmd": "click", "x": 100, "y": 200 }`
    - Server -> Client: `{ "event": "dom_update", "rect": [...] }` (or optimized video chunks)
- **Benefit**: Feels like a local browser (responsive) but runs remotely (secure).

## 6. System-Wide Routing (TUN Interface)
**Goal**: Finish the `vpn` mode integration with `tun-rs`.
- Currently, `p2p-client` provides SOCKS5.
- Next step: Connect SOCKS5 to a virtual network card so *all* apps work without configuration.

## 7. Swarm Entropy Tax (Trustless Key Generation)
**Goal**: Eliminate trust in Cloudflare's RNG by using the Swarm.
- **Mechanism**: Every connected peer *must* provide random bytes (Entropy) to the network.
- **Process**:
    1.  When you connect, the Relay picks 10 random peers.
    2.  It asks them for 32 bytes of randomness.
    3.  It XORs them together to create your $K_{Remote}$.
- **Result**: To break the key, an attacker must control **ALL 10** randomly selected peers. Statistically impossible.
