# ZKS-VPN P2P Exit Peer Verification Guide

This guide explains how to verify the new **P2P Exit Peer** functionality, which enables full VPN capabilities (all TCP/UDP/HTTPS traffic) by routing through a trusted peer.

## Prerequisites

1. **Two Machines** (or two terminals on the same machine for testing):
   - **Exit Peer**: Machine with internet access (e.g., Oracle Cloud VM, Raspberry Pi, or your PC).
   - **Client**: Machine that needs VPN access.
2. **ZKS-VPN Binary**: Built from the latest source (`cargo build --release`).

## Step 1: Deploy the Relay Worker

Ensure the `zks-tunnel-relay` worker is deployed. The CI/CD pipeline should handle this automatically.
- Check GitHub Actions status: [Actions Tab](https://github.com/cswasif/ZKS-Tunnel-VPN/actions)
- Verify URL: `wss://zks-tunnel-relay.your-subdomain.workers.dev`

## Step 2: Start the Exit Peer (Oracle Cloud / VPS)

**Recommended:** Use an Oracle Cloud Free Tier VM (or any VPS) as your Exit Peer for a high-speed, always-on VPN.

1. **SSH into your VM**:
   ```bash
   ssh ubuntu@your-oracle-ip
   ```

2. **Download & Build (or upload binary)**:
   ```bash
   git clone https://github.com/cswasif/ZKS-Tunnel-VPN
   cd ZKS-Tunnel-VPN
   cargo build --release
   ```

3. **Run the Exit Peer**:
   ```bash
   # Generate a secret room ID
   export ROOM_ID="my-secret-vpn-room-88"
   
   # Run in background (use screen/tmux for persistence)
   ./target/release/zks-vpn --mode exit-peer --room $ROOM_ID
   ```
   *You should see: "Connected to relay as Exit Peer", "Waiting for Client..."*

## Step 3: Start the Client (Your PC)

On your local machine:

1. **Run the Client**:
   ```bash
   # Windows PowerShell
   $env:ROOM_ID="my-secret-vpn-room-88"
   .\target\release\zks-vpn.exe --mode p2p-client --room $env:ROOM_ID --port 1080
   ```
   *You should see: "Connected to relay as Client", "SOCKS5 proxy listening on 127.0.0.1:1080"*

## Step 4: Verify Connectivity

Configure your browser or tool to use the SOCKS5 proxy at `127.0.0.1:1080`.

### Test 1: Cloudflare-Protected Site (HTTPS)
This previously failed with the standard `connect()` mode.
```bash
curl -v -x socks5h://127.0.0.1:1080 https://google.com
```
*Expected: HTTP 200 OK (Traffic routed via Exit Peer)*

### Test 2: IP Address Check
Verify you are seeing the Exit Peer's IP (Oracle Cloud IP).
```bash
curl -x socks5h://127.0.0.1:1080 http://ifconfig.me
```

### Test 3: SSH through Tunnel
```bash
ssh -o ProxyCommand="ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p" user@server
```

## Troubleshooting

- **"Room ID required"**: Make sure to pass `--room <id>` to both commands.
- **"Connection refused"**: Ensure the Relay Worker URL is correct in the binary (default) or passed via `--relay`.
- **"Handshake failed"**: Check if both peers are using the same Room ID.

## Architecture Recap

```mermaid
graph LR
    Client[ZKS Client] -- "Encrypted (WSS)" --> Relay[ZKS Relay Worker]
    Relay -- "Encrypted (WSS)" --> Exit[ZKS Exit Peer (Oracle VM)]
    Exit -- "TCP/UDP" --> Internet[Internet]
    
    subgraph "Zero Knowledge Swarm"
    Client
    Relay
    Exit
    end
```
- **Relay**: Blindly forwards encrypted blobs.
- **Encryption**: Double-Key Vernam (Client Key + Remote LavaRand Key).
- **Result**: True P2P VPN with no central point of failure/decryption.
