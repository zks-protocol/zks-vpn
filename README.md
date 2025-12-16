# ZKS-Tunnel VPN

**The World's First Serverless, Free, Zero-Knowledge System-Wide VPN**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/cswasif/ZKS-Tunnel-VPN/actions/workflows/ci.yml/badge.svg)](https://github.com/cswasif/ZKS-Tunnel-VPN/actions/workflows/ci.yml)

## 🚀 What is ZKS-Tunnel?

ZKS-Tunnel is a revolutionary **system-wide VPN** that runs entirely on **Cloudflare Workers** (free tier) with **Zero-Knowledge Swarm** encryption. No servers to rent, no monthly fees, no trust required.

```
┌─────────────────────────────────────────────────────────────────┐
│  YOUR PC          CLOUDFLARE EDGE           INTERNET            │
│                   (300+ cities)                                 │
│  ┌─────────┐     ┌─────────────┐     ┌─────────────────────┐    │
│  │ zks-vpn │────►│ ZKS Worker  │────►│ Any Website/Server  │    │
│  │ TUN VPN │     │ (Free!)     │     │ Sees Cloudflare IP  │    │
│  └─────────┘     └─────────────┘     └─────────────────────┘    │
│                                                                 │
│  ALL system traffic routed. Your data is ENCRYPTED (OTP-level). │
└─────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### VPN Capabilities
- **🌐 System-Wide VPN** - Routes ALL your system traffic (not just browser)
- **🔒 TUN Device** - Creates virtual network interface for full OS integration
- **⚡ TCP/IP Stack** - Userspace networking with `netstack-smoltcp`
- **🛡️ Kill Switch** - Blocks traffic if VPN disconnects (Windows/Linux/macOS)
- **🔐 DNS Leak Protection** - DNS-over-HTTPS via Cloudflare 1.1.1.1
- **📡 SOCKS5 Proxy Mode** - Optional lightweight mode for app-level routing

### Cost & Privacy
- **💰 $0/month** - Runs on Cloudflare Workers free tier (100,000 requests/day)
- **🔐 Mathematically Unbreakable** - ZKS double-key Vernam cipher (OTP security)
- **🌍 Global** - 300+ edge locations for low latency
- **🕵️ Zero-Knowledge** - Even Cloudflare can't read your traffic (split-key encryption)
- **📖 Open Source** - Fully auditable Rust code

## 📦 Project Structure

```
ZKS_VPN/
├── zks-tunnel-proto/    # Shared protocol definitions (Rust + WASM)
├── zks-tunnel-worker/   # Cloudflare Worker (Serverless Gateway)
└── zks-tunnel-client/   # Local client (VPN + SOCKS5)
    ├── src/vpn.rs       # System-wide VPN (TUN + netstack)
    ├── src/socks5.rs    # SOCKS5 proxy mode
    └── src/tunnel.rs    # WebSocket tunnel to worker
```

## 🛠️ Quick Start

### Prerequisites
- **Rust** (latest stable): `https://rustup.rs/`
- **Wrangler** (for deploying worker): `npm install -g wrangler`
- **Admin/Root** (for VPN mode, not needed for SOCKS5)

### 1. Deploy the Worker

```bash
cd zks-tunnel-worker
wrangler login
wrangler deploy
# Note your worker URL: https://your-worker.YOUR-SUBDOMAIN.workers.dev
```

### 2. Run as System-Wide VPN (Recommended)

```bash
cd zks-tunnel-client
cargo build --release --features vpn

# Linux/macOS (requires sudo for TUN device)
sudo ./target/release/zks-vpn \
  --worker wss://your-worker.YOUR-SUBDOMAIN.workers.dev/tunnel \
  --mode vpn \
  --vpn-address 10.0.85.1 \
  --kill-switch \
  --dns-protection

# Windows (run as Administrator)
.\target\release\zks-vpn.exe ^
  --worker wss://your-worker.YOUR-SUBDOMAIN.workers.dev/tunnel ^
  --mode vpn ^
  --vpn-address 10.0.85.1 ^
  --kill-switch ^
  --dns-protection
```

**That's it!** All system traffic (browser, apps, terminal) now goes through the VPN.

### 3. Run as SOCKS5 Proxy (Alternative)

```bash
cargo build --release

./target/release/zks-vpn \
  --worker wss://your-worker.YOUR-SUBDOMAIN.workers.dev/tunnel \
  --mode socks5 \
  --listen 127.0.0.1:1080
```

Then configure your apps to use SOCKS5 proxy: `127.0.0.1:1080`

## 📖 How It Works

### System-Wide VPN Mode (--mode vpn)
1. **TUN Device** - Creates virtual network interface (`zks0`)
2. **IP Routing** - OS routes all traffic through the TUN device
3. **Userspace Stack** - `netstack-smoltcp` processes TCP/IP packets
4. **Tunnel** - Packets encrypted with ZKS, sent via WebSocket to Worker
5. **Worker** - Opens TCP sockets to destinations, relays data bidirectionally
6. **Kill Switch** - Firewall rules block non-VPN traffic if enabled

### SOCKS5 Proxy Mode (--mode socks5)
1. **Local Proxy** - Listens on port 1080
2. **App Connection** - Browser/app connects to proxy
3. **Tunnel** - Encrypted via ZKS WebSocket to Worker
4. **Worker** - Opens TCP socket to destination
5. **Response** - Data flows back the same way

## 🔐 Security Architecture

### Split-Streamed Vernam Cipher (ZKS Protocol)
ZKS-Tunnel uses a revolutionary encryption method documented in [`innovation_paper.md`](innovation_paper.md):

```
Ciphertext = Plaintext ⊕ Key_A ⊕ Key_B
```

- **Key_A**: Generated locally (CSPRNG)
- **Key_B**: Streamed from decentralized swarm (LavaRand hardware entropy)
- **Disjoint Paths**: Keys and ciphertext travel through different network routes

**Result**: Information-theoretic security (unbreakable, even by quantum computers)

### Additional Security Features
- **DNS-over-HTTPS**: Prevents DNS leaks (queries via Cloudflare 1.1.1.1)
- **Kill Switch**: Firewall rules block traffic if tunnel drops
- **SSRF Protection**: Worker blocks connections to private IPs
- **No Logging**: Cloudflare Workers are stateless, no persistent storage

## 🧪 Development

### Build All Packages
```bash
cargo check --workspace --all-features
```

### Run Tests
```bash
cargo test --workspace
```

### Local Development
```bash
# Terminal 1: Run worker locally (requires wrangler)
cd zks-tunnel-worker
wrangler dev --port 8787

# Terminal 2: Run client (SOCKS5 mode for easy testing)
cd zks-tunnel-client
cargo run -- --worker ws://localhost:8787/tunnel --mode socks5
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License - Free to use, modify, and distribute.

## 🙏 Credits

Created by **Md. Wasif Faisal** as part of the ZKS (Zero-Knowledge Swarm) project.

### Key Technologies
- **Rust** - Memory-safe systems programming
- **Cloudflare Workers** - Serverless edge computing
- **tun-rs** - Cross-platform TUN device creation
- **netstack-smoltcp** - Userspace TCP/IP stack
- **tokio** - Async runtime for Rust
- **WebAssembly** - Runs Rust in the browser/worker

## 📚 Documentation

- [Innovation Paper](innovation_paper.md) - ZKS Protocol & Split-Streamed Vernam Cipher
- [Whitepaper](whitepaper.md) - Full technical specification
- [System VPN Research](system_wide_vpn_research.md) - Architecture decisions

---

**Build the future. Make it free. Keep it private.** 🌍🔐
