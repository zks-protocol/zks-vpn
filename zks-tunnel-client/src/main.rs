//! ZKS-Tunnel Client - Local SOCKS5 Proxy & System-Wide VPN
//!
//! This CLI tool provides two modes:
//! 1. SOCKS5 Proxy (default): Creates a local proxy for browser traffic
//! 2. VPN Mode: Routes ALL system traffic through the tunnel
//!
//! Usage:
//!   # SOCKS5 mode (default)
//!   zks-vpn --worker wss://zks-tunnel.user.workers.dev/tunnel
//!
//!   # System-wide VPN mode (requires admin/root)
//!   zks-vpn --worker wss://zks-tunnel.user.workers.dev/tunnel --mode vpn
//!
//! Then configure your browser/system to use SOCKS5 proxy at localhost:1080

use clap::{Parser, ValueEnum};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

mod chain;
mod exit_peer;
mod http_proxy;
mod key_exchange;
mod p2p_client;
mod p2p_relay;
mod p2p_vpn;
mod socks5;
mod stream_manager;
mod tunnel;
mod vpn;

use http_proxy::HttpProxyServer;
use socks5::Socks5Server;
use tunnel::TunnelClient;

#[cfg(feature = "vpn")]
use std::sync::Arc;
#[cfg(feature = "vpn")]
use vpn::{VpnConfig, VpnController};

/// Operating mode for the VPN client
#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq)]
pub enum Mode {
    /// SOCKS5 proxy mode (browser only, raw TCP)
    #[default]
    Socks5,
    /// HTTP proxy mode (uses fetch() for HTTPS, works with all sites)
    Http,
    /// System-wide VPN mode (all traffic, via Cloudflare Worker)
    Vpn,
    /// P2P Client mode - route traffic through Exit Peer (SOCKS5 interface)
    #[value(name = "p2p-client")]
    P2pClient,
    /// P2P VPN mode - system-wide VPN through Exit Peer (Triple-Blind)
    #[value(name = "p2p-vpn")]
    P2pVpn,
    /// Exit Peer mode - forward traffic to Internet (HTTP/TCP proxy)
    #[value(name = "exit-peer")]
    ExitPeer,
    /// Exit Peer VPN mode - Layer 3 VPN packet forwarding (TUN device)
    #[value(name = "exit-peer-vpn")]
    ExitPeerVpn,
}

/// ZKS-Tunnel VPN Client
#[derive(Parser, Debug)]
#[command(name = "zks-vpn")]
#[command(author = "Md Wasif Faisal")]
#[command(version = "0.1.0")]
#[command(about = "Serverless VPN via Cloudflare Workers", long_about = None)]
struct Args {
    /// ZKS-Tunnel Worker WebSocket URL
    #[arg(short, long, default_value = "wss://zks-tunnel.workers.dev/tunnel")]
    worker: String,

    /// Operating mode: socks5 (browser only) or vpn (system-wide)
    #[arg(short, long, value_enum, default_value_t = Mode::Socks5)]
    mode: Mode,

    /// Local SOCKS5 proxy port (socks5 mode only)
    #[arg(short, long, default_value_t = 1080)]
    port: u16,

    /// Bind address (socks5 mode only)
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// TUN device name (vpn mode only)
    #[arg(long, default_value = "zks0")]
    tun_name: String,

    /// Virtual IP address for VPN (vpn mode only)
    #[arg(long, default_value = "10.0.85.1")]
    vpn_address: String,

    /// Enable kill switch - block traffic if VPN disconnects (vpn mode only)
    #[arg(long)]
    kill_switch: bool,

    /// Enable DNS leak protection (vpn mode only)
    #[arg(long)]
    dns_protection: bool,

    /// Room ID for P2P mode (shared between Client and Exit Peer)
    #[arg(long)]
    room: Option<String>,

    /// Relay URL for P2P mode (defaults to zks-tunnel-relay worker)
    #[arg(
        long,
        default_value = "wss://zks-tunnel-relay.md-wasif-faisal.workers.dev"
    )]
    relay: String,

    /// ZKS-Vernam key server URL (for double-key encryption)
    #[arg(long, default_value = "https://zks-vernam.md-wasif-faisal.workers.dev")]
    vernam: String,

    /// Constant Rate Padding in Kbps (traffic analysis defense)
    /// Set to 0 to disable. Example: --padding 100 for 100 Kbps padding
    #[arg(long, default_value_t = 0)]
    padding: u32,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Upstream SOCKS5 proxy (e.g., 127.0.0.1:9050) to route traffic through
    #[arg(long)]
    proxy: Option<String>,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    // Initialize logging
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Display banner
    print_banner(&args);

    // Handle P2P modes separately (they use relay, not tunnel worker)
    match args.mode {
        Mode::P2pClient => {
            let room_id = args.room.clone().unwrap_or_else(|| {
                error!("Room ID required for P2P mode. Use --room <id>");
                std::process::exit(1);
            });
            return p2p_client::run_p2p_client(
                &args.relay,
                &args.vernam,
                &room_id,
                args.port,
                args.proxy,
            )
            .await;
        }
        Mode::P2pVpn => {
            let room_id = args.room.clone().unwrap_or_else(|| {
                error!("Room ID required for P2P VPN mode. Use --room <id>");
                std::process::exit(1);
            });
            return run_p2p_vpn_mode(args, room_id).await;
        }
        Mode::ExitPeer => {
            let room_id = args.room.clone().unwrap_or_else(|| {
                error!("Room ID required for Exit Peer mode. Use --room <id>");
                std::process::exit(1);
            });
            return exit_peer::run_exit_peer(&args.relay, &args.vernam, &room_id).await;
        }
        #[cfg(feature = "vpn")]
        Mode::ExitPeerVpn => {
            let room_id = args.room.clone().unwrap_or_else(|| {
                error!("Room ID required for Exit Peer VPN mode. Use --room <id>");
                std::process::exit(1);
            });
            return exit_peer::run_exit_peer_vpn(&args.relay, &args.vernam, &room_id).await;
        }
        _ => {}
    }

    // For other modes, connect to Worker
    info!("Connecting to ZKS-Tunnel Worker...");
    let tunnel = TunnelClient::connect_ws(&args.worker).await.map_err(|e| {
        error!("❌ Failed to connect: {}", e);
        e
    })?;
    info!("✅ Connected to Worker!");

    match args.mode {
        Mode::Socks5 => run_socks5_mode(args, tunnel).await,
        Mode::Http => run_http_proxy_mode(args, tunnel).await,
        Mode::Vpn => run_vpn_mode(args, tunnel).await,
        Mode::P2pClient | Mode::P2pVpn | Mode::ExitPeer | Mode::ExitPeerVpn => unreachable!(),
    }
}

/// Print the application banner
fn print_banner(args: &Args) {
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║         ZKS-Tunnel VPN - Serverless & Free                   ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  Worker: {}  ", args.worker);

    match args.mode {
        Mode::Socks5 => {
            info!("║  Mode:   SOCKS5 Proxy (browser only)                        ║");
            info!(
                "║  Listen: {}:{}                                  ",
                args.bind, args.port
            );
        }
        Mode::Http => {
            info!("║  Mode:   HTTP Proxy (HTTPS via fetch, all sites work)      ║");
            info!(
                "║  Listen: {}:{}                                  ",
                args.bind, args.port
            );
        }
        Mode::Vpn => {
            info!("║  Mode:   System-Wide VPN (all traffic)                      ║");
            info!(
                "║  TUN:    {}                                             ",
                args.tun_name
            );
            info!(
                "║  VPN IP: {}                                          ",
                args.vpn_address
            );
        }
        Mode::P2pClient => {
            info!("║  Mode:   P2P Client (via Exit Peer)                         ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
            info!(
                "║  Listen: {}:{}                                  ",
                args.bind, args.port
            );
        }
        Mode::ExitPeer => {
            info!("║  Mode:   Exit Peer (forward to Internet)                    ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
        }
        Mode::ExitPeerVpn => {
            info!("║  Mode:   Exit Peer VPN (Layer 3 Forwarding)                 ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
        }
        Mode::P2pVpn => {
            info!("║  Mode:   P2P VPN (Triple-Blind, System-Wide)                ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
            info!(
                "║  VPN IP: {}                                          ",
                args.vpn_address
            );
        }
    }

    info!("╚══════════════════════════════════════════════════════════════╝");
}

/// Run in SOCKS5 proxy mode
async fn run_socks5_mode(args: Args, tunnel: TunnelClient) -> Result<(), BoxError> {
    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    let listener = TcpListener::bind(bind_addr).await?;

    info!("🚀 SOCKS5 proxy listening on {}", bind_addr);
    info!(
        "   Configure your browser to use SOCKS5 proxy: {}:{}",
        args.bind, args.port
    );
    info!("");
    info!("   Firefox: Settings → Network → Manual proxy → SOCKS5");
    info!("   Chrome:  Use SwitchyOmega extension");

    let socks_server = Socks5Server::new(tunnel);
    socks_server.run(listener).await?;

    Ok(())
}

/// Run in HTTP proxy mode (uses fetch() for HTTPS)
async fn run_http_proxy_mode(args: Args, tunnel: TunnelClient) -> Result<(), BoxError> {
    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    let listener = TcpListener::bind(bind_addr).await?;

    info!("🚀 HTTP proxy listening on {}", bind_addr);
    info!(
        "   Configure your browser to use HTTP proxy: {}:{}",
        args.bind, args.port
    );
    info!("");
    info!("   ✅ HTTPS sites work via Cloudflare fetch() API");
    info!("   ✅ All Cloudflare-proxied sites are accessible");

    let http_server = HttpProxyServer::new(tunnel);
    http_server.run(listener).await?;

    Ok(())
}

/// Run in system-wide VPN mode
async fn run_vpn_mode(_args: Args, _tunnel: TunnelClient) -> Result<(), BoxError> {
    // Check if VPN feature is enabled
    #[cfg(not(feature = "vpn"))]
    {
        error!("❌ VPN mode is not enabled!");
        error!("   Rebuild with: cargo build --release --features vpn");
        Err("VPN feature not enabled".into())
    }

    #[cfg(feature = "vpn")]
    {
        // Check for admin/root privileges
        check_privileges()?;

        let vpn_addr: std::net::Ipv4Addr = _args.vpn_address.parse()?;

        let config = VpnConfig {
            device_name: _args.tun_name.clone(),
            address: vpn_addr,
            netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
            dns_protection: _args.dns_protection,
            kill_switch: _args.kill_switch,
        };

        info!("🔒 Starting system-wide VPN...");
        info!("   All traffic will be routed through the tunnel.");

        if _args.kill_switch {
            info!("   Kill switch: ENABLED (traffic blocked if VPN drops)");
        }

        if _args.dns_protection {
            info!("   DNS protection: ENABLED (queries via DoH)");
        }

        let tunnel = Arc::new(_tunnel);
        let vpn = VpnController::new(tunnel, config);

        vpn.start().await?;

        // Wait for Ctrl+C
        info!("");
        info!("Press Ctrl+C to disconnect VPN...");

        tokio::signal::ctrl_c().await?;

        info!("");
        info!("Shutting down VPN...");
        vpn.stop().await?;

        Ok(())
    }
}

/// Run in P2P VPN mode (Triple-Blind Architecture)
async fn run_p2p_vpn_mode(_args: Args, _room_id: String) -> Result<(), BoxError> {
    #[cfg(not(feature = "vpn"))]
    {
        error!("❌ VPN mode is not enabled!");
        error!("   Rebuild with: cargo build --release --features vpn");
        Err("VPN feature not enabled".into())
    }

    #[cfg(feature = "vpn")]
    {
        use p2p_vpn::{P2PVpnConfig, P2PVpnController};

        // Shadow the underscore-prefixed args for use
        let args = _args;
        let room_id = _room_id;

        // Check for admin/root privileges
        check_privileges()?;

        let vpn_addr: std::net::Ipv4Addr = args.vpn_address.parse()?;

        let config = P2PVpnConfig {
            device_name: args.tun_name.clone(),
            address: vpn_addr,
            netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
            dns_protection: args.dns_protection,
            kill_switch: args.kill_switch,
            relay_url: args.relay.clone(),
            vernam_url: args.vernam.clone(),
            room_id,
            proxy: args.proxy.clone(),
            exit_peer_address: std::net::Ipv4Addr::new(10, 0, 85, 2),
        };

        info!("🔒 Starting P2P VPN (Triple-Blind Architecture)...");
        info!("   All traffic will be routed through the Exit Peer.");
        info!("   Your IP is hidden behind the Exit Peer's IP.");

        if args.kill_switch {
            info!("   Kill switch: ENABLED (traffic blocked if VPN drops)");
        }

        if args.dns_protection {
            info!("   DNS protection: ENABLED (queries via DoH)");
        }

        let vpn = P2PVpnController::new(config);

        vpn.start().await?;

        // Wait for Ctrl+C
        info!("");
        info!("Press Ctrl+C to disconnect VPN...");

        tokio::signal::ctrl_c().await?;

        info!("");
        info!("Shutting down P2P VPN...");
        vpn.stop().await?;

        Ok(())
    }
}

/// Check if running with admin/root privileges
#[cfg(feature = "vpn")]
fn check_privileges() -> Result<(), BoxError> {
    #[cfg(target_os = "windows")]
    {
        // On Windows, check if running as Administrator
        // This is a simplified check - full implementation would use Windows API
        tracing::warn!("⚠️  VPN mode requires Administrator privileges on Windows");
        tracing::warn!("   Right-click zks-vpn.exe → Run as administrator");
    }

    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            error!("❌ VPN mode requires root privileges!");
            error!("   Run with: sudo zks-vpn --mode vpn ...");
            return Err("Root privileges required for VPN mode".into());
        }
    }

    Ok(())
}
