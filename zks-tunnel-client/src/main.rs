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
mod ct_ops; // Constant-time cryptographic operations
mod entry_node;
mod exit_node_udp;
mod exit_peer;
mod file_transfer;
mod http_proxy;
mod hybrid_data;
mod key_exchange;
mod p2p_client;
mod p2p_relay;
mod p2p_vpn;
mod packet_pool;
mod socks5;
mod stream_manager;
mod tunnel;
mod vpn;
mod zks_tunnel;

#[cfg(target_os = "linux")]
mod tun_multiqueue;
#[cfg(feature = "vpn")]
mod userspace_nat;

// Platform-specific routing modules
#[cfg(all(target_os = "linux", feature = "vpn"))]
mod linux_routing;
#[cfg(all(target_os = "windows", feature = "vpn"))]
mod windows_routing;

// DNS leak protection
#[cfg(feature = "vpn")]
mod dns_guard;
#[cfg(feature = "vpn")]
mod kill_switch;

#[cfg(windows)]
mod windows_service;

#[cfg(feature = "swarm")]
mod p2p_swarm;

#[cfg(feature = "swarm")]
mod onion;

mod entropy_events;
mod entropy_tax;
mod exit_service;
mod key_rotation;
mod relay_service;
mod replay_protection;
pub mod swarm_entropy_collection;
mod tls_mimicry;
mod traffic_mixer;
mod traffic_shaping;
pub mod true_vernam;

#[cfg(feature = "swarm")]
mod signaling;

#[cfg(feature = "swarm")]
mod swarm_controller;

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
    /// Entry Node mode - UDP relay for Multi-Hop VPN (first hop)
    #[value(name = "entry-node")]
    EntryNode,
    /// Exit Node UDP mode - TUN forwarding for Multi-Hop VPN (second hop)
    #[value(name = "exit-node-udp")]
    ExitNodeUdp,
    /// Exit Peer Hybrid mode - Worker signaling + Cloudflare Tunnel data
    #[value(name = "exit-peer-hybrid")]
    ExitPeerHybrid,
    /// Faisal Swarm mode - P2P mesh with DCUtR hole-punching and bandwidth sharing
    #[cfg(feature = "swarm")]
    #[value(name = "swarm")]
    Swarm,
    /// Send file to peer
    #[value(name = "send-file")]
    SendFile,
    /// Receive file from peer
    #[value(name = "receive-file")]
    ReceiveFile,
}

/// ZKS-Tunnel VPN Client
#[derive(Parser, Debug, Clone)]
#[command(name = "zks-vpn")]
#[command(author = "Md Wasif Faisal")]
#[command(version = "0.1.0")]
#[command(about = "Serverless VPN via Cloudflare Workers", long_about = None)]
pub struct Args {
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

    #[arg(long, default_value = "10.0.85.1")]
    vpn_address: String,

    /// Exit Peer VPN IP address (gateway for routing)
    #[arg(long, default_value = "10.0.85.2")]
    exit_peer_address: String,

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
    #[arg(long, default_value = "https://zks-key.md-wasif-faisal.workers.dev")]
    vernam: String,

    /// Constant Rate Padding in Kbps (traffic analysis defense)
    /// Set to 0 to disable. Example: --padding 100 for 100 Kbps padding
    #[arg(long, default_value_t = 0)]
    padding: u32,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Swarm: Consent to run as exit node (legal requirement)
    #[arg(long)]
    exit_consent: bool,

    /// Swarm: Disable relay service (default: enabled)
    #[arg(long)]
    no_relay: bool,

    /// Swarm: Disable exit service (default: disabled, requires --exit-consent)
    #[arg(long)]
    /// Swarm: Disable exit service (default: disabled, requires --exit-consent)
    #[arg(long)]
    no_exit: bool,

    /// Swarm: Disable VPN client (default: enabled)
    #[arg(long)]
    no_client: bool,

    /// Swarm: Run in Server Mode (Exit Node with NAT, no default route change)
    #[arg(long)]
    server: bool,

    /// Upstream SOCKS5 proxy (e.g., 127.0.0.1:9050) to route traffic through
    #[arg(long)]
    proxy: Option<String>,

    /// Exit Node address for Entry Node mode (e.g., 213.35.103.204:51820)
    #[arg(long, default_value = "213.35.103.204:51820")]
    exit_node: String,

    /// Listen port for Entry Node mode (UDP)
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,

    /// File path for transfer (send-file/receive-file mode)
    #[arg(long)]
    file: Option<String>,

    /// Destination peer ID (send-file mode)
    #[arg(long)]
    dest: Option<String>,

    /// Transfer ticket (receive-file mode)
    #[arg(long)]
    ticket: Option<String>,

    /// Run as a Windows Service
    #[arg(long)]
    service: bool,

    /// Install as a Windows Service
    #[arg(long)]
    install_service: bool,

    /// Uninstall the Windows Service
    #[arg(long)]
    uninstall_service: bool,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    #[cfg(windows)]
    {
        if args.install_service {
            return windows_service::service::install_service();
        }
        if args.uninstall_service {
            return windows_service::service::uninstall_service();
        }
        if args.service {
            return windows_service::service::run().map_err(|e| e.into());
        }
    }

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
            info!("Running Exit Peer in SOCKS5/TCP mode (no TUN device)");
            return exit_peer::run_exit_peer(&args.relay, &args.vernam, &room_id).await;
        }
        Mode::ExitPeerVpn => {
            let room_id = args.room.clone().unwrap_or_else(|| {
                error!("Room ID required for Exit Peer VPN mode. Use --room <id>");
                std::process::exit(1);
            });

            #[cfg(feature = "vpn")]
            {
                info!("Running Exit Peer in VPN mode (TUN device enabled)");
                return exit_peer::run_exit_peer_vpn(&args.relay, &args.vernam, &room_id).await;
            }
            #[cfg(not(feature = "vpn"))]
            {
                error!("❌ Exit Peer VPN mode requires 'vpn' feature!");
                error!("   Rebuild with: cargo build --release --features vpn");
                return Err("VPN feature not enabled".into());
            }
        }
        Mode::EntryNode => {
            use entry_node::EntryNodeConfig;
            let listen_addr: std::net::SocketAddr =
                format!("0.0.0.0:{}", args.listen_port).parse()?;
            let exit_node_addr: std::net::SocketAddr = args.exit_node.parse().map_err(|_| {
                error!("Invalid exit node address: {}", args.exit_node);
                "Invalid exit node address"
            })?;
            return entry_node::run_entry_node(EntryNodeConfig {
                listen_addr,
                exit_node_addr,
            })
            .await;
        }
        Mode::ExitNodeUdp => {
            return exit_node_udp::run_exit_node_udp(args.listen_port).await;
        }
        Mode::ExitPeerHybrid => {
            let room_id = args.room.clone().unwrap_or_else(|| "default".to_string());
            #[cfg(feature = "vpn")]
            {
                return run_exit_peer_hybrid_mode(args, room_id).await;
            }
            #[cfg(not(feature = "vpn"))]
            {
                error!("❌ Hybrid Exit Peer mode requires 'vpn' feature!");
                error!("   Rebuild with: cargo build --release --features vpn");
                return Err("VPN feature not enabled".into());
            }
        }
        #[cfg(feature = "swarm")]
        Mode::Swarm => {
            let room_id = args.room.clone().unwrap_or_else(|| "default".to_string());
            return run_swarm_mode(args, room_id).await;
        }
        Mode::SendFile => {
            let room_id = args.room.clone().unwrap_or_else(|| {
                error!("Room ID required for file transfer. Use --room <id>");
                std::process::exit(1);
            });
            let file_path = args.file.clone().unwrap_or_else(|| {
                error!("File path required. Use --file <path>");
                std::process::exit(1);
            });
            return file_transfer::run_send_file(
                &args.relay,
                &args.vernam,
                &room_id,
                &file_path,
                args.dest,
            )
            .await;
        }
        Mode::ReceiveFile => {
            let room_id = args.room.clone().unwrap_or_else(|| "default".to_string());
            return file_transfer::run_receive_file(
                &args.relay,
                &args.vernam,
                &room_id,
                args.ticket,
            )
            .await;
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
        Mode::P2pClient
        | Mode::P2pVpn
        | Mode::ExitPeer
        | Mode::ExitPeerVpn
        | Mode::EntryNode
        | Mode::ExitNodeUdp
        | Mode::ExitPeerHybrid
        | Mode::SendFile
        | Mode::ReceiveFile => {
            unreachable!()
        }
        #[cfg(feature = "swarm")]
        Mode::Swarm => {
            unreachable!()
        }
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
        Mode::EntryNode => {
            info!("║  Mode:   Entry Node (UDP Relay, Multi-Hop VPN)              ║");
            info!(
                "║  Listen: 0.0.0.0:{}                                      ",
                args.listen_port
            );
            info!("║  Exit:   {}  ", args.exit_node);
        }
        Mode::ExitNodeUdp => {
            info!("║  Mode:   Exit Node UDP (TUN, Multi-Hop VPN)                 ║");
            info!(
                "║  Listen: 0.0.0.0:{}                                      ",
                args.listen_port
            );
        }
        Mode::ExitPeerHybrid => {
            info!("║  Mode:   Exit Peer Hybrid (Worker + Tunnel)                ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
            info!("║  Data:   TCP port 51821 (via Cloudflare Tunnel)            ║");
        }
        Mode::SendFile => {
            info!("║  Mode:   Send File (P2P Encrypted)                          ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
            info!("║  File:   {}  ", args.file.as_deref().unwrap_or("none"));
        }
        Mode::ReceiveFile => {
            info!("║  Mode:   Receive File (P2P Encrypted)                       ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
        }
        #[cfg(feature = "swarm")]
        Mode::Swarm => {
            info!("║  Mode:   Faisal Swarm (P2P Mesh + DCUtR)                    ║");
            info!("║  Room:   {}  ", args.room.as_deref().unwrap_or("none"));
            info!("║  Roles:  Client + Relay + Exit (bandwidth sharing)         ║");
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

/// Start P2P VPN controller
#[cfg(feature = "vpn")]
pub async fn start_p2p_vpn(
    args: Args,
    room_id: String,
) -> Result<p2p_vpn::P2PVpnController, BoxError> {
    use crate::entropy_tax::EntropyTax;
    use p2p_vpn::{P2PVpnConfig, P2PVpnController};
    use std::sync::Arc;
    use tokio::sync::Mutex;

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

        exit_peer_address: args.exit_peer_address.parse()?,
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

    let entropy_tax = Arc::new(Mutex::new(EntropyTax::new()));
    let vpn = P2PVpnController::new(config, entropy_tax);
    vpn.start().await?;

    Ok(vpn)
}

/// Run in P2P VPN mode (Triple-Blind Architecture)
async fn run_p2p_vpn_mode(args: Args, room_id: String) -> Result<(), BoxError> {
    #[cfg(not(feature = "vpn"))]
    {
        error!("❌ VPN mode is not enabled!");
        error!("   Rebuild with: cargo build --release --features vpn");
        Err("VPN feature not enabled".into())
    }

    #[cfg(feature = "vpn")]
    {
        let vpn = start_p2p_vpn(args, room_id).await?;

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

/// Run as Exit Peer in Hybrid mode (Worker signaling + Cloudflare Tunnel data)
///
/// This mode uses:
/// - Cloudflare Worker for signaling (key exchange, room management)  
/// - Cloudflare Tunnel for data (TCP port 51821, unlimited bandwidth)
#[cfg(feature = "vpn")]
async fn run_exit_peer_hybrid_mode(_args: Args, room_id: String) -> Result<(), BoxError> {
    use hybrid_data::{run_hybrid_data_listener, HybridDataState};
    use p2p_relay::{P2PRelay, PeerRole};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Check privileges for TUN device
    check_privileges()?;

    info!("🚀 Starting Hybrid Exit Peer Mode...");
    info!("   Signaling: WebSocket via Cloudflare Worker");
    info!("   Data: TCP port 51821 via Cloudflare Tunnel");

    // Create TUN device
    let device = tun_rs::DeviceBuilder::new()
        .ipv4(std::net::Ipv4Addr::new(10, 0, 85, 2), 24, None)
        .mtu(1400)
        .build_async()?;

    info!("✅ TUN device created (10.0.85.2/24)");

    // Enable IP forwarding and NAT on Linux
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .output();
        info!("Enabled IP forwarding");

        let _ = std::process::Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.0.85.0/24",
                "-j",
                "MASQUERADE",
            ])
            .output();

        // Add FORWARD rules
        let _ = std::process::Command::new("iptables")
            .args(["-I", "FORWARD", "-s", "10.0.85.0/24", "-j", "ACCEPT"])
            .output();
        let _ = std::process::Command::new("iptables")
            .args(["-I", "FORWARD", "-d", "10.0.85.0/24", "-j", "ACCEPT"])
            .output();
        info!("Setup NAT masquerading and forwarding");
    }

    // Create shared state for hybrid data handler
    let state = Arc::new(RwLock::new(HybridDataState {
        _shared_secret: None,
        tun_device: Some(Arc::new(device)),
    }));

    // Start TCP data listener (for Cloudflare Tunnel)
    let state_for_tcp = state.clone();
    let tcp_task = tokio::spawn(async move {
        if let Err(e) = run_hybrid_data_listener(51821, state_for_tcp).await {
            error!("Hybrid data listener error: {}", e);
        }
    });

    // Connect to relay for signaling
    info!("Connecting to relay for signaling...");
    let relay = P2PRelay::connect(
        &_args.relay,
        &_args.vernam,
        &room_id,
        PeerRole::ExitPeer,
        None,
    )
    .await?;

    info!("✅ Connected to relay as Exit Peer (Hybrid Mode)");
    info!("⏳ Waiting for Client to connect...");
    info!("📡 Data port: localhost:51821 (expose via cloudflared)");

    // Wait for Ctrl+C
    info!("");
    info!("Press Ctrl+C to stop...");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received. Shutting down...");
        }
        _ = tcp_task => {
            error!("TCP listener exited unexpectedly");
        }
    }

    // Cleanup
    relay.close().await?;

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "10.0.85.0/24",
                "-j",
                "MASQUERADE",
            ])
            .output();
    }

    info!("✅ Hybrid Exit Peer stopped.");
    Ok(())
}

/// Run as Faisal Swarm node - P2P mesh with DCUtR hole-punching
///
/// Every node is simultaneously:
/// - Client: Uses network for privacy
/// - Relay: Forwards encrypted traffic for others
/// - Exit: Provides internet access for others (native nodes)
#[cfg(feature = "swarm")]
async fn run_swarm_mode(args: Args, room_id: String) -> Result<(), BoxError> {
    use crate::swarm_controller::{SwarmController, SwarmControllerConfig};

    info!("🌐 Starting Faisal Swarm Mode...");
    info!("   Room: {}", room_id);
    info!("   Signaling: {}", args.relay);
    info!("   Mode: Client + Relay + Exit");

    // Create swarm configuration from CLI args
    let config = SwarmControllerConfig {
        enable_client: !args.no_client,
        enable_relay: !args.no_relay,
        enable_exit: !args.no_exit, // Enabled by default unless explicitly disabled
        room_id: room_id.clone(),
        relay_url: args.relay.clone(),
        vernam_url: format!("{}/entropy", args.vernam),
        exit_consent_given: args.exit_consent,
        vpn_address: args.vpn_address.clone(),
        server_mode: args.server,
    };

    info!("🔧 Configuration:");
    info!("   - VPN Client: {}", config.enable_client);
    info!("   - Relay Service: {}", config.enable_relay);
    info!("   - Exit Service: {}", config.enable_exit);

    if config.enable_exit && !args.exit_consent {
        info!("⚠️  Exit Node Active (Default). You are contributing to the swarm!");
        info!("   Use --no-exit to disable if required.");
    }
    info!("");

    // Create and start swarm controller
    let mut controller = SwarmController::new(config);

    info!("📡 Starting swarm services...");
    info!("Press Ctrl+C to stop...");

    // Run swarm with Ctrl+C handling
    tokio::select! {
        result = controller.start() => {
            if let Err(e) = result {
                error!("Swarm error: {}", e);
                return Err(e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received. Shutting down...");
            controller.stop().await?;
        }
    }

    info!("✅ Faisal Swarm stopped.");
    Ok(())
}
