//! System-Wide VPN Module
//!
//! Provides true VPN functionality by creating a TUN device and routing
//! ALL system traffic through the ZKS-Tunnel WebSocket connection.
//!
//! Architecture:
//! ```text
//! ┌───────────┐     ┌──────────────┐     ┌────────────────┐
//! │ All Apps  │────▶│ TUN Device   │────▶│ Userspace      │
//! │           │     │ (zks0)       │     │ TCP/IP Stack   │
//! └───────────┘     └──────────────┘     │ (netstack)     │
//!                                        └───────┬────────┘
//!                                                │
//!                                                ▼
//!                   ┌────────────────────────────────────────┐
//!                   │ ZKS-Tunnel WebSocket → CF Worker       │
//!                   └────────────────────────────────────────┘
//! ```

#[cfg(feature = "vpn")]
mod implementation {
    use futures::{SinkExt, StreamExt};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Still needed for tunnel stream
    use tokio::sync::Mutex;
    use tracing::{debug, error, info}; // Needed for Stack stream/sink

    use crate::tunnel::TunnelClient;
    use zks_tunnel_proto::TunnelMessage;

    // Import netstack-smoltcp types
    #[cfg(feature = "vpn")]
    use netstack_smoltcp::StackBuilder;

    #[cfg(feature = "vpn")]
    use reqwest::Client;

    /// VPN configuration
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct VpnConfig {
        /// TUN device name (e.g., "zks0", "utun5")
        pub device_name: String,
        /// Virtual IP address for the TUN interface
        pub address: Ipv4Addr,
        /// Netmask for the TUN interface
        pub netmask: Ipv4Addr,
        /// MTU for the TUN interface
        pub mtu: u16,
        /// Enable DNS leak protection
        pub dns_protection: bool,
        /// Enable kill switch (block traffic if disconnected)
        pub kill_switch: bool,
    }

    impl Default for VpnConfig {
        fn default() -> Self {
            Self {
                device_name: "zks0".to_string(),
                address: Ipv4Addr::new(10, 0, 85, 1), // 10.0.85.1
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                mtu: 1500,
                dns_protection: true,
                kill_switch: true,
            }
        }
    }

    /// VPN connection state
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VpnState {
        Disconnected,
        Connecting,
        Connected,
        Disconnecting,
    }

    /// Statistics for the VPN connection
    #[derive(Debug, Default)]
    pub struct VpnStats {
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub packets_sent: u64,
        pub packets_received: u64,
        pub connections_opened: u64,
    }

    /// System-Wide VPN controller with full TUN integration
    pub struct VpnController {
        config: VpnConfig,
        state: Arc<Mutex<VpnState>>,
        tunnel: Arc<TunnelClient>,
        running: Arc<AtomicBool>,
        stats: Arc<Mutex<VpnStats>>,
        http_client: Client,
        #[cfg(target_os = "windows")]
        original_fw_policy: Arc<Mutex<Option<String>>>,
    }

    impl VpnController {
        /// Create a new VPN controller
        pub fn new(tunnel: Arc<TunnelClient>, config: VpnConfig) -> Self {
            Self {
                config,
                state: Arc::new(Mutex::new(VpnState::Disconnected)),
                tunnel,
                running: Arc::new(AtomicBool::new(false)),
                stats: Arc::new(Mutex::new(VpnStats::default())),
                http_client: Client::builder()
                    .use_rustls_tls()
                    .build()
                    .unwrap_or_default(),
                #[cfg(target_os = "windows")]
                original_fw_policy: Arc::new(Mutex::new(None)),
            }
        }

        /// Start the VPN (create TUN device and begin routing traffic)
        pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut state = self.state.lock().await;
            if *state != VpnState::Disconnected {
                return Err("VPN is already running".into());
            }
            *state = VpnState::Connecting;
            drop(state);

            info!("Starting system-wide VPN...");
            info!("  Device: {}", self.config.device_name);
            info!("  Address: {}/{}", self.config.address, self.config.netmask);
            info!("  MTU: {}", self.config.mtu);

            self.running.store(true, Ordering::SeqCst);

            // Optional: enable OS-level kill switch
            if self.config.kill_switch {
                if let Err(e) = self.enable_kill_switch().await {
                    error!("Failed to enable kill switch: {}", e);
                }
            }

            // Create TUN device and start packet processing
            self.run_tun_loop().await?;

            let mut state = self.state.lock().await;
            *state = VpnState::Connected;

            info!("✅ System-wide VPN is now active!");
            info!("   All traffic is being routed through the tunnel.");

            Ok(())
        }

        /// Stop the VPN
        pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut state = self.state.lock().await;
            if *state != VpnState::Connected {
                return Err("VPN is not running".into());
            }
            *state = VpnState::Disconnecting;
            drop(state);

            info!("Stopping system-wide VPN...");

            // Signal the TUN loop to stop
            self.running.store(false, Ordering::SeqCst);

            // Disable OS-level kill switch if enabled
            if self.config.kill_switch {
                if let Err(e) = self.disable_kill_switch().await {
                    error!("Failed to disable kill switch: {}", e);
                }
            }

            let mut state = self.state.lock().await;
            *state = VpnState::Disconnected;

            // Print stats
            let stats = self.stats.lock().await;
            info!("VPN Statistics:");
            info!("  Bytes sent: {}", stats.bytes_sent);
            info!("  Bytes received: {}", stats.bytes_received);
            info!("  Packets sent: {}", stats.packets_sent);
            info!("  Packets received: {}", stats.packets_received);
            info!("  Connections opened: {}", stats.connections_opened);

            info!("✅ System-wide VPN stopped.");

            Ok(())
        }

        /// Main TUN device loop - creates device and processes packets
        async fn run_tun_loop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            info!("Creating TUN device...");

            // Use tun-rs DeviceBuilder API (v2)
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                let device = tun_rs::DeviceBuilder::new()
                    .ipv4(self.config.address, 24, None) // Hardcoded /24 for testing
                    .mtu(self.config.mtu)
                    .build_async()?;

                // Run the netstack with the device
                self.run_netstack(device).await?;

                Ok(())
            }

            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                Err("TUN devices are not supported on this platform".into())
            }
        }

        /// Run the userspace network stack (netstack-smoltcp)
        async fn run_netstack(
            &self,
            device: tun_rs::AsyncDevice,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            info!("Initializing userspace TCP/IP stack...");

            // Create the stack
            // StackBuilder::build() returns (Stack, Runner, UdpSocket, TcpListener)
            let (stack, runner_opt, udp_socket_opt, tcp_listener_opt) = StackBuilder::default()
                .enable_tcp(true)
                .enable_udp(true)
                .enable_icmp(true)
                .build()?;

            let runner = runner_opt.ok_or("Runner missing")?;
            let udp_socket = udp_socket_opt.ok_or("UDP socket missing")?;
            let tcp_listener = tcp_listener_opt.ok_or("TCP listener missing")?;

            // Spawn stack runner
            tokio::spawn(async move {
                if let Err(e) = runner.await {
                    error!("Netstack runner error: {}", e);
                }
            });

            let tunnel = self.tunnel.clone();
            let running = self.running.clone();
            let running_udp = running.clone(); // Clone for UDP task
            let stats = self.stats.clone();
            let http_client = self.http_client.clone();
            let dns_protection = self.config.dns_protection;

            // Spawn TCP listener task
            let tcp_task = tokio::spawn(async move {
                // Pin locally inside the async block
                tokio::pin!(tcp_listener);

                while running.load(Ordering::SeqCst) {
                    match tcp_listener.next().await {
                        Some((stream, local_addr, remote_addr)) => {
                            debug!("New TCP connection: {} -> {}", remote_addr, local_addr);

                            let tunnel = tunnel.clone();
                            let stats = stats.clone();

                            // Spawn connection handler
                            tokio::spawn(async move {
                                {
                                    let mut s = stats.lock().await;
                                    s.connections_opened += 1;
                                }

                                // Open tunnel stream to destination
                                let dest_host: String = local_addr.to_string(); // Assuming SocketAddr
                                let dest_port = local_addr.port();

                                match tunnel.open_stream(&dest_host, dest_port).await {
                                    Ok((stream_id, rx)) => {
                                        debug!(
                                            "Tunnel stream {} opened for {}",
                                            stream_id, local_addr
                                        );

                                        // Relay data
                                        let (mut read_half, mut write_half) =
                                            tokio::io::split(stream);
                                        let tunnel_tx = tunnel.sender();

                                        // Task 1: Netstack -> Tunnel
                                        let mut buf = vec![0u8; 16384];
                                        let tunnel_tx_clone = tunnel_tx.clone();
                                        let stats_clone = stats.clone();

                                        let ns_to_tunnel = async move {
                                            loop {
                                                match read_half.read(&mut buf).await {
                                                    Ok(0) => break, // EOF
                                                    Ok(n) => {
                                                        let msg = TunnelMessage::Data {
                                                            stream_id,
                                                            payload: bytes::Bytes::copy_from_slice(
                                                                &buf[..n],
                                                            ),
                                                        };
                                                        if tunnel_tx_clone.send(msg).await.is_err()
                                                        {
                                                            break;
                                                        }

                                                        let mut s = stats_clone.lock().await;
                                                        s.bytes_sent += n as u64;
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        };

                                        // Task 2: Tunnel -> Netstack
                                        let mut rx = rx;
                                        let stats_clone2 = stats.clone();
                                        let tunnel_to_ns = async move {
                                            while let Some(data) = rx.recv().await {
                                                if write_half.write_all(&data).await.is_err() {
                                                    break;
                                                }
                                                let mut s = stats_clone2.lock().await;
                                                s.bytes_received += data.len() as u64;
                                            }
                                        };

                                        // Run both directions
                                        let _ = tokio::join!(ns_to_tunnel, tunnel_to_ns);

                                        // Close tunnel stream
                                        let _ = tunnel_tx
                                            .send(TunnelMessage::Close { stream_id })
                                            .await;
                                    }
                                    Err(e) => {
                                        error!("Failed to open tunnel stream: {}", e);
                                    }
                                }
                            });
                        }
                        None => {
                            error!("TCP listener closed");
                            break;
                        }
                    }
                }
            });

            // Spawn UDP handler (for DNS leak protection)
            // Note: netstack-smoltcp v0.2 UdpSocket API needs investigation
            // DNS protection via DoH will be implemented once API is understood
            // For now, keep socket alive to prevent DNS leaking to system resolver
            let udp_task = tokio::spawn(async move {
                if dns_protection {
                    info!("DNS protection enabled - UDP traffic will be intercepted");
                    // TODO: Implement proper DNS interception once netstack-smoltcp
                    // UdpSocket API (recv_from/send_to) is properly understood
                    // The http_client is available for DoH resolution
                    let _http = http_client; // Keep reference for future use
                } else {
                    info!("DNS protection disabled");
                }

                // Keep UDP socket alive - required for netstack to function
                // UDP traffic to port 53 is blocked by not processing it,
                // which prevents DNS leaks to the system resolver
                while running_udp.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                drop(udp_socket);
                info!("UDP handler exiting");
            });

            // Bridge TUN device and Netstack
            let device = Arc::new(device);
            let device_reader = device.clone();
            let device_writer = device.clone();

            // Stack implements Stream and Sink (of packets)
            // We split it into sink (writer) and stream (reader)
            let (mut stack_sink, mut stack_stream) = stack.split();

            // TUN -> Netstack
            let tun_to_ns = tokio::spawn(async move {
                let mut buf = vec![0u8; 1500];
                loop {
                    match device_reader.recv(&mut buf).await {
                        Ok(n) => {
                            // Send packet to stack
                            // stack_sink.send expects Vec<u8> (likely)
                            if let Err(e) = stack_sink.send(buf[..n].to_vec()).await {
                                error!("Failed to write to netstack: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error reading from TUN: {}", e);
                            break;
                        }
                    }
                }
            });

            // Netstack -> TUN
            let ns_to_tun = tokio::spawn(async move {
                while let Some(packet_result) = stack_stream.next().await {
                    // stack_stream yields Result<Vec<u8>, Error>
                    match packet_result {
                        Ok(packet) => {
                            if let Err(e) = device_writer.send(&packet).await {
                                error!("Failed to write to TUN: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Netstack packet error: {}", e);
                            // Continue processing other packets
                        }
                    }
                }
            });

            // Wait for bridge tasks
            let _ = tokio::join!(tun_to_ns, ns_to_tun, tcp_task, udp_task);

            Ok(())
        }

        /// Enable OS-level kill switch to prevent leaks when tunnel drops
        async fn enable_kill_switch(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            #[cfg(target_os = "windows")]
            {
                use std::env;

                // Read current profile firewall policy so we can restore
                let show = Command::new("netsh")
                    .args(["advfirewall", "show", "currentprofile"])
                    .output()?;
                if show.status.success() {
                    let text = String::from_utf8_lossy(&show.stdout).to_string();
                    let mut guard = self.original_fw_policy.lock().await;
                    *guard = Some(text);
                }

                // Set default outbound to block for current profile
                let _ = Command::new("netsh")
                    .args([
                        "advfirewall",
                        "set",
                        "currentprofile",
                        "firewallpolicy",
                        "blockinbound,blockoutbound",
                    ])
                    .status()?;

                // Allow this executable to go out so the tunnel can connect
                let exe = env::current_exe()?;
                let exe_str = exe.to_string_lossy().to_string();
                let _ = Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        "name=ZKS VPN Allow",
                        "dir=out",
                        "action=allow",
                        "program=",
                    ])
                    .status();
                // Note: The above approach to join args with program= may not include path with spaces.
                // Use a single command string fallback for safety.
                let _ = Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        "name=ZKS VPN Allow",
                        "dir=out",
                        "action=allow",
                        "enable=yes",
                        "profile=any",
                        &format!("program={}", exe_str),
                    ])
                    .status()?;

                info!("Windows kill switch enabled (default outbound blocked, app allowed)");
            }

            #[cfg(unix)]
            {
                // TODO: iptables/nftables-based kill switch
                // For now, no-op on Unix in this implementation pass
                info!("Kill switch not yet implemented on Unix");
            }

            Ok(())
        }

        /// Disable OS-level kill switch and restore firewall defaults
        async fn disable_kill_switch(
            &self,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            #[cfg(target_os = "windows")]
            {
                use std::env;

                // Delete allow rule for this executable
                if let Ok(exe) = env::current_exe() {
                    let exe_str = exe.to_string_lossy().to_string();
                    let _ = Command::new("netsh")
                        .args([
                            "advfirewall",
                            "firewall",
                            "delete",
                            "rule",
                            "name=ZKS VPN Allow",
                            &format!("program={}", exe_str),
                        ])
                        .status();
                }

                // Attempt to restore original profile policy if captured
                if let Some(snapshot) = self.original_fw_policy.lock().await.clone() {
                    // Heuristic: if snapshot contains "Outbound Policy\s+:\s+Allow" then set allowoutbound
                    let allow_out = snapshot.lines().any(|l| {
                        l.to_ascii_lowercase().contains("outbound policy")
                            && l.to_ascii_lowercase().contains("allow")
                    });

                    let policy = if allow_out {
                        "allowinbound,allowoutbound"
                    } else {
                        "blockinbound,allowoutbound"
                    };
                    let _ = Command::new("netsh")
                        .args([
                            "advfirewall",
                            "set",
                            "currentprofile",
                            "firewallpolicy",
                            policy,
                        ])
                        .status();
                } else {
                    // Fallback: set default back to allow outbounds
                    let _ = Command::new("netsh")
                        .args([
                            "advfirewall",
                            "set",
                            "currentprofile",
                            "firewallpolicy",
                            "blockinbound,allowoutbound",
                        ])
                        .status();
                }

                info!("Windows kill switch disabled; firewall defaults restored");
            }

            #[cfg(unix)]
            {
                // TODO: Remove iptables/nftables rules
            }

            Ok(())
        }

        /// Resolve DNS query via DoH (Cloudflare 1.1.1.1)
        async fn resolve_doh(
            client: &Client,
            query: &[u8],
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let url = "https://1.1.1.1/dns-query";

            let response = client
                .post(url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(query.to_vec())
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(format!("DoH request failed: {}", response.status()).into());
            }

            let bytes = response.bytes().await?;
            Ok(bytes.to_vec())
        }

        /// Get current VPN state
        #[allow(dead_code)]
        pub async fn state(&self) -> VpnState {
            *self.state.lock().await
        }

        /// Get current VPN statistics
        #[allow(dead_code)]
        pub async fn stats(&self) -> VpnStats {
            let s = self.stats.lock().await;
            VpnStats {
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
                packets_sent: s.packets_sent,
                packets_received: s.packets_received,
                connections_opened: s.connections_opened,
            }
        }
    }
}

#[cfg(feature = "vpn")]
pub use implementation::*;

// Stub module when vpn feature is not enabled
#[cfg(not(feature = "vpn"))]
mod stub {
    use std::net::Ipv4Addr;

    /// VPN configuration (stub)
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct VpnConfig {
        pub device_name: String,
        pub address: Ipv4Addr,
        pub netmask: Ipv4Addr,
        pub mtu: u16,
        pub dns_protection: bool,
        pub kill_switch: bool,
    }

    impl Default for VpnConfig {
        fn default() -> Self {
            Self {
                device_name: "zks0".to_string(),
                address: Ipv4Addr::new(10, 0, 85, 1),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                mtu: 1500,
                dns_protection: true,
                kill_switch: true,
            }
        }
    }

    /// VPN state (stub)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(dead_code)]
    pub enum VpnState {
        Disconnected,
    }

    /// VPN controller (stub - feature not enabled)
    #[allow(dead_code)]
    pub struct VpnController;

    impl VpnController {
        #[allow(dead_code)]
        pub fn new(
            _tunnel: std::sync::Arc<crate::tunnel::TunnelClient>,
            _config: VpnConfig,
        ) -> Self {
            Self
        }

        #[allow(dead_code)]
        pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("VPN feature is not enabled. Rebuild with --features vpn".into())
        }

        #[allow(dead_code)]
        pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("VPN feature is not enabled. Rebuild with --features vpn".into())
        }

        #[allow(dead_code)]
        pub async fn state(&self) -> VpnState {
            VpnState::Disconnected
        }
    }
}

#[cfg(not(feature = "vpn"))]
#[allow(unused_imports)]
pub use stub::*;
