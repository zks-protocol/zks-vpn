//! ZKS Exit Peer Mode
//!
//! Run as an Exit Peer to route VPN traffic from Clients to the Internet.
//! All traffic is ZKS-encrypted end-to-end.
//!
//! Usage:
//!   zks-vpn --mode exit-peer --room <room_id>

use bytes::Bytes;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zks_tunnel_proto::{StreamId, TunnelMessage};

use crate::p2p_relay::{P2PRelay, PeerRole};

/// Active TCP connection managed by Exit Peer
struct ActiveConnection {
    stream: TcpStream,
}

/// Exit Peer state
#[allow(dead_code)]
struct ExitPeerState {
    /// Active TCP connections (stream_id -> connection)
    connections: HashMap<StreamId, ActiveConnection>,
    /// Next stream ID for outbound connections
    next_stream_id: StreamId,
}

impl ExitPeerState {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            next_stream_id: 1,
        }
    }
}

/// Run as Exit Peer
///
/// Connects to the relay, waits for Client to connect,
/// then forwards all traffic to/from the Internet.
/// Automatically reconnects on connection drop or errors.
pub async fn run_exit_peer(
    relay_url: &str,
    vernam_url: &str,
    room_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║         ZKS-VPN Exit Peer - Zero Knowledge Swarm             ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  Room ID: {:50} ║", room_id);
    info!("║  Relay: {:52} ║", relay_url);
    info!("╚══════════════════════════════════════════════════════════════╝");

    // Outer reconnection loop - Exit Peer will keep trying to reconnect
    let mut retry_count = 0;
    let max_retries = 100; // Allow many retries for long-running service

    loop {
        if retry_count >= max_retries {
            error!("Max retries ({}) reached. Exiting.", max_retries);
            return Err("Max retries reached".into());
        }

        // Connect to relay as Exit Peer
        info!("📡 Connecting to relay (attempt {})...", retry_count + 1);
        let relay = match P2PRelay::connect(relay_url, vernam_url, room_id, PeerRole::ExitPeer, None).await {
            Ok(r) => Arc::new(r),
            Err(e) => {
                warn!("Failed to connect: {}. Retrying in 5s...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                retry_count += 1;
                continue;
            }
        };

        info!("✅ Connected to relay as Exit Peer");
        info!("⏳ Waiting for Client to connect...");

        // Reset retry count on successful connection
        retry_count = 0;

        // State for managing connections (reset on each connection)
        let state = Arc::new(Mutex::new(ExitPeerState::new()));

        // Inner message loop
        let disconnect_reason = loop {
            match relay.recv().await {
                Ok(Some(message)) => {
                    let relay_clone = relay.clone();
                    let state_clone = state.clone();

                    match message {
                        TunnelMessage::Connect {
                            stream_id,
                            host,
                            port,
                        } => {
                            info!("CONNECT request: {}:{} (stream {})", host, port, stream_id);

                            // Spawn task to handle connection
                            tokio::spawn(async move {
                                handle_connect(relay_clone, state_clone, stream_id, &host, port).await;
                            });
                        }

                        TunnelMessage::Data { stream_id, payload } => {
                            debug!("DATA for stream {}: {} bytes", stream_id, payload.len());

                            // Forward data to the connection
                            let mut state = state_clone.lock().await;
                            if let Some(conn) = state.connections.get_mut(&stream_id) {
                                if let Err(e) = conn.stream.write_all(&payload).await {
                                    warn!("Failed to write to stream {}: {}", stream_id, e);
                                }
                            }
                        }

                        TunnelMessage::Close { stream_id } => {
                            debug!("CLOSE stream {}", stream_id);
                            let mut state = state_clone.lock().await;
                            state.connections.remove(&stream_id);
                        }

                        TunnelMessage::Ping => {
                            let _ = relay_clone.send(&TunnelMessage::Pong).await;
                        }

                        TunnelMessage::HttpRequest {
                            stream_id,
                            method,
                            url,
                            headers,
                            body,
                        } => {
                            info!("HTTP {} {} (stream {})", method, url, stream_id);

                            tokio::spawn(async move {
                                handle_http_request(
                                    relay_clone,
                                    stream_id,
                                    &method,
                                    &url,
                                    &headers,
                                    &body,
                                )
                                .await;
                            });
                        }

                        TunnelMessage::DnsQuery { request_id, query } => {
                            info!("DNS Query ID {}", request_id);
                            let relay_clone = relay_clone.clone();
                            tokio::spawn(async move {
                                handle_dns_query(relay_clone, request_id, query).await;
                            });
                        }

                        TunnelMessage::IpPacket { payload } => {
                            debug!("IpPacket received: {} bytes", payload.len());
                            // VPN mode: Forward IP packet to internet
                            // Parse IP header to get destination
                            if payload.len() >= 20 {
                                let version = (payload[0] >> 4) & 0x0F;
                                if version == 4 {
                                    let dst_ip = std::net::Ipv4Addr::new(
                                        payload[16],
                                        payload[17],
                                        payload[18],
                                        payload[19],
                                    );
                                    let protocol = payload[9];
                                    let proto_name = match protocol {
                                        1 => "ICMP",
                                        6 => "TCP",
                                        17 => "UDP",
                                        _ => "OTHER",
                                    };
                                    debug!("IPv4 {} packet to {}", proto_name, dst_ip);
                                }
                            }
                        }

                        _ => {
                            debug!("Unhandled message: {:?}", message);
                        }
                    }
                }
                Ok(None) => {
                    break "Relay connection closed normally";
                }
                Err(e) => {
                    break Box::leak(format!("Relay error: {}", e).into_boxed_str());
                }
            }
        };

        // Log disconnect reason and reconnect
        warn!("🔌 Disconnected: {}. Reconnecting in 3s...", disconnect_reason);
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        retry_count += 1;
    }
}

/// Handle CONNECT request - open TCP connection to target
async fn handle_connect(
    relay: Arc<P2PRelay>,
    state: Arc<Mutex<ExitPeerState>>,
    stream_id: StreamId,
    host: &str,
    port: u16,
) {
    // Try to connect to the target
    let addr = format!("{}:{}", host, port);
    match TcpStream::connect(&addr).await {
        Ok(stream) => {
            info!("Connected to {} (stream {})", addr, stream_id);

            // Send success response
            if let Err(e) = relay
                .send(&TunnelMessage::ConnectSuccess { stream_id })
                .await
            {
                error!("Failed to send ConnectSuccess: {}", e);
                return;
            }

            // Store connection
            {
                let mut state = state.lock().await;
                state
                    .connections
                    .insert(stream_id, ActiveConnection { stream });
            }

            // Start reading from the connection
            let relay_clone = relay.clone();
            let state_clone = state.clone();

            tokio::spawn(async move {
                read_from_connection(relay_clone, state_clone, stream_id).await;
            });
        }
        Err(e) => {
            warn!("Failed to connect to {}: {}", addr, e);

            let _ = relay
                .send(&TunnelMessage::ErrorReply {
                    stream_id,
                    code: 502,
                    message: format!("Connection failed: {}", e),
                })
                .await;
        }
    }
}

/// Read data from TCP connection and send to relay
async fn read_from_connection(
    relay: Arc<P2PRelay>,
    state: Arc<Mutex<ExitPeerState>>,
    stream_id: StreamId,
) {
    let mut buf = [0u8; 16384];

    loop {
        // Get the stream (need to re-acquire each time due to async)
        let read_result = {
            let mut state = state.lock().await;
            if let Some(conn) = state.connections.get_mut(&stream_id) {
                Some(conn.stream.read(&mut buf).await)
            } else {
                None
            }
        };

        match read_result {
            Some(Ok(0)) => {
                // Connection closed
                debug!("Stream {} closed by remote", stream_id);
                let _ = relay.send(&TunnelMessage::Close { stream_id }).await;
                let mut state = state.lock().await;
                state.connections.remove(&stream_id);
                break;
            }
            Some(Ok(n)) => {
                // Send data to client via relay
                let payload = Bytes::copy_from_slice(&buf[..n]);
                if let Err(e) = relay
                    .send(&TunnelMessage::Data { stream_id, payload })
                    .await
                {
                    warn!("Failed to send data for stream {}: {}", stream_id, e);
                    break;
                }
            }
            Some(Err(e)) if e.kind() == ErrorKind::WouldBlock => {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
            Some(Err(e)) => {
                warn!("Read error on stream {}: {}", stream_id, e);
                let _ = relay.send(&TunnelMessage::Close { stream_id }).await;
                let mut state = state.lock().await;
                state.connections.remove(&stream_id);
                break;
            }
            None => {
                // Stream was removed
                break;
            }
        }
    }
}

/// Handle HTTP request via reqwest (for HTTP proxy mode)
async fn handle_http_request(
    relay: Arc<P2PRelay>,
    stream_id: StreamId,
    method: &str,
    url: &str,
    headers: &str,
    body: &[u8],
) {
    let client = reqwest::Client::new();

    // Build request
    let mut request = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "HEAD" => client.head(url),
        "PATCH" => client.patch(url),
        _ => client.get(url),
    };

    // Parse and add headers
    for line in headers.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if !key.eq_ignore_ascii_case("host") {
                request = request.header(key, value);
            }
        }
    }

    // Add body if present
    if !body.is_empty() {
        request = request.body(body.to_vec());
    }

    // Execute request
    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();

            // Collect headers
            let mut resp_headers = String::new();
            for (key, value) in response.headers() {
                if let Ok(v) = value.to_str() {
                    resp_headers.push_str(&format!("{}: {}\r\n", key, v));
                }
            }

            // Get body
            let body = response.bytes().await.unwrap_or_default();

            // Send response
            let _ = relay
                .send(&TunnelMessage::HttpResponse {
                    stream_id,
                    status,
                    headers: resp_headers,
                    body: Bytes::from(body.to_vec()),
                })
                .await;
        }
        Err(e) => {
            let _ = relay
                .send(&TunnelMessage::ErrorReply {
                    stream_id,
                    code: 502,
                    message: format!("HTTP request failed: {}", e),
                })
                .await;
        }
    }
}

/// Handle DNS query by forwarding to public DNS
async fn handle_dns_query(relay: Arc<P2PRelay>, request_id: u32, query: Bytes) {
    // Use a fresh socket for each query
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to bind UDP socket for DNS: {}", e);
            return;
        }
    };

    // Send to Google DNS (8.8.8.8)
    if let Err(e) = socket.send_to(&query, "8.8.8.8:53").await {
        warn!("Failed to send DNS query to 8.8.8.8: {}", e);
        return;
    }

    let mut buf = [0u8; 2048];
    // Wait for response with timeout
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        socket.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((len, _))) => {
            let response = Bytes::copy_from_slice(&buf[..len]);
            let _ = relay
                .send(&TunnelMessage::DnsResponse {
                    request_id,
                    response,
                })
                .await;
            debug!("Forwarded DNS response for ID {}", request_id);
        }
        _ => {
            warn!("DNS query timeout or error for ID {}", request_id);
        }
    }
}

/// Run as Exit Peer in VPN mode (with TUN device for full IP packet forwarding)
///
/// This mode creates a TUN device on the Exit Peer to forward raw IP packets
/// from the Client to the Internet and back.
///
/// Prerequisites on the Exit Peer server:
/// - Linux with TUN support
/// - Root privileges
/// - Enable IP forwarding: sysctl -w net.ipv4.ip_forward=1
/// - Setup NAT: iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
#[cfg(feature = "vpn")]
pub async fn run_exit_peer_vpn(
    relay_url: &str,
    vernam_url: &str,
    room_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::atomic::{AtomicBool, Ordering};

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║      ZKS-VPN Exit Peer VPN Mode - Layer 3 Forwarding         ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  Room ID: {:50} ║", room_id);
    info!("║  Relay: {:52} ║", relay_url);
    info!("╚══════════════════════════════════════════════════════════════╝");

    // Create TUN device for packet forwarding (10.0.85.2 for exit peer)
    info!("Creating TUN device for VPN forwarding...");

    let device = tun_rs::DeviceBuilder::new()
        .ipv4(std::net::Ipv4Addr::new(10, 0, 85, 2), 24, None)
        .mtu(1400)
        .build_async()?;

    info!("✅ TUN device created (10.0.85.2/24)");

    // Enable IP forwarding on Linux
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .output();
        info!("Enabled IP forwarding");

        // Setup NAT (get default interface name)
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
        info!("Setup NAT masquerading");
    }

    let running = Arc::new(AtomicBool::new(true));
    let device = Arc::new(device);

    // Main reconnection loop
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        info!("Connecting to relay...");
        // Connect to relay as Exit Peer
        let relay =
            match P2PRelay::connect(relay_url, vernam_url, room_id, PeerRole::ExitPeer, None).await
            {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    error!("Failed to connect to relay: {}. Retrying in 5s...", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

        info!("✅ Connected to relay as Exit Peer (VPN Mode)");
        info!("⏳ Waiting for Client to connect...");

        let running_clone = running.clone();
        let device_reader = device.clone();
        let device_writer = device.clone();

        // Clone relay for tasks
        let relay_for_recv = relay.clone();
        let relay_for_send = relay.clone();

        // Task 1: Relay -> TUN (packets from Client to Internet)
        let relay_to_tun = tokio::spawn(async move {
            while running_clone.load(Ordering::SeqCst) {
                match relay_for_recv.recv().await {
                    Ok(Some(TunnelMessage::IpPacket { payload })) => {
                        debug!("Received IpPacket: {} bytes", payload.len());
                        if let Err(e) = device_writer.send(&payload).await {
                            warn!("Failed to write to TUN: {}", e);
                        }
                    }
                    Ok(Some(other)) => {
                        debug!("Received non-IpPacket message: {:?}", other);
                    }
                    Ok(None) => {
                        info!("Relay connection closed");
                        break;
                    }
                    Err(e) => {
                        error!("Error receiving from relay: {}", e);
                        break;
                    }
                }
            }
        });

        // Task 2: TUN -> Relay (packets from Internet to Client)
        let running_clone2 = running.clone();
        let tun_to_relay = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while running_clone2.load(Ordering::SeqCst) {
                // Use timeout to allow checking 'running' flag periodically
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(1),
                    device_reader.recv(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) => {
                        let packet = &buf[..n];
                        debug!("TUN read: {} bytes", n);

                        // Send packet to Client
                        let msg = TunnelMessage::IpPacket {
                            payload: Bytes::copy_from_slice(packet),
                        };
                        if let Err(e) = relay_for_send.send(&msg).await {
                            warn!("Failed to send IpPacket to relay: {}", e);
                            // If sending fails, the relay connection is likely dead.
                            // We should probably break to trigger reconnection, but
                            // the recv loop will likely detect it too.
                        }
                    }
                    Ok(Err(e)) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                    Err(_) => {
                        // Timeout - just loop to check running flag
                        continue;
                    }
                }
            }
            info!("Exit Peer TUN reader task stopped");
        });

        info!("✅ Exit Peer VPN mode active - forwarding packets");
        info!("Press Ctrl+C to stop...");

        // Wait for tasks to finish OR Ctrl+C
        tokio::select! {
            _ = relay_to_tun => {
                warn!("Relay connection lost (recv task ended). Reconnecting...");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received. Shutting down...");
                running.store(false, Ordering::SeqCst);
                break;
            }
        }

        // Abort the other task if it's still running
        tun_to_relay.abort();

        if running.load(Ordering::SeqCst) {
            info!("Restarting session in 1s...");
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }

    info!("Shutting down Exit Peer VPN mode...");

    // Cleanup NAT rules on Linux
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

    Ok(())
}
