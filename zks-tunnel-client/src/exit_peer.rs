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

    // Connect to relay as Exit Peer
    let relay = P2PRelay::connect(relay_url, vernam_url, room_id, PeerRole::ExitPeer).await?;
    let relay = Arc::new(relay);

    info!("✅ Connected to relay as Exit Peer");
    info!("⏳ Waiting for Client to connect...");

    // State for managing connections
    let state = Arc::new(Mutex::new(ExitPeerState::new()));

    // Main message loop
    loop {
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

                    _ => {
                        debug!("Unhandled message: {:?}", message);
                    }
                }
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

    Ok(())
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
