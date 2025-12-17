//! ZKS P2P Client Mode
//!
//! Connect to an Exit Peer via the relay and route all traffic through it.
//! Provides a SOCKS5 interface for applications.
//!
//! Usage:
//!   zks-vpn --mode p2p-client --room <room_id> --port 1080

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info};
use zks_tunnel_proto::{StreamId, TunnelMessage};

use crate::p2p_relay::{P2PRelay, PeerRole};

/// Pending connection waiting for response
type PendingMap = Arc<Mutex<HashMap<StreamId, mpsc::Sender<TunnelMessage>>>>;

/// P2P Client state
struct P2PClientState {
    /// Pending connections waiting for response
    pending: PendingMap,
    /// Next stream ID
    next_stream_id: AtomicU32,
}

impl P2PClientState {
    fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: AtomicU32::new(1),
        }
    }

    fn get_next_stream_id(&self) -> StreamId {
        self.next_stream_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// Run as P2P Client
///
/// Connects to the relay, establishes connection to Exit Peer,
/// then provides SOCKS5 interface for local applications.
pub async fn run_p2p_client(
    relay_url: &str,
    vernam_url: &str,
    room_id: &str,
    listen_port: u16,
    proxy: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║         ZKS-VPN P2P Client - Zero Knowledge Swarm            ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║  Room ID: {:50} ║", room_id);
    info!("║  Relay: {:52} ║", relay_url);
    info!("╚══════════════════════════════════════════════════════════════╝");

    // Connect to relay as Client
    let relay = P2PRelay::connect(relay_url, vernam_url, room_id, PeerRole::Client, proxy).await?;
    let relay = Arc::new(relay);

    info!("✅ Connected to relay as Client");
    info!("⏳ Waiting for Exit Peer to connect...");

    // State for managing connections
    let state = Arc::new(P2PClientState::new());

    // Start SOCKS5 listener
    let listener = TcpListener::bind(format!("127.0.0.1:{}", listen_port)).await?;
    info!("🚀 SOCKS5 proxy listening on 127.0.0.1:{}", listen_port);
    info!(
        "   Configure your browser: SOCKS5 proxy = 127.0.0.1:{}",
        listen_port
    );
    info!("");
    info!("   ✅ All traffic routed through Exit Peer");
    info!("   ✅ End-to-end ZKS encryption (double-key Vernam)");

    // Spawn message receiver task
    let relay_recv = relay.clone();
    let state_recv = state.clone();
    tokio::spawn(async move {
        relay_receiver(relay_recv, state_recv).await;
    });

    // Accept SOCKS5 connections
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!("New SOCKS5 connection from {}", addr);

                let relay_clone = relay.clone();
                let state_clone = state.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_socks5(stream, relay_clone, state_clone).await {
                        debug!("SOCKS5 connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Receive messages from relay and dispatch to pending connections
async fn relay_receiver(relay: Arc<P2PRelay>, state: Arc<P2PClientState>) {
    loop {
        match relay.recv().await {
            Ok(Some(message)) => {
                let stream_id = match &message {
                    TunnelMessage::ConnectSuccess { stream_id } => Some(*stream_id),
                    TunnelMessage::Data { stream_id, .. } => Some(*stream_id),
                    TunnelMessage::Close { stream_id } => Some(*stream_id),
                    TunnelMessage::ErrorReply { stream_id, .. } => Some(*stream_id),
                    TunnelMessage::HttpResponse { stream_id, .. } => Some(*stream_id),
                    _ => None,
                };

                if let Some(id) = stream_id {
                    let pending = state.pending.lock().await;
                    if let Some(tx) = pending.get(&id) {
                        let _ = tx.send(message).await;
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
}

/// Handle SOCKS5 connection
async fn handle_socks5(
    mut stream: TcpStream,
    relay: Arc<P2PRelay>,
    state: Arc<P2PClientState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // SOCKS5 handshake
    let mut buf = [0u8; 256];

    // Read greeting
    let n = stream.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err("Invalid SOCKS5 greeting".into());
    }

    // Send no-auth response
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request
    let n = stream.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        // 0x01 = CONNECT
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err("Only CONNECT supported".into());
    }

    // Parse destination
    let (host, port) = match buf[3] {
        0x01 => {
            // IPv4
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip, port)
        }
        0x03 => {
            // Domain
            let len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            (domain, port)
        }
        0x04 => {
            // IPv6 - not supported for simplicity
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err("IPv6 not supported".into());
        }
        _ => {
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err("Invalid address type".into());
        }
    };

    info!("SOCKS5 CONNECT to {}:{}", host, port);

    // Get stream ID
    let stream_id = state.get_next_stream_id();

    // Create channel for responses
    let (tx, mut rx) = mpsc::channel(16);
    {
        let mut pending = state.pending.lock().await;
        pending.insert(stream_id, tx);
    }

    // Send CONNECT to Exit Peer
    relay
        .send(&TunnelMessage::Connect {
            stream_id,
            host: host.clone(),
            port,
        })
        .await?;

    // Wait for response (with timeout)
    let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv()).await;

    match response {
        Ok(Some(TunnelMessage::ConnectSuccess { .. })) => {
            // Send success response
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            info!("Connected to {}:{} via Exit Peer", host, port);
        }
        Ok(Some(TunnelMessage::ErrorReply { message, .. })) => {
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(format!("Connection refused: {}", message).into());
        }
        _ => {
            stream
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err("Connection timeout".into());
        }
    }

    // Bidirectional data relay
    let (mut reader, mut writer) = stream.into_split();

    // Client -> Exit Peer
    let relay_send = relay.clone();
    let send_task = tokio::spawn(async move {
        let mut buf = [0u8; 16384];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    if relay_send
                        .send(&TunnelMessage::Data { stream_id, payload })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = relay_send.send(&TunnelMessage::Close { stream_id }).await;
    });

    // Exit Peer -> Client
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                TunnelMessage::Data { payload, .. } => {
                    if writer.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                TunnelMessage::Close { .. } => break,
                TunnelMessage::ErrorReply { .. } => break,
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }

    // Cleanup
    {
        let mut pending = state.pending.lock().await;
        pending.remove(&stream_id);
    }

    Ok(())
}
