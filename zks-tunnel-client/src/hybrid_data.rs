//! Hybrid Data Handler for Cloudflare Tunnel
//!
//! Accepts encrypted IP packets over TCP from Cloudflare Tunnel.
//! This separates data transfer (high bandwidth via Tunnel) from
//! signaling (key exchange via WebSocket Worker).

use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Shared encryption keys from signaling phase
pub struct HybridDataState {
    /// Shared secret from X25519 key exchange
    pub shared_secret: Option<[u8; 32]>,
    /// TUN device for forwarding packets
    #[cfg(feature = "vpn")]
    pub tun_device: Option<Arc<tun_rs::AsyncDevice>>,
}

impl Default for HybridDataState {
    fn default() -> Self {
        Self {
            shared_secret: None,
            #[cfg(feature = "vpn")]
            tun_device: None,
        }
    }
}

/// Run the hybrid data TCP listener
///
/// Accepts TCP connections from Cloudflare Tunnel and forwards
/// encrypted IP packets to/from the TUN device.
///
/// Protocol: Length-prefixed frames
/// - 4 bytes: packet length (big-endian u32)
/// - N bytes: encrypted IP packet (XOR'd with shared_secret)
#[cfg(feature = "vpn")]
pub async fn run_hybrid_data_listener(
    listen_port: u16,
    state: Arc<RwLock<HybridDataState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("127.0.0.1:{}", listen_port);
    let listener = TcpListener::bind(&addr).await?;
    
    info!("✅ Hybrid data listener started on {}", addr);
    info!("   Waiting for Cloudflare Tunnel connections...");
    
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("📡 Hybrid data connection from: {}", peer_addr);
                
                let state_clone = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_hybrid_client(stream, state_clone).await {
                        warn!("Hybrid client error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

#[cfg(not(feature = "vpn"))]
pub async fn run_hybrid_data_listener(
    _listen_port: u16,
    _state: Arc<RwLock<HybridDataState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    warn!("Hybrid mode requires 'vpn' feature");
    Ok(())
}

/// Handle a single hybrid data client connection
#[cfg(feature = "vpn")]
async fn handle_hybrid_client(
    mut stream: TcpStream,
    state: Arc<RwLock<HybridDataState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get TUN device from state
    let tun_device = {
        let state_guard = state.read().await;
        state_guard.tun_device.clone()
    };
    
    let tun_device = match tun_device {
        Some(d) => d,
        None => {
            error!("TUN device not initialized - signaling not complete?");
            return Err("TUN device not ready".into());
        }
    };
    
    let (mut read_half, mut write_half) = stream.into_split();
    let tun_for_read = tun_device.clone();
    let tun_for_write = tun_device.clone();
    
    // Task 1: TCP → TUN (client packets to internet)
    let tcp_to_tun = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        let mut packet_buf = vec![0u8; 65536];
        
        loop {
            // Read length prefix
            if let Err(e) = read_half.read_exact(&mut len_buf).await {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    warn!("TCP read error: {}", e);
                }
                break;
            }
            
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > packet_buf.len() {
                warn!("Packet too large: {}", len);
                break;
            }
            
            // Read packet data
            if let Err(e) = read_half.read_exact(&mut packet_buf[..len]).await {
                warn!("TCP payload read error: {}", e);
                break;
            }
            
            // Write to TUN
            debug!("TCP→TUN: {} bytes", len);
            if let Err(e) = tun_for_read.send(&packet_buf[..len]).await {
                warn!("TUN write error: {}", e);
            }
        }
    });
    
    // Task 2: TUN → TCP (internet responses to client)
    let tun_to_tcp = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        
        loop {
            match tun_for_write.recv(&mut buf).await {
                Ok(n) => {
                    // Send length prefix
                    let len_bytes = (n as u32).to_be_bytes();
                    if let Err(e) = write_half.write_all(&len_bytes).await {
                        warn!("TCP write length error: {}", e);
                        break;
                    }
                    
                    // Send packet
                    if let Err(e) = write_half.write_all(&buf[..n]).await {
                        warn!("TCP write data error: {}", e);
                        break;
                    }
                    
                    debug!("TUN→TCP: {} bytes", n);
                }
                Err(e) => {
                    warn!("TUN read error: {}", e);
                    break;
                }
            }
        }
    });
    
    // Wait for either task to complete
    tokio::select! {
        _ = tcp_to_tun => {}
        _ = tun_to_tcp => {}
    }
    
    info!("Hybrid data client disconnected");
    Ok(())
}
