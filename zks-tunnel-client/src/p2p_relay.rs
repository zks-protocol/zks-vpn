//! ZKS P2P Relay Connection
//!
//! Manages WebSocket connection to the ZKS-VPN relay for P2P communication
//! between Client and Exit Peer with ZKS double-key Vernam encryption.

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, warn};
use zks_tunnel_proto::TunnelMessage;

/// Peer role in the VPN relay
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Client,
    ExitPeer,
}

impl PeerRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerRole::Client => "client",
            PeerRole::ExitPeer => "exit",
        }
    }
}

/// ZKS encryption keys for double-key Vernam cipher
pub struct ZksKeys {
    /// Local CSPRNG-generated key material
    pub local_key: Vec<u8>,
    /// Remote key from zks-vernam worker (LavaRand)
    pub remote_key: Vec<u8>,
    /// Current position in key stream
    pub position: usize,
}

impl ZksKeys {
    /// Create new ZKS keys (local only, remote fetched later)
    pub fn new_local(size: usize) -> Self {
        let mut local_key = vec![0u8; size];
        getrandom::getrandom(&mut local_key).expect("Failed to generate local key");

        Self {
            local_key,
            remote_key: Vec::new(),
            position: 0,
        }
    }

    /// Fetch remote key from zks-vernam worker
    pub async fn fetch_remote_key(
        &mut self,
        vernam_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key_size = self.local_key.len();
        let url = format!(
            "{}/key/{}",
            vernam_url.trim_end_matches('/'),
            key_size / 16384 + 1
        );

        let response = reqwest::get(&url).await?;
        self.remote_key = response.bytes().await?.to_vec();

        // Truncate to match local key size
        self.remote_key.truncate(key_size);

        info!(
            "Fetched {} bytes of remote key from zks-vernam",
            self.remote_key.len()
        );
        Ok(())
    }

    /// Encrypt data using double-key Vernam cipher
    /// Ciphertext = Plaintext XOR LocalKey XOR RemoteKey
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut encrypted = Vec::with_capacity(data.len());

        for byte in data {
            let local_byte = self
                .local_key
                .get(self.position % self.local_key.len())
                .copied()
                .unwrap_or(0);
            let remote_byte = self
                .remote_key
                .get(self.position % self.remote_key.len())
                .copied()
                .unwrap_or(0);

            encrypted.push(byte ^ local_byte ^ remote_byte);
            self.position += 1;
        }

        encrypted
    }

    /// Decrypt data (same operation as encrypt for Vernam)
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        // Vernam cipher is symmetric
        self.encrypt(data)
    }
}

/// P2P Relay Connection over WebSocket
#[allow(dead_code)]
pub struct P2PRelay {
    /// WebSocket write half
    writer: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    /// WebSocket read half
    reader: Arc<Mutex<SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>>>,
    /// ZKS encryption keys
    keys: Arc<Mutex<ZksKeys>>,
    /// Our peer role
    pub role: PeerRole,
    /// Room ID
    pub room_id: String,
}

#[allow(dead_code)]
impl P2PRelay {
    /// Connect to relay and establish P2P session
    pub async fn connect(
        relay_url: &str,
        vernam_url: &str,
        room_id: &str,
        role: PeerRole,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Build WebSocket URL
        let ws_url = format!(
            "{}/room/{}?role={}",
            relay_url.trim_end_matches('/'),
            room_id,
            role.as_str()
        );

        info!("Connecting to relay: {}", ws_url);

        // Connect WebSocket
        let (ws_stream, response) = tokio_tungstenite::connect_async(&ws_url).await?;
        info!("Connected to relay (status: {})", response.status());

        // Split into read/write
        let (writer, reader) = ws_stream.split();

        // Initialize ZKS keys (1MB of key material)
        let key_size = 1024 * 1024;
        let mut keys = ZksKeys::new_local(key_size);

        // Fetch remote key from zks-vernam
        if !vernam_url.is_empty() {
            if let Err(e) = keys.fetch_remote_key(vernam_url).await {
                warn!(
                    "Failed to fetch remote key, using local-only encryption: {}",
                    e
                );
            }
        }

        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            reader: Arc::new(Mutex::new(reader)),
            keys: Arc::new(Mutex::new(keys)),
            role,
            room_id: room_id.to_string(),
        })
    }

    /// Send ZKS-encrypted message through relay
    pub async fn send(
        &self,
        message: &TunnelMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let encoded = message.encode();

        // Encrypt with ZKS double-key
        let encrypted = {
            let mut keys = self.keys.lock().await;
            keys.encrypt(&encoded)
        };

        // Send as binary
        let mut writer = self.writer.lock().await;
        writer.send(Message::Binary(encrypted)).await?;

        Ok(())
    }

    /// Send raw encrypted bytes
    pub async fn send_raw(
        &self,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let encrypted = {
            let mut keys = self.keys.lock().await;
            keys.encrypt(data)
        };

        let mut writer = self.writer.lock().await;
        writer.send(Message::Binary(encrypted)).await?;

        Ok(())
    }

    /// Receive and decrypt message from relay
    pub async fn recv(
        &self,
    ) -> Result<Option<TunnelMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = self.reader.lock().await;

        while let Some(msg) = reader.next().await {
            match msg? {
                Message::Binary(data) => {
                    // Decrypt with ZKS double-key
                    let decrypted = {
                        let mut keys = self.keys.lock().await;
                        keys.decrypt(&data)
                    };

                    // Decode protocol message
                    match TunnelMessage::decode(&decrypted) {
                        Ok(msg) => return Ok(Some(msg)),
                        Err(e) => {
                            warn!("Failed to decode message: {}", e);
                        }
                    }
                }
                Message::Text(text) => {
                    // Control message from relay (welcome, peer_join, etc.)
                    debug!("Relay control message: {}", text);
                }
                Message::Close(_) => {
                    info!("Relay connection closed");
                    return Ok(None);
                }
                Message::Ping(_) | Message::Pong(_) => {}
                _ => {}
            }
        }

        Ok(None)
    }

    /// Receive raw encrypted bytes
    pub async fn recv_raw(
        &self,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = self.reader.lock().await;

        while let Some(msg) = reader.next().await {
            match msg? {
                Message::Binary(data) => {
                    let decrypted = {
                        let mut keys = self.keys.lock().await;
                        keys.decrypt(&data)
                    };
                    return Ok(Some(decrypted));
                }
                Message::Text(text) => {
                    debug!("Relay control message: {}", text);
                }
                Message::Close(_) => {
                    return Ok(None);
                }
                _ => {}
            }
        }

        Ok(None)
    }

    /// Close the relay connection
    pub async fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut writer = self.writer.lock().await;
        writer.close().await?;
        Ok(())
    }

    /// Start Constant Rate Padding (CRP) for traffic analysis defense
    ///
    /// Sends encrypted padding packets at a constant rate to hide actual traffic patterns.
    /// This prevents timing-based correlation attacks.
    ///
    /// # Arguments
    /// * `rate_kbps` - Padding rate in kilobits per second (e.g., 100 = 100 Kbps)
    /// * `running` - Atomic bool to stop padding when VPN disconnects
    pub fn start_padding(
        &self,
        rate_kbps: u32,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        let writer = self.writer.clone();
        let keys = self.keys.clone();

        tokio::spawn(async move {
            use std::sync::atomic::Ordering;

            // Calculate packet size and interval
            // 1400 bytes/packet (MTU-safe), rate in Kbps
            let packet_size = 1400usize;
            let bytes_per_second = (rate_kbps as f64 * 1024.0 / 8.0) as u64;
            let packets_per_second = bytes_per_second / packet_size as u64;
            let interval_ms = if packets_per_second > 0 {
                1000 / packets_per_second
            } else {
                1000
            };

            info!(
                "CRP: Starting padding at {} Kbps ({} pkt/s, {}ms interval)",
                rate_kbps, packets_per_second, interval_ms
            );

            // Create padding packet (random data that looks like encrypted traffic)
            let mut padding = vec![0u8; packet_size];

            while running.load(Ordering::SeqCst) {
                // Fill with fresh random data for each packet
                getrandom::getrandom(&mut padding).unwrap_or_default();

                // Encrypt padding
                let encrypted = {
                    let mut keys_guard = keys.lock().await;
                    keys_guard.encrypt(&padding)
                };

                // Send padding (ignore errors - connection might be busy)
                let mut writer_guard = writer.lock().await;
                let _ = writer_guard.send(Message::Binary(encrypted)).await;
                drop(writer_guard);

                // Wait for next interval
                tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
            }

            info!("CRP: Padding stopped");
        })
    }
}
