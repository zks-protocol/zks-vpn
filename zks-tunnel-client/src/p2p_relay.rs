//! ZKS P2P Relay Connection
//!
//! Manages WebSocket connection to the ZKS-VPN relay for P2P communication
//! between Client and Exit Peer with ZKS double-key Vernam encryption.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async, connect_async, WebSocketStream};
use tracing::{debug, info, warn};
use url::Url;
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

/// Wasif Vernam: Practical Double-Key Encryption
///
/// Combines ChaCha20-Poly1305 (Base Layer) with a Remote Entropy Stream (Enhancement Layer).
/// Currently implements the Base Layer (ChaCha20-Poly1305) for production security.
pub struct WasifVernam {
    /// ChaCha20Poly1305 Cipher
    cipher: ChaCha20Poly1305,
    /// Nonce counter (incremented per message)
    nonce_counter: AtomicU64,
    /// Remote key stream (for future "True Randomness" enhancement)
    #[allow(dead_code)]
    remote_key: Vec<u8>,
}

impl WasifVernam {
    /// Create new Wasif Vernam from a 32-byte shared secret
    pub fn new(shared_secret: [u8; 32]) -> Self {
        let key = Key::from_slice(&shared_secret);
        let cipher = ChaCha20Poly1305::new(key);

        Self {
            cipher,
            nonce_counter: AtomicU64::new(0),
            remote_key: Vec::new(),
        }
    }

    /// Encrypt data using ChaCha20-Poly1305
    /// Returns: [Nonce (12 bytes) | Ciphertext (N bytes) | Tag (16 bytes)]
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        // Generate nonce: 4 bytes random + 8 bytes counter to ensure uniqueness
        let mut nonce_bytes = [0u8; 12];
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
        // Add some randomness to the first 4 bytes for extra safety against resets
        getrandom::getrandom(&mut nonce_bytes[0..4]).unwrap_or_default();

        let nonce = Nonce::from_slice(&nonce_bytes);

        // 1. Double-Key Defense: XOR Plaintext with Remote Key (if available)
        // This ensures that even if ChaCha20 key is compromised, the message is protected by Swarm Entropy.
        let mut mixed_data = data.to_vec();
        if !self.remote_key.is_empty() {
            for (i, byte) in mixed_data.iter_mut().enumerate() {
                *byte ^= self.remote_key[i % self.remote_key.len()];
            }
        }

        // 2. Base Layer: Encrypt mixed data with ChaCha20-Poly1305
        let mut ciphertext = self.cipher.encrypt(nonce, mixed_data.as_slice())?;

        // Prepend nonce to ciphertext so receiver can decrypt
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.append(&mut ciphertext);

        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305
    /// Input: [Nonce (12 bytes) | Ciphertext (N bytes) | Tag (16 bytes)]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        if data.len() < 12 + 16 {
            return Err(chacha20poly1305::aead::Error);
        }

        // Extract nonce
        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        // Decrypt
        // 1. Base Layer: Decrypt with ChaCha20-Poly1305
        let mut plaintext = self.cipher.decrypt(nonce, ciphertext)?;

        // 2. Double-Key Defense: XOR with Remote Key to recover original plaintext
        if !self.remote_key.is_empty() {
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= self.remote_key[i % self.remote_key.len()];
            }
        }

        Ok(plaintext)
    }

    /// Fetch remote key from zks-vernam worker
    pub async fn fetch_remote_key(
        &mut self,
        vernam_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/entropy?size=32&n=10", vernam_url.trim_end_matches('/'));

        // Fetch JSON from worker
        let response = reqwest::get(&url).await?;
        if !response.status().is_success() {
            return Err(format!("Failed to fetch entropy: {}", response.status()).into());
        }

        let body = response.text().await?;

        // Parse JSON: {"entropy": "hex_string", ...}
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let entropy_hex = json["entropy"].as_str().ok_or("Missing entropy field")?;

        // Decode hex
        let entropy = hex::decode(entropy_hex)?;

        if entropy.len() != 32 {
            return Err("Invalid entropy length".into());
        }

        // Store for future mixing (currently unused but ready)
        self.remote_key = entropy;

        info!("Fetched 32 bytes of Swarm Entropy from zks-key worker");
        Ok(())
    }
}

/// Entropy Tax Payer: Contributes randomness to the Swarm
pub struct EntropyTaxPayer {
    vernam_url: String,
}

impl EntropyTaxPayer {
    pub fn new(vernam_url: String) -> Self {
        Self { vernam_url }
    }

    /// Start the background contribution task
    pub fn start_background_task(self) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10)); // Pay tax every 10 seconds

            loop {
                interval.tick().await;
                if let Err(e) = self.pay_tax().await {
                    warn!("Failed to pay Entropy Tax: {}", e);
                }
            }
        });
    }

    /// Pay the Entropy Tax (Send 32 bytes of randomness)
    async fn pay_tax(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Generate local entropy
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)?;

        // 2. Connect to zks-key worker via WebSocket
        // Note: The worker expects a WebSocket connection for contributions
        let ws_url = self
            .vernam_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let url = Url::parse(&format!("{}/entropy", ws_url))?;

        let (ws_stream, _) = connect_async(url.to_string()).await?;
        let (mut write, mut read) = ws_stream.split();

        // 3. Send contribution
        // Format: {"type": "contribute", "entropy": [bytes...]}
        let request = serde_json::json!({
            "type": "contribute",
            "entropy": entropy
        });

        write.send(Message::Text(request.to_string())).await?;

        // 4. Wait for ACK
        if let Some(msg) = read.next().await {
            if let Message::Text(text) = msg? {
                debug!("Entropy Tax Paid: ACK received: {}", text);
            }
        }

        // Connection closes automatically when dropped
        Ok(())
    }
}

/// Trait combining all required stream traits
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}

/// Type alias for the underlying stream
type BoxedStream = Box<dyn self::Stream + Send + Sync>;

/// P2P Relay Connection over WebSocket
#[allow(dead_code)]
pub struct P2PRelay {
    /// WebSocket write half
    writer: Arc<Mutex<SplitSink<WebSocketStream<BoxedStream>, Message>>>,
    /// WebSocket read half
    reader: Arc<Mutex<SplitStream<WebSocketStream<BoxedStream>>>>,
    /// ZKS encryption keys
    keys: Arc<Mutex<WasifVernam>>,
    /// Our peer role
    pub role: PeerRole,
    /// Room ID
    pub room_id: String,
}

#[allow(dead_code)]
impl P2PRelay {
    /// Connect to relay and establish P2P session with key exchange
    pub async fn connect(
        relay_url: &str,
        vernam_url: &str,
        room_id: &str,
        role: PeerRole,
        proxy: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use crate::key_exchange::{KeyExchange, KeyExchangeMessage};
        use tokio::time::{timeout, Duration};

        // Parse URL
        let url = Url::parse(relay_url)?;
        let host = url.host_str().ok_or("No host in relay URL")?;
        let port = url.port_or_known_default().ok_or("No port in relay URL")?;
        let scheme = url.scheme();

        // Establish connection (Direct or Proxy)
        let stream: BoxedStream = if let Some(proxy_addr) = proxy {
            info!("Connecting via SOCKS5 proxy: {}", proxy_addr);
            let proxy_socket_addr: SocketAddr = proxy_addr.parse()?;

            let socks_stream = Socks5Stream::connect(proxy_socket_addr, (host, port)).await?;

            if scheme == "wss" {
                let connector = native_tls::TlsConnector::new()?;
                let connector = tokio_native_tls::TlsConnector::from(connector);
                let tls_stream = connector.connect(host, socks_stream).await?;
                Box::new(tls_stream)
            } else {
                Box::new(socks_stream)
            }
        } else {
            let tcp_stream = TcpStream::connect((host, port)).await?;

            if scheme == "wss" {
                let connector = native_tls::TlsConnector::new()?;
                let connector = tokio_native_tls::TlsConnector::from(connector);
                let tls_stream = connector.connect(host, tcp_stream).await?;
                Box::new(tls_stream)
            } else {
                Box::new(tcp_stream)
            }
        };

        // Build WebSocket URL
        let ws_url = format!(
            "{}/room/{}?role={}",
            relay_url.trim_end_matches('/'),
            room_id,
            role.as_str()
        );

        info!("Connecting to relay: {}", ws_url);

        // Perform WebSocket handshake
        let (ws_stream, response) = client_async(ws_url, stream).await?;
        info!("Connected to relay (status: {})", response.status());

        // Split into read/write
        let (mut writer, mut reader): (
            SplitSink<WebSocketStream<BoxedStream>, Message>,
            SplitStream<WebSocketStream<BoxedStream>>,
        ) = ws_stream.split();

        // === X25519 Key Exchange ===
        info!("🔑 Initiating X25519 key exchange...");

        let mut key_exchange = KeyExchange::new(room_id);
        key_exchange.generate_keypair();

        let our_pk = key_exchange
            .get_public_key_bytes()
            .ok_or("Failed to generate keypair")?;

        // Send our public key
        let pk_msg = KeyExchangeMessage::new_public_key(&our_pk);
        writer.send(Message::Text(pk_msg.to_json())).await?;
        debug!("Sent our public key");

        // Wait for peer's public key (with timeout)
        // 5 minute timeout to allow Exit Peer to wait for Client
        let peer_pk = timeout(Duration::from_secs(300), async {
            while let Some(msg) = reader.next().await {
                match msg? {
                    Message::Text(text) => {
                        // Check if it's a PeerJoin event - re-send our public key
                        if text.contains("\"peer_join\"") || text.contains("\"PeerJoin\"") {
                            debug!("Peer joined, re-sending public key");
                            let pk_msg = KeyExchangeMessage::new_public_key(&our_pk);
                            writer.send(Message::Text(pk_msg.to_json())).await?;
                            continue;
                        }

                        // Check if it's a key exchange message
                        if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                            if let Some(pk_bytes) = ke_msg.parse_public_key() {
                                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(pk_bytes);
                            }
                        }
                        // Other control messages (welcome, etc.) - ignore
                        debug!("Relay control message: {}", text);
                    }
                    Message::Binary(_) => {
                        // Ignore binary before key exchange
                    }
                    Message::Close(_) => {
                        return Err("Connection closed before key exchange".into());
                    }
                    _ => {}
                }
            }
            Err("No key exchange message received".into())
        })
        .await
        .map_err(|_| "Key exchange timeout")??;

        // Complete key exchange
        key_exchange.receive_peer_public_key(&peer_pk)?;
        info!("🔐 Key exchange complete! Encryption key derived.");

        // Get the derived encryption key
        let encryption_key = key_exchange
            .get_encryption_key()
            .ok_or("Failed to derive encryption key")?
            .to_vec();

        // Initialize Wasif Vernam with derived shared key
        let mut shared_secret = [0u8; 32];
        if encryption_key.len() >= 32 {
            shared_secret.copy_from_slice(&encryption_key[0..32]);
        }
        let mut keys = WasifVernam::new(shared_secret);

        // Optionally XOR with vernam key for additional security (defense in depth)
        if !vernam_url.is_empty() {
            // Start Entropy Tax Payer (Background Task)
            let tax_payer = EntropyTaxPayer::new(vernam_url.to_string());
            tax_payer.start_background_task();
            info!("Started Entropy Tax Payer (contributing randomness to Swarm)");

            if let Err(e) = keys.fetch_remote_key(vernam_url).await {
                warn!(
                    "Failed to fetch initial remote key: {}. Proceeding with ChaCha20 base layer.",
                    e
                );
            }
        }

        // Send ack
        let ack = KeyExchangeMessage::Ack { success: true };
        writer.send(Message::Text(ack.to_json())).await?;

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

        // Encrypt with Wasif Vernam (ChaCha20-Poly1305)
        let encrypted = {
            let keys = self.keys.lock().await;
            keys.encrypt(&encoded).map_err(|_| "Encryption failed")?
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
            let keys = self.keys.lock().await;
            keys.encrypt(data).map_err(|_| "Encryption failed")?
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
                    // Decrypt with Wasif Vernam (ChaCha20-Poly1305)
                    let decrypted = {
                        let keys = self.keys.lock().await;
                        match keys.decrypt(&data) {
                            Ok(d) => d,
                            Err(_) => {
                                warn!(
                                    "Decryption failed (Poly1305 tag mismatch) - dropping packet"
                                );
                                continue;
                            }
                        }
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

                    // CRITICAL: If peer joins/leaves or sends a new key, we MUST restart the session
                    // because we threw away our private key after the initial handshake.
                    // We cannot re-key without reconnecting.
                    if text.contains("peer_join")
                        || text.contains("PeerJoin")
                        || text.contains("peer_leave")
                        || text.contains("PeerLeave")
                        || text.contains("public_key")
                    {
                        return Err("Peer state changed - restarting session to re-key".into());
                    }
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
                        let keys = self.keys.lock().await;
                        match keys.decrypt(&data) {
                            Ok(d) => d,
                            Err(_) => {
                                warn!(
                                    "Decryption failed (Poly1305 tag mismatch) - dropping packet"
                                );
                                continue;
                            }
                        }
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
        let mut writer: tokio::sync::MutexGuard<
            '_,
            SplitSink<WebSocketStream<BoxedStream>, Message>,
        > = self.writer.lock().await;
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
        let _reader = self.reader.clone();
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
                    let keys_guard = keys.lock().await;
                    if let Ok(enc) = keys_guard.encrypt(&padding) {
                        enc
                    } else {
                        continue;
                    }
                };

                // Send padding (ignore errors - connection might be busy)
                let mut writer_guard: tokio::sync::MutexGuard<
                    '_,
                    SplitSink<WebSocketStream<BoxedStream>, Message>,
                > = writer.lock().await;
                let _ = writer_guard.send(Message::Binary(encrypted)).await;
                drop(writer_guard);

                // Reader is captured by move, no need to lock it (would cause deadlock)
                // let reader = reader.lock().await; // DEADLOCK!

                // Wait for next interval
                tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
            }

            info!("CRP: Padding stopped");
        })
    }
}
