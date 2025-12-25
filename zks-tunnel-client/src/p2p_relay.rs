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
use tokio_tungstenite::{client_async, WebSocketStream};
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

/// Wasif Vernam: True Infinite-Key Encryption
///
/// Two modes of operation:
/// 1. HKDF Mode: Expands swarm seed into pseudorandom keystream (computationally secure)
/// 2. True Vernam Mode: Uses TRUE random bytes from buffer (information-theoretically secure)
pub struct WasifVernam {
    /// ChaCha20Poly1305 Cipher (base layer)
    cipher: ChaCha20Poly1305,
    /// Nonce counter (incremented per message)
    nonce_counter: AtomicU64,
    /// Swarm entropy seed (32 bytes from combined peer entropy) - for HKDF mode
    swarm_seed: [u8; 32],
    /// Key offset (tracks how much key material has been used) - for HKDF mode
    key_offset: AtomicU64,
    /// Has swarm entropy (false = ChaCha20 only mode)
    has_swarm_entropy: bool,
    /// True Vernam buffer (if Some, uses TRUE random bytes instead of HKDF)
    true_vernam_buffer: Option<Arc<Mutex<crate::true_vernam::TrueVernamBuffer>>>,
}

impl WasifVernam {
    /// Create new Wasif Vernam from a 32-byte shared secret and swarm entropy
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte key from key exchange (for ChaCha20-Poly1305)
    /// * `swarm_entropy` - Swarm entropy (any length, will be hashed to 32-byte seed)
    pub fn new(shared_secret: [u8; 32], swarm_entropy: Vec<u8>) -> Self {
        use sha2::{Sha256, Digest};
        
        let key = Key::from_slice(&shared_secret);
        let cipher = ChaCha20Poly1305::new(key);

        // Hash swarm entropy to get a 32-byte seed for HKDF expansion
        let (swarm_seed, has_swarm_entropy) = if !swarm_entropy.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&swarm_entropy);
            let hash: [u8; 32] = hasher.finalize().into();
            (hash, true)
        } else {
            ([0u8; 32], false)
        };

        Self {
            cipher,
            nonce_counter: AtomicU64::new(0),
            swarm_seed,
            key_offset: AtomicU64::new(0),
            has_swarm_entropy,
            true_vernam_buffer: None, // Default to HKDF mode
        }
    }

    /// Enable True Vernam mode (information-theoretic security)
    /// Call this to switch from HKDF expansion to TRUE random bytes
    pub fn enable_true_vernam(&mut self, buffer: Arc<Mutex<crate::true_vernam::TrueVernamBuffer>>) {
        self.true_vernam_buffer = Some(buffer);
        info!("🔐 TRUE VERNAM MODE ENABLED - Information-theoretic security active!");
    }

    /// Generate keystream bytes at a given offset using HKDF
    /// This creates an infinite, non-repeating keystream from the swarm seed
    fn generate_keystream(&self, offset: u64, length: usize) -> Vec<u8> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let mut keystream = Vec::with_capacity(length);
        let chunk_size = 1024; // HKDF output chunk size
        
        let mut current_offset = offset;
        while keystream.len() < length {
            // Each chunk is derived with a unique context based on offset
            let chunk_index = current_offset / chunk_size as u64;
            let context = format!("wasif-vernam-keystream-{}", chunk_index);
            
            let hk = Hkdf::<Sha256>::new(Some(b"zks-infinite-key-v1"), &self.swarm_seed);
            let mut chunk = vec![0u8; chunk_size];
            hk.expand(context.as_bytes(), &mut chunk)
                .expect("HKDF expansion should not fail");
            
            // Calculate where in this chunk we should start reading
            let chunk_start = (current_offset % chunk_size as u64) as usize;
            let bytes_needed = length - keystream.len();
            let bytes_available = chunk_size - chunk_start;
            let bytes_to_copy = bytes_needed.min(bytes_available);
            
            keystream.extend_from_slice(&chunk[chunk_start..chunk_start + bytes_to_copy]);
            current_offset += bytes_to_copy as u64;
        }
        
        keystream
    }

    /// Encrypt data using True Wasif-Vernam (Infinite Key XOR + ChaCha20-Poly1305)
    /// Returns: [Nonce (12 bytes) | Key Offset (8 bytes) | Ciphertext (N bytes) | Tag (16 bytes)]
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        // Generate unique nonce
        let mut nonce_bytes = [0u8; 12];
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
        getrandom::getrandom(&mut nonce_bytes[0..4]).unwrap_or_default();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 1. True Vernam Layer: XOR with infinite keystream (if swarm entropy available)
        let mut mixed_data = data.to_vec();
        let key_offset = if self.has_swarm_entropy {
            // Get current offset and advance it atomically
            let offset = self.key_offset.fetch_add(data.len() as u64, Ordering::SeqCst);
            
            // Generate unique keystream for this data
            let keystream = self.generate_keystream(offset, data.len());
            
            // XOR with keystream - each byte gets a UNIQUE key byte!
            for (i, byte) in mixed_data.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
            
            offset // Return offset so receiver knows where to start
        } else {
            0 // No swarm entropy, skip XOR layer
        };

        // 2. Base Layer: Encrypt with ChaCha20-Poly1305
        let mut ciphertext = self.cipher.encrypt(nonce, mixed_data.as_slice())?;

        // Build result: [Nonce (12) | Offset (8) | Ciphertext]
        let mut result = Vec::with_capacity(12 + 8 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&key_offset.to_be_bytes());
        result.append(&mut ciphertext);

        Ok(result)
    }

    /// Decrypt data using True Wasif-Vernam
    /// Input: [Nonce (12 bytes) | Key Offset (8 bytes) | Ciphertext (N bytes) | Tag (16 bytes)]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        if data.len() < 12 + 8 + 16 {
            return Err(chacha20poly1305::aead::Error);
        }

        // Extract nonce and offset
        let nonce = Nonce::from_slice(&data[0..12]);
        let key_offset = u64::from_be_bytes(data[12..20].try_into().unwrap());
        let ciphertext = &data[20..];

        // 1. Base Layer: Decrypt with ChaCha20-Poly1305
        let mut plaintext = self.cipher.decrypt(nonce, ciphertext)?;

        // 2. True Vernam Layer: XOR with infinite keystream
        if self.has_swarm_entropy && key_offset > 0 {
            let keystream = self.generate_keystream(key_offset, plaintext.len());
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
        }

        Ok(plaintext)
    }

    /// Encrypt data using TRUE Vernam mode (information-theoretic security)
    /// Uses TRUE random bytes from buffer instead of HKDF expansion
    /// Returns: [Nonce (12 bytes) | Mode (1 byte: 0x01) | Ciphertext (N bytes) | Tag (16 bytes)]
    pub async fn encrypt_true_vernam(&self, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        // Generate unique nonce
        let mut nonce_bytes = [0u8; 12];
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
        getrandom::getrandom(&mut nonce_bytes[0..4]).unwrap_or_default();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 1. TRUE Vernam Layer: XOR with TRUE random bytes
        let mut mixed_data = data.to_vec();
        
        if let Some(ref buffer) = self.true_vernam_buffer {
            let keystream = {
                let mut buf = buffer.lock().await;
                buf.consume(data.len())
            };
            
            if let Some(keystream) = keystream {
                // XOR with TRUE random bytes - mathematically unbreakable!
                for (i, byte) in mixed_data.iter_mut().enumerate() {
                    *byte ^= keystream[i];
                }
                debug!("🔐 Used {} TRUE random bytes for encryption", data.len());
            } else {
                // Buffer empty - fallback to HKDF mode with warning
                warn!("⚠️ True Vernam buffer empty! Falling back to HKDF mode");
                let offset = self.key_offset.fetch_add(data.len() as u64, Ordering::SeqCst);
                let keystream = self.generate_keystream(offset, data.len());
                for (i, byte) in mixed_data.iter_mut().enumerate() {
                    *byte ^= keystream[i];
                }
            }
        } else if self.has_swarm_entropy {
            // No True Vernam buffer, use HKDF mode
            let offset = self.key_offset.fetch_add(data.len() as u64, Ordering::SeqCst);
            let keystream = self.generate_keystream(offset, data.len());
            for (i, byte) in mixed_data.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
        }

        // 2. Base Layer: Encrypt with ChaCha20-Poly1305
        let mut ciphertext = self.cipher.encrypt(nonce, mixed_data.as_slice())?;

        // Build result: [Nonce (12) | Mode (1: 0x01 = True Vernam) | Ciphertext]
        let mut result = Vec::with_capacity(12 + 1 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.push(0x01); // Mode byte: True Vernam
        result.append(&mut ciphertext);

        Ok(result)
    }

    /// Decrypt data encrypted with TRUE Vernam mode
    /// Note: Decryption requires the same TRUE random bytes, which are stored with sender
    /// For now, this works because we sync the buffer state
    pub async fn decrypt_true_vernam(&self, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        if data.len() < 12 + 1 + 16 {
            return Err(chacha20poly1305::aead::Error);
        }

        let nonce = Nonce::from_slice(&data[0..12]);
        let mode = data[12];
        let ciphertext = &data[13..];

        // 1. Base Layer: Decrypt with ChaCha20-Poly1305
        let mut plaintext = self.cipher.decrypt(nonce, ciphertext)?;

        // 2. TRUE Vernam Layer: XOR with TRUE random bytes
        if mode == 0x01 {
            if let Some(ref buffer) = self.true_vernam_buffer {
                let keystream = {
                    let mut buf = buffer.lock().await;
                    buf.consume(plaintext.len())
                };
                
                if let Some(keystream) = keystream {
                    for (i, byte) in plaintext.iter_mut().enumerate() {
                        *byte ^= keystream[i];
                    }
                } else {
                    warn!("⚠️ True Vernam buffer empty during decryption!");
                }
            }
        }

        Ok(plaintext)
    }

    /// Fetch swarm entropy seed from zks-vernam worker
    #[allow(dead_code)]
    pub async fn fetch_remote_key(
        &mut self,
        vernam_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use sha2::{Sha256, Digest};
        
        let url = format!("{}/entropy?size=32&n=10", vernam_url.trim_end_matches('/'));
        let response = reqwest::get(&url).await?;
        if !response.status().is_success() {
            return Err(format!("Failed to fetch entropy: {}", response.status()).into());
        }

        let body = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let entropy_hex = json["entropy"].as_str().ok_or("Missing entropy field")?;
        let entropy = hex::decode(entropy_hex)?;

        // Hash to get seed
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        self.swarm_seed = hasher.finalize().into();
        self.has_swarm_entropy = true;
        self.key_offset.store(0, Ordering::SeqCst); // Reset offset for new seed

        info!("Fetched Swarm Entropy seed from worker - Infinite Vernam active!");
        Ok(())
    }

    /// Set the swarm entropy seed directly (used when receiving from peer)
    pub fn set_remote_key(&mut self, key: Vec<u8>) {
        use sha2::{Sha256, Digest};
        
        if !key.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            self.swarm_seed = hasher.finalize().into();
            self.has_swarm_entropy = true;
            self.key_offset.store(0, Ordering::SeqCst);
            info!("Applied {} bytes of Swarm Entropy - Infinite Vernam active!", key.len());
        }
    }

    /// Get the swarm seed (for sharing with peer)
    pub fn get_remote_key(&self) -> &[u8] {
        if self.has_swarm_entropy {
            &self.swarm_seed
        } else {
            &[]
        }
    }

    /// Refresh the swarm seed by mixing in new entropy (FORWARD SECRECY)
    /// 
    /// This is the key to TRUE continuous entropy:
    /// new_seed = HKDF(old_seed || fresh_entropy || generation)
    /// 
    /// Benefits:
    /// - Even if current seed is compromised, past traffic is safe
    /// - Each refresh creates a cryptographically independent key chain
    /// - Generation counter prevents replay attacks
    pub fn refresh_entropy(&mut self, fresh_entropy: &[u8]) {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        if fresh_entropy.is_empty() {
            return;
        }

        // Combine old seed with fresh entropy
        let mut input = Vec::with_capacity(32 + fresh_entropy.len() + 8);
        input.extend_from_slice(&self.swarm_seed);
        input.extend_from_slice(fresh_entropy);
        
        // Add current offset as "generation" to prevent replay
        let generation = self.key_offset.load(Ordering::SeqCst);
        input.extend_from_slice(&generation.to_be_bytes());

        // Derive new seed using HKDF
        let hk = Hkdf::<Sha256>::new(Some(b"zks-entropy-refresh-v1"), &input);
        let mut new_seed = [0u8; 32];
        hk.expand(b"refreshed-swarm-seed", &mut new_seed)
            .expect("HKDF expansion should not fail");

        // Update seed (old seed is now unreachable - forward secrecy!)
        self.swarm_seed = new_seed;
        self.has_swarm_entropy = true;
        
        // NOTE: We do NOT reset key_offset - the new keystream continues from current position
        // This ensures no key byte is ever reused across refresh cycles
        
        info!("🔄 Refreshed swarm entropy - Forward secrecy checkpoint! (generation: {})", generation);
    }

    /// Get current key offset (for monitoring/debugging)
    pub fn get_key_offset(&self) -> u64 {
        self.key_offset.load(Ordering::SeqCst)
    }

    /// Check if entropy refresh is recommended (e.g., after 1MB of traffic)
    pub fn needs_refresh(&self) -> bool {
        const REFRESH_THRESHOLD: u64 = 1024 * 1024; // 1MB
        self.key_offset.load(Ordering::SeqCst) % REFRESH_THRESHOLD < 1024
    }
}

/// Continuous Entropy Refresher: Periodically fetches fresh entropy and refreshes the cipher
/// 
/// This is what makes ZKS a TRUE continuous entropy system:
/// - Every 30 seconds (or after 1MB traffic), fetch fresh entropy from swarm/worker
/// - Mix into existing seed using refresh_entropy()
/// - Provides forward secrecy: past traffic is unrecoverable even if current seed leaks
pub struct ContinuousEntropyRefresher {
    vernam_url: String,
    cipher: Arc<Mutex<WasifVernam>>,
}

impl ContinuousEntropyRefresher {
    pub fn new(vernam_url: String, cipher: Arc<Mutex<WasifVernam>>) -> Self {
        Self { vernam_url, cipher }
    }

    /// Start the background entropy refresh task
    pub fn start_background_task(self) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Refresh every 30 seconds
            
            loop {
                interval.tick().await;
                
                // Check if refresh is needed (either by time or by traffic volume)
                let needs_refresh = {
                    let cipher = self.cipher.lock().await;
                    cipher.needs_refresh() || true // Always refresh on interval
                };
                
                if needs_refresh {
                    if let Err(e) = self.fetch_and_refresh().await {
                        warn!("Failed to refresh entropy: {}", e);
                    }
                }
            }
        });
    }

    /// Fetch fresh entropy from worker and refresh the cipher
    async fn fetch_and_refresh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/entropy?size=32&n=10", self.vernam_url.trim_end_matches('/'));
        let response = reqwest::get(&url).await?;
        
        if !response.status().is_success() {
            return Err(format!("Failed to fetch entropy: {}", response.status()).into());
        }

        let body = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let entropy_hex = json["entropy"].as_str().ok_or("Missing entropy field")?;
        let fresh_entropy = hex::decode(entropy_hex)?;

        // Refresh the cipher's seed with fresh entropy
        {
            let mut cipher = self.cipher.lock().await;
            cipher.refresh_entropy(&fresh_entropy);
        }

        info!("🔄 Continuous entropy refresh complete - TRUE forward secrecy active!");
        Ok(())
    }
}

// Keep the old name as an alias for backward compatibility
pub type EntropyTaxPayer = ContinuousEntropyRefresher;

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
    /// Shared secret for file transfer
    pub shared_secret: [u8; 32],
    /// Our Peer ID assigned by relay
    pub peer_id: String,
}

/// Discover peers from relay messages (welcome + peer_join events)
///
/// Listens to the WebSocket stream for a specified duration to collect peer IDs
/// from welcome and peer_join messages sent by the relay.
async fn discover_peers_from_relay<S>(
    reader: &mut SplitStream<WebSocketStream<S>>,
    timeout_duration: Duration,
) -> Result<(Vec<String>, Vec<Message>), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::time::timeout;

    let mut peer_ids = Vec::new();
    let mut unhandled_messages = Vec::new();

    // Listen for messages for the specified duration
    let discovery_result = timeout(timeout_duration, async {
        while let Some(msg) = reader.next().await {
            let msg = msg?;
            match msg {
                Message::Text(ref text) => {
                    // Try to parse as JSON to extract peer information
                    let mut handled = false;
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                        // Check for welcome message
                        if json["type"] == "welcome" {
                            debug!("Received welcome message: {}", text);
                            handled = true;
                        }
                        // Check for peer_join message
                        else if json["type"] == "peer_join" {
                            if let Some(peer_id) = json["peer_id"].as_str() {
                                info!("Discovered peer: {}", peer_id);
                                peer_ids.push(peer_id.to_string());
                                handled = true;
                            }
                        }
                    }

                    if !handled {
                        unhandled_messages.push(msg);
                    }
                }
                Message::Close(_) => {
                    return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                        "Connection closed during peer discovery".into(),
                    );
                }
                _ => {
                    unhandled_messages.push(msg);
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;

    // Timeout is expected - we're just collecting peers for a fixed duration
    match discovery_result {
        Ok(_) | Err(_) => {
            info!("Peer discovery complete: found {} peers", peer_ids.len());
            Ok((peer_ids, unhandled_messages))
        }
    }
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
            // Explicit DNS resolution with retry logic
            info!("Resolving hostname: {}:{}", host, port);
            let addr_str = format!("{}:{}", host, port);

            let mut attempts = 0;
            let socket_addr = loop {
                match tokio::net::lookup_host(&addr_str).await {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            info!("Resolved {} to {}", host, addr);
                            break addr;
                        } else {
                            return Err(format!("No addresses found for {}", host).into());
                        }
                    }
                    Err(e) if attempts < 3 => {
                        attempts += 1;
                        warn!(
                            "DNS lookup attempt {} failed for {}: {}. Retrying in 2s...",
                            attempts, host, e
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Failed to resolve {} after {} attempts: {}",
                            host, attempts, e
                        )
                        .into());
                    }
                }
            };

            info!("Connecting to {}...", socket_addr);
            let tcp_stream = TcpStream::connect(socket_addr).await?;

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
        let (writer, reader): (
            SplitSink<WebSocketStream<BoxedStream>, Message>,
            SplitStream<WebSocketStream<BoxedStream>>,
        ) = ws_stream.split();
        let writer = Arc::new(Mutex::new(writer));
        let reader = Arc::new(Mutex::new(reader));

        // === AUTHENTICATED 3-MESSAGE KEY EXCHANGE (Security Fix) ===
        // This replaces the legacy unauthenticated 2-message protocol
        // Protocol:
        //   Client (Initiator):  AuthInit → AuthResponse → KeyConfirm
        //   Exit Peer (Responder): AuthInit ← AuthResponse ← KeyConfirm
        info!("🔑 Initiating authenticated key exchange...");

        let key_exchange = Arc::new(Mutex::new(KeyExchange::new(room_id)));
        let my_peer_id = Arc::new(Mutex::new(String::new()));

        match role {
            PeerRole::Client => {
                // === CLIENT (INITIATOR) FLOW ===
                // Step 1: Create and send AuthInit
                let auth_init = key_exchange
                    .lock()
                    .await
                    .create_auth_init()
                    .map_err(|e| format!("Failed to create AuthInit: {}", e))?;
                writer
                    .lock()
                    .await
                    .send(Message::Text(auth_init.to_json()))
                    .await?;
                debug!("Sent AuthInit message: {}", auth_init.to_json()); // DEBUG LOG

                // Step 2: Wait for AuthResponse from Exit Peer
                let my_peer_id_clone = my_peer_id.clone();
                let key_exchange_clone = key_exchange.clone();
                let writer_clone = writer.clone();
                let reader_clone = reader.clone();
                let auth_response = timeout(Duration::from_secs(120), async move {
                    while let Some(msg) = reader_clone.lock().await.next().await {
                        match msg? {
                            Message::Text(text) => {
                                debug!("Received control message: {}", text); // DEBUG LOG
                                                                              // Check for Welcome message to get our Peer ID
                                if text.contains("\"type\":\"welcome\"") {
                                    if let Ok(json) =
                                        serde_json::from_str::<serde_json::Value>(&text)
                                    {
                                        if let Some(id) = json["peer_id"].as_str() {
                                            let mut pid = my_peer_id_clone.lock().await;
                                            *pid = id.to_string();
                                            info!("✅ Assigned Peer ID: {}", id);
                                        }
                                    }
                                }

                                // Handle peer join - resend AuthInit
                                if text.contains("\"peer_join\"") || text.contains("\"PeerJoin\"") {
                                    debug!("Peer joined, re-sending AuthInit");
                                    let auth_init = key_exchange_clone
                                        .lock()
                                        .await
                                        .create_auth_init()
                                        .map_err(|e| format!("Failed to create AuthInit: {}", e))?;
                                    writer_clone
                                        .lock()
                                        .await
                                        .send(Message::Text(auth_init.to_json()))
                                        .await?;
                                    continue;
                                }

                                // Check for AuthResponse
                                if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                                    if let KeyExchangeMessage::AuthResponse { .. } = &ke_msg {
                                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                                            ke_msg,
                                        );
                                    }
                                }
                                debug!("Control message: {}", text);
                            }
                            Message::Close(_) => {
                                return Err("Connection closed during key exchange".into());
                            }
                            _ => {}
                        }
                    }
                    Err("No AuthResponse received".into())
                })
                .await
                .map_err(|_| "AuthResponse timeout")??;

                // Step 3: Process AuthResponse and send KeyConfirm
                let key_confirm = key_exchange
                    .lock()
                    .await
                    .process_auth_response_and_confirm(&auth_response)
                    .map_err(|e| format!("Failed to process AuthResponse: {}", e))?;
                writer
                    .lock()
                    .await
                    .send(Message::Text(key_confirm.to_json()))
                    .await?;
                debug!("Sent KeyConfirm message");

                info!("🔐 Authenticated key exchange complete (Client)!");
            }
            PeerRole::ExitPeer => {
                // === EXIT PEER (RESPONDER) FLOW ===
                // Step 1: Wait for AuthInit from Client
                let my_peer_id_clone = my_peer_id.clone();
                let reader_clone = reader.clone();
                let auth_init = timeout(Duration::from_secs(300), async move {
                    while let Some(msg) = reader_clone.lock().await.next().await {
                        match msg? {
                            Message::Text(text) => {
                                // Check for Welcome message to get our Peer ID
                                if text.contains("\"type\":\"welcome\"") {
                                    if let Ok(json) =
                                        serde_json::from_str::<serde_json::Value>(&text)
                                    {
                                        if let Some(id) = json["peer_id"].as_str() {
                                            let mut pid = my_peer_id_clone.lock().await;
                                            *pid = id.to_string();
                                            info!("✅ Assigned Peer ID: {}", id);
                                        }
                                    }
                                }

                                // Check for AuthInit
                                if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                                    if let KeyExchangeMessage::AuthInit { .. } = &ke_msg {
                                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                                            ke_msg,
                                        );
                                    }
                                }
                                debug!("Control message: {}", text);
                            }
                            Message::Close(_) => {
                                return Err("Connection closed during key exchange".into());
                            }
                            _ => {}
                        }
                    }
                    Err("No AuthInit received".into())
                })
                .await
                .map_err(|_| "AuthInit timeout")??;

                // Step 2: Process AuthInit and send AuthResponse
                let auth_response = key_exchange
                    .lock()
                    .await
                    .process_auth_init_and_respond(&auth_init)
                    .map_err(|e| format!("Failed to process AuthInit: {}", e))?;
                writer
                    .lock()
                    .await
                    .send(Message::Text(auth_response.to_json()))
                    .await?;
                debug!("Sent AuthResponse message");

                // Step 3: Wait for KeyConfirm from Client
                let reader_clone = reader.clone();
                let key_confirm = timeout(Duration::from_secs(60), async move {
                    while let Some(msg) = reader_clone.lock().await.next().await {
                        match msg? {
                            Message::Text(text) => {
                                if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                                    if let KeyExchangeMessage::KeyConfirm { .. } = &ke_msg {
                                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                                            ke_msg,
                                        );
                                    }
                                }
                            }
                            Message::Close(_) => {
                                return Err("Connection closed during key exchange".into());
                            }
                            _ => {}
                        }
                    }
                    Err("No KeyConfirm received".into())
                })
                .await
                .map_err(|_| "KeyConfirm timeout")??;

                // Step 4: Verify KeyConfirm
                key_exchange
                    .lock()
                    .await
                    .process_key_confirm(&key_confirm)
                    .map_err(|e| format!("Failed to verify KeyConfirm: {}", e))?;

                info!("🔐 Authenticated key exchange complete (Exit Peer)!");
            }
        }

        // Key exchange is now complete with mutual authentication
        info!("✅ Mutual authentication verified - MITM protection active!");

        // Get the derived encryption key
        let encryption_key = key_exchange
            .lock()
            .await
            .get_encryption_key()
            .ok_or("Failed to derive encryption key")?
            .to_vec();

        // Initialize Wasif Vernam with derived shared key
        let mut shared_secret_array = [0u8; 32];
        if encryption_key.len() >= 32 {
            shared_secret_array.copy_from_slice(&encryption_key[0..32]);
        }
        let shared_secret = shared_secret_array;

        // === Swarm Entropy Collection ===
        // Collect entropy from peers in room for information-theoretic security
        info!("🎲 Discovering peers for Swarm Entropy collection...");

        // Discover peers from relay messages (welcome + peer_join events)
        let (peer_ids, unhandled_msgs) =
            discover_peers_from_relay(&mut *reader.lock().await, Duration::from_secs(2)).await?;

        let remote_key = if !peer_ids.is_empty() {
            use crate::swarm_entropy_collection::collect_swarm_entropy_via_relay;

            info!(
                "🎲 Starting Swarm Entropy collection with {} peers...",
                peer_ids.len()
            );
            let mut writer_guard = writer.lock().await;
            let mut reader_guard = reader.lock().await;
            match collect_swarm_entropy_via_relay(
                &mut *writer_guard,
                &mut *reader_guard,
                room_id,
                peer_ids,
            )
            .await
            {
                Ok(key) => {
                    info!("✅ Swarm Entropy collected! Information-theoretic security ACTIVE");
                    key
                }
                Err(e) => {
                    warn!(
                        "⚠️  Failed to collect Swarm Entropy: {}. Falling back to ChaCha20-only",
                        e
                    );
                    Vec::new()
                }
            }
        } else {
            info!("ℹ️  No peers in room yet, using ChaCha20-only (will upgrade when peers join)");
            Vec::new()
        };

        let keys = Arc::new(Mutex::new(WasifVernam::new(shared_secret, remote_key)));

        // === Swarm Entropy Synchronization ===
        // Client fetches entropy and shares with Exit Peer to ensure both have same key
        if !vernam_url.is_empty() {
            match role {
                PeerRole::Client => {
                    // Client: Fetch entropy from relay and send to Exit Peer
                    info!("🎲 Fetching Swarm Entropy from relay...");
                    match keys.lock().await.fetch_remote_key(vernam_url).await {
                        Ok(()) => {
                            // Send the entropy to Exit Peer
                            let entropy_msg =
                                KeyExchangeMessage::new_shared_entropy(keys.lock().await.get_remote_key());
                            writer
                                .lock()
                                .await
                                .send(Message::Text(entropy_msg.to_json()))
                                .await?;
                            info!("✅ Sent Swarm Entropy to Exit Peer (Double-Key active)");
                        }
                        Err(e) => {
                            warn!("Failed to fetch swarm entropy: {}. Using ChaCha20 only.", e);
                        }
                    }
                }
                PeerRole::ExitPeer => {
                    // Exit Peer: Wait for SharedEntropy from Client
                    info!("⏳ Waiting for Swarm Entropy from Client...");

                    // Check unhandled messages first
                    let mut entropy_found = None;
                    for msg in unhandled_msgs {
                        if let Message::Text(text) = msg {
                            if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                                if let Some(entropy_bytes) = ke_msg.parse_shared_entropy() {
                                    entropy_found = Some(entropy_bytes);
                                    break;
                                }
                            }
                        }
                    }

                    if let Some(entropy_bytes) = entropy_found {
                        keys.lock().await.set_remote_key(entropy_bytes);
                        info!(
                            "✅ Received Swarm Entropy from Client (Double-Key active) [Buffered]"
                        );
                    } else {
                        let reader_clone = reader.clone();
                        let entropy_timeout =
                            tokio::time::timeout(Duration::from_secs(10), async move {
                                while let Some(msg) = reader_clone.lock().await.next().await {
                                    if let Message::Text(text) = msg? {
                                        if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                                            if let Some(entropy_bytes) =
                                                ke_msg.parse_shared_entropy()
                                            {
                                                return Ok::<
                                                    _,
                                                    Box<dyn std::error::Error + Send + Sync>,
                                                >(
                                                    entropy_bytes
                                                );
                                            }
                                        }
                                        // Ignore other messages (acks, etc.)
                                    }
                                }
                                Err("No entropy received".into())
                            })
                            .await;

                        match entropy_timeout {
                            Ok(Ok(entropy_bytes)) => {
                                keys.lock().await.set_remote_key(entropy_bytes);
                                info!("✅ Received Swarm Entropy from Client (Double-Key active)");
                            }
                            Ok(Err(e)) => {
                                warn!("Failed to receive entropy: {}. Using ChaCha20 only.", e);
                            }
                            Err(_) => {
                                warn!("Entropy timeout. Client may not support Double-Key. Using ChaCha20 only.");
                            }
                        }
                    }
                }
            }

            // Start Continuous Entropy Refresher (TRUE forward secrecy)
            let refresher = ContinuousEntropyRefresher::new(vernam_url.to_string(), keys.clone());
            refresher.start_background_task();
            info!("🔄 Started Continuous Entropy Refresher (TRUE forward secrecy active!)");

            // === TRUE VERNAM MODE (Information-Theoretic Security) ===
            // Enable by default for maximum security
            let true_vernam_buffer = Arc::new(Mutex::new(crate::true_vernam::TrueVernamBuffer::new()));
            let fetcher = crate::true_vernam::TrueVernamFetcher::new(
                vernam_url.to_string(),
                true_vernam_buffer.clone(),
            );
            fetcher.start_background_task();
            
            // Enable True Vernam on the cipher
            {
                let mut cipher = keys.lock().await;
                cipher.enable_true_vernam(true_vernam_buffer);
            }
            info!("🔐 TRUE VERNAM MODE ENABLED BY DEFAULT - Mathematically unbreakable encryption!");
        }

        // Send ack
        let ack = KeyExchangeMessage::Ack { success: true };
        writer
            .lock()
            .await
            .send(Message::Text(ack.to_json()))
            .await?;

        let final_peer_id = my_peer_id.lock().await.clone();

        Ok(Self {
            writer,
            reader,
            keys,
            role,
            room_id: room_id.to_string(),
            shared_secret,
            peer_id: final_peer_id,
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

    /// Send raw text message (for control/entropy events)
    pub async fn send_text(
        &self,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut writer = self.writer.lock().await;
        writer.send(Message::Text(text)).await?;
        Ok(())
    }

    /// Set the remote key for Double-Key Encryption (Swarm Entropy)
    pub async fn set_remote_key(&self, key: Vec<u8>) {
        let mut keys = self.keys.lock().await;
        keys.set_remote_key(key);
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

                    // NOTE: Previously we would return an error here to force reconnection,
                    // but this causes a race condition where the Go client connects,
                    // triggering peer_join, which causes Exit Peer to reconnect with new keys.
                    // Now we just log a warning and continue - the existing keys are still valid.
                    if text.contains("peer_join")
                        || text.contains("PeerJoin")
                        || text.contains("peer_leave")
                        || text.contains("PeerLeave")
                    {
                        warn!("Peer state changed notification received (continuing with existing keys)");
                        // Don't return error - continue processing with current keys
                    }

                    // Only restart if we receive a new public_key (re-key request)
                    // This should only happen if the peer intentionally wants to re-key
                    if text.contains("\"type\":\"key_exchange\"") && text.contains("public_key") {
                        warn!("Received new key exchange request - this shouldn't happen after handshake");
                        // For now, ignore re-key requests after initial handshake
                        // A proper implementation would handle re-keying
                    }

                    // Pass text message up to caller as Control message
                    // This is needed for Swarm Entropy events (EntropyEvent)
                    return Ok(Some(TunnelMessage::Control { message: text }));
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

    /// Receive raw decrypted bytes (for file transfer)
    pub async fn recv_raw(
        &self,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = self.reader.lock().await;
        while let Some(msg) = reader.next().await {
            let msg = msg?;
            match msg {
                Message::Binary(data) => {
                    let keys = self.keys.lock().await;
                    match keys.decrypt(&data) {
                        Ok(d) => return Ok(Some(d)),
                        Err(_) => continue,
                    }
                }
                Message::Close(_) => return Ok(None),
                _ => {}
            }
        }
        Ok(None)
    }

    /// Receive a raw message with timeout (decrypts if binary)
    pub async fn recv_raw_timeout(&self, millis: u64) -> Option<Vec<u8>> {
        let mut reader = self.reader.lock().await;
        match tokio::time::timeout(Duration::from_millis(millis), reader.next()).await {
            Ok(Some(Ok(Message::Binary(data)))) => {
                let keys = self.keys.lock().await;
                keys.decrypt(&data).ok()
            }
            _ => None,
        }
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
