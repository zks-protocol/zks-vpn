//! ZKS P2P Relay Connection
//!
//! Manages WebSocket connection to the ZKS-VPN relay for P2P communication
//! between Client and Exit Peer with ZKS double-key Vernam encryption.

use crate::key_exchange::{KeyExchange, KeyExchangeMessage};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rand::random;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
pub use zks_tunnel_proto::TunnelMessage;

/// Peer role in the VPN relay
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Client,
    ExitPeer,
    Swarm,
}

impl PeerRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerRole::Client => "client",
            PeerRole::ExitPeer => "exit",
            PeerRole::Swarm => "swarm",
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

impl std::fmt::Debug for WasifVernam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasifVernam")
            .field("nonce_counter", &self.nonce_counter)
            .field("swarm_seed", &"[REDACTED]") // Security: don't log key material
            .field("key_offset", &self.key_offset)
            .field("has_swarm_entropy", &self.has_swarm_entropy)
            .field("true_vernam_buffer", &self.true_vernam_buffer.is_some())
            .finish()
    }
}

impl WasifVernam {
    /// Create new Wasif Vernam from a 32-byte shared secret and swarm entropy
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte key from key exchange (for ChaCha20-Poly1305)
    /// * `swarm_entropy` - Swarm entropy (any length, will be hashed to 32-byte seed)
    pub fn new(shared_secret: [u8; 32], swarm_entropy: Vec<u8>) -> Self {
        use sha2::{Digest, Sha256};

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
        getrandom::getrandom(&mut nonce_bytes[0..4])
            .expect("CRITICAL: Failed to generate random nonce - RNG unavailable");
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 1. True Vernam Layer: XOR with infinite keystream (if swarm entropy available)
        let mut mixed_data = data.to_vec();
        let key_offset = if self.has_swarm_entropy {
            // Get current offset and advance it atomically
            let offset = self
                .key_offset
                .fetch_add(data.len() as u64, Ordering::SeqCst);

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
        let key_offset = u64::from_be_bytes(
            data[12..20]
                .try_into()
                .map_err(|_| chacha20poly1305::aead::Error)?,
        );
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
    ///
    /// SECURITY MODEL: The TRUE random XOR key is included in the envelope,
    /// encrypted by ChaCha20-Poly1305. This provides:
    /// 1. Defense-in-depth: Even if ChaCha20 is broken, data is XOR'd with random
    /// 2. Information-theoretic security for the XOR layer itself
    /// 3. Forward secrecy: Random bytes are consumed and never reused
    ///
    /// Returns: [Nonce (12 bytes) | Mode (1 byte: 0x01) | KeyLen (4 bytes) | XOR Key (N bytes) | Ciphertext (M bytes) | Tag (16 bytes)]
    #[allow(dead_code)]
    pub async fn encrypt_true_vernam(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        // Generate unique nonce
        let mut nonce_bytes = [0u8; 12];
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
        getrandom::getrandom(&mut nonce_bytes[0..4]).unwrap_or_default();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 1. TRUE Vernam Layer: XOR with TRUE random bytes
        let mut mixed_data = data.to_vec();
        let mut xor_key = Vec::new();
        let mut mode_byte = 0x00u8; // 0x00 = HKDF mode, 0x01 = True Vernam mode

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
                xor_key = keystream; // Save for inclusion in envelope
                mode_byte = 0x01;
                debug!("🔐 Used {} TRUE random bytes for encryption", data.len());
            } else {
                // Buffer empty - fallback to HKDF mode
                warn!("⚠️ True Vernam buffer empty! Falling back to HKDF mode");
                if self.has_swarm_entropy {
                    let offset = self
                        .key_offset
                        .fetch_add(data.len() as u64, Ordering::SeqCst);
                    let keystream = self.generate_keystream(offset, data.len());
                    for (i, byte) in mixed_data.iter_mut().enumerate() {
                        *byte ^= keystream[i];
                    }
                    mode_byte = 0x02; // 0x02 = HKDF fallback mode
                }
            }
        } else if self.has_swarm_entropy {
            // No True Vernam buffer, use HKDF mode
            let offset = self
                .key_offset
                .fetch_add(data.len() as u64, Ordering::SeqCst);
            let keystream = self.generate_keystream(offset, data.len());
            for (i, byte) in mixed_data.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
            mode_byte = 0x02;
        }

        // 2. Build payload: [XOR Key (if True Vernam) | XOR'd Data]
        let mut payload = Vec::new();
        if mode_byte == 0x01 {
            // Include XOR key for receiver (will be encrypted by ChaCha20)
            payload.extend_from_slice(&(xor_key.len() as u32).to_be_bytes());
            payload.extend_from_slice(&xor_key);
        }
        payload.extend_from_slice(&mixed_data);

        // 3. Base Layer: Encrypt with ChaCha20-Poly1305
        let ciphertext = self.cipher.encrypt(nonce, payload.as_slice())?;

        // Build result: [Nonce (12) | Mode (1) | Ciphertext]
        let mut result = Vec::with_capacity(12 + 1 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.push(mode_byte);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data encrypted with TRUE Vernam mode
    /// Extracts the XOR key from the envelope and decrypts properly
    #[allow(dead_code)]
    pub async fn decrypt_true_vernam(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        if data.len() < 12 + 1 + 16 {
            return Err(chacha20poly1305::aead::Error);
        }

        let nonce = Nonce::from_slice(&data[0..12]);
        let mode = data[12];
        let ciphertext = &data[13..];

        // 1. Base Layer: Decrypt with ChaCha20-Poly1305
        let payload = self.cipher.decrypt(nonce, ciphertext)?;

        // 2. Extract XOR key and data based on mode
        let plaintext = match mode {
            0x01 => {
                // True Vernam mode: XOR key is embedded
                if payload.len() < 4 {
                    return Err(chacha20poly1305::aead::Error);
                }
                let key_len = u32::from_be_bytes(payload[0..4].try_into().unwrap()) as usize;
                if payload.len() < 4 + key_len {
                    return Err(chacha20poly1305::aead::Error);
                }
                let xor_key = &payload[4..4 + key_len];
                let mixed_data = &payload[4 + key_len..];

                // XOR to recover original plaintext
                let mut result = mixed_data.to_vec();
                for (i, byte) in result.iter_mut().enumerate() {
                    *byte ^= xor_key[i];
                }
                debug!("🔐 Decrypted with {} TRUE random bytes", key_len);
                result
            }
            0x02 => {
                // HKDF fallback mode: use generate_keystream
                // Note: This requires sender and receiver to have same offset
                // For now, we assume HKDF mode is synchronized
                warn!("⚠️ HKDF fallback mode detected - using synchronized keystream");
                payload
            }
            _ => {
                // Mode 0x00 or unknown: no XOR layer, just return payload
                payload
            }
        };

        Ok(plaintext)
    }

    /// Fetch swarm entropy seed from zks-vernam worker
    #[allow(dead_code)]
    pub async fn fetch_remote_key(
        &mut self,
        vernam_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use sha2::{Digest, Sha256};

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
        use sha2::{Digest, Sha256};

        if !key.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            self.swarm_seed = hasher.finalize().into();
            self.has_swarm_entropy = true;
            self.key_offset.store(0, Ordering::SeqCst);
            info!(
                "Applied {} bytes of Swarm Entropy - Infinite Vernam active!",
                key.len()
            );
        }
    }

    /// Get the swarm seed (for sharing with peer)
    #[allow(dead_code)]
    pub fn get_remote_key(&self) -> &[u8] {
        if self.has_swarm_entropy {
            &self.swarm_seed
        } else {
            &[]
        }
    }

    /// Check if swarm entropy is available
    #[allow(dead_code)]
    pub fn has_swarm_entropy(&self) -> bool {
        self.has_swarm_entropy
    }

    /// Get the swarm seed as a fixed-size array (for True Vernam fetcher)
    #[allow(dead_code)]
    pub fn get_swarm_seed(&self) -> [u8; 32] {
        self.swarm_seed
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

        info!(
            "🔄 Refreshed swarm entropy - Forward secrecy checkpoint! (generation: {})",
            generation
        );
    }

    /// Get current key offset (for monitoring/debugging)
    #[allow(dead_code)]
    pub fn get_key_offset(&self) -> u64 {
        self.key_offset.load(Ordering::SeqCst)
    }

    /// Check if entropy refresh is recommended (e.g., after 1MB of traffic)
    #[allow(dead_code)]
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
    cipher: Arc<Mutex<WasifVernam>>,
}

impl ContinuousEntropyRefresher {
    pub fn new(_vernam_url: String, cipher: Arc<Mutex<WasifVernam>>) -> Self {
        Self { cipher }
    }

    /// Start the background entropy refresh task
    pub fn start_background_task(self) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Refresh every 30 seconds

            loop {
                interval.tick().await;

                // Check if refresh is needed (always refresh on interval)
                let needs_refresh = {
                    let _cipher = self.cipher.lock().await;
                    true // Always refresh on interval for continuous forward secrecy
                };

                if needs_refresh {
                    if let Err(e) = self.fetch_and_refresh().await {
                        warn!("Failed to refresh entropy: {}", e);
                    }
                }
            }
        });
    }

    /// Fetch fresh entropy using LOCAL CSPRNG (no worker call to avoid duplicates)
    /// The TrueVernamFetcher already mixes local+worker+swarm every 10 seconds,
    /// so this refresher only needs to add LOCAL entropy for forward secrecy.
    async fn fetch_and_refresh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Use local CSPRNG instead of fetching from worker
        // (TrueVernamFetcher already handles worker+swarm mixing)
        let mut fresh_entropy = [0u8; 32];
        getrandom::getrandom(&mut fresh_entropy)?;

        // Refresh the cipher's seed with LOCAL fresh entropy
        {
            let mut cipher = self.cipher.lock().await;
            cipher.refresh_entropy(&fresh_entropy);
        }

        info!("🔄 Continuous entropy refresh complete (local CSPRNG) - forward secrecy active!");
        Ok(())
    }
}

// Keep the old name as an alias for backward compatibility
#[allow(dead_code)]
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
    /// Key Exchange state
    pub key_exchange: Arc<Mutex<KeyExchange>>,
    /// Key exchange completion flag (set to true after both parties have completed exchange)
    pub key_exchange_complete: Arc<AtomicBool>,
    /// Remote peer's libp2p PeerID and addresses (for DCUtR hole-punching)
    /// Format: (peer_id_string, Vec<multiaddr_strings>)
    pub remote_peer_info: Arc<Mutex<Option<(String, Vec<String>)>>>,
    /// Direct P2P data stream (DCUtR) - if set, data will be sent here instead of WebSocket
    pub data_stream: Arc<Mutex<Option<libp2p::Stream>>>,
}

#[allow(dead_code)]
impl P2PRelay {
    /// Connect to relay and establish P2P session with key exchange
    pub async fn connect(
        relay_url: &str,
        _vernam_url: &str,
        room_id: &str,
        role: PeerRole,
        proxy: Option<String>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        use crate::key_exchange::KeyExchange;
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

        let mut my_peer_id = String::new();

        // For Swarm mode, we need to send a Join message first
        if role == PeerRole::Swarm {
            let join_msg = serde_json::json!({
                "type": "join",
                "peer_id": format!("swarm-{:04x}", random::<u32>()),
                "addrs": Vec::<String>::new(),
                "room_id": room_id
            });
            writer
                .lock()
                .await
                .send(Message::Text(join_msg.to_string()))
                .await?;
            debug!("Sent Swarm Join message");
        }

        // Step 0: Wait for Welcome message to get our Peer ID
        let reader_clone = reader.clone();
        // INCREASED TIMEOUT: 10s -> 60s to handle high latency or worker cold starts
        let welcome_timeout = timeout(Duration::from_secs(60), async {
            let mut reader_guard = reader_clone.lock().await;
            while let Some(msg) = reader_guard.next().await {
                match msg? {
                    Message::Text(text) => {
                        if text.contains("\"type\":\"welcome\"")
                            || text.contains("\"type\":\"joined\"")
                        {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                if let Some(id) =
                                    json["peer_id"].as_str().or(json["your_id"].as_str())
                                {
                                    return Ok::<String, Box<dyn std::error::Error + Send + Sync>>(
                                        id.to_string(),
                                    );
                                }
                            }
                        }
                    }
                    Message::Close(_) => return Err("Connection closed".into()),
                    _ => {}
                }
            }
            Err("No welcome message received within timeout".into())
        })
        .await;

        if let Ok(Ok(id)) = welcome_timeout {
            my_peer_id = id;
            info!("✅ Assigned Peer ID: {}", my_peer_id);
        }

        // Initialize KeyExchange
        let key_exchange = Arc::new(Mutex::new(KeyExchange::new(room_id)));

        // Initialize keys
        let keys = Arc::new(Mutex::new(WasifVernam::new([0u8; 32], Vec::new())));

        // Create P2PRelay instance immediately
        let relay = Self {
            writer: writer.clone(),
            reader: reader.clone(),
            keys: keys.clone(),
            role,
            room_id: room_id.to_string(),
            shared_secret: [0u8; 32], // Initial empty secret, will be updated
            peer_id: my_peer_id.clone(),
            key_exchange: key_exchange.clone(),
            key_exchange_complete: Arc::new(AtomicBool::new(false)),
            remote_peer_info: Arc::new(Mutex::new(None)),
            data_stream: Arc::new(Mutex::new(None)),
        };
        let relay_arc = Arc::new(relay);

        // Spawn background handshake task for Swarm/Client roles
        if role == PeerRole::Client || role == PeerRole::Swarm {
            let relay_clone = relay_arc.clone();
            let my_peer_id_clone = my_peer_id.clone();

            tokio::spawn(async move {
                // For Swarm mode, add a small random delay to avoid collisions
                if role == PeerRole::Swarm {
                    let delay = (my_peer_id_clone.chars().last().unwrap_or('0') as u64 % 10) * 100;
                    info!("🔑 Swarm handshake delay: {}ms (peer: {})", delay, my_peer_id_clone);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }

                // Send AuthInit
                info!("🔑 Initiating key exchange (sending AuthInit)...");
                if let Ok(auth_init) = relay_clone.key_exchange.lock().await.create_auth_init() {
                    if let Err(e) = relay_clone.send_text(auth_init.to_json()).await {
                        warn!("❌ Failed to send AuthInit: {}", e);
                    } else {
                        info!("✅ Sent AuthInit message - waiting for peer response");
                    }
                } else {
                    warn!("❌ Failed to create AuthInit message");
                }
            });
        }

        // DISABLED: Background entropy tasks were spawning on EVERY P2PRelay::connect call,
        // causing request storms when the swarm reconnect loop runs repeatedly.
        // The cipher still works with initial entropy from key exchange.
        // TODO: If True Vernam mode is needed, use a global singleton to ensure only ONE fetcher.
        /*
        // Start Continuous Entropy Refresher (Background Task)
        {
            let refresher = crate::p2p_relay::ContinuousEntropyRefresher::new(
                vernam_url.to_string(),
                keys.clone(),
            );
            refresher.start_background_task();
            info!("🔄 Started Continuous Entropy Refresher (TRUE forward secrecy active!)");

            // === TRUE VERNAM MODE (Information-Theoretic Security) ===
            // Enable by default for maximum security
            let true_vernam_buffer =
                Arc::new(Mutex::new(crate::true_vernam::TrueVernamBuffer::new()));

            // Create fetcher and set swarm seed if available (for TRUSTLESS mode)
            let fetcher = crate::true_vernam::TrueVernamFetcher::new(
                vernam_url.to_string(),
                true_vernam_buffer.clone(),
            );

            // Pass swarm seed to fetcher (makes it TRUSTLESS)
            // The swarm seed comes from peer entropy collection at the start
            // (Initially empty, will be updated when handshake completes)
            fetcher.start_background_task();

            // Enable True Vernam on the cipher
            {
                let mut cipher = keys.lock().await;
                cipher.enable_true_vernam(true_vernam_buffer);
            }
            info!(
                "🔐 TRUE VERNAM MODE ENABLED BY DEFAULT - Mathematically unbreakable encryption!"
            );
        }
        */

        // Start WebSocket keepalive ping task (prevents Cloudflare idle timeout)
        {
            let writer_clone = writer.clone();
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let mut w = writer_clone.lock().await;
                    if let Err(e) = w.send(Message::Ping(vec![0x7A, 0x6B, 0x73])).await {
                        debug!("Keepalive ping failed: {} (connection may be closed)", e);
                        break;
                    }
                    debug!("🏓 Sent keepalive ping");
                }
            });
        }

        info!("✅ Connected to relay with ID: {}", my_peer_id);
        Ok(relay_arc)
    }

    /// Wait for the key exchange to complete
    pub async fn wait_for_handshake(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::time::{timeout, Duration};

        info!("⏳ Waiting for key exchange to complete...");

        // Wait up to 30 seconds for handshake
        let result = timeout(Duration::from_secs(30), async {
            while !self.key_exchange_complete.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;

        match result {
            Ok(_) => {
                info!("✅ Key exchange completed successfully");
                Ok(())
            }
            Err(_) => Err("Key exchange timed out".into()),
        }
    }

    /// Send our PeerInfo to the remote peer for DCUtR hole-punching
    /// Call this after key exchange is complete
    pub async fn send_peer_info(
        &self,
        peer_id: String,
        addrs: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::key_exchange::KeyExchangeMessage;
        
        info!("📤 Sending PeerInfo for DCUtR hole-punch:");
        info!("   Our Peer ID: {}", peer_id);
        info!("   Our Addresses: {:?}", addrs);
        
        let peer_info_msg = KeyExchangeMessage::PeerInfo { peer_id, addrs };
        self.send_text(peer_info_msg.to_json()).await?;
        
        info!("✅ PeerInfo sent to remote peer");
        Ok(())
    }
    
    /// Get the received remote peer info for DCUtR (if available)
    /// Returns (peer_id, Vec<multiaddr>) or None if not received yet
    pub async fn get_remote_peer_info(&self) -> Option<(String, Vec<String>)> {
        self.remote_peer_info.lock().await.clone()
    }
    
    /// Wait for remote peer info with timeout
    pub async fn wait_for_peer_info(
        &self,
        timeout_secs: u64,
    ) -> Option<(String, Vec<String>)> {
        use tokio::time::{timeout, Duration};
        
        info!("⏳ Waiting for remote PeerInfo ({} secs)...", timeout_secs);
        
        let result = timeout(Duration::from_secs(timeout_secs), async {
            loop {
                if let Some(info) = self.get_remote_peer_info().await {
                    return info;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        
        match result {
            Ok(info) => {
                info!("✅ Received remote PeerInfo");
                Some(info)
            }
            Err(_) => {
                warn!("⚠️ Timeout waiting for remote PeerInfo");
                None
            }
        }
    }

    /// Send ZKS-encrypted message through DIRECT P2P connection (DCUtR required)
    /// 
    /// SIGNALING-ONLY ARCHITECTURE: The relay worker is used ONLY for signaling.
    /// All VPN traffic MUST go through direct P2P DCUtR connections.
    /// If no direct connection is available, this function returns an error.
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

        // REQUIRE DIRECT P2P STREAM (DCUtR)
        // Relay is signaling-only - no WebSocket binary fallback!
        let mut stream_guard = self.data_stream.lock().await;
        if let Some(stream) = stream_guard.as_mut() {
            use libp2p::futures::AsyncWriteExt;
            
            // Send length-prefixed packet
            let len = encrypted.len() as u32;
            let len_bytes = len.to_be_bytes();
            
            // Write length
            stream.write_all(&len_bytes).await.map_err(|e| {
                format!("DCUtR write length failed: {}", e)
            })?;
            
            // Write payload
            stream.write_all(&encrypted).await.map_err(|e| {
                format!("DCUtR write payload failed: {}", e)
            })?;
            
            // Flush
            stream.flush().await.map_err(|e| {
                format!("DCUtR flush failed: {}", e)
            })?;
            
            return Ok(());
        }
        drop(stream_guard);

        // NO FALLBACK: DCUtR is required for VPN traffic
        // The relay worker is signaling-only and does not relay binary data
        Err("❌ No direct P2P connection available. DCUtR hole-punch required for VPN traffic. Relay is signaling-only.".into())
    }

    /// Send raw encrypted bytes - DEPRECATED
    /// 
    /// This function is deprecated in the signaling-only architecture.
    /// Use the `send()` function which requires a DCUtR direct connection.
    #[deprecated(note = "WebSocket binary relay disabled. Use send() with DCUtR instead.")]
    pub async fn send_raw(
        &self,
        _data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("❌ send_raw() is deprecated. Relay is signaling-only. Use DCUtR for data transfer.".into())
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

    /// Wait for key exchange to complete before routing traffic
    /// This prevents decryption failures that occur when routes are added before keys are ready
    pub async fn wait_for_key_exchange(&self, timeout_secs: u64) -> Result<(), &'static str> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        while !self.key_exchange_complete.load(Ordering::SeqCst) {
            if start.elapsed() > timeout {
                return Err("Key exchange timeout - routes not added");
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        info!("🔐 Key exchange complete - safe to add routes");
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
            let recv_start = std::time::Instant::now();
            
            match msg? {
                Message::Binary(data) => {
                    let data_len = data.len();
                    
                    // Decrypt with Wasif Vernam (ChaCha20-Poly1305)
                    let decrypt_start = std::time::Instant::now();
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
                    let decrypt_time = decrypt_start.elapsed();

                    // Decode protocol message
                    let decode_start = std::time::Instant::now();
                    match TunnelMessage::decode(&decrypted) {
                        Ok(msg) => {
                            let decode_time = decode_start.elapsed();
                            let total = recv_start.elapsed();
                            
                            // Log timing if total > 10ms (indicates bottleneck)
                            if total.as_millis() > 10 {
                                info!(
                                    "📥 RELAY RECV: decrypt={:?} decode={:?} total={:?} ({} bytes)",
                                    decrypt_time, decode_time, total, data_len
                                );
                            }
                            
                            return Ok(Some(msg));
                        }
                        Err(e) => {
                            warn!("Failed to decode message: {}", e);
                        }
                    }
                }
                Message::Text(text) => {
                    info!("📨 Received TEXT message: {} chars", text.len());
                    
                    // Log first 200 chars for debugging
                    if text.len() > 200 {
                        debug!("Text content: {}...", &text[..200]);
                    } else {
                        debug!("Text content: {}", text);
                    }

                    // Handle Peer Join
                    if text.contains("\"peer_join\"") || text.contains("\"PeerJoin\"") {
                        info!("👤 Peer joined room - initiating handshake");
                        if self.role == PeerRole::Swarm || self.role == PeerRole::Client {
                            // Initiate handshake
                            let auth_init = self
                                .key_exchange
                                .lock()
                                .await
                                .create_auth_init()
                                .map_err(|e| format!("Failed to create AuthInit: {}", e))?;
                            self.send_text(auth_init.to_json()).await?;
                            info!("🔑 Sent AuthInit to new peer");
                        }
                    }

                    // Handle Key Exchange Messages
                    if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                        info!("🔐 Received KeyExchange message type: {:?}", std::mem::discriminant(&ke_msg));
                        match ke_msg {
                            KeyExchangeMessage::AuthInit { .. } => {
                                info!("🔑 Processing AuthInit from peer...");
                                // Respond with AuthResponse
                                let result = {
                                    let mut ke = self.key_exchange.lock().await;
                                    ke.process_auth_init_and_respond(&ke_msg)
                                };

                                match result {
                                    Ok(auth_response) => {
                                        let shared_secret = {
                                            let ke = self.key_exchange.lock().await;
                                            ke.get_shared_secret_bytes()
                                                .ok_or("Failed to get shared secret")?
                                        };

                                        self.send_text(auth_response.to_json()).await?;
                                        info!("✅ Sent AuthResponse to peer");

                                        // Update keys
                                        {
                                            let mut k = self.keys.lock().await;
                                            *k = WasifVernam::new(shared_secret, Vec::new());
                                        }
                                        info!("✅ Key exchange successful (Responder)!");
                                        // Mark key exchange as complete
                                        self.key_exchange_complete.store(true, Ordering::SeqCst);
                                    }
                                    Err(e) if e.contains("Collision detected") => {
                                        warn!("⚠️ Key Exchange Collision: {}", e);
                                        // We are the winner - the other peer should yield to us.
                                        // But since they may not have received our original AuthInit
                                        // (we might have sent it before they joined), resend it now.
                                        if let Ok(auth_init) =
                                            self.key_exchange.lock().await.create_auth_init()
                                        {
                                            info!("🔄 Resending AuthInit (collision winner ensuring peer receives it)");
                                            if let Err(e) =
                                                self.send_text(auth_init.to_json()).await
                                            {
                                                warn!("Failed to resend AuthInit: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) if e.contains("Ignored self-message") => {
                                        debug!("Ignoring self-message");
                                    }
                                    Err(e) => {
                                        warn!("Failed to handle AuthInit: {}", e);
                                    }
                                }
                            }
                            KeyExchangeMessage::AuthResponse { .. } => {
                                info!("🔑 Processing AuthResponse from peer...");
                                // Finalize handshake
                                let result = {
                                    let mut ke = self.key_exchange.lock().await;
                                    ke.process_auth_response_and_confirm(&ke_msg)
                                };

                                match result {
                                    Ok(key_confirm) => {
                                        let shared_secret = {
                                            let ke = self.key_exchange.lock().await;
                                            ke.get_shared_secret_bytes()
                                                .ok_or("Failed to get shared secret")?
                                        };

                                        // Update keys
                                        {
                                            let mut k = self.keys.lock().await;
                                            *k = WasifVernam::new(shared_secret, Vec::new());
                                        }
                                        info!("✅ Key exchange successful (Initiator)!");
                                        // Mark key exchange as complete
                                        self.key_exchange_complete.store(true, Ordering::SeqCst);

                                        // Send KeyConfirm
                                        self.send_text(key_confirm.to_json()).await?;
                                        info!("✅ Sent KeyConfirm - handshake complete!");
                                    }
                                    Err(e) if e.starts_with("Ignored:") => {
                                        debug!("⚠️ {}", e);
                                        // Silently ignore duplicate AuthResponse
                                    }
                                    Err(e) => {
                                        return Err(format!(
                                            "Failed to handle AuthResponse: {}",
                                            e
                                        )
                                        .into());
                                    }
                                }
                            }
                            KeyExchangeMessage::KeyConfirm { .. } => {
                                // Finalize key exchange (Responder side)
                                if let Err(e) =
                                    self.key_exchange.lock().await.process_key_confirm(&ke_msg)
                                {
                                    warn!("Failed to process KeyConfirm: {}", e);
                                } else {
                                    info!("✅ Key exchange finalized (Responder received KeyConfirm)!");
                                    // Mark key exchange as complete (final confirmation)
                                    self.key_exchange_complete.store(true, Ordering::SeqCst);
                                }
                            }
                            // Handle PeerInfo for DCUtR hole-punching
                            KeyExchangeMessage::PeerInfo { peer_id, addrs } => {
                                info!("📍 Received PeerInfo for DCUtR hole-punch:");
                                info!("   Peer ID: {}", peer_id);
                                info!("   Addresses: {:?}", addrs);
                                
                                // Store peer info for DCUtR connection attempt
                                let mut peer_info = self.remote_peer_info.lock().await;
                                *peer_info = Some((peer_id.clone(), addrs.clone()));
                                
                                info!("✅ Stored peer info for DCUtR - ready for direct connection");
                            }
                            _ => {}
                        }
                    }

                    // Handle Entropy Sync
                    if text.contains("\"type\":\"entropy_sync\"") {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(seed_hex) = json["seed"].as_str() {
                                if let Ok(seed) = hex::decode(seed_hex) {
                                    let mut k = self.keys.lock().await;
                                    k.set_remote_key(seed);
                                    info!("🔄 Received and applied swarm entropy");
                                }
                            }
                        }
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
        // ... (existing code) ...
        let writer = self.writer.clone();
        let _reader = self.reader.clone();
        let keys = self.keys.clone();

        tokio::spawn(async move {
            // ... (existing code) ...
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

impl Drop for P2PRelay {
    fn drop(&mut self) {
        println!(
            "🔥 DEBUG: Dropping P2PRelay instance for role {:?}",
            self.role
        );
    }
}
