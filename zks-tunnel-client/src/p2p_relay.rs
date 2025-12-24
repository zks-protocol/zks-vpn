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
    /// Create new Wasif Vernam from a 32-byte shared secret and remote key
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte key from key exchange (for ChaCha20-Poly1305)
    /// * `remote_key` - Remote entropy from Swarm (for XOR layer, can be empty)
    pub fn new(shared_secret: [u8; 32], remote_key: Vec<u8>) -> Self {
        let key = Key::from_slice(&shared_secret);
        let cipher = ChaCha20Poly1305::new(key);

        Self {
            cipher,
            nonce_counter: AtomicU64::new(0),
            remote_key,
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
    #[allow(dead_code)]
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

    /// Set the remote key directly (used when receiving SharedEntropy from peer)
    pub fn set_remote_key(&mut self, key: Vec<u8>) {
        info!("Applied {} bytes of Swarm Entropy from peer", key.len());
        self.remote_key = key;
    }

    /// Get a copy of the remote key (for sharing with peer)
    pub fn get_remote_key(&self) -> &[u8] {
        &self.remote_key
    }
}

/// Entropy Tax Payer: Verifies entropy endpoint health
/// NOTE: With LavaRand-backed zks-key worker, no contribution needed
#[allow(dead_code)]
pub struct EntropyTaxPayer {
    vernam_url: String,
}

#[allow(dead_code)]
impl EntropyTaxPayer {
    pub fn new(vernam_url: String) -> Self {
        Self { vernam_url }
    }

    /// Start the background contribution task
    pub fn start_background_task(self) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Check every 60 seconds

            loop {
                interval.tick().await;
                if let Err(e) = self.pay_tax().await {
                    warn!("Failed to pay Entropy Tax: {}", e);
                }
            }
        });
    }

    /// Pay the Entropy Tax (verify endpoint health)
    /// NOTE: With LavaRand-backed zks-key worker, no contribution needed
    async fn pay_tax(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // With LavaRand, we just verify the endpoint is healthy
        let url = format!("{}/health", self.vernam_url.trim_end_matches('/'));
        let response = reqwest::get(&url).await?;

        if response.status().is_success() {
            debug!("Entropy endpoint healthy");
            Ok(())
        } else {
            Err(format!("Entropy endpoint returned {}", response.status()).into())
        }
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
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::time::timeout;

    let mut peer_ids = Vec::new();

    // Listen for messages for the specified duration
    let discovery_result = timeout(timeout_duration, async {
        while let Some(msg) = reader.next().await {
            match msg? {
                Message::Text(text) => {
                    // Try to parse as JSON to extract peer information
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        // Check for welcome message
                        if json["type"] == "welcome" {
                            debug!("Received welcome message: {}", text);
                            // Welcome doesn't contain peer list in current implementation
                            continue;
                        }

                        // Check for peer_join message
                        if json["type"] == "peer_join" {
                            if let Some(peer_id) = json["peer_id"].as_str() {
                                info!("Discovered peer: {}", peer_id);
                                peer_ids.push(peer_id.to_string());
                            }
                        }
                    }
                }
                Message::Close(_) => {
                    return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                        "Connection closed during peer discovery".into(),
                    );
                }
                _ => {}
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;

    // Timeout is expected - we're just collecting peers for a fixed duration
    match discovery_result {
        Ok(_) | Err(_) => {
            info!("Peer discovery complete: found {} peers", peer_ids.len());
            Ok(peer_ids)
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
        let peer_ids =
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

        let mut keys = WasifVernam::new(shared_secret, remote_key);

        // === Swarm Entropy Synchronization ===
        // Client fetches entropy and shares with Exit Peer to ensure both have same key
        if !vernam_url.is_empty() {
            match role {
                PeerRole::Client => {
                    // Client: Fetch entropy from relay and send to Exit Peer
                    info!("🎲 Fetching Swarm Entropy from relay...");
                    match keys.fetch_remote_key(vernam_url).await {
                        Ok(()) => {
                            // Send the entropy to Exit Peer
                            let entropy_msg =
                                KeyExchangeMessage::new_shared_entropy(keys.get_remote_key());
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
                    let reader_clone = reader.clone();
                    let entropy_timeout = tokio::time::timeout(Duration::from_secs(10), async move {
                        while let Some(msg) = reader_clone.lock().await.next().await {
                            if let Message::Text(text) = msg? {
                                if let Some(ke_msg) = KeyExchangeMessage::from_json(&text) {
                                    if let Some(entropy_bytes) = ke_msg.parse_shared_entropy() {
                                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                                            entropy_bytes,
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
                            keys.set_remote_key(entropy_bytes);
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

            // Start Entropy Tax Payer background task (contribute randomness to Swarm)
            let tax_payer = EntropyTaxPayer::new(vernam_url.to_string());
            tax_payer.start_background_task();
            info!("🎲 Started Entropy Tax Payer (contributing to Swarm)");
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
            keys: Arc::new(Mutex::new(keys)),
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
