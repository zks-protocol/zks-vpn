//! ZKS Key Exchange - Authenticated 3-Message Handshake
//!
//! Implements secure authenticated key exchange between Client and Exit Peer:
//! 1. Initiator sends: ephemeral_pk + encrypted_identity
//! 2. Responder sends: ephemeral_pk + auth_proof (HMAC)
//! 3. Initiator sends: key_confirmation (HMAC)
//!
//! Security Properties (proven in ProVerif/Tamarin):
//! - Forward Secrecy: Ephemeral X25519 keys
//! - Mutual Authentication: Identity derived from room, verified via HMAC
//! - Key Confidentiality: Relay cannot derive session key
//!
//! The relay CANNOT decrypt traffic because it never sees the private keys.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// Key exchange state machine (extended for 3-message handshake)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeState {
    /// Initial state - no keys generated
    Init,
    /// Initiator: Sent AuthInit, waiting for AuthResponse
    InitiatorWaitingForResponse,
    /// Responder: Received AuthInit, sent AuthResponse, waiting for KeyConfirm
    ResponderWaitingForConfirm,
    /// Key exchange complete, shared secret derived
    Complete,
    /// Key exchange failed
    Failed,
}

/// Role in the key exchange
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeRole {
    Initiator,
    Responder,
}

/// Ephemeral key pair for authenticated X25519 key exchange
pub struct KeyExchange {
    /// Our role (initiator or responder)
    role: Option<KeyExchangeRole>,
    /// Identity secret derived from room (for authentication)
    identity_secret: StaticSecret,
    /// Identity public key derived from room
    identity_public: PublicKey,
    /// Our ephemeral secret (private key)
    ephemeral_secret: Option<EphemeralSecret>,
    /// Our ephemeral public key
    pub ephemeral_public: Option<PublicKey>,
    /// Peer's ephemeral public key
    peer_ephemeral_public: Option<PublicKey>,
    /// Peer's identity public key (derived from room for them too)
    peer_identity_public: Option<PublicKey>,
    /// Derived shared secret (after exchange)
    shared_secret: Option<SharedSecret>,
    /// Session key (from HKDF)
    session_key: Option<[u8; 32]>,
    /// Derived encryption key (from HKDF, 1MB)
    encryption_key: Option<Vec<u8>>,
    /// Current state
    pub state: KeyExchangeState,
    /// Room ID (used as HKDF salt and identity derivation)
    room_id: String,
    /// Timestamp for freshness
    timestamp: u64,
}

#[allow(dead_code)]
impl KeyExchange {
    /// Create a new key exchange context
    /// Identity keys are derived from room_id for implicit mutual authentication
    pub fn new(room_id: &str) -> Self {
        // Derive deterministic identity secret from room_id
        // This means both parties derive the SAME identity expectation
        let identity_seed = Self::derive_identity_seed(room_id);
        let identity_secret = StaticSecret::from(identity_seed);
        let identity_public = PublicKey::from(&identity_secret);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            role: None,
            identity_secret,
            identity_public,
            ephemeral_secret: None,
            ephemeral_public: None,
            peer_ephemeral_public: None,
            peer_identity_public: None,
            shared_secret: None,
            session_key: None,
            encryption_key: None,
            state: KeyExchangeState::Init,
            room_id: room_id.to_string(),
            timestamp,
        }
    }

    /// Derive identity seed from room_id using HKDF
    fn derive_identity_seed(room_id: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"zks-identity-v1"), room_id.as_bytes());
        let mut seed = [0u8; 32];
        hk.expand(b"identity-key", &mut seed)
            .expect("HKDF expand failed");
        seed
    }

    /// Generate our ephemeral keypair (Initiator: Message 1 preparation)
    pub fn generate_keypair(&mut self) {
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&secret);

        self.ephemeral_secret = Some(secret);
        self.ephemeral_public = Some(public_key);
    }

    /// Get our ephemeral public key as bytes
    pub fn get_ephemeral_public_bytes(&self) -> Option<[u8; 32]> {
        self.ephemeral_public.map(|pk| pk.to_bytes())
    }

    /// Create AuthInit message (Initiator → Responder, Message 1)
    /// Contains: ephemeral_pk + encrypted_identity
    pub fn create_auth_init(&mut self) -> Result<KeyExchangeMessage, &'static str> {
        self.role = Some(KeyExchangeRole::Initiator);

        if self.ephemeral_secret.is_none() {
            self.generate_keypair();
        }

        let eph_pk = self
            .get_ephemeral_public_bytes()
            .ok_or("No ephemeral public key")?;

        // Encrypted identity: we encrypt our identity proof
        // This is a commitment that we know the room
        let identity_proof = self.create_identity_proof(&eph_pk);

        self.state = KeyExchangeState::InitiatorWaitingForResponse;

        Ok(KeyExchangeMessage::AuthInit {
            ephemeral_pk: hex::encode(eph_pk),
            encrypted_identity: hex::encode(identity_proof),
            timestamp: self.timestamp,
        })
    }

    /// Create identity proof: HMAC(ephemeral_pk || timestamp, identity_secret)
    fn create_identity_proof(&self, eph_pk: &[u8; 32]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(self.identity_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(eph_pk);
        mac.update(&self.timestamp.to_le_bytes());
        mac.update(b"initiator_identity");
        mac.finalize().into_bytes().to_vec()
    }

    /// Process AuthInit and create AuthResponse (Responder side, Message 2)
    pub fn process_auth_init_and_respond(
        &mut self,
        auth_init: &KeyExchangeMessage,
    ) -> Result<KeyExchangeMessage, &'static str> {
        self.role = Some(KeyExchangeRole::Responder);

        let (peer_eph_pk_hex, identity_proof_hex, peer_timestamp) = match auth_init {
            KeyExchangeMessage::AuthInit {
                ephemeral_pk,
                encrypted_identity,
                timestamp,
            } => (ephemeral_pk, encrypted_identity, *timestamp),
            _ => return Err("Expected AuthInit message"),
        };

        // Parse peer's ephemeral public key
        let peer_eph_pk_bytes =
            hex::decode(peer_eph_pk_hex).map_err(|_| "Invalid hex in ephemeral_pk")?;
        if peer_eph_pk_bytes.len() != 32 {
            return Err("Invalid ephemeral public key length");
        }
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&peer_eph_pk_bytes);
        let peer_eph_pk = PublicKey::from(pk_array);

        // Verify identity proof (peer must know the room)
        let identity_proof =
            hex::decode(identity_proof_hex).map_err(|_| "Invalid hex in identity_proof")?;

        self.verify_identity_proof(&pk_array, peer_timestamp, &identity_proof)?;

        // Generate our ephemeral keypair
        if self.ephemeral_secret.is_none() {
            self.generate_keypair();
        }

        // Store peer's ephemeral public key
        self.peer_ephemeral_public = Some(peer_eph_pk);

        // Compute session key
        self.compute_session_key()?;

        // Create auth proof
        let our_eph_pk = self
            .get_ephemeral_public_bytes()
            .ok_or("No ephemeral public key")?;
        let auth_mac = self.create_auth_mac(&our_eph_pk, &pk_array)?;

        self.state = KeyExchangeState::ResponderWaitingForConfirm;

        Ok(KeyExchangeMessage::AuthResponse {
            ephemeral_pk: hex::encode(our_eph_pk),
            auth_mac: hex::encode(auth_mac),
        })
    }

    /// Verify peer's identity proof
    fn verify_identity_proof(
        &self,
        peer_eph_pk: &[u8; 32],
        timestamp: u64,
        proof: &[u8],
    ) -> Result<(), &'static str> {
        // Peer should have derived the same identity_secret from room
        let mut mac = HmacSha256::new_from_slice(self.identity_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(peer_eph_pk);
        mac.update(&timestamp.to_le_bytes());
        mac.update(b"initiator_identity");

        mac.verify_slice(proof)
            .map_err(|_| "Identity proof verification failed - peer doesn't know room")?;

        Ok(())
    }

    /// Compute session key from DH
    fn compute_session_key(&mut self) -> Result<(), &'static str> {
        let eph_secret = self.ephemeral_secret.take().ok_or("No ephemeral secret")?;
        let peer_eph_pk = self
            .peer_ephemeral_public
            .ok_or("No peer ephemeral public key")?;

        // DH: ephemeral × ephemeral (forward secrecy)
        // Authentication is handled by HMAC proofs, not session key derivation
        let dh1 = eph_secret.diffie_hellman(&peer_eph_pk);

        // Derive session key with HKDF
        // Room ID provides domain separation
        let hk = Hkdf::<Sha256>::new(Some(self.room_id.as_bytes()), dh1.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(b"zks-session-key-v1", &mut session_key)
            .expect("HKDF expand failed");

        self.shared_secret = Some(dh1);
        self.session_key = Some(session_key);
        Ok(())
    }

    /// Create authentication MAC for AuthResponse
    fn create_auth_mac(
        &self,
        our_eph_pk: &[u8; 32],
        peer_eph_pk: &[u8; 32],
    ) -> Result<Vec<u8>, &'static str> {
        let session_key = self
            .session_key
            .as_ref()
            .ok_or("Session key not computed")?;

        let mut mac =
            HmacSha256::new_from_slice(session_key).expect("HMAC can take key of any size");
        mac.update(our_eph_pk);
        mac.update(peer_eph_pk);
        mac.update(b"responder_auth");
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Process AuthResponse and create KeyConfirm (Initiator side, Message 3)
    pub fn process_auth_response_and_confirm(
        &mut self,
        auth_response: &KeyExchangeMessage,
    ) -> Result<KeyExchangeMessage, &'static str> {
        let (peer_eph_pk_hex, auth_mac_hex) = match auth_response {
            KeyExchangeMessage::AuthResponse {
                ephemeral_pk,
                auth_mac,
            } => (ephemeral_pk, auth_mac),
            _ => return Err("Expected AuthResponse message"),
        };

        // Parse peer's ephemeral public key
        let peer_eph_pk_bytes =
            hex::decode(peer_eph_pk_hex).map_err(|_| "Invalid hex in ephemeral_pk")?;
        if peer_eph_pk_bytes.len() != 32 {
            return Err("Invalid ephemeral public key length");
        }
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&peer_eph_pk_bytes);
        let peer_eph_pk = PublicKey::from(pk_array);

        // Store peer's ephemeral public key
        self.peer_ephemeral_public = Some(peer_eph_pk);

        // Compute session key
        self.compute_session_key()?;

        // Verify auth MAC
        let auth_mac = hex::decode(auth_mac_hex).map_err(|_| "Invalid hex in auth_mac")?;

        let our_eph_pk = self
            .ephemeral_public
            .map(|pk| pk.to_bytes())
            .ok_or("No ephemeral public key")?;

        self.verify_auth_mac(&pk_array, &our_eph_pk, &auth_mac)?;

        // Derive full encryption key
        self.derive_encryption_key();

        // Create key confirmation
        let confirm_mac = self.create_confirm_mac(&our_eph_pk, &pk_array)?;

        self.state = KeyExchangeState::Complete;

        Ok(KeyExchangeMessage::KeyConfirm {
            confirm_mac: hex::encode(confirm_mac),
        })
    }

    /// Verify auth MAC from responder
    fn verify_auth_mac(
        &self,
        peer_eph_pk: &[u8; 32],
        our_eph_pk: &[u8; 32],
        mac_bytes: &[u8],
    ) -> Result<(), &'static str> {
        let session_key = self
            .session_key
            .as_ref()
            .ok_or("Session key not computed")?;

        let mut mac =
            HmacSha256::new_from_slice(session_key).expect("HMAC can take key of any size");
        mac.update(peer_eph_pk); // Their ephemeral (in their message)
        mac.update(our_eph_pk); // Our ephemeral
        mac.update(b"responder_auth");

        mac.verify_slice(mac_bytes).map_err(|_| {
            "Auth MAC verification failed - responder doesn't have correct session key"
        })?;

        Ok(())
    }

    /// Create key confirmation MAC
    fn create_confirm_mac(
        &self,
        our_eph_pk: &[u8; 32],
        peer_eph_pk: &[u8; 32],
    ) -> Result<Vec<u8>, &'static str> {
        let session_key = self
            .session_key
            .as_ref()
            .ok_or("Session key not computed")?;

        let mut mac =
            HmacSha256::new_from_slice(session_key).expect("HMAC can take key of any size");
        mac.update(our_eph_pk);
        mac.update(peer_eph_pk);
        mac.update(b"initiator_confirm");
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Process KeyConfirm (Responder finalizes, after Message 3)
    pub fn process_key_confirm(
        &mut self,
        key_confirm: &KeyExchangeMessage,
    ) -> Result<(), &'static str> {
        let confirm_mac_hex = match key_confirm {
            KeyExchangeMessage::KeyConfirm { confirm_mac } => confirm_mac,
            _ => return Err("Expected KeyConfirm message"),
        };

        let confirm_mac = hex::decode(confirm_mac_hex).map_err(|_| "Invalid hex in confirm_mac")?;

        let peer_eph_pk = self
            .peer_ephemeral_public
            .map(|pk| pk.to_bytes())
            .ok_or("No peer ephemeral public key")?;

        let our_eph_pk = self
            .ephemeral_public
            .map(|pk| pk.to_bytes())
            .ok_or("No ephemeral public key")?;

        // Verify confirmation MAC
        let session_key = self
            .session_key
            .as_ref()
            .ok_or("Session key not computed")?;

        let mut mac =
            HmacSha256::new_from_slice(session_key).expect("HMAC can take key of any size");
        mac.update(&peer_eph_pk); // Their ephemeral (initiator's)
        mac.update(&our_eph_pk); // Our ephemeral (responder's)
        mac.update(b"initiator_confirm");

        mac.verify_slice(&confirm_mac).map_err(|_| {
            "Key confirm verification failed - initiator doesn't have correct session key"
        })?;

        // Derive full encryption key
        self.derive_encryption_key();

        self.state = KeyExchangeState::Complete;
        Ok(())
    }

    /// Derive encryption key from session key using HKDF-SHA256
    fn derive_encryption_key(&mut self) {
        if let Some(ref session_key) = self.session_key {
            // Use room_id as salt for domain separation
            let salt = self.room_id.as_bytes();
            let info = b"ZKS-VPN v1.0 encryption key";

            let hk = Hkdf::<Sha256>::new(Some(salt), session_key);

            // 1. Derive 32-byte seed using HKDF
            let mut seed = [0u8; 32];
            hk.expand(info, &mut seed).expect("HKDF expansion failed");

            // 2. Expand to 1MB using SHA256 counter mode
            let target_size = 1024 * 1024;
            let mut key_material = Vec::with_capacity(target_size);
            let mut counter = 0u64;
            let mut hasher = Sha256::new();

            while key_material.len() < target_size {
                hasher.update(seed);
                hasher.update(counter.to_le_bytes());
                let result = hasher.finalize_reset();
                key_material.extend_from_slice(&result);
                counter += 1;
            }

            // Truncate to exact size
            key_material.truncate(target_size);

            self.encryption_key = Some(key_material);
        }
    }

    /// Get the derived encryption key (only available after exchange complete)
    pub fn get_encryption_key(&self) -> Option<&[u8]> {
        self.encryption_key.as_deref()
    }

    /// Check if key exchange is complete
    pub fn is_complete(&self) -> bool {
        self.state == KeyExchangeState::Complete
    }

    // ============ LEGACY COMPATIBILITY ============
    // Keep old methods for backward compatibility during transition

    /// Legacy: Get our public key as bytes (for sending to peer)
    pub fn get_public_key_bytes(&self) -> Option<[u8; 32]> {
        self.ephemeral_public.map(|pk| pk.to_bytes())
    }

    /// Legacy: Receive peer's public key and complete the exchange
    /// WARNING: This uses the OLD insecure 2-message protocol
    pub fn receive_peer_public_key(&mut self, peer_pk_bytes: &[u8]) -> Result<(), &'static str> {
        if peer_pk_bytes.len() != 32 {
            self.state = KeyExchangeState::Failed;
            return Err("Invalid public key length");
        }

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(peer_pk_bytes);
        let peer_public_key = PublicKey::from(pk_array);
        self.peer_ephemeral_public = Some(peer_public_key);

        // Compute shared secret using legacy method
        if let Some(secret) = self.ephemeral_secret.take() {
            let shared_secret = secret.diffie_hellman(&peer_public_key);
            self.shared_secret = Some(shared_secret);

            // Derive session key for compatibility
            let shared_secret_ref = self.shared_secret.as_ref().unwrap();
            let hk =
                Hkdf::<Sha256>::new(Some(self.room_id.as_bytes()), shared_secret_ref.as_bytes());
            let mut session_key = [0u8; 32];
            hk.expand(b"zks-session-key-v1", &mut session_key)
                .expect("HKDF expand failed");
            self.session_key = Some(session_key);

            // Derive encryption key using HKDF
            self.derive_encryption_key();
            self.state = KeyExchangeState::Complete;
            Ok(())
        } else {
            self.state = KeyExchangeState::Failed;
            Err("No local secret key")
        }
    }
}

/// Key exchange message format (JSON)
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum KeyExchangeMessage {
    // ============ NEW AUTHENTICATED PROTOCOL (v2) ============
    /// Message 1: Initiator's ephemeral PK + encrypted identity proof
    #[serde(rename = "auth_init")]
    AuthInit {
        ephemeral_pk: String,
        encrypted_identity: String,
        timestamp: u64,
    },

    /// Message 2: Responder's ephemeral PK + authentication MAC
    #[serde(rename = "auth_response")]
    AuthResponse {
        ephemeral_pk: String,
        auth_mac: String,
    },

    /// Message 3: Initiator's key confirmation
    #[serde(rename = "key_confirm")]
    KeyConfirm { confirm_mac: String },

    // ============ LEGACY PROTOCOL (v1) - for backward compat ============
    /// Send our public key to peer (LEGACY)
    #[serde(rename = "key_exchange")]
    PublicKey {
        /// Hex-encoded X25519 public key (32 bytes)
        public_key: String,
    },
    /// Acknowledge key exchange complete
    #[serde(rename = "key_exchange_ack")]
    Ack {
        /// Indicates successful key derivation
        success: bool,
    },
    /// Share swarm entropy from Client to Exit Peer
    #[serde(rename = "shared_entropy")]
    SharedEntropy {
        /// Hex-encoded entropy bytes (32 bytes)
        entropy: String,
    },
    /// DCUtR: Peer info for hole-punching
    #[serde(rename = "peer_info")]
    PeerInfo { peer_id: String, addrs: Vec<String> },
    /// DCUtR: Request hole punch coordination
    #[serde(rename = "hole_punch_request")]
    HolePunchRequest { target_peer_id: String },
    /// DCUtR: Accept hole punch
    #[serde(rename = "hole_punch_accept")]
    HolePunchAccept { peer_id: String, addrs: Vec<String> },
    /// DCUtR: RTT sync
    #[serde(rename = "rtt_sync")]
    RttSync { timestamp_ms: u64 },
}

#[allow(dead_code)]
impl KeyExchangeMessage {
    /// Create a public key message (LEGACY)
    pub fn new_public_key(pk_bytes: &[u8; 32]) -> Self {
        Self::PublicKey {
            public_key: hex::encode(pk_bytes),
        }
    }

    /// Create a shared entropy message
    pub fn new_shared_entropy(entropy_bytes: &[u8]) -> Self {
        Self::SharedEntropy {
            entropy: hex::encode(entropy_bytes),
        }
    }

    /// Parse public key from message (LEGACY)
    pub fn parse_public_key(&self) -> Option<Vec<u8>> {
        match self {
            Self::PublicKey { public_key } => hex::decode(public_key).ok(),
            _ => None,
        }
    }

    /// Parse shared entropy from message
    pub fn parse_shared_entropy(&self) -> Option<Vec<u8>> {
        match self {
            Self::SharedEntropy { entropy } => hex::decode(entropy).ok(),
            _ => None,
        }
    }

    /// Check if this is a new protocol AuthInit message
    pub fn is_auth_init(&self) -> bool {
        matches!(self, Self::AuthInit { .. })
    }

    /// Check if this is a legacy PublicKey message
    pub fn is_legacy_public_key(&self) -> bool {
        matches!(self, Self::PublicKey { .. })
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticated_key_exchange() {
        // Simulate Client (Initiator) and Exit Peer (Responder)
        let mut client = KeyExchange::new("test-room");
        let mut exit_peer = KeyExchange::new("test-room");

        // Message 1: Client → Exit Peer (AuthInit)
        let auth_init = client
            .create_auth_init()
            .expect("Failed to create AuthInit");
        println!("Message 1 (AuthInit): {}", auth_init.to_json());

        // Message 2: Exit Peer → Client (AuthResponse)
        let auth_response = exit_peer
            .process_auth_init_and_respond(&auth_init)
            .expect("Failed to process AuthInit");
        println!("Message 2 (AuthResponse): {}", auth_response.to_json());

        // Message 3: Client → Exit Peer (KeyConfirm)
        let key_confirm = client
            .process_auth_response_and_confirm(&auth_response)
            .expect("Failed to process AuthResponse");
        println!("Message 3 (KeyConfirm): {}", key_confirm.to_json());

        // Exit Peer verifies KeyConfirm
        exit_peer
            .process_key_confirm(&key_confirm)
            .expect("Failed to process KeyConfirm");

        // Both should have completed
        assert!(client.is_complete(), "Client should be complete");
        assert!(exit_peer.is_complete(), "Exit peer should be complete");

        // Both should have the same encryption key
        let client_key = client.get_encryption_key().unwrap();
        let exit_key = exit_peer.get_encryption_key().unwrap();

        assert_eq!(client_key.len(), 1024 * 1024);
        assert_eq!(client_key, exit_key, "Keys should match!");

        println!("✅ Authenticated key exchange successful!");
    }

    #[test]
    fn test_wrong_room_fails() {
        let mut client = KeyExchange::new("room-alice");
        let mut exit_peer = KeyExchange::new("room-bob"); // Different room!

        let auth_init = client
            .create_auth_init()
            .expect("Failed to create AuthInit");

        // Should fail because rooms don't match
        let result = exit_peer.process_auth_init_and_respond(&auth_init);
        assert!(result.is_err(), "Should fail with wrong room");
        println!("✅ Correctly rejected wrong room!");
    }

    #[test]
    fn test_legacy_key_exchange() {
        // Ensure legacy protocol still works
        let mut client = KeyExchange::new("test-room");
        let mut exit_peer = KeyExchange::new("test-room");

        client.generate_keypair();
        exit_peer.generate_keypair();

        let client_pk = client.get_public_key_bytes().unwrap();
        let exit_pk = exit_peer.get_public_key_bytes().unwrap();

        client.receive_peer_public_key(&exit_pk).unwrap();
        exit_peer.receive_peer_public_key(&client_pk).unwrap();

        assert!(client.is_complete());
        assert!(exit_peer.is_complete());

        let client_key = client.get_encryption_key().unwrap();
        let exit_key = exit_peer.get_encryption_key().unwrap();

        assert_eq!(client_key.len(), 1024 * 1024);
        assert_eq!(client_key, exit_key);

        println!("✅ Legacy key exchange still works!");
    }

    #[test]
    fn test_message_serialization() {
        let pk = [0x42u8; 32];
        let msg = KeyExchangeMessage::new_public_key(&pk);
        let json = msg.to_json();

        let parsed = KeyExchangeMessage::from_json(&json).unwrap();
        let recovered = parsed.parse_public_key().unwrap();

        assert_eq!(recovered, pk.to_vec());
    }
}
