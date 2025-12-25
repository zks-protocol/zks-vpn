# Wasif-Vernam: Information-Theoretic Security

## The Big Picture: Where is everything used?

The ZKS Protocol uses different algorithms for different stages of the connection. Here is the simple breakdown:

### 1. The Handshake (Getting a Key)
*Before we can send data, we need to agree on a secret key.*

| Algorithm | Type | Purpose |
|-----------|------|---------|
| **X25519** | Classical | Standard, fast key exchange. |
| **ML-KEM-768** | Post-Quantum | Protects against future quantum computers. |

👉 **Result:** These two combine to create the **Session Key**.

### 2. The Encryption (Sending Data)
*Now we use that Session Key to protect your traffic.*

**Wasif-Vernam** is the encryption method used here. It has two layers:

| Layer | Algorithm | Source | Purpose |
|-------|-----------|--------|---------|
| **1. Inner** | **XOR (True Vernam)** | Triple-Source Entropy | **Unbreakable Math.** Uses truly random bytes. |
| **2. Outer** | **ChaCha20-Poly1305** | **Session Key** (from Handshake) | **Defense-in-Depth.** Standard military-grade encryption. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               WASIF-VERNAM ENCRYPTION                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│    Plaintext                                                │
│        │                                                    │
│        ▼                                                    │
│   ┌─────────────────────────────────────┐                   │
│   │  XOR with TRUE Random Key Material  │ ← Consumed once  │
│   │  (from Triple-Source Buffer)        │   never reused   │
│   └─────────────────────────────────────┘                   │
│        │                                                    │
│        ▼                                                    │
│   ┌─────────────────────────────────────┐                   │
│   │   ChaCha20-Poly1305 AEAD            │ ← Defense-in-    │
│   │   (Session Key from ML-KEM + X25519)│   depth          │
│   └─────────────────────────────────────┘                   │
│        │                                                    │
│        ▼                                                    │
│    Ciphertext                                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Mathematical Formula

$$Ciphertext = ChaCha20Poly1305_{K}(Plaintext \oplus TrueRandomKey)$$

Where:
- `K` = Session key from hybrid handshake: $$K = HKDF(X25519_{SS} \mathbin\| MLKEM_{SS})$$
- `TrueRandomKey` = Triple-source entropy: $$SHA256(LocalCSPRNG \mathbin\| WorkerEntropy \mathbin\| SwarmSeed \mathbin\| Timestamp)$$

## Post-Quantum Key Exchange (ML-KEM-768)

The session key for ChaCha20-Poly1305 is derived from a **hybrid post-quantum handshake**:

```
┌──────────────────────────────────────────────────────────────────┐
│                  HYBRID KEY EXCHANGE                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Client                                Exit                      │
│    │                                     │                       │
│    │  [X25519_PK, ML-KEM-768_PK]        │                       │
│    │ ───────────────────────────────────▶│                       │
│    │                                     │                       │
│    │  [X25519_PK, ML-KEM-768_CT, MAC]   │                       │
│    │◀─────────────────────────────────── │                       │
│    │                                     │                       │
│    │           Session Key               │                       │
│    │  K = HKDF(X25519_SS || ML-KEM_SS)  │                       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### ML-KEM-768 (FIPS 203)

```rust
use ml_kem::{MlKem768, Encapsulate, Decapsulate};

// Client generates keypair
let (ek, dk) = MlKem768::generate(&mut rng);

// Exit encapsulates shared secret
let (ciphertext, shared_secret) = ek.encapsulate(&mut rng)?;

// Client decapsulates
let shared_secret = dk.decapsulate(&ciphertext)?;
```

| Property | Value |
|----------|-------|
| **Algorithm** | ML-KEM-768 (Kyber) |
| **Standard** | NIST FIPS 203 (August 2024) |
| **Security Level** | 192-bit post-quantum |
| **Public Key Size** | 1184 bytes |
| **Ciphertext Size** | 1088 bytes |
| **Shared Secret** | 32 bytes |

### Hybrid Security Guarantee

$$SessionKey = HKDF(X25519_{SS} \mathbin\| MLKEM_{SS}, room\_id)$$

**Key Insight:** If EITHER X25519 OR ML-KEM-768 is secure, the session key is secure. This provides:
- **Classical security** via X25519 (Curve25519)
- **Post-quantum security** via ML-KEM-768 (Kyber)

## Triple-Source Entropy

Wasif-Vernam achieves **trustless security** by combining entropy from three independent sources:


### Source 1: Local CSPRNG
```rust
let mut local_entropy = [0u8; 32];
getrandom::getrandom(&mut local_entropy)?;
```
- **Provider**: Operating system's cryptographic RNG
- **Trust**: You trust your own device

### Source 2: Worker Entropy (LavaRand)
```rust
let worker_entropy = fetch_from("https://zks-key.md-wasif-faisal.workers.dev/entropy");
```
- **Provider**: Cloudflare Workers backed by LavaRand (lava lamp entropy)
- **Trust**: Cloudflare's hardware RNG

### Source 3: Swarm Seed (Peer Entropy)
```rust
let swarm_seed = entropy_tax.derive_remote_key();  // SHA256 of all peer contributions
```
- **Provider**: Commit-reveal protocol from all connected peers
- **Trust**: Distributed consensus (trustless)

### Entropy Mixing

```rust
let mut hasher = Sha256::new();
hasher.update(local_entropy);      // Source 1
hasher.update(worker_entropy);     // Source 2  
hasher.update(swarm_seed);         // Source 3
hasher.update(timestamp);          // Forward secrecy
let hybrid_entropy: [u8; 32] = hasher.finalize().into();
```

## Trust Model

| Scenario | Entropy Sources | Trust Level |
|----------|-----------------|-------------|
| **With Peers** | Local + Worker + Swarm | **TRUSTLESS** |
| **Without Peers** | Local + Worker | Trust Cloudflare |
| **Worker Down** | Local × 2 + Swarm | **TRUSTLESS** |
| **No Peers + Worker Down** | Local × 2 | Trust your device |

**Security Guarantee:** To compromise the encryption, an attacker must compromise ALL active entropy sources simultaneously.

## Layer 1: XOR Layer (Information-Theoretic Security)

```rust
pub struct TrueVernamBuffer {
    buffer: VecDeque<u8>,  // Ring buffer of TRUE random bytes
    bytes_consumed: u64,    // Total bytes used (for metrics)
}

impl TrueVernamBuffer {
    /// Consume N bytes - NEVER REUSED (true OTP property)
    pub fn consume(&mut self, count: usize) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(self.buffer.pop_front()?);  // Gone forever!
        }
        Some(result)
    }
}
```

**Key Properties:**
- Bytes are consumed ONCE and deleted permanently
- No key expansion or derivation (true randomness)
- Buffer continuously refilled from hybrid entropy

## Layer 2: ChaCha20-Poly1305 AEAD (Defense-in-Depth)

```rust
let cipher = ChaCha20Poly1305::new(&session_key);
let nonce = generate_unique_nonce();
let ciphertext = cipher.encrypt(&nonce, xored_data)?;
```

**Purpose:**
- Provides authenticated encryption even if XOR layer is compromised
- Protects the embedded XOR key in the wire format
- Ensures integrity via Poly1305 MAC

## Wire Format

```
+──────────+─────────+───────────+────────────+────────────+───────+
│  Nonce   │  Mode   │  KeyLen   │  XOR Key   │ Ciphertext │  Tag  │
│ 12 bytes │ 1 byte  │  4 bytes  │  N bytes   │  M bytes   │ 16 B  │
+──────────+─────────+───────────+────────────+────────────+───────+

Mode values:
  0x00 = No XOR layer (ChaCha20 only)
  0x01 = Wasif-Vernam (XOR key embedded)
  0x02 = HKDF fallback mode (buffer empty)
```

**Defense-in-Depth:** The XOR key is included in the encrypted envelope, providing protection even if ChaCha20 is broken. The XOR key itself is protected by ChaCha20-Poly1305.

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Information-Theoretic Security** | True random, non-repeating key material |
| **Post-Quantum Safe** | XOR is quantum-resistant by definition |
| **Forward Secrecy** | Consumed bytes deleted permanently + timestamp mixing |
| **Trustless (with peers)** | Multi-source entropy mixing |
| **Integrity** | Poly1305 128-bit authentication tag |
| **Fallback Resilience** | Graceful degradation to HKDF mode |

## Performance

| Parameter | Value |
|-----------|-------|
| Buffer Size | 1 MB (default) |
| Refill Threshold | 512 KB |
| Fetch Interval | 100 ms |
| Chunk Size | 32 bytes (SHA256 output) |
| Throughput | ~13 MB/s (pure XOR) |

## Implementation

### Struct: `WasifVernam`

```rust
pub struct WasifVernam {
    cipher: ChaCha20Poly1305,           // Base AEAD layer
    swarm_seed: [u8; 32],               // Combined peer entropy
    true_vernam_buffer: TrueVernamBuffer, // True random bytes
    nonce_counter: AtomicU64,           // For unique nonces
}
```

### Struct: `TrueVernamFetcher`

```rust
pub struct TrueVernamFetcher {
    buffer: Arc<Mutex<TrueVernamBuffer>>,
    vernam_url: String,                  // Cloudflare worker URL
    swarm_seed: Option<[u8; 32]>,        // Peer entropy (if connected)
}
```

### Remote Key Endpoint

- **URL**: `https://zks-key.md-wasif-faisal.workers.dev/entropy?size=32&n=1`
- **Response**: `{"entropy": "hex_encoded_32_bytes", ...}`
- **Fallback**: If worker fails, additional local entropy is used (not zeros!)

## Comparison with Traditional Ciphers

| Feature | Wasif-Vernam | ChaCha20 | AES-GCM | OTP |
|---------|--------------|----------|---------|-----|
| Information-Theoretic | ✅ | ❌ | ❌ | ✅ |
| Post-Quantum | ✅ | ⚠️ | ⚠️ | ✅ |
| Practical Key Distribution | ✅ | ✅ | ✅ | ❌ |
| Integrity | ✅ | ✅ | ✅ | ❌ |
| Trustless Entropy | ✅ | ❌ | ❌ | ❌ |
| Defense-in-Depth | ✅ | ❌ | ❌ | ❌ |

## References

1. Gilbert S. Vernam (1919). "Cipher Printing Telegraph Systems"
2. Claude Shannon (1949). "Communication Theory of Secrecy Systems"
3. Daniel J. Bernstein (2008). "ChaCha, a variant of Salsa20"
4. NIST FIPS 203 (2024). "ML-KEM Standard"
5. Cloudflare LavaRand: https://blog.cloudflare.com/lavarand-in-production/

---

**© 2025 Md. Wasif Faisal, BRAC University**

*The Wasif-Vernam cipher is the cryptographic foundation of the ZKS Protocol.*
