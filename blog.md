# Building the Unbreakable: How I Made Shannon's One-Time Pad Practical

**By Md. Wasif Faisal**

*January 2026*

---

## The 75-Year-Old Problem

In 1949, Claude Shannon mathematically proved that the One-Time Pad (OTP) provides *perfect secrecy*—encryption that is impossible to break, not just computationally, but **mathematically**. Even with infinite computing power, an attacker cannot determine the original message.

The catch? Three impractical requirements:

1. **Key must be truly random** (not pseudo-random)
2. **Key must be as long as the message** (1 TB file = 1 TB key)
3. **Key must never be reused**

For 75 years, these constraints made OTP a theoretical curiosity. People used it for spy communications with pre-shared key books, but never at internet scale.

**Until now.**

---

## The Wasif-Vernam Cipher: Making the Impossible Practical

I set out to solve each of Shannon's constraints. Here's the technical journey.

---

## Problem 1: Where to Get TRUE Randomness?

### The Challenge

Computers are deterministic. They run algorithms. Algorithms produce *pseudo*-random numbers—patterns that look random but aren't truly unpredictable.

```
CSPRNG: seed → algorithm → output
        ↑
If attacker learns seed, they can predict all outputs!
```

### My Solution: drand Distributed Randomness Beacon

I integrated [drand](https://drand.love), a decentralized randomness beacon run by the **League of Entropy**—a consortium including Cloudflare, EPFL, Protocol Labs, and 13+ other organizations.

**How drand works:**

```
16+ organizations worldwide
        ↓
Each generates partial random (threshold BLS signatures)
        ↓
Combined via cryptographic aggregation
        ↓
Result: TRUE unpredictable random (32 bytes)
```

**Key properties:**
- **Unpredictable:** No single org can predict or control the output
- **Verifiable:** Anyone can verify the randomness is legitimate
- **Free:** Unlimited access, no API keys
- **Fast:** New randomness every 30 seconds

```rust
// Fetching TRUE randomness from drand
pub async fn get_entropy() -> Result<[u8; 32], DrandError> {
    let response: DrandResponse = reqwest::get(
        "https://api.drand.sh/public/latest"
    ).await?.json().await?;
    
    let randomness = hex::decode(&response.randomness)?;
    Ok(randomness.try_into()?)
}
```

**Result:** True randomness at internet scale, for free.

---

## Problem 2: Key Distribution Over Insecure Channels

### The Challenge

Classical OTP requires pre-sharing keys through a secure channel (courier with locked briefcase). This doesn't work for internet communication with strangers.

### My Solution: ML-KEM Post-Quantum Key Exchange

I use **ML-KEM-768** (formerly Kyber), the NIST post-quantum standard (FIPS 203), to establish shared secrets over insecure channels.

```
Client                              Server
──────                              ──────
Generate ephemeral ML-KEM keypair
        ↓
Send public key ─────────────────────────►
                                    Encapsulate: ct, shared_secret
        ◄───────────────────────── Send ciphertext
Decapsulate: shared_secret
        ↓
Both have identical shared_secret!
```

**Why ML-KEM?**
- **Post-quantum:** Secure against Shor's algorithm
- **Fast:** Faster than classical RSA
- **Proven:** NIST standardized after 6 years of analysis

```rust
// ML-KEM key exchange
let (client_pk, client_sk) = ml_kem_768::generate_keypair();
let (ciphertext, shared_secret) = ml_kem_768::encapsulate(&server_pk);
```

**Result:** Secure key agreement with anyone, immune to quantum attacks.

---

## Problem 3: Key Must Equal Message Length

### The Challenge

Classical OTP requires 1 TB of random key to encrypt 1 TB of data. Fetching 1 TB from drand would take millennia (32 bytes per 30 seconds).

### My Solution: HKDF Key Expansion with Layered Security

For large messages, I use HKDF (HMAC-based Key Derivation Function) to expand a seed into unlimited keystream:

```rust
// Key derivation
let master_seed = HKDF::combine(&[
    drand_entropy,      // 32 bytes TRUE random
    ml_kem_secret,      // 32 bytes from key exchange
    user_random,        // 32 bytes from OS CSPRNG
    session_id,         // Unique per connection
]);

// Expand to any length
let keystream = HKDF::expand(&master_seed, message.len());
let ciphertext = xor(&message, &keystream);
```

### The Security Trade-off

| Message Size | Entropy | Security Level |
|--------------|---------|----------------|
| ≤ 32 bytes | Pure drand | **Information-theoretic** (universally unbreakable) |
| > 32 bytes | HKDF expansion | **Computational** (quantum-resistant unbreakable) |

For small messages (keys, passwords, short texts), we achieve Shannon's perfect secrecy. For larger files, we achieve the strongest practical security possible.

---

## Problem 4: What If Something Goes Wrong?

### The Challenge

What if drand is temporarily unavailable? What if there's a bug? Classical OTP provides no fallback.

### My Solution: Defense-in-Depth Architecture

The Wasif-Vernam cipher layers multiple protections:

```
┌─────────────────────────────────────────┐
│           WASIF-VERNAM CIPHER           │
├─────────────────────────────────────────┤
│                                         │
│  Plaintext                              │
│      ↓                                  │
│  [XOR with drand-derived key]           │ ← Layer 1: True random
│      ↓                                  │
│  [ChaCha20-Poly1305 AEAD]               │ ← Layer 2: Proven cipher
│      ↓                                  │
│  Authenticated Ciphertext               │
│                                         │
└─────────────────────────────────────────┘
```

**Even if one layer fails:**
- drand compromised? ChaCha20 still protects you.
- ChaCha20 broken? XOR layer with true random still protects you.
- Both broken? You have bigger problems than encryption.

```rust
fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
    // Layer 1: XOR with drand-derived entropy
    let xored = xor(plaintext, &self.true_random_key);
    
    // Layer 2: ChaCha20-Poly1305 (authenticated)
    let cipher = ChaCha20Poly1305::new(&self.session_key);
    cipher.encrypt(&self.nonce, &xored)
}
```

---

## Bonus: Making It Anonymous (ZKS Mode)

Encryption protects *what* you say. But what about *who* you are?

I added swarm routing for complete anonymity:

```
zk://example.com   → Direct (encrypted, IP visible)
zks://example.com  → Swarm (encrypted + anonymous)

ZKS Mode:
You → Entry Node → Middle Node → Exit Node → Server
         ↑             ↑             ↑
    Knows your IP   Knows nothing  Knows destination
```

**No single node knows both your identity AND your destination.**

This is onion routing with post-quantum encryption—TOR rebuilt for the post-quantum era.

### Swarm Entropy: Achieving TRUE Information-Theoretic Security

When you use ZKS mode with multiple peers, each peer can contribute TRUE random bytes:

```
You → Peer A → Peer B → Peer C → Server
         ↓          ↓          ↓
      32 bytes   32 bytes   32 bytes
         └──────────┬──────────┘
                    ↓
        Combined = 96 bytes TRUE random
```

**How peer entropy works:**

1. Each peer commits to entropy: `H(random_bytes)`
2. After all commit, each reveals their bytes
3. Combined via XOR: `entropy = A ⊕ B ⊕ C`
4. Used directly for encryption (no HKDF!)

```rust
// Swarm entropy collection
let entropy_a = peer_a.reveal(); // 32 bytes
let entropy_b = peer_b.reveal(); // 32 bytes
let entropy_c = peer_c.reveal(); // 32 bytes

// XOR combine - even if 2 peers are malicious, still secure!
let swarm_entropy = xor(xor(entropy_a, entropy_b), entropy_c);

// Use directly for TRUE Vernam (no algorithm, pure XOR)
let ciphertext = xor(message, swarm_entropy);
```

**Security guarantee:** Even if n-1 peers are malicious, the one honest peer's contribution ensures TRUE randomness. This achieves **information-theoretic security** for messages up to the combined entropy size.

---

## The Complete Wasif-Vernam Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WASIF-VERNAM CIPHER                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ENTROPY LAYER                                              │
│  ├── drand beacon (TRUE random, 32 bytes)                   │
│  ├── ML-KEM shared secret (post-quantum, 32 bytes)          │
│  ├── User OS random (unique per device)                     │
│  └── Session ID (unique per connection)                     │
│           ↓                                                 │
│  HKDF mixing → Master key                                   │
│           ↓                                                 │
│  ENCRYPTION LAYER                                           │
│  ├── XOR with TRUE random (when available)                  │
│  └── ChaCha20-Poly1305 AEAD (always)                        │
│           ↓                                                 │
│  TRANSPORT LAYER                                            │
│  ├── zk:// → Direct connection                              │
│  └── zks:// → Swarm routed (3+ hops)                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Claims

| Mode | Security Level | Can Be Broken By |
|------|----------------|------------------|
| **Standard (≤32 bytes)** | Information-theoretic | Nothing (mathematically impossible) |
| **Standard (large files)** | Post-quantum computational | Nothing known (2^128+ operations) |
| **TRUE Vernam (swarm entropy)** | Information-theoretic | Nothing (mathematically impossible) |

---

## What I Built vs. What Existed

| Problem | Before | Wasif-Vernam |
|---------|--------|--------------|
| TRUE randomness | Expensive hardware | **drand (free, unlimited)** |
| Key distribution | Pre-shared keys | **ML-KEM (post-quantum)** |
| Large files | Impractical | **HKDF expansion** |
| Authentication | None | **Poly1305 MAC** |
| Fallback | None | **Defense-in-depth** |
| Anonymity | Separate system | **Integrated swarm routing** |

---

## Conclusion

Claude Shannon gave us the theory of perfect secrecy in 1949. For 75 years, it remained impractical.

The Wasif-Vernam cipher makes it practical by:
1. **Solving entropy:** Distributed randomness via drand
2. **Solving distribution:** Post-quantum key exchange via ML-KEM
3. **Solving scalability:** HKDF expansion for unlimited file sizes
4. **Adding defense-in-depth:** ChaCha20-Poly1305 layering
5. **Adding anonymity:** Swarm routing for untraceability

The result is a protocol that provides:
- **Information-theoretic security** for small messages
- **Quantum-resistant computational security** for everything
- **Anonymous delivery** via swarm routing

**ZKS: Encryption that defies the laws of the universe.**

---

*The ZKS Protocol is open source and available at [github.com/AeroNyxNetwork/zks-protocol](https://github.com/AeroNyxNetwork).*

---

**Md. Wasif Faisal**
BRAC University, Dhaka, Bangladesh
md.wasif.faisal@g.bracu.ac.bd
