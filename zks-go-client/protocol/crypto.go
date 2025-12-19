// Package protocol implements ZKS encryption using ChaCha20-Poly1305 and X25519.
// This matches the Rust implementation in zks-tunnel-client/src/p2p_relay.rs
package protocol

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// WasifVernam implements the ZKS double-key Vernam cipher
// Currently uses ChaCha20-Poly1305 base layer only (remote key XOR disabled)
type WasifVernam struct {
	cipher       cipher.AEAD // Standard AEAD interface
	nonceCounter uint64
	remoteKey    []byte // For future "True Randomness" enhancement
}

// NewWasifVernam creates a new cipher from a 32-byte shared secret
func NewWasifVernam(sharedSecret [32]byte) (*WasifVernam, error) {
	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	return &WasifVernam{
		cipher:       aead,
		nonceCounter: 0,
		remoteKey:    nil,
	}, nil
}

// Encrypt encrypts data using ChaCha20-Poly1305
// Returns: [Nonce (12 bytes) | Ciphertext (N bytes) | Tag (16 bytes)]
func (w *WasifVernam) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate nonce: 4 bytes random + 8 bytes counter (big-endian)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce[:4]); err != nil {
		return nil, err
	}
	counter := atomic.AddUint64(&w.nonceCounter, 1) - 1
	binary.BigEndian.PutUint64(nonce[4:], counter)

	// Optional: XOR plaintext with remote key (currently disabled)
	data := plaintext
	if len(w.remoteKey) > 0 {
		data = make([]byte, len(plaintext))
		copy(data, plaintext)
		for i := range data {
			data[i] ^= w.remoteKey[i%len(w.remoteKey)]
		}
	}

	// Encrypt with ChaCha20-Poly1305
	ciphertext := w.cipher.Seal(nil, nonce, data, nil)

	// Prepend nonce to ciphertext
	result := make([]byte, 12+len(ciphertext))
	copy(result[:12], nonce)
	copy(result[12:], ciphertext)

	return result, nil
}

// Decrypt decrypts data using ChaCha20-Poly1305
// Input: [Nonce (12 bytes) | Ciphertext (N bytes) | Tag (16 bytes)]
func (w *WasifVernam) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 12+16 {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	// Decrypt with ChaCha20-Poly1305
	plaintext, err := w.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Optional: XOR with remote key to recover original (currently disabled)
	if len(w.remoteKey) > 0 {
		for i := range plaintext {
			plaintext[i] ^= w.remoteKey[i%len(w.remoteKey)]
		}
	}

	return plaintext, nil
}

// EncryptTo encrypts plaintext into dst using ChaCha20-Poly1305.
// dst must have enough capacity to hold the result (len(plaintext) + 12 + 16).
// Returns the slice of dst containing the encrypted data.
func (w *WasifVernam) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	// Generate nonce: 4 bytes random + 8 bytes counter (big-endian)
	// We write nonce directly to dst[:12]
	if len(dst) < 12+len(plaintext)+16 {
		return nil, errors.New("destination buffer too small")
	}

	nonce := dst[:12]
	if _, err := io.ReadFull(rand.Reader, nonce[:4]); err != nil {
		return nil, err
	}
	counter := atomic.AddUint64(&w.nonceCounter, 1) - 1
	binary.BigEndian.PutUint64(nonce[4:], counter)

	// Optional: XOR plaintext with remote key (currently disabled)
	// For zero-copy, we handle this carefully. If we had XOR, we'd need to
	// XOR into a temporary buffer or directly into dst if we support in-place.
	// Since it's disabled, we just use plaintext.
	data := plaintext
	if len(w.remoteKey) > 0 {
		// XOR logic would go here, potentially needing a copy if not in-place
		// For now, keeping it simple as it's disabled
		data = make([]byte, len(plaintext))
		copy(data, plaintext)
		for i := range data {
			data[i] ^= w.remoteKey[i%len(w.remoteKey)]
		}
	}

	// Encrypt with ChaCha20-Poly1305
	// Seal appends to dst[:12], so we pass dst[:12] as the "out" slice
	// The result will be dst[:12+len(ciphertext)+tag]
	ciphertext := w.cipher.Seal(dst[:12], nonce, data, nil)

	return ciphertext, nil
}

// DecryptTo decrypts data into dst using ChaCha20-Poly1305.
// dst must have enough capacity to hold the plaintext.
// Returns the slice of dst containing the decrypted data.
func (w *WasifVernam) DecryptTo(dst, data []byte) ([]byte, error) {
	if len(data) < 12+16 {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	// Decrypt with ChaCha20-Poly1305
	// Open appends to dst[:0]
	plaintext, err := w.cipher.Open(dst[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Optional: XOR with remote key to recover original (currently disabled)
	if len(w.remoteKey) > 0 {
		for i := range plaintext {
			plaintext[i] ^= w.remoteKey[i%len(w.remoteKey)]
		}
	}

	return plaintext, nil
}

// KeyExchange handles X25519 key exchange
type KeyExchange struct {
	privateKey [32]byte
	PublicKey  [32]byte
	roomID     string
}

// NewKeyExchange creates a new key exchange context with ephemeral keys
func NewKeyExchange(roomID string) (*KeyExchange, error) {
	ke := &KeyExchange{roomID: roomID}

	// Generate random private key
	if _, err := io.ReadFull(rand.Reader, ke.privateKey[:]); err != nil {
		return nil, err
	}

	// NOTE: Do NOT manually clamp the private key here!
	// The curve25519 library performs clamping internally during ScalarBaseMult.
	// Manual clamping would cause double-clamping and key mismatch with Rust.

	// Derive public key - ScalarBaseMult handles clamping internally
	curve25519.ScalarBaseMult(&ke.PublicKey, &ke.privateKey)

	return ke, nil
}

// GetPublicKeyHex returns the public key as hex string for JSON exchange
func (ke *KeyExchange) GetPublicKeyHex() string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, 64)
	for i, b := range ke.PublicKey {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

// ComputeSharedSecret computes the shared secret from peer's public key
// and derives the final encryption key using HKDF-SHA256 + SHA256 counter mode
// This MUST match the Rust implementation in key_exchange.rs
func (ke *KeyExchange) ComputeSharedSecret(peerPubKeyBytes []byte) ([32]byte, error) {
	if len(peerPubKeyBytes) != 32 {
		return [32]byte{}, errors.New("invalid peer public key length")
	}

	var peerPubKey [32]byte
	copy(peerPubKey[:], peerPubKeyBytes)

	// X25519 Diffie-Hellman
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &ke.privateKey, &peerPubKey)

	// Step 1: Derive 32-byte SEED using HKDF-SHA256
	// Salt: room_id bytes
	// Info: "ZKS-VPN v1.0 encryption key"
	salt := []byte(ke.roomID)
	info := []byte("ZKS-VPN v1.0 encryption key")

	hkdfReader := hkdf.New(sha256.New, sharedSecret[:], salt, info)
	var seed [32]byte
	if _, err := io.ReadFull(hkdfReader, seed[:]); err != nil {
		return [32]byte{}, err
	}

	// Step 2: Expand seed to 1MB using SHA256 counter mode (matches Rust)
	// This creates a cryptographically secure stream from the seed
	h := sha256.New()
	var counter uint64 = 0

	// We only need the first 32 bytes, so just do first iteration
	h.Write(seed[:])
	// Rust uses little-endian counter
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, counter)
	h.Write(counterBytes)
	
	encryptionKey := h.Sum(nil)
	
	var result [32]byte
	copy(result[:], encryptionKey[:32])

	return result, nil
}

// ParseHexPublicKey parses a hex-encoded public key
func ParseHexPublicKey(hexStr string) ([]byte, error) {
	if len(hexStr) != 64 {
		return nil, errors.New("invalid hex public key length")
	}

	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		high := hexCharToInt(hexStr[i*2])
		low := hexCharToInt(hexStr[i*2+1])
		if high < 0 || low < 0 {
			return nil, errors.New("invalid hex character")
		}
		result[i] = byte(high<<4 | low)
	}
	return result, nil
}

func hexCharToInt(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}
