//! ZKS Tunnel State Machine
//!
//! Pure protocol handler with NO IO dependencies.
//! Inspired by BoringTun's `Tunn` architecture.
//!
//! This separates packet framing/encryption from network IO,
//! making it easy to:
//! - Unit test without mocking network
//! - Swap transports (TCP/UDP/WebSocket/QUIC)
//! - Add features like FEC without touching IO code

use std::io;
use tracing::debug;

/// Maximum packet size (MTU + headers)
pub const MAX_PACKET_SIZE: usize = 65536;

/// Overhead for length prefix (4 bytes)
pub const FRAME_OVERHEAD: usize = 4;

/// Error types for tunnel operations
#[derive(Debug, Clone)]
pub enum TunnelError {
    /// Packet too large
    PacketTooLarge(usize),
    /// Invalid frame (corrupted length prefix)
    InvalidFrame,
    /// Buffer too small
    BufferTooSmall,
    /// Encryption/decryption failed
    CryptoError(String),
    /// Tunnel not ready (no key)
    NotReady,
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::PacketTooLarge(size) => write!(f, "Packet too large: {} bytes", size),
            TunnelError::InvalidFrame => write!(f, "Invalid frame"),
            TunnelError::BufferTooSmall => write!(f, "Buffer too small"),
            TunnelError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            TunnelError::NotReady => write!(f, "Tunnel not ready"),
        }
    }
}

impl std::error::Error for TunnelError {}

/// Tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Active and ready for data
    Active,
    /// Error state (e.g., crypto failure)
    Error,
}

/// Result of processing data
#[derive(Debug)]
pub enum TunnResult {
    /// Nothing more to do
    Done,
    /// Write this data to the network
    WriteToNetwork(usize), // Number of bytes written to dst buffer
    /// Write this data to the TUN device
    WriteToTunnel(usize), // Number of bytes written to dst buffer
    /// Error occurred
    Err(TunnelError),
}

/// Pure state machine for ZKS tunnel protocol
///
/// Handles:
/// - Length-prefixed framing (4 bytes big-endian + payload)
/// - Optional XOR encryption (Wasif-Vernam cipher)
/// - State management
///
/// Does NOT handle:
/// - Network IO
/// - TUN device IO
/// - Async operations
pub struct ZksTunnel {
    /// Encryption key from key exchange (32 bytes) - ALWAYS REQUIRED
    key: [u8; 32],
    /// Current state
    state: TunnelState,
    /// Bytes sent
    tx_bytes: usize,
    /// Bytes received
    rx_bytes: usize,
    /// Buffer for partial frame reception
    partial_frame: Vec<u8>,
    /// Expected frame length (if we've read the header)
    expected_len: Option<usize>,
}

impl ZksTunnel {
    /// Create a new tunnel with encryption key (REQUIRED)
    ///
    /// ZKS-VPN always encrypts traffic. A key must be provided
    /// from the key exchange phase.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            state: TunnelState::Active,
            tx_bytes: 0,
            rx_bytes: 0,
            partial_frame: Vec::with_capacity(MAX_PACKET_SIZE),
            expected_len: None,
        }
    }

    /// Get current state
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Get the encryption key (for key rotation)
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Update the encryption key (for key rotation)
    pub fn rotate_key(&mut self, new_key: [u8; 32]) {
        self.key = new_key;
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.tx_bytes, self.rx_bytes)
    }

    /// Encapsulate data for network transmission
    ///
    /// Takes raw data (e.g., from TUN device) and produces a framed,
    /// optionally encrypted packet ready for the network.
    ///
    /// Format: [4 bytes length (big-endian)] [payload]
    ///
    /// # Arguments
    /// * `data` - Raw data to encapsulate
    /// * `dst` - Destination buffer (must be at least data.len() + FRAME_OVERHEAD)
    ///
    /// # Returns
    /// * `WriteToNetwork(n)` - Write first `n` bytes of `dst` to network
    /// * `Err(...)` - Error occurred
    pub fn encapsulate(&mut self, data: &[u8], dst: &mut [u8]) -> TunnResult {
        let total_len = data.len() + FRAME_OVERHEAD;

        // Check buffer size
        if dst.len() < total_len {
            return TunnResult::Err(TunnelError::BufferTooSmall);
        }

        // Check packet size
        if data.len() > MAX_PACKET_SIZE - FRAME_OVERHEAD {
            return TunnResult::Err(TunnelError::PacketTooLarge(data.len()));
        }

        // Write length prefix (big-endian u32)
        let len_bytes = (data.len() as u32).to_be_bytes();
        dst[..4].copy_from_slice(&len_bytes);

        // XOR encryption (Wasif-Vernam cipher) - ALWAYS ACTIVE
        for (i, &byte) in data.iter().enumerate() {
            dst[4 + i] = byte ^ self.key[i % 32];
        }

        self.tx_bytes += total_len;
        debug!("Encapsulated {} bytes -> {} bytes", data.len(), total_len);

        TunnResult::WriteToNetwork(total_len)
    }

    /// Decapsulate data received from network
    ///
    /// Takes framed network data and extracts the payload.
    /// Handles partial frames (call multiple times with more data).
    ///
    /// # Arguments
    /// * `data` - Raw network data
    /// * `dst` - Destination buffer for extracted payload
    ///
    /// # Returns
    /// * `WriteToTunnel(n)` - Write first `n` bytes of `dst` to TUN
    /// * `Done` - Need more data (partial frame)
    /// * `Err(...)` - Error occurred
    pub fn decapsulate(&mut self, data: &[u8], dst: &mut [u8]) -> TunnResult {
        // Append to partial buffer
        self.partial_frame.extend_from_slice(data);
        self.rx_bytes += data.len();

        // Do we have a length header?
        if self.expected_len.is_none() && self.partial_frame.len() >= 4 {
            let len_bytes: [u8; 4] = self.partial_frame[..4].try_into().unwrap();
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len > MAX_PACKET_SIZE - FRAME_OVERHEAD {
                self.partial_frame.clear();
                return TunnResult::Err(TunnelError::PacketTooLarge(len));
            }

            self.expected_len = Some(len);
        }

        // Do we have a complete frame?
        if let Some(expected_len) = self.expected_len {
            let total_needed = 4 + expected_len;

            if self.partial_frame.len() >= total_needed {
                // Check destination buffer
                if dst.len() < expected_len {
                    return TunnResult::Err(TunnelError::BufferTooSmall);
                }

                // Extract and decrypt payload - ALWAYS DECRYPT
                let payload = &self.partial_frame[4..total_needed];

                // XOR decryption (Wasif-Vernam cipher)
                for (i, &byte) in payload.iter().enumerate() {
                    dst[i] = byte ^ self.key[i % 32];
                }

                debug!("Decapsulated {} bytes", expected_len);

                // Remove consumed data
                self.partial_frame.drain(..total_needed);
                self.expected_len = None;

                return TunnResult::WriteToTunnel(expected_len);
            }
        }

        // Need more data
        TunnResult::Done
    }

    /// Reset the tunnel state (for reconnection)
    pub fn reset(&mut self) {
        self.partial_frame.clear();
        self.expected_len = None;
        self.tx_bytes = 0;
        self.rx_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encapsulate_decapsulate() {
        let key = [0x42u8; 32];
        let mut tunnel = ZksTunnel::new(key);
        let data = b"Hello, ZKS!";
        let mut enc_buf = [0u8; 256];
        let mut dec_buf = [0u8; 256];

        // Encapsulate
        match tunnel.encapsulate(data, &mut enc_buf) {
            TunnResult::WriteToNetwork(n) => {
                assert_eq!(n, data.len() + 4);

                // Verify payload is encrypted (different from plaintext)
                assert_ne!(&enc_buf[4..4 + data.len()], data);

                // Decapsulate
                match tunnel.decapsulate(&enc_buf[..n], &mut dec_buf) {
                    TunnResult::WriteToTunnel(m) => {
                        assert_eq!(m, data.len());
                        assert_eq!(&dec_buf[..m], data);
                    }
                    _ => panic!("Expected WriteToTunnel"),
                }
            }
            _ => panic!("Expected WriteToNetwork"),
        }
    }

    #[test]
    fn test_encryption_is_mandatory() {
        let key = [0xABu8; 32];
        let mut tunnel = ZksTunnel::new(key);
        let data = b"Secret message";
        let mut enc_buf = [0u8; 256];

        // Encapsulate
        match tunnel.encapsulate(data, &mut enc_buf) {
            TunnResult::WriteToNetwork(n) => {
                // Payload MUST be different from plaintext (encrypted)
                let encrypted_payload = &enc_buf[4..n];
                assert_ne!(encrypted_payload, data);
                
                // Verify XOR encryption: payload[i] = data[i] ^ key[i % 32]
                for (i, &byte) in data.iter().enumerate() {
                    assert_eq!(encrypted_payload[i], byte ^ key[i % 32]);
                }
            }
            _ => panic!("Expected WriteToNetwork"),
        }
    }

    #[test]
    fn test_partial_frame() {
        let key = [0x55u8; 32];
        let mut tunnel = ZksTunnel::new(key);
        let data = b"Split me";
        let mut enc_buf = [0u8; 256];
        let mut dec_buf = [0u8; 256];

        // Encapsulate full frame
        let n = match tunnel.encapsulate(data, &mut enc_buf) {
            TunnResult::WriteToNetwork(n) => n,
            _ => panic!("Expected WriteToNetwork"),
        };

        // Feed partial data (first 5 bytes)
        match tunnel.decapsulate(&enc_buf[..5], &mut dec_buf) {
            TunnResult::Done => {} // Expected - need more data
            _ => panic!("Expected Done for partial frame"),
        }

        // Feed remaining data
        match tunnel.decapsulate(&enc_buf[5..n], &mut dec_buf) {
            TunnResult::WriteToTunnel(m) => {
                assert_eq!(m, data.len());
                assert_eq!(&dec_buf[..m], data);
            }
            _ => panic!("Expected WriteToTunnel"),
        }
    }

    #[test]
    fn test_key_rotation() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let mut tunnel = ZksTunnel::new(key1);
        
        assert_eq!(tunnel.key(), &key1);
        
        tunnel.rotate_key(key2);
        assert_eq!(tunnel.key(), &key2);
    }
}
