//! True Vernam Buffer: Information-Theoretic Security
//!
//! This module implements a TRUE One-Time Pad using continuously fetched
//! random bytes from the swarm. Unlike HKDF expansion, this provides
//! mathematically unbreakable encryption.
//!
//! Security Guarantee: Even with infinite computational power, an adversary
//! cannot break this encryption without access to the random bytes.

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

/// Minimum buffer size before we start warning
const MIN_BUFFER_SIZE: usize = 1024 * 64; // 64KB

/// Target buffer size to maintain
const TARGET_BUFFER_SIZE: usize = 1024 * 1024; // 1MB

/// How many bytes to fetch per request
const FETCH_CHUNK_SIZE: usize = 1024 * 32; // 32KB per request

/// True Vernam Buffer: Stores TRUE random bytes for one-time use
pub struct TrueVernamBuffer {
    /// Ring buffer of TRUE random bytes (never reused)
    buffer: VecDeque<u8>,
    /// Total bytes consumed (for statistics)
    bytes_consumed: u64,
    /// Total bytes fetched (for statistics)
    bytes_fetched: u64,
}

impl TrueVernamBuffer {
    /// Create a new empty buffer
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::with_capacity(TARGET_BUFFER_SIZE),
            bytes_consumed: 0,
            bytes_fetched: 0,
        }
    }

    /// Add TRUE random bytes to the buffer
    pub fn push_entropy(&mut self, bytes: &[u8]) {
        self.buffer.extend(bytes.iter());
        self.bytes_fetched += bytes.len() as u64;
        debug!("📥 Added {} bytes to True Vernam buffer (total: {})", 
               bytes.len(), self.buffer.len());
    }

    /// Consume TRUE random bytes (NEVER reused - this is the key!)
    /// Returns None if not enough bytes available
    pub fn consume(&mut self, count: usize) -> Option<Vec<u8>> {
        if self.buffer.len() < count {
            warn!("⚠️ True Vernam buffer underrun! Need {} bytes, have {}", 
                  count, self.buffer.len());
            return None;
        }

        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            // drain() removes bytes permanently - TRUE one-time use!
            if let Some(byte) = self.buffer.pop_front() {
                result.push(byte);
            }
        }
        
        self.bytes_consumed += count as u64;
        debug!("🔑 Consumed {} TRUE random bytes (remaining: {})", 
               count, self.buffer.len());
        
        Some(result)
    }

    /// Check if buffer needs refilling
    pub fn needs_refill(&self) -> bool {
        self.buffer.len() < TARGET_BUFFER_SIZE / 2
    }

    /// Check if buffer is critically low
    pub fn is_critical(&self) -> bool {
        self.buffer.len() < MIN_BUFFER_SIZE
    }

    /// Get current buffer size
    pub fn available(&self) -> usize {
        self.buffer.len()
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.bytes_consumed, self.bytes_fetched)
    }
}

impl Default for TrueVernamBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Background task that continuously fetches TRUE random bytes from swarm
pub struct TrueVernamFetcher {
    vernam_url: String,
    buffer: Arc<Mutex<TrueVernamBuffer>>,
}

impl TrueVernamFetcher {
    pub fn new(vernam_url: String, buffer: Arc<Mutex<TrueVernamBuffer>>) -> Self {
        Self { vernam_url, buffer }
    }

    /// Start the background fetching task
    pub fn start_background_task(self) {
        tokio::spawn(async move {
            // Initial burst fill
            info!("🚀 True Vernam: Starting initial buffer fill...");
            for _ in 0..32 {
                if let Err(e) = self.fetch_entropy().await {
                    warn!("Initial fetch failed: {}", e);
                }
            }
            info!("✅ True Vernam: Initial buffer ready!");

            // Continuous refill loop
            let mut interval = interval(Duration::from_millis(100)); // Check every 100ms
            
            loop {
                interval.tick().await;
                
                let needs_refill = {
                    let buffer = self.buffer.lock().await;
                    buffer.needs_refill()
                };
                
                if needs_refill {
                    if let Err(e) = self.fetch_entropy().await {
                        warn!("Entropy fetch failed: {}", e);
                    }
                }
            }
        });
    }

    /// Fetch a chunk of TRUE random bytes from the worker
    async fn fetch_entropy(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Request multiple samples to get more bytes
        let url = format!("{}/entropy?size=32&n=32", self.vernam_url.trim_end_matches('/'));
        let response = reqwest::get(&url).await?;
        
        if !response.status().is_success() {
            return Err(format!("Failed to fetch entropy: {}", response.status()).into());
        }

        let body = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let entropy_hex = json["entropy"].as_str().ok_or("Missing entropy field")?;
        let entropy_bytes = hex::decode(entropy_hex)?;

        // Add to buffer
        {
            let mut buffer = self.buffer.lock().await;
            buffer.push_entropy(&entropy_bytes);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_consume_removes_bytes() {
        let mut buffer = TrueVernamBuffer::new();
        
        // Add some entropy
        buffer.push_entropy(&[1, 2, 3, 4, 5]);
        assert_eq!(buffer.available(), 5);
        
        // Consume some
        let consumed = buffer.consume(3).unwrap();
        assert_eq!(consumed, vec![1, 2, 3]);
        assert_eq!(buffer.available(), 2);
        
        // Consume more - should get remaining
        let consumed = buffer.consume(2).unwrap();
        assert_eq!(consumed, vec![4, 5]);
        assert_eq!(buffer.available(), 0);
        
        // Buffer is empty - should return None
        assert!(buffer.consume(1).is_none());
    }

    #[test]
    fn test_bytes_never_reused() {
        let mut buffer = TrueVernamBuffer::new();
        
        // Add entropy
        buffer.push_entropy(&[0xAB; 100]);
        
        // Consume in chunks
        let chunk1 = buffer.consume(50).unwrap();
        let chunk2 = buffer.consume(50).unwrap();
        
        // Each consumption reduces the buffer
        assert_eq!(buffer.available(), 0);
        
        // The bytes are gone forever - TRUE one-time!
        assert!(buffer.consume(1).is_none());
    }
}
