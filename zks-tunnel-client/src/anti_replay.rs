//! Enhanced Anti-Replay Attack Protection
//!
//! Implements Citadel-style replay attack prevention using a HashSet-based
//! circular buffer with support for out-of-order packet delivery.
//!
//! # Features
//! - Thread-safe packet ID (PID) generation and tracking
//! - Efficient HashSet-based history window (O(1) lookup)
//! - Handles out-of-order packet delivery (UDP reordering)
//! - Protection against delayed replay attacks
//! - Zero-allocation NoHashHasher for u64 PIDs
//!
//! # Security Model
//! - Each outgoing packet gets a unique, monotonically increasing PID
//! - PIDs are encrypted with the packet payload
//! - Receiver tracks PIDs in a sliding window
//! - Duplicate or out-of-window PIDs are rejected as replay attacks

use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// History window size - number of PIDs to track
/// Allows for packet reordering within this window
pub const HISTORY_LEN: u64 = 1024;

/// Zero-allocation hasher for u64 PIDs
/// Since PIDs are already unique u64s, we use them directly as hash values
struct NoHashHasher<T>(u64, PhantomData<T>);

impl<T> Default for NoHashHasher<T> {
    fn default() -> Self {
        NoHashHasher(0, PhantomData)
    }
}

impl<T> Hasher for NoHashHasher<T> {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, _: &[u8]) {
        panic!("NoHashHasher: Invalid use - only write_u64 is supported")
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n
    }
}

impl<T> BuildHasher for NoHashHasher<T> {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}

/// Anti-Replay Attack Container
///
/// Prevents replay attacks by tracking packet IDs in a sliding window.
/// Supports out-of-order packet delivery within the window size.
pub struct AntiReplayContainer {
    /// (base_counter, seen_pids) - base_counter tracks the sliding window position
    history: Mutex<(u64, HashSet<u64, NoHashHasher<u64>>)>,
    /// Counter for outgoing packets (monotonically increasing)
    counter_out: AtomicU64,
    /// Window size (configurable, default: HISTORY_LEN)
    window_size: u64,
}

impl AntiReplayContainer {
    /// Create a new container with default window size
    pub fn new() -> Self {
        Self::with_window_size(HISTORY_LEN)
    }

    /// Create with custom window size
    pub fn with_window_size(window_size: u64) -> Self {
        Self {
            history: Mutex::new((
                0,
                HashSet::with_capacity_and_hasher(window_size as usize, NoHashHasher::default()),
            )),
            counter_out: AtomicU64::new(0),
            window_size,
        }
    }

    /// Get the next PID for an outgoing packet
    #[inline]
    pub fn get_next_pid(&self) -> u64 {
        self.counter_out.fetch_add(1, Ordering::Relaxed)
    }

    /// Validate a received PID
    ///
    /// Returns `true` if the PID is valid (not a replay).
    /// Returns `false` if:
    /// - The PID was already seen (duplicate)
    /// - The PID is too old (below window)
    /// - The PID is too far ahead (above window)
    ///
    /// If valid, the PID is recorded in the history.
    pub fn validate_pid(&self, pid: u64) -> bool {
        let mut queue = self.history.lock().unwrap();
        let (ref mut base_counter, ref mut seen_pids) = *queue;

        // Check if we've already seen this PID
        if seen_pids.contains(&pid) {
            tracing::warn!(
                "🚨 REPLAY ATTACK DETECTED: PID {} already received!",
                pid
            );
            return false;
        }

        // Calculate the valid window: [base_counter, base_counter + window_size)
        // base_counter = the oldest PID still acceptable
        let min_acceptable = *base_counter;
        let max_acceptable = base_counter.saturating_add(self.window_size);

        // Reject PIDs below the window (too old / delayed replay)
        if pid < min_acceptable {
            tracing::warn!(
                "🚨 DELAYED REPLAY ATTACK: PID {} is too old (min: {})",
                pid,
                min_acceptable
            );
            return false;
        }

        // Reject PIDs too far ahead (potential attack or severe desync)
        if pid >= max_acceptable {
            tracing::warn!(
                "🚨 PID {} is too far ahead (max: {}), possible attack or desync",
                pid,
                max_acceptable
            );
            return false;
        }

        // PID is valid - add to history
        seen_pids.insert(pid);

        // Slide the window if we've filled up the buffer
        // Remove old entries and advance base_counter
        while seen_pids.len() > self.window_size as usize {
            seen_pids.remove(base_counter);
            *base_counter += 1;
        }

        true
    }

    /// Check if any packets have been tracked
    pub fn has_tracked_packets(&self) -> bool {
        let counter = self.counter_out.load(Ordering::Relaxed);
        let queue = self.history.lock().unwrap();
        counter > 0 || queue.0 > 0 || !queue.1.is_empty()
    }

    /// Reset all counters (call on re-keying)
    pub fn reset(&self) {
        self.counter_out.store(0, Ordering::Relaxed);
        let mut lock = self.history.lock().unwrap();
        lock.0 = 0;
        lock.1 = HashSet::with_capacity_and_hasher(
            self.window_size as usize,
            NoHashHasher::default(),
        );
        tracing::debug!("🔄 Anti-replay container reset");
    }

    /// Get current outgoing counter value
    pub fn current_counter(&self) -> u64 {
        self.counter_out.load(Ordering::Relaxed)
    }

    /// Get number of tracked PIDs in history
    pub fn history_size(&self) -> usize {
        self.history.lock().unwrap().1.len()
    }
}

impl Default for AntiReplayContainer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_next_pid() {
        let container = AntiReplayContainer::new();
        assert_eq!(container.get_next_pid(), 0);
        assert_eq!(container.get_next_pid(), 1);
        assert_eq!(container.get_next_pid(), 2);
    }

    #[test]
    fn test_validate_fresh_pid() {
        let container = AntiReplayContainer::new();
        assert!(container.validate_pid(0));
        assert!(container.validate_pid(1));
        assert!(container.validate_pid(2));
    }

    #[test]
    fn test_reject_duplicate_pid() {
        let container = AntiReplayContainer::new();
        assert!(container.validate_pid(5));
        assert!(!container.validate_pid(5)); // Duplicate - should fail
    }

    #[test]
    fn test_out_of_order_packets() {
        let container = AntiReplayContainer::new();
        // Packets arrive out of order
        assert!(container.validate_pid(10));
        assert!(container.validate_pid(8));  // Earlier packet arrives late
        assert!(container.validate_pid(12));
        assert!(container.validate_pid(9));  // Another late arrival
        
        // All should be in history
        assert_eq!(container.history_size(), 4);
    }

    #[test]
    fn test_delayed_replay_protection() {
        let container = AntiReplayContainer::with_window_size(10);
        
        // Fill up the window
        for i in 0..20 {
            container.validate_pid(i);
        }
        
        // Try to replay a very old PID (should fail)
        assert!(!container.validate_pid(0));
        assert!(!container.validate_pid(5));
    }

    #[test]
    fn test_reset() {
        let container = AntiReplayContainer::new();
        container.get_next_pid();
        container.get_next_pid();
        container.validate_pid(100);
        
        assert!(container.has_tracked_packets());
        
        container.reset();
        
        assert_eq!(container.current_counter(), 0);
        assert_eq!(container.history_size(), 0);
    }

    #[test]
    fn test_window_sliding() {
        let container = AntiReplayContainer::with_window_size(5);
        
        // Add PIDs 0-4
        for i in 0..5 {
            assert!(container.validate_pid(i));
        }
        assert_eq!(container.history_size(), 5);
        
        // Add PID 5 - should push out PID 0
        assert!(container.validate_pid(5));
        assert_eq!(container.history_size(), 5);
        
        // PID 0 should now be rejected (too old)
        assert!(!container.validate_pid(0));
    }
}
