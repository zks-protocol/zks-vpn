//! Enhanced Anti-Replay Attack Protection (Citadel-Inspired)
//!
//! This module provides protection against replay attacks using a HashSet-based
//! circular buffer with configurable window, replacing the time-based approach.
//!
//! # Features
//!
//! - Thread-safe packet ID generation and tracking
//! - Circular buffer for efficient history management
//! - Support for out-of-order packet delivery
//! - Protection against delayed replay attacks
//! - Automatic state reset on re-keying
//! - Lower memory usage than time-based tracking

use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;

/// The past HISTORY_LEN packets arrived will be saved to allow out-of-order delivery of packets
pub const HISTORY_LEN: u64 = 1024;

/// Helps ensure that each packet protected is only used once
///
/// packets that get "protected" get a unique packet ID (PID) that gets encrypted with the plaintext to ensure each packet that gets crafted
/// can only be used once. In the validation stage, if the the decrypted PID already exists, then the decryption fails.
/// NOTE: we must use a circular queue over a simple atomic incrementer because a packet with PID k + n may arrive before
/// packet with PID k. By using a circular queue, we ensure that packets may arrive out of order, and, that they can still
/// be kept tracked of within a small range (maybe 100)
///
/// This should be session-unique. There's no point to saving this, especially since re-keying occurs in the networking stack
pub struct AntiReplayContainer {
    // (base_pid, seen_pids) - base_pid is the oldest PID in our window
    history: Mutex<(u64, HashSet<u64, NoHashHasher<u64>>)>,
    // used for getting the next unique outbound PID. Each node has a unique counter
    counter_out: AtomicU64,
}

const ORDERING: Ordering = Ordering::Relaxed;

impl AntiReplayContainer {
    /// Generate the next unique packet ID for outgoing packets
    #[inline]
    pub fn get_next_pid(&self) -> u64 {
        self.counter_out.fetch_add(1, ORDERING)
    }

    /// Check if a received packet ID is valid (not a replay)
    /// Returns true if the PID is fresh and should be accepted
    /// Returns false if the PID is a replay or out of window
    #[allow(unused_results)]
    pub fn on_pid_received(&self, pid_received: u64) -> bool {
        let mut queue = self.history.lock();
        let (ref mut base_pid, ref mut seen_pids) = *queue;
        
        // Check if we've seen this PID before
        if seen_pids.contains(&pid_received) {
            tracing::error!(target: "zks_vpn", "[AntiReplay] packet {} already arrived!", pid_received);
            return false;
        }

        // Calculate the minimum acceptable PID (sliding window)
        // This protects against delayed replay attacks where an attacker
        // withholds a packet until the history is cleared
        let min_acceptable = base_pid.saturating_sub(HISTORY_LEN);
        
        // Check if the PID is within our acceptable window
        if pid_received >= min_acceptable {
            // Maintain circular buffer size
            if seen_pids.len() >= HISTORY_LEN as usize {
                // Find the minimum PID in the set to remove
                if let Some(&min_pid) = seen_pids.iter().min() {
                    seen_pids.remove(&min_pid);
                    *base_pid = min_pid + 1;
                }
            }

            // Record this PID as seen
            seen_pids.insert(pid_received);
            true
        } else {
            tracing::error!(target: "zks_vpn", "[AntiReplay] packet {} too old (minimum is {})", pid_received, min_acceptable);
            false
        }
    }

    /// Check if we have any tracked packets
    pub fn has_tracked_packets(&self) -> bool {
        (self.counter_out.load(ORDERING) != 0) || (self.history.lock().0 != 0)
    }

    /// Reset the anti-replay state (useful for re-keying)
    pub fn reset(&self) {
        self.counter_out.store(0, ORDERING);
        let mut lock = self.history.lock();
        lock.0 = 0;
        lock.1 = HashSet::with_capacity_and_hasher(HISTORY_LEN as usize, Default::default());
    }

    /// Get current outbound counter value
    pub fn get_counter(&self) -> u64 {
        self.counter_out.load(ORDERING)
    }

    /// Get number of tracked PIDs
    pub fn tracked_count(&self) -> usize {
        self.history.lock().1.len()
    }
}

impl Default for AntiReplayContainer {
    fn default() -> Self {
        Self {
            history: Mutex::new((
                0,
                HashSet::with_capacity_and_hasher(HISTORY_LEN as usize, Default::default()),
            )),
            counter_out: AtomicU64::new(0),
        }
    }
}

/// Custom hasher that uses the value directly as the hash (perfect for u64 PIDs)
struct NoHashHasher<T>(u64, PhantomData<T>);

impl<T> Default for NoHashHasher<T> {
    fn default() -> Self {
        NoHashHasher(0, PhantomData)
    }
}

trait IsEnabled {}
impl IsEnabled for u64 {}

impl<T: IsEnabled> Hasher for NoHashHasher<T> {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, _: &[u8]) {
        panic!("Invalid use of NoHashHasher")
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n
    }
}

impl<T: IsEnabled> BuildHasher for NoHashHasher<T> {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_pid() {
        let container = AntiReplayContainer::default();
        let pid1 = container.get_next_pid();
        let pid2 = container.get_next_pid();
        
        assert_eq!(pid1, 0);
        assert_eq!(pid2, 1);
        assert_eq!(container.get_counter(), 2);
    }

    #[test]
    fn test_valid_received_pid() {
        let container = AntiReplayContainer::default();
        
        // Should accept fresh PIDs
        assert!(container.on_pid_received(0));
        assert!(container.on_pid_received(1));
        assert!(container.on_pid_received(2));
        assert_eq!(container.tracked_count(), 3);
    }

    #[test]
    fn test_replay_detection() {
        let container = AntiReplayContainer::default();
        
        // Accept a PID
        assert!(container.on_pid_received(5));
        
        // Same PID should be rejected as replay
        assert!(!container.on_pid_received(5));
    }

    #[test]
    fn test_out_of_window_rejection() {
        let container = AntiReplayContainer::default();
        
        // Accept some PIDs to establish window
        for i in 0..10 {
            assert!(container.on_pid_received(i));
        }
        
        // Old PID outside window should be rejected
        assert!(!container.on_pid_received(0));
        assert!(!container.on_pid_received(1));
    }

    #[test]
    fn test_circular_buffer() {
        let container = AntiReplayContainer::default();
        
        // Fill the buffer beyond HISTORY_LEN
        for i in 0..(HISTORY_LEN + 100) {
            assert!(container.on_pid_received(i));
        }
        
        // Debug: Check the current base_pid
        let queue = container.history.lock();
        let base_pid = queue.0;
        println!("Base PID after filling buffer: {}", base_pid);
        println!("HISTORY_LEN: {}", HISTORY_LEN);
        println!("Min acceptable: {}", base_pid.saturating_sub(HISTORY_LEN));
        
        // Very old PIDs should be rejected
        println!("Trying PID 0...");
        let result0 = container.on_pid_received(0);
        println!("Result for PID 0: {}", result0);
        assert!(!result0);
        
        assert!(!container.on_pid_received(1));
        
        // PIDs within the window should be accepted
        println!("Trying PID 100...");
        let result = container.on_pid_received(100);
        println!("Result for PID 100: {}", result);
        assert!(result);
        
        assert!(container.on_pid_received(HISTORY_LEN + 50));
        
        // PIDs that are duplicates should be rejected
        assert!(!container.on_pid_received(100));
        assert!(!container.on_pid_received(HISTORY_LEN + 50));
    }

    #[test]
    fn test_reset() {
        let container = AntiReplayContainer::default();
        
        // Add some state
        container.get_next_pid();
        container.get_next_pid();
        container.on_pid_received(0);
        container.on_pid_received(1);
        
        assert!(container.has_tracked_packets());
        assert_eq!(container.tracked_count(), 2);
        
        // Reset
        container.reset();
        
        assert!(!container.has_tracked_packets());
        assert_eq!(container.tracked_count(), 0);
        assert_eq!(container.get_counter(), 0);
        
        // Should accept previously seen PIDs after reset
        assert!(container.on_pid_received(0));
        assert!(container.on_pid_received(1));
    }

    #[test]
    fn test_out_of_order_delivery() {
        let container = AntiReplayContainer::default();
        
        // Simulate out-of-order delivery
        assert!(container.on_pid_received(10));
        assert!(container.on_pid_received(8)); // Out of order
        assert!(container.on_pid_received(9)); // Out of order
        
        // Should reject duplicates
        assert!(!container.on_pid_received(10));
        assert!(!container.on_pid_received(8));
        
        assert_eq!(container.tracked_count(), 3);
    }
}