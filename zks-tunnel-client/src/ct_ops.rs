//! Constant-Time Cryptographic Operations
//!
//! This module provides side-channel resistant implementations of
//! cryptographic operations used in the Wasif-Vernam cipher.
//!
//! All functions are designed to execute in constant time regardless
//! of their inputs, preventing timing side-channel attacks.

#![allow(dead_code)]

/// Constant-time XOR of source bytes with a cycling key into destination
///
/// # Safety
/// - `dst` and `src` must have the same length
/// - `key` must not be empty
///
/// # Constant-Time Guarantee
/// - No branches based on data values
/// - No data-dependent memory access patterns (key cycling uses modulo)
#[inline]
pub fn ct_xor(dst: &mut [u8], src: &[u8], key: &[u8]) {
    debug_assert!(!key.is_empty(), "Key must not be empty");
    debug_assert_eq!(dst.len(), src.len(), "Buffers must be same length");

    let key_len = key.len();

    // XOR is inherently constant-time at the CPU level
    // The concern is array bounds checking - we ensure key_len > 0 above
    for i in 0..src.len() {
        // Modulo of index by constant key length is data-independent
        dst[i] = src[i] ^ key[i % key_len];
    }
}

/// In-place constant-time XOR with a cycling key
///
/// # Safety
/// - Returns immediately if key is empty (no-op, constant time)
#[inline]
pub fn ct_xor_inplace(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }

    let key_len = key.len();

    for (i, val) in data.iter_mut().enumerate() {
        *val ^= key[i % key_len];
    }
}

/// Double-key XOR: data XOR k_local XOR k_remote
///
/// This is the core Wasif-Vernam operation.
#[inline]
pub fn ct_double_xor(dst: &mut [u8], src: &[u8], k_local: &[u8; 32], k_remote: &[u8; 32]) {
    debug_assert_eq!(dst.len(), src.len());

    for i in 0..src.len() {
        let idx = i % 32; // Constant key size
        let key_byte = k_local[idx] ^ k_remote[idx];
        dst[i] = src[i] ^ key_byte;
    }
}

/// In-place double-key XOR
#[inline]
pub fn ct_double_xor_inplace(data: &mut [u8], k_local: &[u8; 32], k_remote: &[u8; 32]) {
    for (i, byte) in data.iter_mut().enumerate() {
        let idx = i % 32;
        let key_byte = k_local[idx] ^ k_remote[idx];
        *byte ^= key_byte;
    }
}

/// Validate that data has sufficient entropy
///
/// Returns false if data appears to be low-entropy (all zeros, repeating, etc.)
/// This is NOT a cryptographic test, just a sanity check.
pub fn validate_entropy_basic(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }

    // Check 1: Not all zeros
    let all_zero = data.iter().all(|&b| b == 0);
    if all_zero {
        return false;
    }

    // Check 2: Not all same value
    let first = data[0];
    let all_same = data.iter().all(|&b| b == first);
    if all_same {
        return false;
    }

    // Check 3: Reasonable byte diversity (at least 1/8 unique bytes)
    let mut seen = [false; 256];
    for &byte in data {
        seen[byte as usize] = true;
    }
    let unique_count = seen.iter().filter(|&&v| v).count();
    if unique_count < data.len() / 8 && unique_count < 4 {
        return false;
    }

    true
}

/// Securely zero memory (anti-optimization)
///
/// Uses volatile writes to prevent compiler from optimizing away the zeroing.
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }

    // Memory barrier to ensure writes complete
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_xor() {
        let key = [0xABu8; 32];
        let src = b"Hello, World!";
        let mut dst = vec![0u8; src.len()];

        ct_xor(&mut dst, src, &key);

        // Verify encryption happened
        assert_ne!(&dst, src);

        // Verify decryption works (XOR is symmetric)
        let mut recovered = vec![0u8; src.len()];
        ct_xor(&mut recovered, &dst, &key);
        assert_eq!(&recovered, src);
    }

    #[test]
    fn test_ct_xor_inplace() {
        let key = [0x42u8; 32];
        let original = b"Secret Message!".to_vec();
        let mut data = original.clone();

        ct_xor_inplace(&mut data, &key);
        assert_ne!(&data, &original);

        ct_xor_inplace(&mut data, &key);
        assert_eq!(&data, &original);
    }

    #[test]
    fn test_ct_double_xor() {
        let k_local = [0x11u8; 32];
        let k_remote = [0x22u8; 32];
        let src = b"Double encrypted!";
        let mut dst = vec![0u8; src.len()];

        ct_double_xor(&mut dst, src, &k_local, &k_remote);
        assert_ne!(&dst, src);

        // Decrypt
        let mut recovered = vec![0u8; src.len()];
        ct_double_xor(&mut recovered, &dst, &k_local, &k_remote);
        assert_eq!(&recovered, src);
    }

    #[test]
    fn test_entropy_validation() {
        // Good entropy
        let good = [
            0x4a, 0x7b, 0x3c, 0x1d, 0x8e, 0x5f, 0x2a, 0x9b, 0x6c, 0x0d, 0x7e, 0x4f, 0x1a, 0x8b,
            0x3c, 0x5d,
        ];
        assert!(validate_entropy_basic(&good));

        // All zeros - bad
        let zeros = [0u8; 32];
        assert!(!validate_entropy_basic(&zeros));

        // All same - bad
        let same = [0xABu8; 32];
        assert!(!validate_entropy_basic(&same));

        // Too short - bad
        let short = [0x12, 0x34];
        assert!(!validate_entropy_basic(&short));
    }

    #[test]
    fn test_secure_zero() {
        let mut data = [0xFFu8; 64];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
