//! STUN Security Hardening Module
//!
//! This module provides security enhancements for STUN protocol implementation
//! based on RFC 5389 best practices and production-ready implementations.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// STUN FINGERPRINT calculation and validation
pub struct StunFingerprint {
    /// CRC32 polynomial for STUN fingerprint
    crc32_table: [u32; 256],
}

impl StunFingerprint {
    pub fn new() -> Self {
        let mut crc32_table = [0u32; 256];
        for i in 0..256 {
            let mut crc = i as u32;
            for _ in 0..8 {
                if crc & 1 == 1 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
            crc32_table[i] = crc;
        }
        Self { crc32_table }
    }

    /// Calculate STUN fingerprint for a message
    pub fn calculate(&self, message: &[u8]) -> u32 {
        let mut crc = 0xFFFFFFFFu32;
        for &byte in message {
            let index = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ self.crc32_table[index];
        }
        !crc ^ 0x5354554E // XOR with STUN magic
    }

    /// Validate STUN fingerprint
    pub fn validate(&self, message: &[u8], expected_fingerprint: u32) -> bool {
        self.calculate(message) == expected_fingerprint
    }
}

/// Transaction ID management with replay protection
pub struct TransactionIdManager {
    /// Set of recently used transaction IDs
    used_ids: Arc<Mutex<HashSet<[u8; 12]>>>,
    /// Maximum age of transaction IDs to track (seconds)
    max_age: Duration,
    /// Cleanup interval
    cleanup_interval: Duration,
}

impl TransactionIdManager {
    pub fn new() -> Self {
        Self {
            used_ids: Arc::new(Mutex::new(HashSet::new())),
            max_age: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60), // 1 minute
        }
    }

    /// Generate a cryptographically secure transaction ID
    pub fn generate_secure_id(&self) -> [u8; 12] {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut id = [0u8; 12];
        
        // Ensure uniqueness and include timestamp for replay protection
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        rng.fill_bytes(&mut id[4..]);
        id[0..4].copy_from_slice(&timestamp.to_be_bytes());
        
        // Check for collision and regenerate if necessary
        let mut used_ids = self.used_ids.lock().unwrap();
        while used_ids.contains(&id) {
            rng.fill_bytes(&mut id[4..]);
        }
        
        used_ids.insert(id);
        id
    }

    /// Validate transaction ID (check for replay)
    pub fn validate_id(&self, id: &[u8; 12]) -> bool {
        let used_ids = self.used_ids.lock().unwrap();
        
        // Extract timestamp from ID
        let timestamp_bytes = &id[0..4];
        let timestamp = u32::from_be_bytes([
            timestamp_bytes[0], timestamp_bytes[1], 
            timestamp_bytes[2], timestamp_bytes[3]
        ]) as u64;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Check if ID is too old (replay protection)
        if current_time.saturating_sub(timestamp) > self.max_age.as_secs() {
            return false;
        }
        
        // Check for duplicate
        !used_ids.contains(id)
    }

    /// Clean up old transaction IDs
    pub fn cleanup_old_ids(&self) {
        let mut used_ids = self.used_ids.lock().unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        used_ids.retain(|id| {
            let timestamp_bytes = &id[0..4];
            let timestamp = u32::from_be_bytes([
                timestamp_bytes[0], timestamp_bytes[1], 
                timestamp_bytes[2], timestamp_bytes[3]
            ]) as u64;
            
            current_time.saturating_sub(timestamp) <= self.max_age.as_secs()
        });
    }
}

/// STUN message validation with bounds checking
pub struct StunMessageValidator {
    max_message_size: usize,
    max_attributes: usize,
}

impl StunMessageValidator {
    pub fn new() -> Self {
        Self {
            max_message_size: 65535, // RFC 5389 maximum
            max_attributes: 128,    // Reasonable limit
        }
    }

    /// Validate STUN message structure
    pub fn validate_message(&self, message: &[u8]) -> Result<(), StunSecurityError> {
        if message.len() < 20 {
            return Err(StunSecurityError::MessageTooShort);
        }
        
        if message.len() > self.max_message_size {
            return Err(StunSecurityError::MessageTooLong);
        }
        
        // Check magic cookie
        if message[4..8] != [0x21, 0x12, 0xA4, 0x42] {
            return Err(StunSecurityError::InvalidMagicCookie);
        }
        
        // Validate message length
        let message_length = u16::from_be_bytes([message[2], message[3]]) as usize;
        if message_length + 20 > message.len() {
            return Err(StunSecurityError::InvalidLength);
        }
        
        // Validate attributes
        self.validate_attributes(&message[20..])?;
        
        Ok(())
    }

    /// Validate STUN attributes
    fn validate_attributes(&self, attributes: &[u8]) -> Result<(), StunSecurityError> {
        let mut offset = 0;
        let mut attribute_count = 0;
        
        while offset < attributes.len() && attribute_count < self.max_attributes {
            if offset + 4 > attributes.len() {
                return Err(StunSecurityError::InvalidAttribute);
            }
            
            let attr_type = u16::from_be_bytes([attributes[offset], attributes[offset + 1]]);
            let attr_length = u16::from_be_bytes([attributes[offset + 2], attributes[offset + 3]]) as usize;
            
            // Check for padding alignment
            let padded_length = (attr_length + 3) & !3;
            if offset + 4 + padded_length > attributes.len() {
                return Err(StunSecurityError::InvalidAttribute);
            }
            
            // Validate attribute-specific constraints
            match attr_type {
                0x0001 => self.validate_mapped_address(&attributes[offset + 4..offset + 4 + attr_length])?,
                0x0020 => self.validate_xor_mapped_address(&attributes[offset + 4..offset + 4 + attr_length])?,
                0x8028 => self.validate_fingerprint(&attributes[offset + 4..offset + 4 + attr_length])?,
                _ => {} // Unknown attributes are allowed
            }
            
            offset += 4 + padded_length;
            attribute_count += 1;
        }
        
        if attribute_count >= self.max_attributes {
            return Err(StunSecurityError::TooManyAttributes);
        }
        
        Ok(())
    }

    fn validate_mapped_address(&self, data: &[u8]) -> Result<(), StunSecurityError> {
        if data.len() < 4 {
            return Err(StunSecurityError::InvalidMappedAddress);
        }
        
        let family = data[1];
        match family {
            0x01 => { // IPv4
                if data.len() != 8 {
                    return Err(StunSecurityError::InvalidMappedAddress);
                }
            }
            0x02 => { // IPv6
                if data.len() != 20 {
                    return Err(StunSecurityError::InvalidMappedAddress);
                }
            }
            _ => return Err(StunSecurityError::InvalidAddressFamily),
        }
        
        Ok(())
    }

    fn validate_xor_mapped_address(&self, data: &[u8]) -> Result<(), StunSecurityError> {
        // Same validation as mapped address
        self.validate_mapped_address(data)
    }

    fn validate_fingerprint(&self, data: &[u8]) -> Result<(), StunSecurityError> {
        if data.len() != 4 {
            return Err(StunSecurityError::InvalidFingerprint);
        }
        Ok(())
    }
}

/// Port prediction with overflow protection
pub struct SafePortPredictor {
    min_port: u16,
    max_port: u16,
}

impl SafePortPredictor {
    pub fn new() -> Self {
        Self {
            min_port: 1024,  // Avoid privileged ports
            max_port: 65535, // Maximum valid port
        }
    }

    /// Safely predict next port with overflow protection
    pub fn predict_next_port(&self, current_port: u16, delta: i32) -> Option<u16> {
        if delta == 0 {
            return Some(current_port);
        }
        
        let new_port = if delta > 0 {
            current_port.checked_add(delta as u16)?
        } else {
            current_port.checked_sub((-delta) as u16)?
        };
        
        if new_port < self.min_port || new_port > self.max_port {
            return None;
        }
        
        Some(new_port)
    }

    /// Validate port is in valid range
    pub fn validate_port(&self, port: u16) -> bool {
        port >= self.min_port && port <= self.max_port
    }
}

/// STUN security errors
#[derive(Debug, thiserror::Error)]
pub enum StunSecurityError {
    #[error("Message too short")]
    MessageTooShort,
    
    #[error("Message too long")]
    MessageTooLong,
    
    #[error("Invalid magic cookie")]
    InvalidMagicCookie,
    
    #[error("Invalid message length")]
    InvalidLength,
    
    #[error("Invalid attribute")]
    InvalidAttribute,
    
    #[error("Too many attributes")]
    TooManyAttributes,
    
    #[error("Invalid mapped address")]
    InvalidMappedAddress,
    
    #[error("Invalid address family")]
    InvalidAddressFamily,
    
    #[error("Invalid fingerprint")]
    InvalidFingerprint,
    
    #[error("Transaction ID replay detected")]
    ReplayDetected,
    
    #[error("Transaction ID too old")]
    IdTooOld,
    
    #[error("Port prediction overflow")]
    PortOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_calculation() {
        let fingerprint = StunFingerprint::new();
        let message = b"test message";
        let fp = fingerprint.calculate(message);
        assert!(fingerprint.validate(message, fp));
    }

    #[test]
    fn test_transaction_id_generation() {
        let manager = TransactionIdManager::new();
        let id1 = manager.generate_secure_id();
        let id2 = manager.generate_secure_id();
        
        assert_ne!(id1, id2);
        assert!(manager.validate_id(&id1));
        assert!(manager.validate_id(&id2));
    }

    #[test]
    fn test_message_validation() {
        let validator = StunMessageValidator::new();
        
        // Valid STUN message (minimal)
        let mut message = vec![0u8; 20];
        message[0] = 0x00; // Binding Request
        message[1] = 0x01;
        message[4] = 0x21; // Magic cookie
        message[5] = 0x12;
        message[6] = 0xA4;
        message[7] = 0x42;
        
        assert!(validator.validate_message(&message).is_ok());
    }

    #[test]
    fn test_safe_port_prediction() {
        let predictor = SafePortPredictor::new();
        
        assert_eq!(predictor.predict_next_port(5000, 1), Some(5001));
        assert_eq!(predictor.predict_next_port(5000, -1), Some(4999));
        assert_eq!(predictor.predict_next_port(1023, -1), None); // Below minimum
        assert_eq!(predictor.predict_next_port(65535, 1), None); // Above maximum
    }
}