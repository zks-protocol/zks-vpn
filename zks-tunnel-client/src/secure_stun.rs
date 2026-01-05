//! Secure STUN Query Implementation
//!
//! This module provides a secure STUN implementation with:
//! - FINGERPRINT validation
//! - Transaction ID replay protection
//! - Message integrity verification
//! - Bounds checking and overflow protection

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::stun_security::{StunFingerprint, TransactionIdManager, StunMessageValidator};

/// Secure STUN query result
#[derive(Debug, Clone)]
pub struct SecureStunResult {
    pub mapped_port: u16,
    pub mapped_address: String,
    pub server_response_time: Duration,
    pub transaction_id: [u8; 12],
}

/// Secure STUN query with full RFC 5389 compliance
pub async fn secure_query_stun_server(
    stun_server: &str,
    local_port: Option<u16>,
) -> Result<SecureStunResult, Box<dyn std::error::Error>> {
    let server_addr: SocketAddr = stun_server.parse()?;
    
    // Initialize security components
    let fingerprint = StunFingerprint::new();
    let transaction_manager = TransactionIdManager::new();
    let validator = StunMessageValidator::new();
    
    // Generate secure transaction ID
    let transaction_id = transaction_manager.generate_secure_id();
    
    // Create UDP socket with optional local port binding
    let bind_addr = format!("0.0.0.0:{}", local_port.unwrap_or(0));
    let socket = UdpSocket::bind(&bind_addr).await?;
    let local_addr = socket.local_addr()?;
    
    info!("🔍 Querying STUN server {} from {}", server_addr, local_addr);
    
    // Build secure STUN binding request with FINGERPRINT
    let request = build_secure_stun_request(&transaction_id, &fingerprint)?;
    
    // Send request with retry logic
    let start_time = SystemTime::now();
    let mut last_error = None;
    
    for attempt in 0..3 {
        if attempt > 0 {
            debug!("🔄 STUN retry attempt {}", attempt + 1);
            tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
        }
        
        match socket.send_to(&request, server_addr).await {
            Ok(_) => debug!("📤 STUN request sent (attempt {})", attempt + 1),
            Err(e) => {
                warn!("⚠️ Failed to send STUN request: {}", e);
                last_error = Some(e);
                continue;
            }
        }
        
        // Receive response with timeout
        let mut buffer = vec![0u8; 1500];
        match timeout(Duration::from_secs(3), socket.recv_from(&mut buffer)).await {
            Ok(Ok((len, from_addr))) => {
                if from_addr != server_addr {
                    warn!("⚠️ STUN response from unexpected address: {}", from_addr);
                    continue;
                }
                
                buffer.truncate(len);
                
                // Validate response
                match validate_stun_response(&buffer, &transaction_id, &validator, &fingerprint) {
                    Ok(result) => {
                        let response_time = SystemTime::now()
                            .duration_since(start_time)
                            .unwrap_or(Duration::from_secs(0));
                        
                        info!("✅ Secure STUN query successful: {} -> {} ({}ms)", 
                              local_addr.port(), result.mapped_port, 
                              response_time.as_millis());
                        
                        return Ok(SecureStunResult {
                            mapped_port: result.mapped_port,
                            mapped_address: result.mapped_address,
                            server_response_time: response_time,
                            transaction_id,
                        });
                    }
                    Err(e) => {
                        warn!("⚠️ STUN response validation failed: {}", e);
                        last_error = Some(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()));
                        continue;
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("⚠️ STUN receive error: {}", e);
                last_error = Some(e);
                continue;
            }
            Err(_) => {
                warn!("⏰ STUN response timeout");
                last_error = Some(std::io::Error::new(std::io::ErrorKind::TimedOut, "STUN timeout"));
                continue;
            }
        }
    }
    
    Err(format!("STUN query failed after 3 attempts: {:?}", last_error).into())
}

/// Build secure STUN binding request with FINGERPRINT
fn build_secure_stun_request(
    transaction_id: &[u8; 12],
    fingerprint: &StunFingerprint,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut request = vec![];
    
    // STUN header (20 bytes)
    request.extend_from_slice(&[0x00, 0x01]); // Message Type: Binding Request
    request.extend_from_slice(&[0x00, 0x08]); // Message Length: 8 bytes (for FINGERPRINT)
    request.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
    request.extend_from_slice(transaction_id); // Transaction ID (12 bytes)
    
    // FINGERPRINT attribute (8 bytes total)
    request.extend_from_slice(&[0x80, 0x28]); // Attribute Type: FINGERPRINT (0x8028)
    request.extend_from_slice(&[0x00, 0x04]); // Attribute Length: 4 bytes
    
    // Calculate fingerprint (placeholder, will be updated)
    let placeholder_fp = 0u32;
    request.extend_from_slice(&placeholder_fp.to_be_bytes());
    
    // Calculate actual fingerprint and update
    let actual_fingerprint = fingerprint.calculate(&request);
    let fp_offset = request.len() - 4;
    request[fp_offset..fp_offset + 4].copy_from_slice(&actual_fingerprint.to_be_bytes());
    
    Ok(request)
}

/// Validate STUN response with comprehensive security checks
fn validate_stun_response(
    response: &[u8],
    expected_transaction_id: &[u8; 12],
    validator: &StunMessageValidator,
    fingerprint: &StunFingerprint,
) -> Result<StunValidationResult, Box<dyn std::error::Error>> {
    // Basic message validation
    validator.validate_message(response)?;
    
    // Verify message type (Binding Success Response)
    let message_type = u16::from_be_bytes([response[0], response[1]]);
    if message_type != 0x0101 {
        return Err(format!("Invalid STUN message type: 0x{:04x}", message_type).into());
    }
    
    // Verify transaction ID
    let response_transaction_id = &response[8..20];
    if response_transaction_id != expected_transaction_id {
        return Err("Transaction ID mismatch".into());
    }
    
    // Extract and validate FINGERPRINT if present
    let mut has_fingerprint = false;
    let mut fingerprint_value = 0u32;
    
    // Parse attributes to find XOR-MAPPED-ADDRESS and FINGERPRINT
    let message_length = u16::from_be_bytes([response[2], response[3]]) as usize;
    let mut pos = 20;
    let mut mapped_port = 0u16;
    let mut mapped_address = String::new();
    
    while pos + 4 <= response.len() && pos < 20 + message_length {
        let attr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let attr_length = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;
        
        match attr_type {
            0x0020 => { // XOR-MAPPED-ADDRESS
                if pos + 4 + attr_length <= response.len() && attr_length >= 8 {
                    let family = response[pos + 5];
                    let xor_port = u16::from_be_bytes([response[pos + 6], response[pos + 7]]);
                    mapped_port = xor_port ^ 0x2112; // XOR with magic cookie high bytes
                    
                    if family == 0x01 { // IPv4
                        let xor_addr = u32::from_be_bytes([
                            response[pos + 8], response[pos + 9], 
                            response[pos + 10], response[pos + 11]
                        ]);
                        let addr = xor_addr ^ 0x2112A442; // XOR with magic cookie
                        mapped_address = format!("{}.{}.{}.{}", 
                            (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
                            (addr >> 8) & 0xFF, addr & 0xFF);
                    }
                }
            }
            0x8028 => { // FINGERPRINT
                if attr_length == 4 && pos + 8 <= response.len() {
                    has_fingerprint = true;
                    fingerprint_value = u32::from_be_bytes([
                        response[pos + 4], response[pos + 5], 
                        response[pos + 6], response[pos + 7]
                    ]);
                }
            }
            _ => {}
        }
        
        // Move to next attribute (aligned to 4 bytes)
        let padded_length = (attr_length + 3) & !3;
        pos += 4 + padded_length;
    }
    
    // Validate FINGERPRINT if present
    if has_fingerprint {
        // Remove FINGERPRINT from calculation
        let mut message_without_fp = response.to_vec();
        let fp_pos = message_without_fp.len() - 8; // FINGERPRINT attribute is 8 bytes total
        message_without_fp.truncate(fp_pos);
        
        if !fingerprint.validate(&message_without_fp, fingerprint_value) {
            return Err("Invalid fingerprint".into());
        }
    }
    
    if mapped_port == 0 {
        return Err("No mapped address found".into());
    }
    
    Ok(StunValidationResult {
        mapped_port,
        mapped_address,
        has_fingerprint,
    })
}

/// STUN validation result
#[derive(Debug, Clone)]
struct StunValidationResult {
    pub mapped_port: u16,
    pub mapped_address: String,
    pub has_fingerprint: bool,
}

/// Extended STUN security errors
#[derive(Debug, thiserror::Error)]
pub enum StunSecurityError {
    #[error("{0}")]
    ValidationError(#[from] crate::stun_security::StunSecurityError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_secure_stun_request_building() {
        let fingerprint = StunFingerprint::new();
        let transaction_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                            0x09, 0x0A, 0x0B, 0x0C];
        
        let request = build_secure_stun_request(&transaction_id, &fingerprint).unwrap();
        
        // Verify header
        assert_eq!(&request[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&request[4..8], &[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
        assert_eq!(&request[8..20], &transaction_id); // Transaction ID
        
        // Verify FINGERPRINT attribute
        assert_eq!(&request[20..22], &[0x80, 0x28]); // FINGERPRINT type
        assert_eq!(&request[22..24], &[0x00, 0x04]); // Length 4
        
        // Verify fingerprint calculation
        let mut test_request = request.clone();
        test_request[24..28].copy_from_slice(&[0u8; 4]); // Zero out fingerprint
        let expected_fp = fingerprint.calculate(&test_request);
        let actual_fp = u32::from_be_bytes([request[24], request[25], request[26], request[27]]);
        assert_eq!(expected_fp, actual_fp);
    }
}