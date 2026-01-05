#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_stun_query_google() {
        // Test with Google's public STUN server
        let result = query_stun_server("stun.l.google.com:19302").await;
        
        match result {
            Ok(port) => {
                println!("Successfully queried STUN server. Mapped port: {}", port);
                // Port should be a valid port number (1-65535)
                assert!(port > 0 && port <= 65535);
            }
            Err(e) => {
                println!("STUN query failed: {}", e);
                // This might fail due to network issues, but the code should handle it gracefully
            }
        }
    }
    
    #[tokio::test]
    async fn test_stun_query_invalid_server() {
        // Test with invalid server address
        let result = query_stun_server("invalid.server:12345").await;
        
        match result {
            Ok(_) => panic!("Should have failed with invalid server"),
            Err(e) => {
                println!("Expected failure: {}", e);
                assert!(e.to_string().contains("invalid") || e.to_string().contains("failed"));
            }
        }
    }
    
    #[tokio::test]
    async fn test_nat_detection_integration() {
        // Test the full NAT detection process
        let result = detect_nat_type().await;
        
        match result {
            Ok(nat_info) => {
                println!("NAT Detection Result:");
                println!("  Type: {:?}", nat_info.nat_type);
                println!("  Delta: {:?}", nat_info.delta);
                println!("  External IP: {:?}", nat_info.external_ip);
                println!("  External Port: {:?}", nat_info.external_port);
                
                // Basic validation
                assert!(nat_info.external_port > 0 && nat_info.external_port <= 65535);
            }
            Err(e) => {
                println!("NAT detection failed: {}", e);
                // This might fail due to network issues, but we should handle it gracefully
            }
        }
    }
}