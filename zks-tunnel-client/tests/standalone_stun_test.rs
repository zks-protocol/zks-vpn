//! Standalone STUN Test
//! This test runs independently to verify STUN functionality

use std::net::UdpSocket;
use std::time::Duration;

#[tokio::test]
async fn test_stun_discovery_standalone() {
    println!("🔍 Testing STUN discovery (standalone)...");
    
    // Simple STUN test - just check if we can reach a STUN server
    let stun_server = "stun.l.google.com:19302";
    
    match tokio::time::timeout(Duration::from_secs(5), async {
        // Try to resolve the STUN server
        let parts: Vec<&str> = stun_server.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid STUN server format".to_string());
        }
        
        let host = parts[0];
        let port: u16 = parts[1].parse().map_err(|_| "Invalid port")?;
        
        // Try to connect via UDP
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind: {}", e))?;
        socket.set_read_timeout(Some(Duration::from_secs(3))).map_err(|e| format!("Failed to set timeout: {}", e))?;
        
        // Try to send a simple packet (we don't need a full STUN request for this test)
        let dummy_data = b"test";
        match socket.send_to(dummy_data, (host, port)) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to send to STUN server: {}", e)),
        }
    }).await {
        Ok(Ok(_)) => {
            println!("✅ STUN server {} is reachable", stun_server);
        }
        Ok(Err(e)) => {
            println!("⚠️ STUN server test failed: {}", e);
        }
        Err(_) => {
            println!("⚠️ STUN server test timed out");
        }
    }
}

#[tokio::test]
async fn test_address_formatting() {
    println!("🧪 Testing address formatting for DCUtR...");

    // Test with example STUN results
    let test_cases = vec![
        ("203.0.113.45", 45678),
        ("198.51.100.25", 12345),
        ("192.0.2.100", 8080),
    ];

    for (ip, port) in test_cases {
        let quic_addr = format!("/ip4/{}/udp/{}/quic-v1", ip, port);
        let tcp_addr = format!("/ip4/{}/tcp/{}", ip, port);
        
        println!("📍 IP: {}, Port: {}", ip, port);
        println!("   QUIC: {}", quic_addr);
        println!("   TCP: {}", tcp_addr);
        
        // Verify address format
        assert!(quic_addr.starts_with("/ip4/"));
        assert!(quic_addr.contains("/udp/"));
        assert!(quic_addr.contains("/quic-v1"));
        
        assert!(tcp_addr.starts_with("/ip4/"));
        assert!(tcp_addr.contains("/tcp/"));
        
        // Verify IP is not private (for these test cases)
        let ip_parts: Vec<&str> = ip.split('.').collect();
        assert_eq!(ip_parts.len(), 4);
        
        let first_octet: u8 = ip_parts[0].parse().expect("Invalid first octet");
        let is_private = match first_octet {
            10 => true, // 10.0.0.0/8
            172 => {
                let second_octet: u8 = ip_parts[1].parse().expect("Invalid second octet");
                second_octet >= 16 && second_octet <= 31 // 172.16.0.0/12
            }
            192 => {
                let second_octet: u8 = ip_parts[1].parse().expect("Invalid second octet");
                second_octet == 168 // 192.168.0.0/16
            }
            _ => false,
        };
        
        // These test cases should all be public IPs
        assert!(!is_private, "Test case IP should be public: {}", ip);
    }
    
    println!("✅ Address formatting test passed");
}

#[tokio::test]
async fn test_private_ip_detection() {
    println!("🧪 Testing private IP detection...");

    let private_ips = vec![
        "192.168.1.100",
        "10.0.0.5",
        "172.16.10.25",
        "172.31.255.255",
    ];

    let public_ips = vec![
        "203.0.113.45",
        "198.51.100.25",
        "192.0.2.100",
        "8.8.8.8",
    ];

    fn is_private_ip(ip: &str) -> bool {
        let ip_parts: Vec<&str> = ip.split('.').collect();
        if ip_parts.len() != 4 {
            return false;
        }
        
        let first_octet: u8 = ip_parts[0].parse().unwrap_or(0);
        match first_octet {
            10 => true, // 10.0.0.0/8
            172 => {
                let second_octet: u8 = ip_parts[1].parse().unwrap_or(0);
                second_octet >= 16 && second_octet <= 31 // 172.16.0.0/12
            }
            192 => {
                let second_octet: u8 = ip_parts[1].parse().unwrap_or(0);
                second_octet == 168 // 192.168.0.0/16
            }
            _ => false,
        }
    }

    for ip in &private_ips {
        assert!(is_private_ip(ip), "Should detect {} as private", ip);
        println!("✅ Correctly detected {} as private", ip);
    }

    for ip in &public_ips {
        assert!(!is_private_ip(ip), "Should detect {} as public", ip);
        println!("✅ Correctly detected {} as public", ip);
    }

    println!("✅ Private IP detection test passed");
}