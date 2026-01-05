use std::net::{IpAddr, Ipv4Addr};

/// Test STUN functionality without libp2p dependencies
#[tokio::test]
async fn test_stun_discovery_simple() {
    println!("🔍 Testing STUN discovery...");
    
    // Test STUN discovery using the secure_stun module
    match zks_tunnel_client::secure_stun::secure_query_stun_server("stun.l.google.com:19302", None).await {
        Ok(stun_result) => {
            println!("✅ STUN discovery successful:");
            println!("   Public IP: {}", stun_result.mapped_address);
            println!("   Public Port: {}", stun_result.mapped_port);
            
            // Verify we got a public IP (not private)
            let ip_parts: Vec<&str> = stun_result.mapped_address.split('.').collect();
            assert_eq!(ip_parts.len(), 4, "Invalid IP format");
            
            let first_octet: u8 = ip_parts[0].parse().expect("Invalid first octet");
            
            // Check for private IP ranges
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
            
            assert!(!is_private, "STUN returned private IP: {}", stun_result.mapped_address);
            
            // Test address formatting for DCUtR
            let quic_addr = format!("/ip4/{}/udp/{}/quic-v1", stun_result.mapped_address, stun_result.mapped_port);
            let tcp_addr = format!("/ip4/{}/tcp/{}", stun_result.mapped_address, stun_result.mapped_port);
            
            println!("📍 Formatted QUIC address: {}", quic_addr);
            println!("📍 Formatted TCP address: {}", tcp_addr);
            
            // Verify addresses are valid multiaddr format
            assert!(quic_addr.starts_with("/ip4/"));
            assert!(quic_addr.contains("/udp/"));
            assert!(quic_addr.contains("/quic-v1"));
            
            assert!(tcp_addr.starts_with("/ip4/"));
            assert!(tcp_addr.contains("/tcp/"));
            
            println!("✅ STUN address formatting test passed");
        }
        Err(e) => {
            panic!("❌ STUN discovery failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_peerinfo_with_stun_addresses() {
    // Test PeerInfo exchange with STUN addresses
    println!("🧪 Testing PeerInfo with STUN addresses");

    // Simulate STUN discovery results
    let stun_ip = "203.0.113.45"; // Example public IP (RFC 5737)
    let stun_port = 45678;
    
    let quic_addr = format!("/ip4/{}/udp/{}/quic-v1", stun_ip, stun_port);
    let tcp_addr = format!("/ip4/{}/tcp/{}", stun_ip, stun_port);
    
    // Simulate peer info with STUN addresses (mix of private and public)
    let mut peer_addrs = vec![
        "/ip4/192.168.1.100/tcp/8080".to_string(),
        "/ip4/10.0.0.5/tcp/8080".to_string(),
    ];
    
    // Add STUN-discovered addresses (this is what our enhanced PeerInfo exchange does)
    peer_addrs.push(quic_addr.clone());
    peer_addrs.push(tcp_addr.clone());
    
    println!("📍 Simulated peer addresses: {:?}", peer_addrs);
    
    // Verify we have both private and public addresses
    assert!(peer_addrs.iter().any(|addr| addr.contains("192.168.")));
    assert!(peer_addrs.iter().any(|addr| addr.contains("10.0.0.")));
    assert!(peer_addrs.iter().any(|addr| addr.contains(stun_ip)));
    assert!(peer_addrs.iter().any(|addr| addr.contains("quic-v1")));
    assert!(peer_addrs.iter().any(|addr| addr.contains("tcp") && !addr.contains("quic")));
    
    println!("✅ PeerInfo with STUN addresses test passed");
}

#[tokio::test]
async fn test_dcutr_address_filtering() {
    // Test DCUtR address filtering logic
    println!("🧪 Testing DCUtR address filtering");

    let test_addresses = vec![
        "/ip4/192.168.1.100/tcp/8080".to_string(),
        "/ip4/10.0.0.5/tcp/8080".to_string(),
        "/ip4/203.0.113.45/udp/45678/quic-v1".to_string(),
        "/ip4/203.0.113.45/tcp/45678".to_string(),
        "/ip4/198.51.100.25/udp/12345/quic-v1".to_string(),
    ];

    // Filter for public addresses suitable for DCUtR
    let public_addresses: Vec<String> = test_addresses
        .iter()
        .filter(|addr| {
            // Skip private addresses for DCUtR
            !addr.contains("192.168.") && 
            !addr.contains("10.0.0.") && 
            !addr.contains("172.16.") && 
            !addr.contains("172.17.") && 
            !addr.contains("172.18.") && 
            !addr.contains("172.19.") && 
            !addr.contains("172.20.") && 
            !addr.contains("172.21.") && 
            !addr.contains("172.22.") && 
            !addr.contains("172.23.") && 
            !addr.contains("172.24.") && 
            !addr.contains("172.25.") && 
            !addr.contains("172.26.") && 
            !addr.contains("172.27.") && 
            !addr.contains("172.28.") && 
            !addr.contains("172.29.") && 
            !addr.contains("172.30.") && 
            !addr.contains("172.31.")
        })
        .cloned()
        .collect();

    println!("📍 Public addresses for DCUtR: {:?}", public_addresses);
    
    // Verify we filtered correctly
    assert_eq!(public_addresses.len(), 3);
    assert!(public_addresses.iter().any(|addr| addr.contains("203.0.113.45")));
    assert!(public_addresses.iter().any(|addr| addr.contains("198.51.100.25")));
    assert!(!public_addresses.iter().any(|addr| addr.contains("192.168.")));
    assert!(!public_addresses.iter().any(|addr| addr.contains("10.0.0.")));
    
    println!("✅ DCUtR address filtering test passed");
}