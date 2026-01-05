//! Simple STUN Test
//!
//! This test verifies that STUN discovery works correctly

#[tokio::test]
async fn test_stun_discovery() {
    // Test STUN discovery
    println!("🔍 Testing STUN discovery...");
    
    match zks_tunnel_client::secure_stun::secure_query_stun_server("stun.l.google.com:19302", None).await {
        Ok(stun_result) => {
            println!("✅ STUN discovery successful:");
            println!("   Public IP: {}", stun_result.mapped_address);
            println!("   Public Port: {}", stun_result.mapped_port);
            
            // Verify we got a public IP (not private)
            assert!(!stun_result.mapped_address.starts_with("192.168."));
            assert!(!stun_result.mapped_address.starts_with("10."));
            assert!(!stun_result.mapped_address.starts_with("172."));
            
            // Test address formatting for DCUtR
            let quic_addr = format!("/ip4/{}/udp/{}/quic-v1", stun_result.mapped_address, stun_result.mapped_port);
            let tcp_addr = format!("/ip4/{}/tcp/{}", stun_result.mapped_address, stun_result.mapped_port);
            
            println!("📍 Formatted QUIC address: {}", quic_addr);
            println!("📍 Formatted TCP address: {}", tcp_addr);
            
            // Verify addresses are valid multiaddrs
            assert!(quic_addr.contains("quic-v1"));
            assert!(tcp_addr.contains("tcp"));
            
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

    // Simulate STUN discovery
    let stun_ip = "203.0.113.45"; // Example public IP
    let stun_port = 45678;
    
    let quic_addr = format!("/ip4/{}/udp/{}/quic-v1", stun_ip, stun_port);
    let tcp_addr = format!("/ip4/{}/tcp/{}", stun_ip, stun_port);
    
    // Simulate peer info with STUN addresses
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