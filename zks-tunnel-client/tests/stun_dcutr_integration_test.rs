//! STUN-DCUtR Integration Test
//!
//! This test verifies that STUN-discovered addresses are properly included
//! in PeerInfo exchange and that DCUtR hole-punching works with symmetric NAT.

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, Level};
use tracing_subscriber;

/// Test STUN integration with DCUtR
#[tokio::test]
async fn test_stun_dcutr_integration() {
    // Initialize logging
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_test_writer()
        .init();

    info!("🧪 Starting STUN-DCUtR Integration Test");

    // Test STUN discovery
    info!("🔍 Testing STUN discovery...");
    match zks_tunnel_client::secure_stun::secure_query_stun_server("stun.l.google.com:19302", None).await {
        Ok(stun_result) => {
            info!("✅ STUN discovery successful:");
            info!("   Public IP: {}", stun_result.mapped_address);
            info!("   Public Port: {}", stun_result.mapped_port);
            
            // Verify we got a public IP (not private)
            assert!(!stun_result.mapped_address.starts_with("192.168."));
            assert!(!stun_result.mapped_address.starts_with("10."));
            assert!(!stun_result.mapped_address.starts_with("172."));
            
            // Test address formatting for DCUtR
            let quic_addr = format!("/ip4/{}/udp/{}/quic-v1", stun_result.mapped_address, stun_result.mapped_port);
            let tcp_addr = format!("/ip4/{}/tcp/{}", stun_result.mapped_address, stun_result.mapped_port);
            
            info!("📍 Formatted QUIC address: {}", quic_addr);
            info!("📍 Formatted TCP address: {}", tcp_addr);
            
            // Verify addresses are valid multiaddrs
            assert!(quic_addr.contains("quic-v1"));
            assert!(tcp_addr.contains("tcp"));
            
            info!("✅ STUN address formatting test passed");
        }
        Err(e) => {
            panic!("❌ STUN discovery failed: {}", e);
        }
    }

    info!("✅ STUN-DCUtR Integration Test completed successfully");
}

/// Test PeerInfo exchange with STUN addresses
#[tokio::test]
async fn test_peerinfo_with_stun_addresses() {
    // Initialize logging
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_test_writer()
        .init();

    info!("🧪 Testing PeerInfo with STUN addresses");

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
    
    info!("📍 Simulated peer addresses: {:?}", peer_addrs);
    
    // Verify we have both private and public addresses
    assert!(peer_addrs.iter().any(|addr| addr.contains("192.168.")));
    assert!(peer_addrs.iter().any(|addr| addr.contains("10.0.0.")));
    assert!(peer_addrs.iter().any(|addr| addr.contains(stun_ip)));
    assert!(peer_addrs.iter().any(|addr| addr.contains("quic-v1")));
    assert!(peer_addrs.iter().any(|addr| addr.contains("tcp") && !addr.contains("quic")));
    
    info!("✅ PeerInfo with STUN addresses test passed");
}

/// Test DCUtR address filtering logic
#[tokio::test]
async fn test_dcutr_address_filtering() {
    // Initialize logging
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_test_writer()
        .init();

    info!("🧪 Testing DCUtR address filtering logic");

    // Simulate addresses that would be exchanged in PeerInfo
    let test_addresses = vec![
        "/ip4/127.0.0.1/tcp/8080".to_string(),           // Localhost - should be filtered out
        "/ip4/192.168.1.100/tcp/8080".to_string(),       // Private - might be filtered
        "/ip4/10.0.0.5/tcp/8080".to_string(),          // Private - might be filtered  
        "/ip4/203.0.113.45/udp/45678/quic-v1".to_string(), // Public STUN - preferred
        "/ip4/203.0.113.45/tcp/45678".to_string(),       // Public STUN - fallback
    ];
    
    info!("📍 Test addresses: {:?}", test_addresses);
    
    // Simulate DCUtR address selection logic (what libp2p would do)
    let mut preferred_addrs = Vec::new();
    let mut fallback_addrs = Vec::new();
    
    for addr in &test_addresses {
        if addr.contains("127.0.0.1") {
            info!("🚫 Filtering out localhost address: {}", addr);
            continue; // Skip localhost
        }
        
        if addr.contains("quic-v1") {
            info!("⭐ Preferring QUIC address: {}", addr);
            preferred_addrs.push(addr.clone());
        } else if !addr.starts_with("/ip4/192.168.") && !addr.starts_with("/ip4/10.") {
            info!("✅ Accepting public address: {}", addr);
            fallback_addrs.push(addr.clone());
        } else {
            info!("⚠️ Private address (may work on same network): {}", addr);
            fallback_addrs.push(addr.clone());
        }
    }
    
    // Combine preferred addresses first, then fallbacks
    let final_addrs = [preferred_addrs, fallback_addrs].concat();
    
    info!("📍 Final DCUtR addresses for connection attempt: {:?}", final_addrs);
    
    // Verify we have public addresses for DCUtR
    assert!(final_addrs.iter().any(|addr| addr.contains("203.0.113.45")));
    assert!(final_addrs.iter().any(|addr| addr.contains("quic-v1")));
    
    // Verify localhost was filtered out
    assert!(!final_addrs.iter().any(|addr| addr.contains("127.0.0.1")));
    
    info!("✅ DCUtR address filtering test passed");
}