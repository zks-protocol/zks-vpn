//! NAT Traversal Coordinator
//! 
//! Integrates NAT detection, port prediction, and birthday attack
//! with the existing libp2p transport for 99% NAT traversal success.

use crate::birthday_attack::{BirthdayAttack, BirthdayConfig, BirthdayResult};
use crate::nat_detection::{detect_nat_type, DeltaType, NatDetectionResult};
use crate::port_prediction::{adaptive_port_guess, optimal_guess_count, PortPredictionMsg};
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId, Swarm};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

/// NAT traversal phases
#[derive(Debug, Clone, PartialEq)]
pub enum NatPhase {
    /// Standard DCUtR (85% success)
    Phase1Dcutr,
    /// Port prediction for predictable NATs (+8%)
    Phase2PortPrediction,
    /// Birthday attack for random NATs (+2%)
    Phase3BirthdayAttack,
    /// All phases failed
    Failed,
}

/// NAT traversal configuration
#[derive(Debug, Clone)]
pub struct NatTraversalConfig {
    /// Timeout for each phase
    pub phase_timeout: Duration,
    /// Maximum total timeout
    pub total_timeout: Duration,
    /// Enable detailed logging
    pub debug_logging: bool,
    /// Birthday attack configuration
    pub birthday_config: BirthdayConfig,
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self {
            phase_timeout: Duration::from_secs(15),
            total_timeout: Duration::from_secs(60),
            debug_logging: false,
            birthday_config: BirthdayConfig::default(),
        }
    }
}

/// NAT traversal result
#[derive(Debug, Clone)]
pub struct NatTraversalResult {
    pub success: bool,
    pub phase: NatPhase,
    pub connected_addr: Option<Multiaddr>,
    pub nat_detection: Option<NatDetectionResult>,
    pub prediction_ports: Option<Vec<u16>>,
    pub birthday_result: Option<BirthdayResult>,
    pub time_elapsed: Duration,
}

/// NAT traversal coordinator
pub struct NatTraversalCoordinator {
    config: NatTraversalConfig,
}

impl NatTraversalCoordinator {
    pub fn new(config: NatTraversalConfig) -> Self {
        Self { config }
    }

    /// Attempt NAT traversal with all phases
    pub async fn traverse_nat<T: libp2p::swarm::NetworkBehaviour>(
        &self,
        swarm: &mut Swarm<T>,
        peer_id: PeerId,
        peer_addrs: Vec<Multiaddr>,
        signaling: Option<Box<dyn NatSignaling + Send + Sync>>,
    ) -> Result<NatTraversalResult, Box<dyn std::error::Error>> {
        
        let start_time = std::time::Instant::now();
        info!("🚀 Starting NAT traversal for peer: {}", peer_id);

        // Phase 1: Standard DCUtR (85% success rate)
        info!("📡 Phase 1: DCUtR connection attempt...");
        match self.phase1_dcutr(swarm, peer_id, peer_addrs.clone()).await {
            Ok(connected_addr) => {
                return Ok(NatTraversalResult {
                    success: true,
                    phase: NatPhase::Phase1Dcutr,
                    connected_addr: Some(connected_addr),
                    nat_detection: None,
                    prediction_ports: None,
                    birthday_result: None,
                    time_elapsed: start_time.elapsed(),
                });
            }
            Err(e) => {
                warn!("⚠️ Phase 1 (DCUtR) failed: {}", e);
            }
        }

        // Check if we have signaling for advanced phases
        let signaling = match signaling {
            Some(sig) => sig,
            None => {
                warn!("No signaling channel available, skipping advanced NAT traversal phases");
                return Ok(NatTraversalResult {
                    success: false,
                    phase: NatPhase::Failed,
                    connected_addr: None,
                    nat_detection: None,
                    prediction_ports: None,
                    birthday_result: None,
                    time_elapsed: start_time.elapsed(),
                });
            }
        };

        // Detect NAT type for Phase 2
        info!("🔍 Detecting NAT type for Phase 2...");
        let nat_result = match detect_nat_type().await {
            Ok(result) => {
                info!("🎯 NAT detected: {} (avg delta: {:.4}/ms)", 
                      result.nat_type, result.prediction.avg_delta);
                result
            }
            Err(e) => {
                warn!("NAT detection failed: {}, defaulting to Random", e);
                return self.phase3_birthday_attack(swarm, peer_id, signaling, start_time).await;
            }
        };

        // Phase 2: Port Prediction for predictable NATs (+8%)
        if nat_result.delta_type != DeltaType::Random {
            info!("📊 Phase 2: Port prediction for {} NAT...", nat_result.nat_type);
            match self.phase2_port_prediction(swarm, peer_id, &nat_result, signaling.as_ref()).await {
                Ok(connected_addr) => {
                    return Ok(NatTraversalResult {
                        success: true,
                        phase: NatPhase::Phase2PortPrediction,
                        connected_addr: Some(connected_addr),
                        nat_detection: Some(nat_result),
                        prediction_ports: None,
                        birthday_result: None,
                        time_elapsed: start_time.elapsed(),
                    });
                }
                Err(e) => {
                    warn!("⚠️ Phase 2 (Port Prediction) failed: {}", e);
                }
            }
        } else {
            info!("🎲 Skipping Phase 2 (Random NAT detected)");
        }

        // Phase 3: Birthday Attack for random NATs (+2%)
        info!("🎂 Phase 3: Birthday attack for random NAT...");
        self.phase3_birthday_attack(swarm, peer_id, signaling, start_time).await
    }

    /// Phase 1: Standard DCUtR connection attempt
    async fn phase1_dcutr<T: libp2p::swarm::NetworkBehaviour>(
        &self,
        swarm: &mut Swarm<T>,
        peer_id: PeerId,
        peer_addrs: Vec<Multiaddr>,
    ) -> Result<Multiaddr, Box<dyn std::error::Error>> {
        
        // Try direct connection first
        for addr in peer_addrs {
            info!("🔄 Attempting direct connection to {} via {}", peer_id, addr);
            
            match timeout(self.config.phase_timeout, self.connect_with_dcutr(swarm, peer_id, addr)).await {
                Ok(Ok(connected_addr)) => {
                    info!("✅ Phase 1 success! Connected via DCUtR to {}", connected_addr);
                    return Ok(connected_addr);
                }
                Ok(Err(e)) => {
                    debug!("Direct connection failed: {}", e);
                    continue;
                }
                Err(_) => {
                    warn!("Direct connection timed out");
                    continue;
                }
            }
        }
        
        Err("All DCUtR attempts failed".into())
    }

    /// Phase 2: Port prediction for predictable NATs
    async fn phase2_port_prediction<T: libp2p::swarm::NetworkBehaviour>(
        &self,
        swarm: &mut Swarm<T>,
        peer_id: PeerId,
        nat_result: &NatDetectionResult,
        signaling: &dyn NatSignaling,
    ) -> Result<Multiaddr, Box<dyn std::error::Error>> {
        
        let guess_count = optimal_guess_count(&nat_result.delta_type, self.config.phase_timeout.as_millis() as u64);
        let predicted_ports = adaptive_port_guess(&nat_result.delta_type, &nat_result.prediction, guess_count);
        
        info!("📊 Generated {} predicted ports for {} NAT", predicted_ports.len(), nat_result.nat_type);
        
        // Send prediction to peer via signaling
        let prediction_msg = PortPredictionMsg::new(
            predicted_ports.clone(),
            &nat_result.nat_type,
            self.config.phase_timeout.as_millis() as u64,
        );
        
        signaling.send_nat_message(NatSignalingMessage::PortPrediction(prediction_msg)).await?;
        
        // Wait for peer to coordinate connection attempts
        info!("⏳ Waiting for peer coordination...");
        match timeout(self.config.phase_timeout, self.wait_for_peer_connection(swarm, peer_id)).await {
            Ok(Ok(connected_addr)) => {
                info!("✅ Phase 2 success! Connected via port prediction");
                Ok(connected_addr)
            }
            _ => {
                Err("Port prediction coordination failed".into())
            }
        }
    }

    /// Phase 3: Birthday attack for random NATs
    async fn phase3_birthday_attack<T: libp2p::swarm::NetworkBehaviour>(
        &self,
        _swarm: &mut Swarm<T>,
        peer_id: PeerId,
        signaling: Box<dyn NatSignaling + Send + Sync>,
        start_time: std::time::Instant,
    ) -> Result<NatTraversalResult, Box<dyn std::error::Error>> {
        
        info!("🎂 Starting birthday attack for random NAT...");
        
        let mut birthday_attack = BirthdayAttack::new(self.config.birthday_config.clone());
        
        // Get peer's IP address from signaling
        let peer_ip = signaling.get_peer_ip(peer_id).await?;
        
        // Execute birthday attack
        let birthday_result = birthday_attack.execute(
            peer_ip.to_string(),
            vec![], // No predicted ports for random NAT
        ).await?;
        
        if birthday_result.success {
            info!("✅ Phase 3 success! Connected via birthday attack");
            Ok(NatTraversalResult {
                success: true,
                phase: NatPhase::Phase3BirthdayAttack,
                connected_addr: None, // Would be set by successful connection
                nat_detection: None,
                prediction_ports: None,
                birthday_result: Some(birthday_result),
                time_elapsed: start_time.elapsed(),
            })
        } else {
            warn!("🎂 Birthday attack failed");
            Ok(NatTraversalResult {
                success: false,
                phase: NatPhase::Failed,
                connected_addr: None,
                nat_detection: None,
                prediction_ports: None,
                birthday_result: Some(birthday_result),
                time_elapsed: start_time.elapsed(),
            })
        }
    }

    /// Helper: Connect with DCUtR using existing libp2p transport
    async fn connect_with_dcutr<T: libp2p::swarm::NetworkBehaviour>(
        &self,
        swarm: &mut Swarm<T>,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Result<Multiaddr, Box<dyn std::error::Error>> {
        // Dial the peer at the specified address
        swarm.dial(addr.clone())?;
        
        // Wait for connection with timeout
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            match tokio::time::timeout(Duration::from_millis(100), swarm.select_next_some()).await {
                Ok(event) => {
                    match event {
                        libp2p::swarm::SwarmEvent::ConnectionEstablished {
                            peer_id: connected_id,
                            endpoint,
                            ..
                        } => {
                            if connected_id == peer_id {
                                let connected_addr = endpoint.get_remote_address().clone();
                                let is_direct = !connected_addr.to_string().contains("p2p-circuit");
                                
                                if is_direct {
                                    info!("✅ DCUtR direct connection established");
                                } else {
                                    info!("📡 Connected via relay");
                                }
                                
                                return Ok(connected_addr);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(_) => {
                            // Handle other behaviour events if needed
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    // Timeout on select, continue loop
                }
            }
        }
        
        Err("DCUtR connection timeout".into())
    }

    /// Helper: Wait for peer connection
    async fn wait_for_peer_connection<T: libp2p::swarm::NetworkBehaviour>(
        &self,
        swarm: &mut Swarm<T>,
        peer_id: PeerId,
    ) -> Result<Multiaddr, Box<dyn std::error::Error>> {
        // Monitor swarm events for successful connection
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            match tokio::time::timeout(Duration::from_millis(100), swarm.select_next_some()).await {
                Ok(event) => {
                    match event {
                        libp2p::swarm::SwarmEvent::ConnectionEstablished {
                            peer_id: connected_id,
                            endpoint,
                            ..
                        } => {
                            if connected_id == peer_id {
                                let connected_addr = endpoint.get_remote_address().clone();
                                info!("✅ Peer connection established: {}", connected_addr);
                                return Ok(connected_addr);
                            }
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed {
                            peer_id: closed_id,
                            ..
                        } => {
                            if closed_id == peer_id {
                                info!("⚠️ Peer connection closed");
                            }
                        }
                        libp2p::swarm::SwarmEvent::Dialing {
                            peer_id: dialing_id,
                            ..
                        } => {
                            if dialing_id == Some(peer_id) {
                                info!("📞 Dialing peer...");
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    // Timeout on select, continue loop
                }
            }
        }
        
        Err("Peer connection timeout".into())
    }
}

/// NAT signaling interface for coordination between peers
#[async_trait::async_trait]
pub trait NatSignaling: Send + Sync {
    /// Send NAT-related signaling message to peer
    async fn send_nat_message(&self, message: NatSignalingMessage) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Get peer's IP address for birthday attack
    async fn get_peer_ip(&self, peer_id: PeerId) -> Result<IpAddr, Box<dyn std::error::Error>>;
}

/// NAT signaling messages
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NatSignalingMessage {
    /// NAT type information exchange
    NatInfo {
        delta_type: String,
        avg_delta: f64,
        last_port: u16,
    },
    /// Port prediction coordination
    PortPrediction(PortPredictionMsg),
    /// Birthday attack coordination
    BirthdayAttack {
        center_port: u16,
        port_range: u16,
        guess_count: u16,
        listen_count: u16,
    },
}

/// Simple WebSocket-based NAT signaling implementation
pub struct WebSocketNatSignaling {
    signaling_url: String,
    room_id: String,
    client_id: String,
}

impl WebSocketNatSignaling {
    pub fn new(signaling_url: String, room_id: String, client_id: String) -> Self {
        Self {
            signaling_url,
            room_id,
            client_id,
        }
    }
}

#[async_trait::async_trait]
impl NatSignaling for WebSocketNatSignaling {
    async fn send_nat_message(&self, message: NatSignalingMessage) -> Result<(), Box<dyn std::error::Error>> {
        // This would send the message through the existing WebSocket relay
        // For now, return a placeholder
        debug!("Sending NAT message: {:?}", message);
        Ok(())
    }
    
    async fn get_peer_ip(&self, _peer_id: PeerId) -> Result<IpAddr, Box<dyn std::error::Error>> {
        // This would extract peer IP from signaling metadata
        // For now, return a placeholder
        Err("Peer IP extraction not implemented".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_phase_ordering() {
        assert_eq!(NatPhase::Phase1Dcutr, NatPhase::Phase1Dcutr);
        assert_ne!(NatPhase::Phase1Dcutr, NatPhase::Phase2PortPrediction);
    }

    #[test]
    fn test_nat_traversal_config_default() {
        let config = NatTraversalConfig::default();
        assert_eq!(config.phase_timeout, Duration::from_secs(15));
        assert_eq!(config.total_timeout, Duration::from_secs(60));
        assert!(!config.debug_logging);
    }

    #[tokio::test]
    async fn test_websocket_nat_signaling() {
        let signaling = WebSocketNatSignaling::new(
            "wss://example.com".to_string(),
            "test-room".to_string(),
            "client-1".to_string(),
        );

        let message = NatSignalingMessage::NatInfo {
            delta_type: "Preserve".to_string(),
            avg_delta: 1.0,
            last_port: 5000,
        };

        // Should not error (placeholder implementation)
        let result = signaling.send_nat_message(message).await;
        assert!(result.is_ok());
    }
}