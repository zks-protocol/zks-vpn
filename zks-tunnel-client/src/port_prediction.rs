//! Port Prediction Algorithms for NAT Traversal
//! 
//! Implements advanced port prediction using:
//! - Linear prediction for predictable NATs (EQUAL, PRESERVE)
//! - Poisson distribution sampling for complex NATs (INDEPENDENT, DEPENDENT)
//! - Birthday attack for random NATs

use rand_distr::{Distribution, Poisson};
use std::collections::HashSet;
use tracing::{debug, info};

/// Poisson sampling port prediction (from NATPoked)
/// 
/// Uses Poisson distribution to predict port allocation based on observed
/// average delta and time elapsed since last observation.
pub fn poisson_port_guess(
    prediction: &crate::nat_detection::PortPrediction,
    guess_count: usize,
) -> Vec<u16> {
    let now = now_ms() - prediction.test_finished_at;
    let poisson = Poisson::new(prediction.avg_delta.abs()).unwrap();
    let mut rng = rand::thread_rng();
    
    let mut ports = Vec::with_capacity(guess_count);
    let mut cumulative = 0i32;
    
    for i in 1..=guess_count {
        let sample = poisson.sample(&mut rng) as i32;
        cumulative += sample;
        
        let port = (prediction.last_port as f64 
            + i as f64 * prediction.avg_delta * now as f64 
            + cumulative as f64) as i32;
        
        // Wrap to valid port range
        let valid_port = ((port % 65536) + 65536) % 65536;
        let valid_port = if valid_port < 1024 { valid_port + 1024 } else { valid_port };
        
        ports.push(valid_port as u16);
    }
    
    debug!("Poisson prediction: {} ports around {:.0}", guess_count, prediction.last_port as f64 + prediction.avg_delta * now as f64);
    ports
}

/// Linear port prediction (simple delta)
/// 
/// Predicts ports based on consistent linear progression.
pub fn linear_port_guess(last_port: u16, delta: i16, count: usize) -> Vec<u16> {
    let ports: Vec<u16> = (1..=count)
        .map(|i| {
            let predicted = last_port as i32 + i as i32 * delta as i32;
            let normalized = ((predicted % 65536) + 65536) % 65536;
            normalized as u16
        })
        .collect();
    
    debug!("Linear prediction: {} ports starting from {} with delta {}", count, last_port, delta);
    ports
}

/// Birthday attack port prediction for random NATs
/// 
/// Uses the birthday paradox principle - with 50 guesses and 50 listening ports,
/// we get ~97% collision probability. This is effective against random port allocation.
pub fn birthday_attack_guess(center_port: u16, range: u16, count: usize) -> Vec<u16> {
    let half_range = range / 2;
    let start_port = center_port.saturating_sub(half_range);
    let end_port = (center_port + half_range).min(65535);
    
    let mut ports = Vec::with_capacity(count);
    let mut used = HashSet::new();
    let mut rng = rand::thread_rng();
    
    while ports.len() < count {
        let port = start_port + (rand::Rng::gen_range(&mut rng, 0..(end_port - start_port + 1)));
        
        if used.insert(port) {
            ports.push(port);
        }
    }
    
    ports.sort_unstable();
    debug!("Birthday attack: {} ports in range {}-{}", count, start_port, end_port);
    ports
}

/// Adaptive port prediction based on NAT type
/// 
/// Selects the appropriate prediction algorithm based on detected NAT behavior.
pub fn adaptive_port_guess(
    nat_type: &crate::nat_detection::DeltaType,
    prediction: &crate::nat_detection::PortPrediction,
    guess_count: usize,
) -> Vec<u16> {
    match nat_type {
        crate::nat_detection::DeltaType::Equal => {
            // Equal NAT: port stays the same
            vec![prediction.last_port]
        }
        crate::nat_detection::DeltaType::Preserve => {
            // Preserve NAT: consistent linear progression
            linear_port_guess(prediction.last_port, 1, guess_count)
        }
        crate::nat_detection::DeltaType::Independent { value: _ } => {
            // Independent NAT: use Poisson distribution
            poisson_port_guess(prediction, guess_count)
        }
        crate::nat_detection::DeltaType::Dependent { value } => {
            // Dependent NAT: use Poisson with observed delta
            let mut adjusted_prediction = prediction.clone();
            adjusted_prediction.avg_delta = *value as f64;
            poisson_port_guess(&adjusted_prediction, guess_count)
        }
        crate::nat_detection::DeltaType::Random => {
            // Random NAT: use birthday attack
            birthday_attack_guess(prediction.last_port, 1000, guess_count)
        }
    }
}

/// Get current timestamp in milliseconds
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Calculate optimal guess count based on NAT type and time budget
pub fn optimal_guess_count(nat_type: &crate::nat_detection::DeltaType, _time_budget_ms: u64) -> usize {
    match nat_type {
        crate::nat_detection::DeltaType::Equal => 1,      // Only need 1 guess
        crate::nat_detection::DeltaType::Preserve => 20,   // Small range for linear
        crate::nat_detection::DeltaType::Independent { .. } => 50,  // Medium range for Poisson
        crate::nat_detection::DeltaType::Dependent { .. } => 50,   // Medium range for dependent
        crate::nat_detection::DeltaType::Random => 100,  // Large range for birthday attack
    }
}

/// Port prediction message for signaling between peers
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PortPredictionMsg {
    pub ports: Vec<u16>,
    pub nat_type: String,
    pub timestamp_ms: u64,
    pub valid_for_ms: u64,
}

impl PortPredictionMsg {
    pub fn new(ports: Vec<u16>, nat_type: &str, valid_for_ms: u64) -> Self {
        Self {
            ports,
            nat_type: nat_type.to_string(),
            timestamp_ms: now_ms(),
            valid_for_ms,
        }
    }
    
    pub fn is_expired(&self) -> bool {
        now_ms() > self.timestamp_ms + self.valid_for_ms
    }
}

/// Birthday attack configuration
#[derive(Debug, Clone)]
pub struct BirthdayAttackConfig {
    pub center_port: u16,
    pub range: u16,
    pub guess_count: usize,
    pub listen_count: usize,
    pub timeout_ms: u64,
}

impl Default for BirthdayAttackConfig {
    fn default() -> Self {
        Self {
            center_port: 30000,
            range: 2000,
            guess_count: 50,
            listen_count: 50,
            timeout_ms: 10000, // 10 seconds
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat_detection::{DeltaType, PortPrediction};

    #[test]
    fn test_linear_port_guess() {
        let ports = linear_port_guess(5000, 1, 5);
        assert_eq!(ports, vec![5001, 5002, 5003, 5004, 5005]);
    }

    #[test]
    fn test_linear_port_wraparound() {
        let ports = linear_port_guess(65534, 2, 3);
        assert_eq!(ports, vec![0, 2, 4]); // Wraps around
    }

    #[test]
    fn test_birthday_attack_guess() {
        let ports = birthday_attack_guess(30000, 100, 10);
        assert_eq!(ports.len(), 10);
        
        // All ports should be in range
        for port in &ports {
            assert!(*port >= 29950 && *port <= 30050);
        }
        
        // Should be sorted
        assert!(ports.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_adaptive_equal_nat() {
        let prediction = PortPrediction {
            avg_delta: 0.0,
            time_elapsed_ms: 1000,
            last_port: 5000,
            test_finished_at: now_ms() - 1000,
        };
        
        let ports = adaptive_port_guess(&DeltaType::Equal, &prediction, 10);
        assert_eq!(ports, vec![5000]); // Only one port for Equal NAT
    }

    #[test]
    fn test_adaptive_preserve_nat() {
        let prediction = PortPrediction {
            avg_delta: 1.0,
            time_elapsed_ms: 1000,
            last_port: 5000,
            test_finished_at: now_ms() - 1000,
        };
        
        let ports = adaptive_port_guess(&DeltaType::Preserve, &prediction, 5);
        assert_eq!(ports, vec![5001, 5002, 5003, 5004, 5005]);
    }

    #[test]
    fn test_port_prediction_msg() {
        let msg = PortPredictionMsg::new(vec![5000, 5001, 5002], "Preserve", 5000);
        assert_eq!(msg.ports, vec![5000, 5001, 5002]);
        assert_eq!(msg.nat_type, "Preserve");
        assert!(!msg.is_expired());
    }
}