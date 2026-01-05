//! Secure Port Prediction Algorithms for NAT Traversal
//! 
//! Implements secure port prediction with:
//! - Overflow protection
//! - Bounds checking
//! - Cryptographically secure random number generation
//! - Safe arithmetic operations

use rand_distr::{Distribution, Poisson};
use std::collections::HashSet;
use tracing::{debug, info, warn};

/// Secure port prediction with overflow protection
pub struct SecurePortPredictor {
    min_port: u16,
    max_port: u16,
    max_attempts: usize,
}

impl Default for SecurePortPredictor {
    fn default() -> Self {
        Self {
            min_port: 1024,
            max_port: 65535,
            max_attempts: 1000,
        }
    }
}

impl SecurePortPredictor {
    pub fn new(min_port: u16, max_port: u16, max_attempts: usize) -> Self {
        Self {
            min_port: min_port.max(1024),
            max_port: max_port.min(65535),
            max_attempts,
        }
    }

    /// Secure Poisson port prediction with overflow protection
    pub fn secure_poisson_port_guess(
        &self,
        prediction: &crate::nat_detection::PortPrediction,
        guess_count: usize,
    ) -> Result<Vec<u16>, PortPredictionError> {
        if guess_count > self.max_attempts {
            return Err(PortPredictionError::TooManyAttempts(guess_count));
        }

        let now = self.safe_now_ms().saturating_sub(prediction.test_finished_at);
        let poisson_lambda = prediction.avg_delta.abs();
        
        // Validate Poisson parameter to prevent extreme values
        if poisson_lambda > 1000.0 {
            warn!("Poisson lambda too large: {}, clamping to 1000", poisson_lambda);
        }
        let safe_lambda = poisson_lambda.min(1000.0);
        
        let poisson = Poisson::new(safe_lambda)?;
        let mut rng = rand::thread_rng();
        
        let mut ports = Vec::with_capacity(guess_count);
        let mut cumulative = 0i64; // Use i64 for intermediate calculations
        
        for i in 1..=guess_count {
            let sample = poisson.sample(&mut rng) as i64;
            cumulative = cumulative.saturating_add(sample);
            
            // Safe port calculation with overflow protection
            let base_port = prediction.last_port as i64;
            let time_factor = i as i64 * safe_lambda as i64 * now as i64;
            let predicted_port = base_port
                .saturating_add(time_factor)
                .saturating_add(cumulative);
            
            // Normalize to valid port range
            let valid_port = self.normalize_port(predicted_port);
            
            if ports.len() < guess_count && !ports.contains(&valid_port) {
                ports.push(valid_port);
            }
        }
        
        debug!("Secure Poisson prediction: {} unique ports", ports.len());
        Ok(ports)
    }

    /// Secure linear port prediction with overflow protection
    pub fn secure_linear_port_guess(
        &self,
        last_port: u16,
        delta: i16,
        count: usize,
    ) -> Result<Vec<u16>, PortPredictionError> {
        if count > self.max_attempts {
            return Err(PortPredictionError::TooManyAttempts(count));
        }

        let mut ports = Vec::with_capacity(count);
        
        for i in 1..=count {
            // Use i64 for intermediate calculations to prevent overflow
            let predicted = last_port as i64 + i as i64 * delta as i64;
            let normalized = self.normalize_port(predicted);
            
            if !ports.contains(&normalized) {
                ports.push(normalized);
            }
        }
        
        debug!("Secure linear prediction: {} unique ports", ports.len());
        Ok(ports)
    }

    /// Secure birthday attack port prediction with cryptographic randomness
    pub fn secure_birthday_attack_guess(
        &self,
        center_port: u16,
        range: u16,
        count: usize,
    ) -> Result<Vec<u16>, PortPredictionError> {
        if count > self.max_attempts {
            return Err(PortPredictionError::TooManyAttempts(count));
        }

        let half_range = range / 2;
        let start_port = center_port.saturating_sub(half_range).max(self.min_port);
        let end_port = (center_port.saturating_add(half_range)).min(self.max_port);
        
        if start_port >= end_port {
            return Err(PortPredictionError::InvalidRange(start_port, end_port));
        }

        let range_size = end_port.saturating_sub(start_port) as usize;
        if count > range_size {
            warn!("Requesting {} ports from range of size {}", count, range_size);
        }

        let mut ports = Vec::with_capacity(count.min(range_size));
        let mut used = HashSet::with_capacity(count);
        let mut rng = rand::thread_rng();
        
        let mut attempts = 0;
        while ports.len() < count && attempts < self.max_attempts {
            let port_offset = rand::Rng::gen_range(&mut rng, 0..range_size);
            let port = start_port + port_offset as u16;
            
            if used.insert(port) {
                ports.push(port);
            }
            attempts += 1;
        }
        
        ports.sort_unstable();
        debug!("Secure birthday attack: {} unique ports in range {}-{} (attempts: {})", 
               ports.len(), start_port, end_port, attempts);
        
        Ok(ports)
    }

    /// Adaptive secure port prediction based on NAT type
    pub fn secure_adaptive_port_guess(
        &self,
        nat_type: &crate::nat_detection::DeltaType,
        prediction: &crate::nat_detection::PortPrediction,
        guess_count: usize,
    ) -> Result<Vec<u16>, PortPredictionError> {
        match nat_type {
            crate::nat_detection::DeltaType::Equal => {
                // Equal NAT: port stays the same
                Ok(vec![prediction.last_port])
            }
            crate::nat_detection::DeltaType::Preserve => {
                // Preserve NAT: consistent linear progression
                self.secure_linear_port_guess(prediction.last_port, 1, guess_count)
            }
            crate::nat_detection::DeltaType::Independent { value: _ } => {
                // Independent NAT: use Poisson distribution
                self.secure_poisson_port_guess(prediction, guess_count)
            }
            crate::nat_detection::DeltaType::Dependent { value } => {
                // Dependent NAT: use Poisson with observed delta
                let mut adjusted_prediction = prediction.clone();
                adjusted_prediction.avg_delta = *value as f64;
                self.secure_poisson_port_guess(&adjusted_prediction, guess_count)
            }
            crate::nat_detection::DeltaType::Random => {
                // Random NAT: use secure birthday attack
                self.secure_birthday_attack_guess(prediction.last_port, 1000, guess_count)
            }
        }
    }

    /// Calculate optimal secure guess count based on NAT type and constraints
    pub fn optimal_secure_guess_count(
        &self,
        nat_type: &crate::nat_detection::DeltaType,
        time_budget_ms: u64,
    ) -> usize {
        let base_count = match nat_type {
            crate::nat_detection::DeltaType::Equal => 1,
            crate::nat_detection::DeltaType::Preserve => 20,
            crate::nat_detection::DeltaType::Independent { .. } => 50,
            crate::nat_detection::DeltaType::Dependent { .. } => 50,
            crate::nat_detection::DeltaType::Random => 100,
        };

        // Adjust based on time budget (assuming ~100ms per attempt)
        let max_by_time = (time_budget_ms / 100).max(1) as usize;
        base_count.min(max_by_time).min(self.max_attempts)
    }

    /// Normalize port value to valid range with overflow protection
    fn normalize_port(&self, port: i64) -> u16 {
        let clamped = port.clamp(self.min_port as i64, self.max_port as i64);
        
        // Handle wraparound for negative values
        if clamped < 0 {
            self.max_port
        } else if clamped > u16::MAX as i64 {
            self.min_port
        } else {
            clamped as u16
        }
    }

    /// Safe timestamp generation with overflow protection
    fn safe_now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_millis() as u64
    }

    /// Validate port range for security
    pub fn validate_port_range(&self, ports: &[u16]) -> Result<(), PortPredictionError> {
        for port in ports {
            if *port < self.min_port || *port > self.max_port {
                return Err(PortPredictionError::PortOutOfRange(*port, self.min_port, self.max_port));
            }
        }
        Ok(())
    }
}

/// Secure port prediction errors
#[derive(Debug, thiserror::Error)]
pub enum PortPredictionError {
    #[error("Too many attempts requested: {0}")]
    TooManyAttempts(usize),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Port out of range: {0} (valid range: {1}-{2})")]
    PortOutOfRange(u16, u16, u16),
    
    #[error("Invalid port range: {0}-{1}")]
    InvalidRange(u16, u16),
    
    #[error("Poisson parameter error")]
    PoissonError,
}

impl From<rand_distr::PoissonError> for PortPredictionError {
    fn from(_: rand_distr::PoissonError) -> Self {
        PortPredictionError::PoissonError
    }
}

/// Secure port prediction message with validation
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SecurePortPredictionMsg {
    pub ports: Vec<u16>,
    pub nat_type: String,
    pub timestamp_ms: u64,
    pub valid_for_ms: u64,
    pub max_port: u16,
    pub min_port: u16,
}

impl SecurePortPredictionMsg {
    pub fn new(ports: Vec<u16>, nat_type: &str, valid_for_ms: u64, min_port: u16, max_port: u16) -> Result<Self, PortPredictionError> {
        let predictor = SecurePortPredictor::new(min_port, max_port, 1000);
        predictor.validate_port_range(&ports)?;
        
        Ok(Self {
            ports,
            nat_type: nat_type.to_string(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0))
                .as_millis() as u64,
            valid_for_ms,
            max_port,
            min_port,
        })
    }
    
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_millis() as u64;
        now > self.timestamp_ms.saturating_add(self.valid_for_ms)
    }
    
    pub fn validate(&self) -> Result<(), PortPredictionError> {
        let predictor = SecurePortPredictor::new(self.min_port, self.max_port, 1000);
        predictor.validate_port_range(&self.ports)?;
        
        if self.is_expired() {
            return Err(PortPredictionError::InvalidParameter("Message expired".to_string()));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat_detection::{DeltaType, PortPrediction};

    #[test]
    fn test_secure_linear_port_guess() {
        let predictor = SecurePortPredictor::default();
        let ports = predictor.secure_linear_port_guess(5000, 1, 5).unwrap();
        assert_eq!(ports, vec![5001, 5002, 5003, 5004, 5005]);
    }

    #[test]
    fn test_secure_linear_port_wraparound() {
        let predictor = SecurePortPredictor::default();
        let ports = predictor.secure_linear_port_guess(65534, 2, 3).unwrap();
        assert_eq!(ports, vec![0, 2, 4]); // Wraps around safely
    }

    #[test]
    fn test_secure_birthday_attack_guess() {
        let predictor = SecurePortPredictor::default();
        let ports = predictor.secure_birthday_attack_guess(30000, 100, 10).unwrap();
        assert_eq!(ports.len(), 10);
        
        // All ports should be in valid range
        for port in &ports {
            assert!(*port >= 1024 && *port <= 65535);
        }
        
        // Should be sorted
        assert!(ports.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_secure_adaptive_equal_nat() {
        let predictor = SecurePortPredictor::default();
        let prediction = PortPrediction {
            avg_delta: 0.0,
            time_elapsed_ms: 1000,
            last_port: 5000,
            test_finished_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64 - 1000,
        };
        
        let ports = predictor.secure_adaptive_port_guess(&DeltaType::Equal, &prediction, 10).unwrap();
        assert_eq!(ports, vec![5000]); // Only one port for Equal NAT
    }

    #[test]
    fn test_port_validation() {
        let predictor = SecurePortPredictor::new(2000, 3000, 100);
        let valid_ports = vec![2500, 2750, 2999];
        assert!(predictor.validate_port_range(&valid_ports).is_ok());
        
        let invalid_ports = vec![500, 2500, 3500];
        assert!(predictor.validate_port_range(&invalid_ports).is_err());
    }

    #[test]
    fn test_overflow_protection() {
        let predictor = SecurePortPredictor::default();
        
        // Test extreme values that would cause overflow in naive implementation
        let ports = predictor.secure_linear_port_guess(60000, 10000, 10).unwrap();
        assert_eq!(ports.len(), 10);
        
        // All ports should be in valid range despite extreme delta
        for port in &ports {
            assert!(*port >= 1024 && *port <= 65535);
        }
    }
}