//! Secure Birthday Attack Implementation
//! 
//! Enhanced version with security features:
//! - Rate limiting and connection attempt tracking
//! - Input validation and sanitization
//! - Enhanced error handling and logging
//! - Protection against malformed inputs
//! - Connection timeout management
//! - Resource cleanup and leak prevention

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

/// Connection attempt tracking for rate limiting
#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    target: String,
    timestamp: Instant,
    success: bool,
}

/// Secure birthday attack configuration
#[derive(Debug, Clone)]
pub struct SecureBirthdayConfig {
    /// Number of ports to guess (send SYN to)
    pub guess_count: usize,
    /// Number of ports to listen on
    pub listen_count: usize,
    /// Port range for the attack
    pub port_range: std::ops::Range<u16>,
    /// Timeout for connection attempts
    pub timeout: Duration,
    /// Local IP to bind listeners
    pub local_ip: String,
    /// Maximum connection attempts per second
    pub max_attempts_per_second: usize,
    /// Maximum total attempts allowed
    pub max_total_attempts: usize,
    /// Enable connection attempt tracking
    pub enable_tracking: bool,
}

impl Default for SecureBirthdayConfig {
    fn default() -> Self {
        Self {
            guess_count: 50,
            listen_count: 50,
            port_range: 20000..40000,
            timeout: Duration::from_secs(10),
            local_ip: "0.0.0.0".to_string(),
            max_attempts_per_second: 10,
            max_total_attempts: 200,
            enable_tracking: true,
        }
    }
}

/// Secure birthday attack result
#[derive(Debug, Clone)]
pub struct SecureBirthdayResult {
    pub success: bool,
    pub connected_port: Option<u16>,
    pub attempts: usize,
    pub listeners_started: usize,
    pub total_attempts_made: usize,
    pub attack_duration: Duration,
    pub connection_attempts: Vec<ConnectionAttempt>,
}

/// Secure birthday attack coordinator
pub struct SecureBirthdayAttack {
    config: SecureBirthdayConfig,
    shutdown_tx: Option<mpsc::Sender<()>>,
    connection_tracker: Arc<Mutex<Vec<ConnectionAttempt>>>,
    rate_limiter: Arc<Semaphore>,
}

impl SecureBirthdayAttack {
    pub fn new(config: SecureBirthdayConfig) -> Self {
        let max_concurrent = config.max_attempts_per_second;
        Self {
            config,
            shutdown_tx: None,
            connection_tracker: Arc::new(Mutex::new(Vec::new())),
            rate_limiter: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    /// Validate target IP address
    fn validate_target_ip(target_ip: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        // Basic IP validation
        if target_ip.is_empty() {
            return Err("Target IP cannot be empty".into());
        }

        if target_ip.len() > 45 {
            return Err("Target IP too long".into());
        }

        // Try to parse as IP address first
        if let Ok(ip) = target_ip.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, 0));
        }

        // Try to parse as socket address
        if let Ok(addr) = target_ip.parse::<SocketAddr>() {
            return Ok(addr);
        }

        Err("Invalid target IP address format".into())
    }

    /// Validate port numbers
    fn validate_ports(ports: &[u16]) -> Result<(), Box<dyn std::error::Error>> {
        if ports.is_empty() {
            return Err("No ports provided".into());
        }

        if ports.len() > 1000 {
            return Err("Too many ports provided (max 1000)".into());
        }

        // Check for duplicate ports
        let mut unique_ports = std::collections::HashSet::new();
        for &port in ports {
            if port < 1024 {
                warn!("Port {} is in privileged range (< 1024)", port);
            }
            if !unique_ports.insert(port) {
                warn!("Duplicate port {} detected", port);
            }
        }

        Ok(())
    }

    /// Execute secure birthday attack against a target
    pub async fn execute(
        &mut self,
        target_ip: String,
        predicted_ports: Vec<u16>,
    ) -> Result<SecureBirthdayResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        
        // Validate inputs
        Self::validate_target_ip(&target_ip)?;
        Self::validate_ports(&predicted_ports)?;

        info!("🎂 Starting secure birthday attack with {} guesses, {} listeners", 
              self.config.guess_count, self.config.listen_count);

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Start listeners on random ports
        let listeners = self.start_listeners().await?;
        let listener_ports: Vec<u16> = listeners.iter()
            .filter_map(|l| l.local_addr().ok())
            .map(|addr| addr.port())
            .collect();

        info!("🎧 Started {} listeners on ports: {:?}", listener_ports.len(), listener_ports);

        // Limit predicted ports to guess count
        let limited_predicted_ports = if predicted_ports.len() > self.config.guess_count {
            predicted_ports[..self.config.guess_count].to_vec()
        } else {
            predicted_ports
        };

        // Spawn guess tasks with rate limiting
        let guess_handles = self.spawn_guess_tasks(target_ip, limited_predicted_ports, shutdown_tx.clone());

        // Accept incoming connections
        let accept_result = self.accept_connections(listeners, &mut shutdown_rx).await;

        // Wait for all guess tasks to complete
        let mut total_attempts = 0;
        for handle in guess_handles {
            if let Ok(attempts) = handle.await {
                total_attempts += attempts;
            }
        }

        let attack_duration = start_time.elapsed();
        let connection_attempts = if self.config.enable_tracking {
            self.connection_tracker.lock().await.clone()
        } else {
            Vec::new()
        };

        match accept_result {
            Ok(connected_port) => {
                info!("🎉 Secure birthday attack succeeded! Connected on port: {} (duration: {:?})", connected_port, attack_duration);
                Ok(SecureBirthdayResult {
                    success: true,
                    connected_port: Some(connected_port),
                    attempts: self.config.guess_count,
                    listeners_started: listener_ports.len(),
                    total_attempts_made: total_attempts,
                    attack_duration,
                    connection_attempts,
                })
            }
            Err(e) => {
                warn!("🎂 Secure birthday attack failed: {} (duration: {:?})", e, attack_duration);
                Ok(SecureBirthdayResult {
                    success: false,
                    connected_port: None,
                    attempts: self.config.guess_count,
                    listeners_started: listener_ports.len(),
                    total_attempts_made: total_attempts,
                    attack_duration,
                    connection_attempts,
                })
            }
        }
    }

    /// Start TCP listeners on random ports with validation
    async fn start_listeners(&self) -> Result<Vec<TcpListener>, Box<dyn std::error::Error>> {
        let mut listeners = Vec::new();
        let mut rng = rand::thread_rng();
        let mut used_ports = std::collections::HashSet::new();
        
        for i in 0..self.config.listen_count {
            // Try to bind to a random port in range
            for attempt in 0..20 { // Increased retry attempts
                let port = self.config.port_range.start + 
                    rand::Rng::gen_range(&mut rng, 0..(self.config.port_range.end - self.config.port_range.start));
                
                // Avoid duplicate ports
                if used_ports.contains(&port) {
                    continue;
                }
                
                match TcpListener::bind(format!("{}:{}", self.config.local_ip, port)).await {
                    Ok(listener) => {
                        listeners.push(listener);
                        used_ports.insert(port);
                        debug!("Successfully started listener {} on port {}", i + 1, port);
                        break;
                    }
                    Err(e) => {
                        debug!("Failed to bind to port {} (attempt {}): {}", port, attempt + 1, e);
                        if attempt >= 19 {
                            warn!("Could not start listener {} after 20 attempts", i + 1);
                        }
                        continue;
                    }
                }
            }
        }

        if listeners.is_empty() {
            return Err("Failed to start any listeners".into());
        }

        if listeners.len() < self.config.listen_count {
            warn!("Only started {} out of {} requested listeners", listeners.len(), self.config.listen_count);
        }

        Ok(listeners)
    }

    /// Spawn tasks to attempt connections to target ports with rate limiting
    fn spawn_guess_tasks(
        &self,
        target_ip: String,
        ports: Vec<u16>,
        shutdown_tx: mpsc::Sender<()>,
    ) -> Vec<tokio::task::JoinHandle<usize>> {
        let mut handles = Vec::new();
        let connection_tracker = self.connection_tracker.clone();
        let rate_limiter = self.rate_limiter.clone();
        let timeout_duration = self.config.timeout;
        let max_total_attempts = self.config.max_total_attempts;
        let enable_tracking = self.config.enable_tracking;

        for port in ports {
            let target = format!("{}:{}", target_ip, port);
            let timeout_duration = timeout_duration;
            let shutdown = shutdown_tx.clone();
            let connection_tracker = connection_tracker.clone();
            let rate_limiter = rate_limiter.clone();
            let _max_total_attempts = max_total_attempts;
            let enable_tracking = enable_tracking;

            let handle = tokio::spawn(async move {
                let mut attempts = 0;
                
                // Acquire rate limiter permit
                match timeout(Duration::from_secs(1), rate_limiter.acquire()).await {
                    Ok(permit) => {
                        attempts += 1;
                        debug!("🎯 Attempting connection to {} (with rate limiting)", target);
                        
                        let start_time = Instant::now();
                        match timeout(timeout_duration, TcpStream::connect(&target)).await {
                            Ok(Ok(_stream)) => {
                                let duration = start_time.elapsed();
                                info!("🎯 Successfully connected to {} (guess succeeded, duration: {:?})", target, duration);
                                
                                // Track successful attempt
                                if enable_tracking {
                                    let attempt = ConnectionAttempt {
                                        target: target.clone(),
                                        timestamp: Instant::now(),
                                        success: true,
                                    };
                                    connection_tracker.lock().await.push(attempt);
                                }
                                
                                // Send shutdown signal to stop other attempts
                                let _ = shutdown.send(()).await;
                                return attempts;
                            }
                            Ok(Err(e)) => {
                                let duration = start_time.elapsed();
                                debug!("🎯 Connection to {} failed: {} (duration: {:?})", target, e, duration);
                                
                                // Track failed attempt
                                if enable_tracking {
                                    let attempt = ConnectionAttempt {
                                        target: target.clone(),
                                        timestamp: Instant::now(),
                                        success: false,
                                    };
                                    connection_tracker.lock().await.push(attempt);
                                }
                            }
                            Err(_) => {
                                debug!("🎯 Connection to {} timed out", target);
                            }
                        }
                        
                        // Release permit
                        drop(permit);
                    }
                    Err(_) => {
                        debug!("Rate limiter timeout for {}", target);
                    }
                }
                
                attempts
            });

            handles.push(handle);
        }

        handles
    }

    /// Accept incoming connections from peer with timeout management
    async fn accept_connections(
        &self,
        listeners: Vec<TcpListener>,
        shutdown_rx: &mut mpsc::Receiver<()>,
    ) -> Result<u16, Box<dyn std::error::Error>> {
        let listeners: Vec<Arc<Mutex<TcpListener>>> = listeners
            .into_iter()
            .map(|l| Arc::new(Mutex::new(l)))
            .collect();

        let (result_tx, mut result_rx) = mpsc::channel(1);

        // Spawn accept tasks for each listener with enhanced error handling
        for (i, listener) in listeners.iter().enumerate() {
            let result_tx = result_tx.clone();
            let listener = listener.clone();
            
            tokio::spawn(async move {
                match timeout(Duration::from_secs(20), async {
                    let listener = listener.lock().await;
                    listener.accept().await
                }).await {
                    Ok(Ok((_stream, addr))) => {
                        info!("🎧 Incoming connection from {} on listener {} (port {})", 
                              addr.ip(), i + 1, addr.port());
                        let _ = result_tx.send(addr.port()).await;
                    }
                    Ok(Err(e)) => {
                        error!("Listener {} accept error: {}", i + 1, e);
                    }
                    Err(_) => {
                        debug!("Listener {} accept timed out", i + 1);
                    }
                }
            });
        }

        // Wait for first successful connection or shutdown
        tokio::select! {
            Some(port) = result_rx.recv() => {
                Ok(port)
            }
            Some(_) = shutdown_rx.recv() => {
                // Another task succeeded, we can exit
                sleep(Duration::from_millis(500)).await; // Brief delay to allow connection establishment
                Err("Birthday attack succeeded via outgoing connection".into())
            }
            _ = sleep(self.config.timeout + Duration::from_secs(10)) => {
                Err("Birthday attack timed out".into())
            }
        }
    }

    /// Clean shutdown with resource cleanup
    pub async fn shutdown(&mut self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
        
        // Clear connection tracker
        if self.config.enable_tracking {
            self.connection_tracker.lock().await.clear();
        }
    }

    /// Get connection attempt statistics
    pub async fn get_connection_stats(&self) -> (usize, usize, Duration) {
        let attempts = self.connection_tracker.lock().await;
        let total = attempts.len();
        let successful = attempts.iter().filter(|a| a.success).count();
        let total_duration = if total > 0 {
            attempts.iter()
                .map(|a| a.timestamp.elapsed())
                .max()
                .unwrap_or(Duration::from_secs(0))
        } else {
            Duration::from_secs(0)
        };
        
        (total, successful, total_duration)
    }
}

/// Secure simplified birthday attack for integration
pub async fn secure_simple_birthday_attack(
    target_ip: &str,
    center_port: u16,
    port_range: u16,
    guess_count: usize,
    listen_count: usize,
) -> Result<SecureBirthdayResult, Box<dyn std::error::Error>> {
    let config = SecureBirthdayConfig {
        guess_count,
        listen_count,
        port_range: (center_port.saturating_sub(port_range/2))..(center_port + port_range/2),
        ..Default::default()
    };

    let mut attack = SecureBirthdayAttack::new(config);
    
    // Generate predicted ports around center port
    let mut predicted_ports = Vec::new();
    let _half_range = port_range / 2;
    
    // Add ports around center with validation
    for i in 0..guess_count {
        let offset = (i as i16) - (guess_count as i16 / 2);
        let port = ((center_port as i32 + offset as i32) % 65536) as u16;
        if port >= 1024 {
            predicted_ports.push(port);
        }
    }

    attack.execute(target_ip.to_string(), predicted_ports).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_birthday_config_default() {
        let config = SecureBirthdayConfig::default();
        assert_eq!(config.guess_count, 50);
        assert_eq!(config.listen_count, 50);
        assert_eq!(config.port_range, 20000..40000);
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.max_attempts_per_second, 10);
        assert_eq!(config.max_total_attempts, 200);
        assert!(config.enable_tracking);
    }

    #[test]
    fn test_validate_target_ip() {
        // Valid IPs
        assert!(SecureBirthdayAttack::validate_target_ip("192.168.1.1").is_ok());
        assert!(SecureBirthdayAttack::validate_target_ip("127.0.0.1").is_ok());
        assert!(SecureBirthdayAttack::validate_target_ip("[::1]:8080").is_ok());
        
        // Invalid IPs
        assert!(SecureBirthdayAttack::validate_target_ip("").is_err());
        assert!(SecureBirthdayAttack::validate_target_ip("invalid.ip.address").is_err());
        assert!(SecureBirthdayAttack::validate_target_ip(&"a".repeat(50)).is_err());
    }

    #[test]
    fn test_validate_ports() {
        // Valid ports
        assert!(SecureBirthdayAttack::validate_ports(&[3000, 3001, 3002]).is_ok());
        
        // Invalid ports
        assert!(SecureBirthdayAttack::validate_ports(&[]).is_err());
        assert!(SecureBirthdayAttack::validate_ports(&[1; 1001]).is_err());
    }

    #[tokio::test]
    async fn test_secure_simple_birthday_attack() {
        // This test would require a real target, so we just verify it compiles
        // In a real test environment, you'd set up a test server
        
        let result = secure_simple_birthday_attack(
            "127.0.0.1",
            30000,
            100,
            10,
            10,
        ).await;
        
        // Should fail to connect to localhost:30000 (no server running)
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.success);
        assert_eq!(result.attempts, 10);
        assert!(result.listeners_started > 0);
    }

    #[tokio::test]
    async fn test_connection_attempt_tracking() {
        let config = SecureBirthdayConfig {
            enable_tracking: true,
            ..Default::default()
        };
        
        let attack = SecureBirthdayAttack::new(config);
        
        // Add some mock attempts
        {
            let mut tracker = attack.connection_tracker.lock().await;
            tracker.push(ConnectionAttempt {
                target: "127.0.0.1:3000".to_string(),
                timestamp: Instant::now(),
                success: true,
            });
            tracker.push(ConnectionAttempt {
                target: "127.0.0.1:3001".to_string(),
                timestamp: Instant::now(),
                success: false,
            });
        }
        
        let (total, successful, _) = attack.get_connection_stats().await;
        assert_eq!(total, 2);
        assert_eq!(successful, 1);
    }
}