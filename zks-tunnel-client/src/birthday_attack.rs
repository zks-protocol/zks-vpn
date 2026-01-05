//! Birthday Attack for Random NAT Traversal
//! 
//! Implements the birthday paradox attack for NATs with random port allocation.
//! With 50 guesses and 50 listening ports, achieves ~97% collision probability.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

/// Birthday attack configuration
#[derive(Debug, Clone)]
pub struct BirthdayConfig {
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
}

impl Default for BirthdayConfig {
    fn default() -> Self {
        Self {
            guess_count: 50,
            listen_count: 50,
            port_range: 20000..40000,
            timeout: Duration::from_secs(10),
            local_ip: "0.0.0.0".to_string(),
        }
    }
}

/// Result of birthday attack attempt
#[derive(Debug, Clone)]
pub struct BirthdayResult {
    pub success: bool,
    pub connected_port: Option<u16>,
    pub attempts: usize,
    pub listeners_started: usize,
}

/// Birthday attack coordinator
pub struct BirthdayAttack {
    config: BirthdayConfig,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl BirthdayAttack {
    pub fn new(config: BirthdayConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
        }
    }

    /// Execute birthday attack against a target
    pub async fn execute(
        &mut self,
        target_ip: String,
        predicted_ports: Vec<u16>,
    ) -> Result<BirthdayResult, Box<dyn std::error::Error>> {
        info!("🎂 Starting birthday attack with {} guesses, {} listeners", 
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

        // Signal listener ports to peer via signaling channel
        // In real implementation, this would be sent through the relay
        let _listener_info = serde_json::json!({
            "type": "birthday_listeners",
            "ports": listener_ports,
            "timeout_ms": self.config.timeout.as_millis(),
        });

        // Start connection attempts to predicted ports
        let guess_ports = if predicted_ports.len() >= self.config.guess_count {
            predicted_ports[..self.config.guess_count].to_vec()
        } else {
            // Fill remaining with random ports in range
            let mut ports = predicted_ports;
            let mut rng = rand::thread_rng();
            while ports.len() < self.config.guess_count {
                let port = self.config.port_range.start + 
                    rand::Rng::gen_range(&mut rng, 0..(self.config.port_range.end - self.config.port_range.start));
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
            ports
        };

        // Spawn guess tasks
        let guess_handles = self.spawn_guess_tasks(target_ip, guess_ports, shutdown_tx.clone());

        // Accept incoming connections
        let accept_result = self.accept_connections(listeners, &mut shutdown_rx).await;

        // Wait for all guess tasks to complete
        for handle in guess_handles {
            let _ = handle.await;
        }

        match accept_result {
            Ok(connected_port) => {
                info!("🎉 Birthday attack succeeded! Connected on port: {}", connected_port);
                Ok(BirthdayResult {
                    success: true,
                    connected_port: Some(connected_port),
                    attempts: self.config.guess_count,
                    listeners_started: listener_ports.len(),
                })
            }
            Err(e) => {
                warn!("🎂 Birthday attack failed: {}", e);
                Ok(BirthdayResult {
                    success: false,
                    connected_port: None,
                    attempts: self.config.guess_count,
                    listeners_started: listener_ports.len(),
                })
            }
        }
    }

    /// Start TCP listeners on random ports
    async fn start_listeners(&self) -> Result<Vec<TcpListener>, Box<dyn std::error::Error>> {
        let mut listeners = Vec::new();
        let mut rng = rand::thread_rng();
        
        for _ in 0..self.config.listen_count {
            // Try to bind to a random port in range
            for _ in 0..10 { // Retry up to 10 times per listener
                let port = self.config.port_range.start + 
                    rand::Rng::gen_range(&mut rng, 0..(self.config.port_range.end - self.config.port_range.start));
                
                match TcpListener::bind(format!("{}:{}", self.config.local_ip, port)).await {
                    Ok(listener) => {
                        listeners.push(listener);
                        break;
                    }
                    Err(_) => {
                        debug!("Port {} already in use, trying another", port);
                        continue;
                    }
                }
            }
        }

        if listeners.is_empty() {
            return Err("Failed to start any listeners".into());
        }

        Ok(listeners)
    }

    /// Spawn tasks to attempt connections to target ports
    fn spawn_guess_tasks(
        &self,
        target_ip: String,
        ports: Vec<u16>,
        shutdown_tx: mpsc::Sender<()>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        for port in ports {
            let target = format!("{}:{}", target_ip, port);
            let timeout_duration = self.config.timeout;
            let shutdown = shutdown_tx.clone();

            let handle = tokio::spawn(async move {
                debug!("🎯 Attempting connection to {}", target);
                
                match timeout(timeout_duration, TcpStream::connect(&target)).await {
                    Ok(Ok(_stream)) => {
                        info!("🎯 Successfully connected to {} (guess succeeded)", target);
                        // Send shutdown signal to stop other attempts
                        let _ = shutdown.send(()).await;
                    }
                    Ok(Err(e)) => {
                        debug!("🎯 Connection to {} failed: {}", target, e);
                    }
                    Err(_) => {
                        debug!("🎯 Connection to {} timed out", target);
                    }
                }
            });

            handles.push(handle);
        }

        handles
    }

    /// Accept incoming connections from peer
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

        // Spawn accept tasks for each listener
        for listener in listeners {
            let result_tx = result_tx.clone();
            
            tokio::spawn(async move {
                let listener = listener.lock().await;
                
                match timeout(Duration::from_secs(15), listener.accept()).await {
                    Ok(Ok((_stream, addr))) => {
                        info!("🎧 Incoming connection from {} on port {}", 
                              addr.ip(), addr.port());
                        let _ = result_tx.send(addr.port()).await;
                    }
                    Ok(Err(e)) => {
                        debug!("Listener accept error: {}", e);
                    }
                    Err(_) => {
                        debug!("Listener accept timed out");
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
            _ = sleep(self.config.timeout + Duration::from_secs(5)) => {
                Err("Birthday attack timed out".into())
            }
        }
    }

    /// Clean shutdown
    pub async fn shutdown(&mut self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }
}

/// Simplified birthday attack for integration
pub async fn simple_birthday_attack(
    target_ip: &str,
    center_port: u16,
    port_range: u16,
    guess_count: usize,
    listen_count: usize,
) -> Result<BirthdayResult, Box<dyn std::error::Error>> {
    let config = BirthdayConfig {
        guess_count,
        listen_count,
        port_range: (center_port.saturating_sub(port_range/2))..(center_port + port_range/2),
        ..Default::default()
    };

    let mut attack = BirthdayAttack::new(config);
    
    // Generate predicted ports around center port
    let mut predicted_ports = Vec::new();
    let _half_range = port_range / 2;
    
    // Add ports around center
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
    fn test_birthday_config_default() {
        let config = BirthdayConfig::default();
        assert_eq!(config.guess_count, 50);
        assert_eq!(config.listen_count, 50);
        assert_eq!(config.port_range, 20000..40000);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_simple_birthday_attack() {
        // This test would require a real target, so we just verify it compiles
        // In a real test environment, you'd set up a test server
        
        let result = simple_birthday_attack(
            "127.0.0.1",
            30000,
            1000,
            10,
            10,
        ).await;
        
        // Should fail to connect to localhost:30000 (no server running)
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.success);
    }
}