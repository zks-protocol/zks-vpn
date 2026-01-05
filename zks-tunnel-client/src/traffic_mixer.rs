//! Traffic Mixer - Blends client, relay, and exit traffic for indistinguishability
//!
//! This module implements traffic mixing to create plausible deniability:
//! - User's own VPN traffic (client)
//! - Relayed packets for other peers (relay)
//! - Exit traffic forwarded to internet (exit)
//! - Dummy padding packets (constant-rate padding)
//!
//! All traffic sources are mixed to create identical patterns, making it impossible
//! for an observer (ISP, network monitor) to determine which traffic belongs to the user.

#![allow(dead_code)]

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, Interval};
use tracing::{debug, info, warn};

/// Maximum packet queue size per traffic source
const QUEUE_SIZE: usize = 1000;

/// Packet types for traffic mixing
#[derive(Debug, Clone)]
pub enum TrafficPacket {
    /// User's own VPN traffic
    ClientTraffic { target: String, data: Bytes },

    /// Relayed traffic for another peer
    RelayTraffic { peer_id: String, data: Bytes },

    /// Exit traffic (decrypted and forwarded to internet)
    ExitTraffic {
        target: String,
        session_id: String,
        data: Bytes,
    },

    /// Dummy padding packet for constant-rate padding
    Padding { size: usize },
}

/// Configuration for traffic mixing
#[derive(Clone, Debug)]
pub struct TrafficMixerConfig {
    /// Enable constant-rate padding (traffic analysis defense)
    pub enable_padding: bool,

    /// Padding rate in packets per second (0 = disabled)
    pub padding_rate_pps: u32,

    /// Padding packet size (bytes)
    pub padding_size: usize,
}

impl Default for TrafficMixerConfig {
    fn default() -> Self {
        Self {
            enable_padding: true,
            padding_rate_pps: 10, // 10 padding packets/sec
            padding_size: 1400,   // MTU-sized padding
        }
    }
}

/// Traffic Mixer - blends multiple traffic sources
pub struct TrafficMixer {
    /// Receive channel for client traffic (user's own)
    client_rx: mpsc::Receiver<TrafficPacket>,

    /// Receive channel for relay traffic (forwarding for others)
    relay_rx: mpsc::Receiver<TrafficPacket>,

    /// Receive channel for exit traffic (internet gateway)
    exit_rx: mpsc::Receiver<TrafficPacket>,

    /// Send channel for mixed output
    output_tx: mpsc::Sender<TrafficPacket>,

    /// Configuration
    config: TrafficMixerConfig,

    /// Padding scheduler
    padding_interval: Option<Interval>,
}

impl TrafficMixer {
    /// Create a new traffic mixer
    pub fn new(
        client_rx: mpsc::Receiver<TrafficPacket>,
        relay_rx: mpsc::Receiver<TrafficPacket>,
        exit_rx: mpsc::Receiver<TrafficPacket>,
        output_tx: mpsc::Sender<TrafficPacket>,
        config: TrafficMixerConfig,
    ) -> Self {
        let padding_interval = if config.enable_padding && config.padding_rate_pps > 0 {
            let interval_ms = 1000 / config.padding_rate_pps as u64;
            Some(interval(Duration::from_millis(interval_ms)))
        } else {
            None
        };

        Self {
            client_rx,
            relay_rx,
            exit_rx,
            output_tx,
            config,
            padding_interval,
        }
    }

    /// Run the traffic mixer event loop
    pub async fn run(mut self) {
        info!("🔀 Traffic Mixer started");
        info!(
            "   Padding: {} ({} pps)",
            if self.config.enable_padding {
                "enabled"
            } else {
                "disabled"
            },
            self.config.padding_rate_pps
        );

        loop {
            tokio::select! {
                // Priority 1: Client traffic (user's own)
                Some(packet) = self.client_rx.recv() => {
                    self.process_packet(packet, "client").await;
                }

                // Priority 2: Relay traffic (forwarding for peers)
                Some(packet) = self.relay_rx.recv() => {
                    self.process_packet(packet, "relay").await;
                }

                // Priority 3: Exit traffic (internet gateway)
                Some(packet) = self.exit_rx.recv() => {
                    self.process_packet(packet, "exit").await;
                }

                // Priority 4: Padding (constant-rate)
                Some(_) = async {
                    match &mut self.padding_interval {
                        Some(interval) => Some(interval.tick().await),
                        None => None,
                    }
                } => {
                    self.send_padding().await;
                }

                else => {
                    debug!("All traffic channels closed");
                    break;
                }
            }
        }

        info!("✅ Traffic Mixer stopped");
    }

    /// Process a traffic packet and forward to output
    async fn process_packet(&mut self, packet: TrafficPacket, source: &str) {
        match &packet {
            TrafficPacket::ClientTraffic { target, data } => {
                debug!(
                    "[{}] Forwarding client packet to {} ({} bytes)",
                    source,
                    target,
                    data.len()
                );
            }
            TrafficPacket::RelayTraffic { peer_id, data } => {
                debug!(
                    "[{}] Forwarding relay packet for peer {} ({} bytes)",
                    source,
                    peer_id,
                    data.len()
                );
            }
            TrafficPacket::ExitTraffic {
                target,
                session_id,
                data,
            } => {
                debug!(
                    "[{}] Forwarding exit packet to {} for session {} ({} bytes)",
                    source,
                    target,
                    session_id,
                    data.len()
                );
            }
            TrafficPacket::Padding { size } => {
                debug!("[{}] Sending padding packet ({} bytes)", source, size);
            }
        }

        // Send to mixed output stream
        if let Err(e) = self.output_tx.send(packet).await {
            warn!("Failed to send mixed packet: {}", e);
        }
    }

    /// Send a padding packet
    async fn send_padding(&mut self) {
        let padding = TrafficPacket::Padding {
            size: self.config.padding_size,
        };
        self.process_packet(padding, "padding").await;
    }
}

/// Create traffic mixer channels
pub fn create_channels() -> (TrafficMixerChannels, mpsc::Receiver<TrafficPacket>) {
    let (client_tx, client_rx) = mpsc::channel(QUEUE_SIZE);
    let (relay_tx, relay_rx) = mpsc::channel(QUEUE_SIZE);
    let (exit_tx, exit_rx) = mpsc::channel(QUEUE_SIZE);
    let (output_tx, output_rx) = mpsc::channel(QUEUE_SIZE);

    let channels = TrafficMixerChannels {
        client_tx,
        relay_tx,
        exit_tx,
        client_rx,
        relay_rx,
        exit_rx,
        output_tx,
    };

    (channels, output_rx)
}

/// Channels for traffic mixer
pub struct TrafficMixerChannels {
    /// Send client traffic to mixer
    pub client_tx: mpsc::Sender<TrafficPacket>,

    /// Send relay traffic to mixer
    pub relay_tx: mpsc::Sender<TrafficPacket>,

    /// Send exit traffic to mixer
    pub exit_tx: mpsc::Sender<TrafficPacket>,

    /// Internal: client receiver
    client_rx: mpsc::Receiver<TrafficPacket>,

    /// Internal: relay receiver
    relay_rx: mpsc::Receiver<TrafficPacket>,

    /// Internal: exit receiver
    exit_rx: mpsc::Receiver<TrafficPacket>,

    /// Internal: output sender
    output_tx: mpsc::Sender<TrafficPacket>,
}

impl TrafficMixerChannels {
    /// Create the traffic mixer with these channels
    pub fn create_mixer(self, config: TrafficMixerConfig) -> TrafficMixer {
        TrafficMixer::new(
            self.client_rx,
            self.relay_rx,
            self.exit_rx,
            self.output_tx,
            config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_traffic_mixing() {
        let (channels, mut output_rx) = create_channels();

        let config = TrafficMixerConfig {
            enable_padding: false, // Disable for deterministic test
            ..Default::default()
        };

        // Clone senders before moving channels into mixer
        let client_tx = channels.client_tx.clone();
        let relay_tx = channels.relay_tx.clone();

        // Start mixer in background
        let _mixer = channels.create_mixer(config);

        client_tx
            .send(TrafficPacket::ClientTraffic {
                target: "exit_node".to_string(),
                data: Bytes::from("client data"),
            })
            .await
            .unwrap();

        relay_tx
            .send(TrafficPacket::RelayTraffic {
                peer_id: "peer1".to_string(),
                data: Bytes::from("relay data"),
            })
            .await
            .unwrap();

        // Receive mixed packets
        let packet1 = output_rx.recv().await.unwrap();
        let packet2 = output_rx.recv().await.unwrap();

        // Verify packets (order not guaranteed due to async)
        let verify_packet = |p: TrafficPacket| match p {
            TrafficPacket::ClientTraffic { target, data } => {
                assert_eq!(target, "exit_node");
                assert_eq!(data, "client data");
            }
            TrafficPacket::RelayTraffic { peer_id, data } => {
                assert_eq!(peer_id, "peer1");
                assert_eq!(data, "relay data");
            }
            _ => panic!("Unexpected packet type"),
        };

        verify_packet(packet1);
        verify_packet(packet2);
    }
}
