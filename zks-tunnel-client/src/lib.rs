#![allow(clippy::should_implement_trait)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::type_complexity)]
#![allow(clippy::len_zero)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::let_unit_value)]
#![allow(clippy::empty_line_after_outer_attr)]
#![allow(clippy::new_without_default)]
#![allow(dead_code)]
#![allow(unused_imports)]
pub mod chain;
pub mod ct_ops;
pub mod entry_node;
pub mod exit_node_udp;
pub mod exit_peer;
pub mod file_transfer;
pub mod http_proxy;
pub mod hybrid_data;
pub mod key_exchange;
pub mod p2p_client;
pub mod p2p_relay;
pub mod p2p_vpn;
pub mod packet_pool;
pub mod socks5;
pub mod stream_manager;
pub mod tunnel;
pub mod vpn;
pub mod zks_tunnel;

#[cfg(target_os = "linux")]
pub mod tun_multiqueue;
#[cfg(feature = "vpn")]
pub mod userspace_nat;

// Platform-specific routing modules
#[cfg(all(target_os = "linux", feature = "vpn"))]
pub mod linux_routing;
#[cfg(all(target_os = "windows", feature = "vpn"))]
pub mod windows_routing;

// DNS leak protection
#[cfg(feature = "vpn")]
pub mod dns_guard;
#[cfg(feature = "vpn")]
pub mod kill_switch;

pub mod cli;
pub mod utils;

#[cfg(windows)]
pub mod windows_service;

#[cfg(feature = "swarm")]
pub mod p2p_swarm;
pub mod swarm;

#[cfg(feature = "swarm")]
pub mod onion;

pub mod nat_detection;
pub mod port_prediction;
pub mod nat_traversal;
pub mod birthday_attack;
pub mod stun_security;
pub mod secure_stun;
pub mod secure_port_prediction;
pub mod secure_birthday_attack;

pub mod entropy_events;
pub mod entropy_tax;
#[cfg(feature = "vpn")]
pub mod exit_forwarder;
pub mod exit_service;
pub mod key_rotation;
pub mod recursive_chain;  // Citadel-inspired double-ratchet key evolution
pub mod relay_service;
pub mod anti_replay;  // Citadel-inspired anti-replay (replaces old replay_protection)
pub mod anti_replay_enhanced;  // Enhanced anti-replay with circular buffer
#[cfg(feature = "quantum")]
pub mod pq_signatures;  // Post-quantum ML-DSA-65 signatures
pub mod swarm_entropy_collection;
pub mod tls_mimicry;
pub mod traffic_mixer;
pub mod traffic_shaping;
pub mod scramble;  // Citadel-inspired ciphertext scrambling for traffic analysis resistance
pub mod true_vernam;

#[cfg(feature = "swarm")]
pub mod signaling;

#[cfg(feature = "swarm")]
pub mod libp2p_transport;

#[cfg(feature = "swarm")]
pub mod swarm_controller;
