//! Linux Routing Management via Netlink
//!
//! This module provides routing management for Linux using the rtnetlink library
//! instead of shell commands, following Mullvad VPN's approach for reliability.
//!
//! NOTE: This is a stub implementation. Full implementation will use rtnetlink 0.19+ API.

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use tracing::info;

#[cfg(target_os = "linux")]
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Add a default route via netlink (STUB - not yet implemented)
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub async fn add_default_route(
    _gateway: Ipv4Addr,
    _interface_index: u32,
    _metric: u32,
) -> Result<()> {
    info!("Linux routing via netlink - not yet implemented");
    info!("Use shell commands for now (ip route add default via ...)");
    Ok(())
}

/// Add a specific route via netlink (STUB - not yet implemented)
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub async fn add_route(
    _destination: Ipv4Addr,
    _prefix_len: u8,
    _gateway: Ipv4Addr,
    _interface_index: u32,
    _metric: u32,
) -> Result<()> {
    info!("Linux routing via netlink - not yet implemented");
    Ok(())
}

/// Delete a default route via netlink (STUB - not yet implemented)
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub async fn delete_default_route(_gateway: Ipv4Addr) -> Result<()> {
    info!("Linux routing cleanup via netlink - not yet implemented");
    Ok(())
}

/// Delete a specific route via netlink (STUB - not yet implemented)
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub async fn delete_route(
    _destination: Ipv4Addr,
    _prefix_len: u8,
    _gateway: Ipv4Addr,
) -> Result<()> {
    info!("Linux routing cleanup via netlink - not yet implemented");
    Ok(())
}
