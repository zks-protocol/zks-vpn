//! Linux Routing Management via Netlink
//!
//! This module provides routing management for Linux using the rtnetlink library
//! instead of shell commands, following Mullvad VPN's approach for reliability.

#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use tracing::{debug, error, info, warn};

#[cfg(target_os = "linux")]
use ipnetwork::Ipv4Network;
#[cfg(target_os = "linux")]
use rtnetlink::{new_connection, Handle, IpVersion};

#[cfg(target_os = "linux")]
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Add a default route via netlink
#[cfg(target_os = "linux")]
pub async fn add_default_route(gateway: Ipv4Addr, interface_index: u32, metric: u32) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    
    // Add default route (0.0.0.0/0)
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(Ipv4Addr::new(0, 0, 0, 0), 0)
        .gateway(gateway)
        .output_interface(interface_index)
        .priority(metric)
        .execute()
        .await?;
    
    info!(
        "✅ Added default route via {} (IF: {}, metric: {})",
        gateway, interface_index, metric
    );
    Ok(())
}

/// Add a specific route via netlink
#[cfg(target_os = "linux")]
pub async fn add_route(
    destination: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    interface_index: u32,
    metric: u32,
) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(destination, prefix_len)
        .gateway(gateway)
        .output_interface(interface_index)
        .priority(metric)
        .execute()
        .await?;
    
    info!(
        "✅ Added route {}/{} via {} (IF: {}, metric: {})",
        destination,
        prefix_len,
        gateway,
        interface_index,
        metric
    );
    Ok(())
}

/// Delete a default route via netlink
#[cfg(target_os = "linux")]
pub async fn delete_default_route(gateway: Ipv4Addr) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    
    // Get all IPv4 routes
    let mut routes = handle.route().get(IpVersion::V4).execute();
    
    // Find and delete default route
    while let Some(route) = routes.try_next().await? {
        // Check if this is a default route (0.0.0.0/0)
        if let Some(dest) = route.destination_prefix() {
            if dest.prefix_len == 0 {
                // Check if gateway matches
                if let Some(gw) = route.gateway() {
                    if gw == IpAddr::V4(gateway) {
                        handle.route().del(route).execute().await?;
                        info!("✅ Deleted default route via {}", gateway);
                        return Ok(());
                    }
                }
            }
        }
    }
    
    debug!("Default route via {} not found", gateway);
    Ok(())
}

/// Delete a specific route via netlink
#[cfg(target_os = "linux")]
pub async fn delete_route(
    destination: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    
    let mut routes = handle.route().get(IpVersion::V4).execute();
    
    while let Some(route) = routes.try_next().await? {
        if let Some(dest) = route.destination_prefix() {
            if dest.prefix_len == prefix_len {
                if let IpAddr::V4(dest_addr) = dest.addr {
                    if dest_addr == destination {
                        if let Some(gw) = route.gateway() {
                            if gw == IpAddr::V4(gateway) {
                                handle.route().del(route).execute().await?;
                                info!(
                                    "✅ Deleted route {}/{} via {}",
                                    destination, prefix_len, gateway
                                );
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
    
    debug!("Route {}/{} via {} not found", destination, prefix_len, gateway);
    Ok(())
}
