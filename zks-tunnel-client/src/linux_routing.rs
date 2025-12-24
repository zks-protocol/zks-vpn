//! Linux Routing Management via Netlink
//!
//! This module provides routing management for Linux using the rtnetlink library
//! instead of shell commands, following Mullvad VPN's approach for reliability.

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use tracing::{debug, info};

#[cfg(target_os = "linux")]
use rtnetlink::Handle;

#[cfg(target_os = "linux")]
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Add a default route via netlink (0.0.0.0/0)
#[cfg(target_os = "linux")]
pub async fn add_default_route(gateway: Ipv4Addr, interface_index: u32, metric: u32) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Add default route (0.0.0.0/0) - rtnetlink 0.15.0 API
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
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Add route using rtnetlink 0.15.0 API
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
        destination, prefix_len, gateway, interface_index, metric
    );
    Ok(())
}

/// Delete a default route via netlink
#[cfg(target_os = "linux")]
pub async fn delete_default_route(gateway: Ipv4Addr) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Delete default route (0.0.0.0/0) using rtnetlink 0.15.0 API
    handle
        .route()
        .del()
        .v4()
        .destination_prefix(Ipv4Addr::new(0, 0, 0, 0), 0)
        .gateway(gateway)
        .execute()
        .await?;

    info!("✅ Deleted default route via {}", gateway);
    Ok(())
}

/// Delete a specific route via netlink
#[cfg(target_os = "linux")]
pub async fn delete_route(destination: Ipv4Addr, prefix_len: u8, gateway: Ipv4Addr) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Delete route using rtnetlink 0.15.0 API
    handle
        .route()
        .del()
        .v4()
        .destination_prefix(destination, prefix_len)
        .gateway(gateway)
        .execute()
        .await?;

    info!(
        "✅ Deleted route {}/{} via {}",
        destination, prefix_len, gateway
    );
    Ok(())
}

/// Helper function to get route handle for advanced operations
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub async fn get_handle() -> Result<Handle> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires root privileges
    async fn test_add_delete_route() {
        let dest = Ipv4Addr::new(10, 0, 0, 0);
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let interface_index = 1; // lo interface
        let metric = 100;

        // Add route
        add_route(dest, 8, gateway, interface_index, metric)
            .await
            .expect("Failed to add route");

        // Delete route
        delete_route(dest, 8, gateway)
            .await
            .expect("Failed to delete route");
    }
}
