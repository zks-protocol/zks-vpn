//! Linux Routing Management via Netlink
//!
//! This module provides routing management for Linux using the rtnetlink library
//! instead of shell commands, following Mullvad VPN's approach for reliability.

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use tracing::info;

#[cfg(target_os = "linux")]
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
#[cfg(target_os = "linux")]
use netlink_packet_route::AddressFamily;
#[cfg(target_os = "linux")]
use rtnetlink::new_connection;

#[cfg(target_os = "linux")]
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Add a default route via netlink (0.0.0.0/0)
#[cfg(target_os = "linux")]
pub async fn add_default_route(gateway: Ipv4Addr, interface_index: u32, metric: u32) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Build route message for rtnetlink 0.15.0
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.destination_prefix_length = 0; // 0.0.0.0/0
    route.header.table = 254; // RT_TABLE_MAIN
    route.header.protocol = RouteProtocol::Boot;
    route.header.scope = RouteScope::Universe;
    route.header.kind = RouteType::Unicast;

    // Add destination (0.0.0.0/0)
    route
        .attributes
        .push(RouteAttribute::Destination(RouteAddress::Other(vec![
            0, 0, 0, 0,
        ])));

    // Add gateway
    route
        .attributes
        .push(RouteAttribute::Gateway(RouteAddress::Other(
            gateway.octets().to_vec(),
        )));

    // Add output interface
    route.attributes.push(RouteAttribute::Oif(interface_index));

    // Add metric/priority
    route.attributes.push(RouteAttribute::Priority(metric));

    handle.route().add(route).execute().await?;

    info!(
        "✅ Added default route via {} (IF: {}, metric: {})",
        gateway, interface_index, metric
    );
    Ok(())
}

/// Delete a default route via netlink
#[cfg(target_os = "linux")]
pub async fn delete_default_route(gateway: Ipv4Addr) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Build route message for deletion
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.destination_prefix_length = 0; // 0.0.0.0/0
    route.header.table = 254; // RT_TABLE_MAIN
    route.header.protocol = RouteProtocol::Boot;
    route.header.scope = RouteScope::Universe;
    route.header.kind = RouteType::Unicast;

    // Add destination (0.0.0.0/0)
    route
        .attributes
        .push(RouteAttribute::Destination(RouteAddress::Other(vec![
            0, 0, 0, 0,
        ])));

    // Add gateway
    route
        .attributes
        .push(RouteAttribute::Gateway(RouteAddress::Other(
            gateway.octets().to_vec(),
        )));

    handle.route().del(route).execute().await?;

    info!("✅ Deleted default route via {}", gateway);
    Ok(())
}
