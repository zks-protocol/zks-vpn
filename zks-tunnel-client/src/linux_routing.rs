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

/// Get the default WAN interface name by parsing `ip route` output
#[cfg(target_os = "linux")]
pub fn get_default_interface() -> Option<String> {
    use std::process::Command;

    // Run: ip route show default
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Example output: "default via 192.168.0.1 dev eth0 proto dhcp metric 100"
    // We want to extract the interface name after "dev "
    for line in stdout.lines() {
        if line.starts_with("default") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Find "dev" and return the next word
            for (i, part) in parts.iter().enumerate() {
                if *part == "dev" && i + 1 < parts.len() {
                    let interface = parts[i + 1].to_string();
                    info!("🌐 Detected default WAN interface: {}", interface);
                    return Some(interface);
                }
            }
        }
    }

    None
}

/// Enable NAT MASQUERADE for VPN traffic exiting to the internet
/// This is required for Exit node functionality - forwards VPN client traffic to the internet
#[cfg(target_os = "linux")]
pub fn enable_nat_masquerade(vpn_subnet: &str, wan_interface: &str) -> Result<()> {
    use std::process::Command;

    // First, enable IP forwarding
    match Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()
    {
        Ok(output) if output.status.success() => {
            info!("✅ IP forwarding enabled");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("⚠️ Failed to enable IP forwarding: {}", stderr);
        }
        Err(e) => {
            tracing::warn!("⚠️ Could not run sysctl: {}", e);
        }
    }

    // Check if rule already exists to avoid duplicates
    let check = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            vpn_subnet,
            "-o",
            wan_interface,
            "-j",
            "MASQUERADE",
        ])
        .output();

    if check.map(|o| o.status.success()).unwrap_or(false) {
        info!(
            "✅ NAT MASQUERADE already configured for {} -> {}",
            vpn_subnet, wan_interface
        );
        return Ok(());
    }

    // Add MASQUERADE rule: traffic from VPN subnet going out WAN interface gets NAT'd
    let output = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            vpn_subnet,
            "-o",
            wan_interface,
            "-j",
            "MASQUERADE",
        ])
        .output()?;

    if output.status.success() {
        info!(
            "✅ NAT MASQUERADE enabled: {} -> {} (TCP/ICMP forwarding ready)",
            vpn_subnet, wan_interface
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to add iptables MASQUERADE: {}", stderr).into())
    }
}
