//! Windows Routing Management via Win32 API
//!
//! This module provides routing management for Windows using the Win32 IP Helper API
//! instead of shell commands, following Mullvad VPN's approach for reliability.

#[cfg(target_os = "windows")]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(target_os = "windows")]
use tracing::{debug, error, info, warn};
#[cfg(target_os = "windows")]
use widestring::WideCString;

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry,
        MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_IN},
};

#[cfg(target_os = "windows")]
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Add a route via Win32 API
#[cfg(target_os = "windows")]
pub fn add_route(
    destination: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    interface_index: u32,
    metric: u32,
) -> Result<()> {
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        
        // Initialize the row structure
        InitializeIpForwardEntry(&raw mut row);
        
        // Set interface
        row.InterfaceIndex = interface_index;
        
        // Set destination prefix
        row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        let dest_bytes = destination.octets();
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b1 = dest_bytes[0];
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b2 = dest_bytes[1];
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b3 = dest_bytes[2];
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b4 = dest_bytes[3];
        
        // Calculate prefix length from netmask
        row.DestinationPrefix.PrefixLength = netmask_to_prefix_len(netmask);
        
        // Set next hop (gateway)
        row.NextHop.Ipv4.sin_family = AF_INET;
        let gw_bytes = gateway.octets();
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b1 = gw_bytes[0];
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b2 = gw_bytes[1];
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b3 = gw_bytes[2];
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b4 = gw_bytes[3];
        
        // Set metric
        row.Metric = metric;
        
        // Set protocol and origin
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Origin = NlroManual;
        
        let status = CreateIpForwardEntry2(&raw const row);
        
        if status == ERROR_SUCCESS {
            info!(
                "✅ Added route {}/{} via {} (IF: {}, metric: {})",
                destination,
                row.DestinationPrefix.PrefixLength,
                gateway,
                interface_index,
                metric
            );
            Ok(())
        } else {
            let err_msg = format!("Failed to add route: Win32 error {}", status);
            error!("{}", err_msg);
            Err(err_msg.into())
        }
    }
}

/// Delete a route via Win32 API
#[cfg(target_os = "windows")]
pub fn delete_route(
    destination: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    interface_index: u32,
) -> Result<()> {
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        
        // Set interface
        row.InterfaceIndex = interface_index;
        
        // Set destination
        row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        let dest_bytes = destination.octets();
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b1 = dest_bytes[0];
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b2 = dest_bytes[1];
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b3 = dest_bytes[2];
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b4 = dest_bytes[3];
        
        row.DestinationPrefix.PrefixLength = netmask_to_prefix_len(netmask);
        
        // Set next hop
        row.NextHop.Ipv4.sin_family = AF_INET;
        let gw_bytes = gateway.octets();
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b1 = gw_bytes[0];
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b2 = gw_bytes[1];
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b3 = gw_bytes[2];
        row.NextHop.Ipv4.sin_addr.S_un.S_un_b.s_b4 = gw_bytes[3];
        
        let status = DeleteIpForwardEntry2(&raw const row);
        
        if status == ERROR_SUCCESS {
            info!(
                "✅ Deleted route {}/{} via {} (IF: {})",
                destination,
                row.DestinationPrefix.PrefixLength,
                gateway,
                interface_index
            );
            Ok(())
        } else {
            debug!("Route not found or already deleted: Win32 error {}", status);
            Ok(()) // Ignore errors for route deletion
        }
    }
}

/// Convert netmask to prefix length
#[cfg(target_os = "windows")]
fn netmask_to_prefix_len(netmask: Ipv4Addr) -> u8 {
    let mask_bits = u32::from_be_bytes(netmask.octets());
    mask_bits.count_ones() as u8
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;
    
    #[test]
    fn test_netmask_conversion() {
        assert_eq!(netmask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(netmask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix_len(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix_len(Ipv4Addr::new(128, 0, 0, 0)), 1);
    }
}
