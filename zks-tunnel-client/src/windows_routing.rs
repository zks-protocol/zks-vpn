//! Windows Routing Management via Win32 API
//!
//! This module provides routing management for Windows using the Win32 IP Helper API
//! instead of shell commands, following Mullvad VPN's approach for reliability.

#[cfg(target_os = "windows")]
use std::net::Ipv4Addr;
#[cfg(target_os = "windows")]
use tracing::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, GetAdaptersAddresses, GetIpInterfaceEntry,
        InitializeIpForwardEntry, SetIpInterfaceEntry, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
        MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    },
    Networking::WinSock::{NlroManual, AF_INET, AF_INET6, AF_UNSPEC, MIB_IPPROTO_NETMGMT},
};

#[cfg(target_os = "windows")]
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Get TUN interface index by name pattern (e.g., "tun")
#[cfg(target_os = "windows")]
pub fn get_tun_interface_index(name_pattern: &str) -> Result<u32> {
    unsafe {
        const BUFFER_SIZE: usize = 15 * 1024;
        let mut buffer: Vec<u8> = vec![0; BUFFER_SIZE];
        let mut buffer_size = buffer.len() as u32;

        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        // Note: Removed GAA_FLAG_SKIP_FRIENDLY_NAME to allow searching by FriendlyName

        let status = GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &raw mut buffer_size,
        );

        if status != ERROR_SUCCESS {
            if status == ERROR_BUFFER_OVERFLOW {
                buffer.resize(buffer_size as usize, 0);
                let status = GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &raw mut buffer_size,
                );
                if status != ERROR_SUCCESS {
                    return Err(format!("GetAdaptersAddresses failed: {}", status).into());
                }
            } else if status == ERROR_NO_DATA {
                return Err("No network adapters found".into());
            } else {
                return Err(format!("GetAdaptersAddresses failed: {}", status).into());
            }
        }

        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        let mut all_adapters: Vec<String> = Vec::new();

        while !adapter.is_null() {
            let adapter_ref = &*adapter;
            let pattern_lower = name_pattern.to_lowercase();
            let index = adapter_ref.Anonymous1.Anonymous.IfIndex;

            // Check AdapterName (GUID-like name)
            if !adapter_ref.AdapterName.is_null() {
                let adapter_name = std::ffi::CStr::from_ptr(adapter_ref.AdapterName as *const i8)
                    .to_string_lossy();
                all_adapters.push(format!("{}(idx:{})", adapter_name, index));

                if adapter_name.to_lowercase().contains(&pattern_lower) {
                    info!(
                        "Found TUN adapter by AdapterName: {} (index: {})",
                        adapter_name, index
                    );
                    return Ok(index);
                }
            }

            // Check FriendlyName (user-visible name like "Wintun Userspace Tunnel")
            if !adapter_ref.FriendlyName.is_null() {
                // FriendlyName is a wide string (PWSTR)
                let friendly_name = widestring_to_string(adapter_ref.FriendlyName);

                if friendly_name.to_lowercase().contains(&pattern_lower) {
                    info!(
                        "Found TUN adapter by FriendlyName: {} (index: {})",
                        friendly_name, index
                    );
                    return Ok(index);
                }
            }

            // Check Description (e.g., "Wintun Tunnel")
            if !adapter_ref.Description.is_null() {
                let description = widestring_to_string(adapter_ref.Description);

                if description.to_lowercase().contains(&pattern_lower) {
                    info!(
                        "Found TUN adapter by Description: {} (index: {})",
                        description, index
                    );
                    return Ok(index);
                }
            }

            adapter = adapter_ref.Next;
        }

        debug!("Available adapters: {:?}", all_adapters);
        Err(format!("No adapter matching '{}' found", name_pattern).into())
    }
}

/// Helper function to convert Windows wide string (PWSTR) to Rust String
#[cfg(target_os = "windows")]
fn widestring_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

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
                destination, row.DestinationPrefix.PrefixLength, gateway, interface_index, metric
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
                destination, row.DestinationPrefix.PrefixLength, gateway, interface_index
            );
            Ok(())
        } else {
            debug!("Route not found or already deleted: Win32 error {}", status);
            Ok(()) // Ignore errors for route deletion
        }
    }
}

/// Enable IP forwarding on a specific interface
#[cfg(target_os = "windows")]
pub fn enable_ip_forwarding(interface_index: u32) -> Result<()> {
    info!(
        "Enabling IP forwarding for interface index: {}",
        interface_index
    );

    unsafe {
        // Enable for IPv4
        let mut row_v4: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        row_v4.Family = AF_INET;
        row_v4.InterfaceIndex = interface_index;

        let status = GetIpInterfaceEntry(&mut row_v4);
        if status == ERROR_SUCCESS {
            if row_v4.ForwardingEnabled == 0 {
                row_v4.ForwardingEnabled = 1; // TRUE
                let status = SetIpInterfaceEntry(&mut row_v4);
                if status == ERROR_SUCCESS {
                    info!(
                        "✅ Programmatically enabled IPv4 forwarding for interface {}",
                        interface_index
                    );
                } else {
                    warn!(
                        "Failed to set IPv4 forwarding for interface {}: error {}",
                        interface_index, status
                    );
                }
            } else {
                debug!(
                    "IPv4 forwarding already enabled for interface {}",
                    interface_index
                );
            }
        } else {
            warn!(
                "Failed to get IPv4 interface entry for {}: error {}",
                interface_index, status
            );
        }

        // Enable for IPv6
        let mut row_v6: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        row_v6.Family = AF_INET6;
        row_v6.InterfaceIndex = interface_index;

        let status = GetIpInterfaceEntry(&mut row_v6);
        if status == ERROR_SUCCESS {
            if row_v6.ForwardingEnabled == 0 {
                row_v6.ForwardingEnabled = 1; // TRUE
                let status = SetIpInterfaceEntry(&mut row_v6);
                if status == ERROR_SUCCESS {
                    info!(
                        "✅ Programmatically enabled IPv6 forwarding for interface {}",
                        interface_index
                    );
                } else {
                    warn!(
                        "Failed to set IPv6 forwarding for interface {}: error {}",
                        interface_index, status
                    );
                }
            } else {
                debug!(
                    "IPv6 forwarding already enabled for interface {}",
                    interface_index
                );
            }
        } else {
            // IPv6 might not be enabled on the interface, don't treat as fatal error
            debug!(
                "Failed to get IPv6 interface entry for {}: error {}",
                interface_index, status
            );
        }
    }

    Ok(())
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
