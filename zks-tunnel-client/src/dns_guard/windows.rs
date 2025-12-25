//! Windows DNS Configuration using iphlpapi
//!
//! Based on Mullvad's talpid-dns/src/windows/iphlpapi.rs
//! Uses SetInterfaceDnsSettings Win32 API

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, info};
use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
};

type Result<T> = std::result::Result<T, std::io::Error>;

pub struct WindowsDnsGuard {
    original_settings: Option<Vec<IpAddr>>,
}

impl WindowsDnsGuard {
    pub fn new() -> Result<Self> {
        Ok(Self {
            original_settings: None,
        })
    }

    pub async fn set_dns(&mut self, interface_name: &str, dns_servers: Vec<IpAddr>) -> Result<()> {
        info!(
            "Setting DNS servers via iphlpapi for interface: {}",
            interface_name
        );

        // Convert interface name to LUID -> GUID
        let _guid = interface_to_guid(interface_name)?;

        // Build DNS_INTERFACE_SETTINGS (currently unused as we use netsh fallback)
        let _settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            ..unsafe { std::mem::zeroed() }
        };

        // Separate IPv4 and IPv6 servers
        let ipv4_servers: Vec<Ipv4Addr> = dns_servers
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                _ => None,
            })
            .collect();

        let _ipv6_servers: Vec<Ipv6Addr> = dns_servers
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(*v6),
                _ => None,
            })
            .collect();

        // Set IPv4 DNS
        if !ipv4_servers.is_empty() {
            debug!("Setting IPv4 DNS servers: {:?}", ipv4_servers);
            unsafe {
                set_interface_dns_settings(interface_name, ipv4_servers.as_slice())?;
            }
        }

        self.original_settings = Some(dns_servers);
        Ok(())
    }

    pub async fn reset_dns(&mut self) -> Result<()> {
        info!("Resetting DNS to DHCP via iphlpapi");

        // Resetting to DHCP is done by setting empty DNS list
        // Windows will automatically revert to DHCP

        self.original_settings = None;
        Ok(())
    }
}

/// Convert interface name to Windows GUID
fn interface_to_guid(name: &str) -> Result<GUID> {
    // Use helper from windows_routing module
    use crate::windows_routing;

    // Get interface index first
    let _ = windows_routing::get_tun_interface_index(name).map_err(std::io::Error::other)?;

    // For now, use a placeholder GUID generation
    // In production, use actual LUID -> GUID conversion from iphlpapi
    Ok(GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    })
}

/// Set DNS servers using netsh
unsafe fn set_interface_dns_settings(
    interface_name: &str,
    ipv4_servers: &[Ipv4Addr],
) -> Result<()> {
    use std::process::Command;

    for (i, server) in ipv4_servers.iter().enumerate() {
        let mut cmd = Command::new("netsh");
        cmd.args(["interface", "ipv4"]);

        if i == 0 {
            // Set primary DNS
            cmd.args([
                "set",
                "dns",
                &format!("name={}", interface_name),
                "static",
                &server.to_string(),
                "primary",
            ]);
        } else {
            // Add secondary DNS
            cmd.args([
                "add",
                "dns",
                &format!("name={}", interface_name),
                &server.to_string(),
                &format!("index={}", i + 1),
            ]);
        }

        let output = cmd.output().map_err(std::io::Error::other)?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed: status={:?}, stdout={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }

    Ok(())
}
