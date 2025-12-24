//! DNS Leak Protection for ZKS VPN
//!
//! Based on Mullvad VPN's talpid-dns implementation
//! https://github.com/mullvad/mullvadvpn-app/tree/main/talpid-dns
//!
//! This module ensures all DNS queries go through the VPN tunnel,
//! preventing DNS leaks that could de-anonymize users.

use std::net::IpAddr;
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// DNS Guard for preventing DNS leaks
pub struct DnsGuard {
    #[cfg(target_os = "windows")]
    inner: windows::WindowsDnsGuard,

    #[cfg(target_os = "linux")]
    inner: linux::LinuxDnsGuard,

    original_dns: Vec<IpAddr>,
    enabled: bool,
}

impl DnsGuard {
    /// Create a new DNS guard
    pub fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(target_os = "windows")]
            inner: windows::WindowsDnsGuard::new()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?,

            #[cfg(target_os = "linux")]
            inner: linux::LinuxDnsGuard::new()?,

            original_dns: Vec::new(),
            enabled: false,
        })
    }

    /// Enable DNS protection with specified DNS server
    /// Sets the VPN DNS and blocks all other DNS traffic
    pub async fn enable(&mut self, interface_name: &str, dns_servers: Vec<IpAddr>) -> Result<()> {
        if self.enabled {
            warn!("DNS guard already enabled");
            return Ok(());
        }

        info!(
            "Enabling DNS leak protection with servers: {:?}",
            dns_servers
        );

        // Platform-specific DNS configuration
        #[cfg(target_os = "windows")]
        self.inner
            .set_dns(interface_name, dns_servers.clone())
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        #[cfg(target_os = "linux")]
        self.inner
            .set_dns(interface_name, dns_servers.clone())
            .await?;

        self.original_dns = dns_servers;
        self.enabled = true;

        info!("✅ DNS leak protection enabled");
        Ok(())
    }

    /// Disable DNS protection and restore original DNS
    pub async fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        info!("Disabling DNS leak protection");

        #[cfg(target_os = "windows")]
        self.inner
            .reset_dns()
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        #[cfg(target_os = "linux")]
        self.inner.reset_dns().await?;

        self.enabled = false;

        info!("✅ DNS leak protection disabled");
        Ok(())
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if self.enabled {
            debug!("DNS guard dropped while enabled");
            // DNS settings will be restored when process exits
            // No need for complex tokio runtime creation in Drop
        }
    }
}
