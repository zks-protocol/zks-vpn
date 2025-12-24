use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn};

pub struct LinuxKillSwitch;

impl LinuxKillSwitch {
    pub fn new() -> Self {
        Self
    }

    pub async fn enable(
        &self,
        allowed_ips: Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if nftables is available
        if Command::new("nft").arg("--version").output().is_err() {
            warn!("nftables not found, falling back to iptables (TODO)");
            return Err(
                std::io::Error::new(std::io::ErrorKind::NotFound, "nftables not found").into(),
            );
        }

        // Clean up any existing rules to ensure clean state
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "zks_vpn"])
            .output();

        // Create table
        Command::new("nft")
            .args(["add", "table", "inet", "zks_vpn"])
            .output()?;

        // Create chains with default drop policy
        Command::new("nft")
            .args([
                "add",
                "chain",
                "inet",
                "zks_vpn",
                "input",
                "{ type filter hook input priority 0; policy drop; }",
            ])
            .output()?;
        Command::new("nft")
            .args([
                "add",
                "chain",
                "inet",
                "zks_vpn",
                "output",
                "{ type filter hook output priority 0; policy drop; }",
            ])
            .output()?;

        // Allow loopback
        Command::new("nft")
            .args([
                "add", "rule", "inet", "zks_vpn", "input", "iifname", "lo", "accept",
            ])
            .output()?;
        Command::new("nft")
            .args([
                "add", "rule", "inet", "zks_vpn", "output", "oifname", "lo", "accept",
            ])
            .output()?;

        // Allow established/related
        Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                "zks_vpn",
                "input",
                "ct",
                "state",
                "established,related",
                "accept",
            ])
            .output()?;
        Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                "zks_vpn",
                "output",
                "ct",
                "state",
                "established,related",
                "accept",
            ])
            .output()?;

        // Allow TUN interface (VPN traffic)
        Command::new("nft")
            .args([
                "add", "rule", "inet", "zks_vpn", "input", "iifname", "tun*", "accept",
            ])
            .output()?;
        Command::new("nft")
            .args([
                "add", "rule", "inet", "zks_vpn", "output", "oifname", "tun*", "accept",
            ])
            .output()?;

        // Allow DHCP (UDP 67/68)
        Command::new("nft")
            .args([
                "add", "rule", "inet", "zks_vpn", "output", "udp", "dport", "{67, 68}", "accept",
            ])
            .output()?;
        Command::new("nft")
            .args([
                "add", "rule", "inet", "zks_vpn", "input", "udp", "sport", "{67, 68}", "accept",
            ])
            .output()?;

        // Allow specific IPs (Relay/Exit)
        for ip in allowed_ips {
            let ip_str = ip.to_string();
            Command::new("nft")
                .args([
                    "add", "rule", "inet", "zks_vpn", "output", "ip", "daddr", &ip_str, "accept",
                ])
                .output()?;
            Command::new("nft")
                .args([
                    "add", "rule", "inet", "zks_vpn", "input", "ip", "saddr", &ip_str, "accept",
                ])
                .output()?;
        }

        info!("Kill switch enabled (nftables) - all non-VPN traffic blocked");
        Ok(())
    }

    pub async fn update_allowed_ips(
        &self,
        allowed_ips: Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Re-enable to refresh rules
        self.enable(allowed_ips).await
    }

    pub async fn disable(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Delete table
        Command::new("nft")
            .args(["delete", "table", "inet", "zks_vpn"])
            .output()?;

        info!("Kill switch disabled (nftables)");
        Ok(())
    }
}
