use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub struct WindowsKillSwitch {
    original_fw_policy: Arc<Mutex<Option<String>>>,
}

impl WindowsKillSwitch {
    pub fn new() -> Self {
        Self {
            original_fw_policy: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn enable(
        &self,
        allowed_ips: Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::env;

        // Save current policy
        let show = Command::new("netsh")
            .args(["advfirewall", "show", "currentprofile"])
            .output()?;
        if show.status.success() {
            let text = String::from_utf8_lossy(&show.stdout).to_string();
            let mut guard = self.original_fw_policy.lock().await;
            *guard = Some(text);
        }

        // Block all outbound by default
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                "currentprofile",
                "firewallpolicy",
                "blockinbound,blockoutbound",
            ])
            .output()?;

        // Allow this executable
        if let Ok(exe) = env::current_exe() {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=ZKS-VPN",
                    "dir=out",
                    "action=allow",
                    &format!("program={}", exe.display()),
                ])
                .output()?;
        }

        // Allow localhost
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=ZKS-Localhost",
                "dir=out",
                "action=allow",
                "remoteip=127.0.0.0/8",
            ])
            .output()?;

        // Allow specific IPs (Relay/Exit)
        for ip in allowed_ips {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=ZKS-AllowIP",
                    "dir=out",
                    "action=allow",
                    &format!("remoteip={}", ip),
                ])
                .output()?;
        }

        info!("Kill switch enabled - all non-VPN traffic blocked");
        Ok(())
    }

    pub async fn update_allowed_ips(
        &self,
        allowed_ips: Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Remove old IP rules
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=ZKS-AllowIP",
            ])
            .output()?;

        // Add new IP rules
        for ip in allowed_ips {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=ZKS-AllowIP",
                    "dir=out",
                    "action=allow",
                    &format!("remoteip={}", ip),
                ])
                .output()?;
        }
        Ok(())
    }

    pub async fn disable(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Delete our rules
        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=ZKS-VPN"])
            .output()?;

        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=ZKS-Localhost",
            ])
            .output()?;

        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=ZKS-AllowIP",
            ])
            .output()?;

        // Restore default policy
        // Note: This is a simplification. Ideally we parse original_fw_policy.
        // For now, we set it to "blockinbound,allowoutbound" which is standard.
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                "currentprofile",
                "firewallpolicy",
                "blockinbound,allowoutbound",
            ])
            .output()?;

        info!("Kill switch disabled");
        Ok(())
    }
}
