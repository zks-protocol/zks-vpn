use std::net::IpAddr;

#[cfg(target_os = "linux")]
use self::linux::LinuxKillSwitch as InnerKillSwitch;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
use self::stub::StubKillSwitch as InnerKillSwitch;
#[cfg(target_os = "windows")]
use self::windows::WindowsKillSwitch as InnerKillSwitch;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub mod stub;
#[cfg(target_os = "windows")]
pub mod windows;

pub struct KillSwitch {
    inner: InnerKillSwitch,
    enabled: bool,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            inner: InnerKillSwitch::new(),
            enabled: false,
        }
    }

    pub async fn enable(
        &mut self,
        allowed_ips: Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.enabled {
            // If already enabled, just update IPs if supported
            self.inner.update_allowed_ips(allowed_ips).await?;
            return Ok(());
        }
        self.inner.enable(allowed_ips).await?;
        self.enabled = true;
        Ok(())
    }

    pub async fn disable(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.enabled {
            return Ok(());
        }
        self.inner.disable().await?;
        self.enabled = false;
        Ok(())
    }
}
