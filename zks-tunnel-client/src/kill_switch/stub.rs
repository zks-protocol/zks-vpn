use std::net::IpAddr;

pub struct StubKillSwitch;

impl StubKillSwitch {
    pub fn new() -> Self {
        Self
    }

    pub async fn enable(
        &self,
        _allowed_ips: Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn update_allowed_ips(
        &self,
        _allowed_ips: Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub async fn disable(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
