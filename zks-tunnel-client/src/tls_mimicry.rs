//! TLS Protocol Mimicry Module
//!
//! Makes ZKS traffic look like TLS 1.3 to evade Deep Packet Inspection (DPI).
//!
//! Features:
//! - TLS record layer framing
//! - SNI (Server Name Indication) injection
//! - Dummy packet generation (adaptive)
//! - Zero-copy framing

use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// TLS content types
#[allow(dead_code)]
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
#[allow(dead_code)]
const TLS_CONTENT_TYPE_APPLICATION: u8 = 0x17;
#[allow(dead_code)]
const TLS_CONTENT_TYPE_ALERT: u8 = 0x15;

/// TLS version (1.2 for compatibility)
#[allow(dead_code)]
const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];

/// TLS mimicry configuration
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TlsMimicryConfig {
    /// Enable TLS framing
    pub enabled: bool,
    /// Target domain for SNI
    pub target_domain: String,
    /// Enable dummy packets
    pub dummy_packets: bool,
    /// Minimum packet rate (packets per second)
    pub min_rate: f64,
}

#[allow(dead_code)]
impl TlsMimicryConfig {
    /// Default configuration (balanced mode)
    pub fn default() -> Self {
        Self {
            enabled: true,
            target_domain: "cloudflare.com".to_string(),
            dummy_packets: false,
            min_rate: 10.0,
        }
    }

    /// Stealth mode (full mimicry)
    pub fn stealth() -> Self {
        Self {
            enabled: true,
            target_domain: "cloudflare.com".to_string(),
            dummy_packets: true,
            min_rate: 20.0,
        }
    }
}

/// TLS record layer framing
#[allow(dead_code)]
pub struct TlsMimicry {
    /// Configuration
    config: TlsMimicryConfig,
    /// Pre-allocated TLS record header buffer
    header_buf: [u8; 5],
}

impl TlsMimicry {
    /// Create new TLS mimicry with configuration
    pub fn new(config: TlsMimicryConfig) -> Self {
        Self {
            config,
            header_buf: [0u8; 5],
        }
    }

    /// Wrap payload in TLS record layer format
    pub fn wrap_in_tls_record(&mut self, payload: &[u8], content_type: u8) -> Vec<u8> {
        if !self.config.enabled {
            return payload.to_vec();
        }

        let record_len = payload.len();

        // TLS Record Header: [Type (1) | Version (2) | Length (2)]
        self.header_buf[0] = content_type;
        self.header_buf[1..3].copy_from_slice(&TLS_VERSION_1_2);
        self.header_buf[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());

        // Combine header + payload
        let mut result = Vec::with_capacity(5 + record_len);
        result.extend_from_slice(&self.header_buf);
        result.extend_from_slice(payload);
        result
    }

    /// Wrap handshake message (for key exchange)
    pub fn wrap_handshake(&mut self, zks_message: &[u8]) -> Vec<u8> {
        self.wrap_in_tls_record(zks_message, TLS_CONTENT_TYPE_HANDSHAKE)
    }

    /// Wrap application data (for VPN traffic)
    pub fn wrap_application(&mut self, zks_message: &[u8]) -> Vec<u8> {
        self.wrap_in_tls_record(zks_message, TLS_CONTENT_TYPE_APPLICATION)
    }

    /// Unwrap TLS record (extract payload)
    pub fn unwrap_tls_record(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if !self.config.enabled {
            return Ok(data.to_vec());
        }

        if data.len() < 5 {
            return Err("TLS record too short".to_string());
        }

        // Verify TLS record header
        let _content_type = data[0];
        let version = &data[1..3];
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if version != TLS_VERSION_1_2 {
            return Err("Invalid TLS version".to_string());
        }

        if data.len() < 5 + length {
            return Err("Incomplete TLS record".to_string());
        }

        // Extract payload
        Ok(data[5..5 + length].to_vec())
    }
}

/// SNI (Server Name Indication) injection
#[allow(dead_code)]
pub struct SniInjector {
    /// Target domain for SNI
    target_domain: String,
}

#[allow(dead_code)]
impl SniInjector {
    /// Create new SNI injector
    pub fn new(target_domain: String) -> Self {
        Self { target_domain }
    }

    /// Build SNI extension for TLS ClientHello
    pub fn build_sni_extension(&self) -> Vec<u8> {
        let domain_bytes = self.target_domain.as_bytes();
        let mut extension = Vec::new();

        // Extension Type: server_name (0x0000)
        extension.extend_from_slice(&[0x00, 0x00]);

        // Extension Length
        let ext_len = (domain_bytes.len() + 5) as u16;
        extension.extend_from_slice(&ext_len.to_be_bytes());

        // SNI List Length
        let list_len = (domain_bytes.len() + 3) as u16;
        extension.extend_from_slice(&list_len.to_be_bytes());

        // Name Type: host_name (0x00)
        extension.push(0x00);

        // Name Length
        let name_len = domain_bytes.len() as u16;
        extension.extend_from_slice(&name_len.to_be_bytes());

        // Name
        extension.extend_from_slice(domain_bytes);

        extension
    }

    /// Inject SNI into ClientHello message
    pub fn inject_sni(&self, client_hello: &mut Vec<u8>) {
        let sni_extension = self.build_sni_extension();
        client_hello.extend_from_slice(&sni_extension);
    }
}

/// Dummy packet generator (adaptive)
#[allow(dead_code)]
pub struct DummyPacketGenerator {
    /// Configuration
    config: TlsMimicryConfig,
    /// Last real packet time
    last_real_packet: Instant,
    /// Dummy packet interval
    dummy_interval: Duration,
}

impl DummyPacketGenerator {
    /// Create new dummy packet generator
    pub fn new(config: TlsMimicryConfig) -> Self {
        let dummy_interval = Duration::from_secs_f64(1.0 / config.min_rate);
        Self {
            config,
            last_real_packet: Instant::now(),
            dummy_interval,
        }
    }

    /// Update last real packet time
    pub fn mark_real_packet(&mut self) {
        self.last_real_packet = Instant::now();
    }

    /// Check if dummy packet should be sent
    pub fn should_send_dummy(&self) -> bool {
        if !self.config.dummy_packets {
            return false;
        }

        self.last_real_packet.elapsed() > self.dummy_interval
    }

    /// Generate dummy packet (random size, random content)
    pub fn generate_dummy_packet(&self) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Random size between 300-1200 bytes
        let size = rng.gen_range(300..1200);
        let mut packet = vec![0u8; size];
        getrandom::getrandom(&mut packet).ok();
        packet
    }

    /// Send dummy packet if needed
    pub async fn maintain_rate<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), std::io::Error> {
        if self.should_send_dummy() {
            let dummy = self.generate_dummy_packet();
            writer.write_all(&dummy).await?;
            self.last_real_packet = Instant::now();
        }
        Ok(())
    }
}

/// Combined TLS mimicry with all features
#[allow(dead_code)]
pub struct CombinedTlsMimicry {
    tls_mimicry: TlsMimicry,
    sni_injector: SniInjector,
    dummy_generator: DummyPacketGenerator,
}

#[allow(dead_code)]
impl CombinedTlsMimicry {
    /// Create new combined TLS mimicry
    pub fn new(config: TlsMimicryConfig) -> Self {
        let sni_injector = SniInjector::new(config.target_domain.clone());
        let dummy_generator = DummyPacketGenerator::new(config.clone());
        let tls_mimicry = TlsMimicry::new(config);

        Self {
            tls_mimicry,
            sni_injector,
            dummy_generator,
        }
    }

    /// Wrap handshake with TLS framing and SNI
    pub fn wrap_handshake_with_sni(&mut self, zks_message: &[u8]) -> Vec<u8> {
        // Note: SNI injection would require parsing TLS ClientHello structure
        // For now, we just wrap in TLS record layer
        self.tls_mimicry.wrap_handshake(zks_message)
    }

    /// Wrap application data with TLS framing
    pub fn wrap_application(&mut self, zks_message: &[u8]) -> Vec<u8> {
        self.dummy_generator.mark_real_packet();
        self.tls_mimicry.wrap_application(zks_message)
    }

    /// Unwrap TLS record
    pub fn unwrap(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.tls_mimicry.unwrap_tls_record(data)
    }

    /// Maintain dummy packet rate
    pub async fn maintain_rate<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), std::io::Error> {
        self.dummy_generator.maintain_rate(writer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_record_framing() {
        let config = TlsMimicryConfig::default();
        let mut mimicry = TlsMimicry::new(config);

        let payload = b"Hello, World!";
        let wrapped = mimicry.wrap_application(payload);

        // Check TLS record header
        assert_eq!(wrapped[0], TLS_CONTENT_TYPE_APPLICATION);
        assert_eq!(&wrapped[1..3], &TLS_VERSION_1_2);
        assert_eq!(
            u16::from_be_bytes([wrapped[3], wrapped[4]]),
            payload.len() as u16
        );

        // Check payload
        assert_eq!(&wrapped[5..], payload);

        // Unwrap
        let unwrapped = mimicry.unwrap_tls_record(&wrapped).unwrap();
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn test_sni_extension() {
        let injector = SniInjector::new("cloudflare.com".to_string());
        let sni = injector.build_sni_extension();

        // Check extension type (server_name = 0x0000)
        assert_eq!(&sni[0..2], &[0x00, 0x00]);

        // Check domain is present
        assert!(sni.windows(14).any(|w| w == b"cloudflare.com"));
    }

    #[test]
    fn test_dummy_packet_generation() {
        let config = TlsMimicryConfig::stealth();
        let generator = DummyPacketGenerator::new(config);

        let dummy = generator.generate_dummy_packet();

        // Check size is in expected range
        assert!(dummy.len() >= 300 && dummy.len() <= 1200);
    }
}
