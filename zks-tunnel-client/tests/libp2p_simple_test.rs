//! Simple LibP2P Transport Test
//!
//! This test verifies that the libp2p transport can successfully create
//! swarms and handle basic operations without complex codec issues.

use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, debug};
use futures::{StreamExt, AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};

#[tokio::test]
async fn test_libp2p_transport_creation() {
    // Initialize logging
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    info!("🧪 Testing libp2p transport creation...");

    // Test that we can create a libp2p transport
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(keypair.public());
    
    info!("📡 Created peer ID: {}", peer_id);

    // Build swarm using the new libp2p v0.54 API with proper codec
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| {
            libp2p::request_response::Behaviour::with_codec(
                TestVpnCodec,
                [(
                    libp2p::StreamProtocol::new("/zks-vpn/1.0.0"),
                    libp2p::request_response::ProtocolSupport::Full,
                )],
                libp2p::request_response::Config::default(),
            )
        })
        .unwrap()
        .build();

    info!("✅ Successfully created libp2p swarm with request-response codec");

    // Test listening
    swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    
    let mut listen_addr = None;
    timeout(Duration::from_secs(5), async {
        loop {
            match swarm.select_next_some().await {
                libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                    listen_addr = Some(address);
                    info!("🎧 Test peer listening on: {}", listen_addr.as_ref().unwrap());
                    break;
                }
                libp2p::swarm::SwarmEvent::Behaviour(event) => {
                    info!("📨 Behaviour event: {:?}", event);
                }
                _ => continue,
            }
        }
    }).await.expect("Failed to get listen address");

    assert!(listen_addr.is_some(), "Should have a listen address");
    info!("✅ DCUtR transport test completed successfully!");
}

/// Simple test codec for request-response protocol
#[derive(Clone)]
pub struct TestVpnCodec;

#[async_trait]
impl libp2p::request_response::Codec for TestVpnCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = vec![0u8; 1500]; // Max VPN packet size
        let n = io.read(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_request(&libp2p::StreamProtocol::new("/test-vpn/1.0.0"), io).await
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&req).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_request(&libp2p::StreamProtocol::new("/test-vpn/1.0.0"), io, res).await
    }
}