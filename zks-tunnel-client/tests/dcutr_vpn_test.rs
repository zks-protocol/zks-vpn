//! DCUtR VPN Data Transfer Test
//!
//! This test verifies that DCUtR can establish direct P2P connections
//! and transfer VPN data using the request-response protocol.

use std::time::Duration;
use tokio::time::timeout;
use tracing::info;
use futures::{StreamExt, AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::{request_response, swarm::{SwarmEvent}, StreamProtocol};

#[tokio::test]
async fn test_dcutr_vpn_data_transfer() {
    // Initialize logging
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    info!("🧪 Starting DCUtR VPN data transfer test...");

    // Create two peers
    let keypair1 = libp2p::identity::Keypair::generate_ed25519();
    let peer_id1 = libp2p::PeerId::from(keypair1.public());
    let keypair2 = libp2p::identity::Keypair::generate_ed25519();
    let peer_id2 = libp2p::PeerId::from(keypair2.public());

    info!("📡 Created peer 1: {}", peer_id1);
    info!("📡 Created peer 2: {}", peer_id2);

    // Build swarm for peer 1
    let mut swarm1 = libp2p::SwarmBuilder::with_existing_identity(keypair1)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| {
            request_response::Behaviour::with_codec(
                TestVpnCodec,
                [(
                    libp2p::StreamProtocol::new("/zks-vpn/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            )
        })
        .unwrap()
        .build();

    // Build swarm for peer 2
    let mut swarm2 = libp2p::SwarmBuilder::with_existing_identity(keypair2)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| {
            request_response::Behaviour::with_codec(
                TestVpnCodec,
                [(
                    libp2p::StreamProtocol::new("/zks-vpn/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            )
        })
        .unwrap()
        .build();

    // Start listening on both peers
    swarm1.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    swarm2.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    // Get listen addresses
    let mut addr1 = None;
    let mut addr2 = None;

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = event {
                        addr1 = Some(address);
                        info!("🎧 Peer 1 listening on: {}", addr1.as_ref().unwrap());
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = event {
                        addr2 = Some(address);
                        info!("🎧 Peer 2 listening on: {}", addr2.as_ref().unwrap());
                    }
                }
            }
            if addr1.is_some() && addr2.is_some() {
                break;
            }
        }
    }).await.expect("Failed to get listen addresses");

    info!("✅ Both peers are listening");

    // Connect peer 1 to peer 2
    let dial_addr = addr2.as_ref().unwrap().clone().with_p2p(peer_id2).unwrap();
    swarm1.dial(dial_addr).unwrap();
    info!("📞 Peer 1 dialing peer 2...");

    // Wait for connection
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == peer_id2 {
                            info!("🔗 Peer 1 connected to peer 2");
                            break;
                        }
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == peer_id1 {
                            info!("🔗 Peer 2 connected to peer 1");
                        }
                    }
                }
            }
        }
    }).await.expect("Failed to establish connection");

    info!("✅ Connection established between peers");

    // Test VPN data transfer - peer 1 sends request to peer 2
    let test_data = b"Hello VPN World!".to_vec();
    let request_id = swarm1.behaviour_mut().send_request(&peer_id2, test_data.clone());
    info!("📤 Peer 1 sent VPN request to peer 2 (request_id: {:?})", request_id);

    // Wait for response
    let response_received = timeout(Duration::from_secs(10), async {
        let mut received = false;
        loop {
            tokio::select! {
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::Behaviour(request_response::Event::Message { peer, message, .. }) = event {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                info!("📨 Peer 2 received request: {:?}", String::from_utf8_lossy(&request));
                                // Echo the request back as response
                                swarm2.behaviour_mut().send_response(channel, request).unwrap();
                                info!("📤 Peer 2 sent response");
                            }
                            _ => {}
                        }
                    }
                }
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::Behaviour(request_response::Event::Message { peer, message, .. }) = event {
                        match message {
                            request_response::Message::Response { response, .. } => {
                                info!("📨 Peer 1 received response: {:?}", String::from_utf8_lossy(&response));
                                if response == test_data {
                                    info!("✅ Response matches original request!");
                                    received = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        received
    }).await.expect("Failed to complete data transfer");

    assert!(response_received, "Should receive matching response");
    info!("✅ DCUtR VPN data transfer test completed successfully!");
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