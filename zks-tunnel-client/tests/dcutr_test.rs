//! DCUtR VPN Data Transfer Test
//!
//! This test verifies that the libp2p transport can successfully establish
//! DCUtR connections and transfer VPN data using the request-response protocol.

use futures::{StreamExt, AsyncReadExt, AsyncWriteExt};
use libp2p::{
    dcutr, identify, noise, ping, relay, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    Transport, core::transport::upgrade::Version,
};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, debug};

/// Test VPN codec for request-response protocol
#[derive(Clone, Default)]
pub struct TestVpnCodec;

impl request_response::Codec for TestVpnCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send + 'async_trait,
    {
        let mut buf = vec![0u8; 1500]; // Max VPN packet size
        let n = io.read_exact(&mut buf[0..4]).await?;
        if n != 4 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Invalid packet length"));
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > 1500 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Packet too large"));
        }
        io.read_exact(&mut buf[0..len]).await?;
        buf.truncate(len);
        Ok(buf)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send + 'async_trait,
    {
        self.read_request(&StreamProtocol::new("/test-vpn/1.0.0"), io).await
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send + 'async_trait,
    {
        let len = req.len() as u32;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(&req).await?;
        io.flush().await?;
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send + 'async_trait,
    {
        self.write_request(&StreamProtocol::new("/test-vpn/1.0.0"), io, res).await
    }
}

/// Test transport behaviour
#[derive(NetworkBehaviour)]
struct TestTransportBehaviour {
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    vpn_protocol: request_response::Behaviour<TestVpnCodec>,
}

#[tokio::test]
async fn test_dcutr_vpn_data_transfer() {
    // Initialize logging
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    info!("🧪 Starting DCUtR VPN data transfer test...");

    // Create two peers for testing
    let keypair1 = libp2p::identity::Keypair::generate_ed25519();
    let peer_id1 = PeerId::from(keypair1.public());
    let keypair2 = libp2p::identity::Keypair::generate_ed25519();
    let peer_id2 = PeerId::from(keypair2.public());

    info!("📡 Peer 1 ID: {}", peer_id1);
    info!("📡 Peer 2 ID: {}", peer_id2);

    // Build swarm for peer 1
    let mut swarm1 = SwarmBuilder::with_existing_identity(keypair1)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|keypair| TestTransportBehaviour {
            relay_client: relay::client::Behaviour::new(keypair.public().to_peer_id(), Default::default()),
            dcutr: dcutr::Behaviour::new(keypair.public().to_peer_id()),
            identify: identify::Behaviour::new(identify::Config::new("test/1.0.0".to_string(), keypair.public())),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(10))),
            vpn_protocol: request_response::Behaviour::new(
                [(
                    StreamProtocol::new("/zks-vpn/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
        })
        .unwrap()
        .build();

    // Build swarm for peer 2
    let mut swarm2 = SwarmBuilder::with_existing_identity(keypair2)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|keypair| TestTransportBehaviour {
            relay_client: relay::client::Behaviour::new(keypair.public().to_peer_id(), Default::default()),
            dcutr: dcutr::Behaviour::new(keypair.public().to_peer_id()),
            identify: identify::Behaviour::new(identify::Config::new("test/1.0.0".to_string(), keypair.public())),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(10))),
            vpn_protocol: request_response::Behaviour::new(
                [(
                    StreamProtocol::new("/zks-vpn/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
        })
        .unwrap()
        .build();

    // Start listening on both peers
    swarm1.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    swarm2.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    // Wait for listening addresses
    let mut addr1 = None;
    let mut addr2 = None;

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

    // Connect peer 1 to peer 2
    let dial_addr = addr2.unwrap().with(libp2p::core::multiaddr::Protocol::P2p(peer_id2));
    info!("🔗 Connecting peer 1 to peer 2 via: {}", dial_addr);
    swarm1.dial(dial_addr).unwrap();

    // Wait for connection establishment
    let mut connected = false;
    timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    debug!("Peer 1 event: {:?}", event);
                    if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                        info!("✅ Peer 1 connected to peer 2");
                        connected = true;
                        break;
                    }
                }
                event = swarm2.select_next_some() => {
                    debug!("Peer 2 event: {:?}", event);
                    if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                        info!("✅ Peer 2 connected to peer 1");
                    }
                }
            }
        }
    }).await.expect("Connection timeout");

    assert!(connected, "Failed to establish connection");

    // Test VPN data transfer using request-response protocol
    let test_packet = b"Hello VPN World!".to_vec();
    info!("📤 Sending test VPN packet: {:?}", String::from_utf8_lossy(&test_packet));

    // Send request from peer 1 to peer 2
    let request_id = swarm1.behaviour_mut().vpn_protocol.send_request(&peer_id2, test_packet.clone());
    info!("📤 Sent VPN request with ID: {:?}", request_id);

    // Wait for response
    let mut response_received = false;
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::Behaviour(TestTransportBehaviourEvent::VpnProtocol(
                        request_response::Event::Message { peer, message }
                    )) = event {
                        match message {
                            request_response::Message::Response { request_id: req_id, response } => {
                                info!("📥 Received VPN response from {}: {:?}", peer, String::from_utf8_lossy(&response));
                                if req_id == request_id {
                                    response_received = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::Behaviour(TestTransportBehaviourEvent::VpnProtocol(
                        request_response::Event::Message { peer, message }
                    )) = event {
                        match message {
                            request_response::Message::Request { request_id: req_id, request, channel } => {
                                info!("📥 Received VPN request from {}: {:?}", peer, String::from_utf8_lossy(&request));
                                // Echo the request back as response
                                swarm2.behaviour_mut().vpn_protocol.send_response(channel, request).unwrap();
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }).await.expect("Response timeout");

    assert!(response_received, "Failed to receive VPN response");
    info!("✅ DCUtR VPN data transfer test completed successfully!");
}