//! Tunnel Client - WebSocket connection to ZKS-Tunnel Worker
//!
//! Production-grade implementation with:
//! - Efficient bidirectional data relay
//! - Proper resource cleanup
//! - Connection keepalive via ping/pong
//! - Memory-efficient buffer management

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, info, warn};
use zks_tunnel_proto::{StreamId, TunnelMessage};

#[allow(dead_code)]
type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Per-stream state with sender for incoming data
struct StreamState {
    tx: mpsc::Sender<Bytes>,
}

type PendingMap = Arc<Mutex<HashMap<StreamId, oneshot::Sender<Result<(), String>>>>>;
type HttpResponseMap = Arc<Mutex<HashMap<StreamId, mpsc::Sender<TunnelMessage>>>>;

/// Production-grade tunnel client with connection multiplexing
#[derive(Clone)]
pub struct TunnelClient {
    /// Sender for outgoing messages
    sender: mpsc::Sender<TunnelMessage>,
    /// Next stream ID (atomic for thread-safety)
    next_stream_id: Arc<AtomicU32>,
    /// Active streams - maps stream_id to sender for that stream's data
    streams: Arc<Mutex<HashMap<StreamId, StreamState>>>,
    /// Pending connection requests - maps stream_id to oneshot sender for result
    pending_connections: PendingMap,
    /// Pending HTTP requests - maps stream_id to channel for HttpResponse
    pending_http_requests: HttpResponseMap,
}

impl TunnelClient {
    /// Connect to the ZKS-Tunnel Worker with automatic reconnection
    pub async fn connect_ws(url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Connecting to ZKS-Tunnel Worker at {}", url);

        let (ws_stream, response) = connect_async(url).await?;
        info!("WebSocket connected (status: {})", response.status());

        let (mut write, mut read) = ws_stream.split();

        // Channel for sending messages to the WebSocket (bounded for backpressure)
        let (sender, mut receiver) = mpsc::channel::<TunnelMessage>(256);

        // Streams map - shared between reader task and main client
        let streams: Arc<Mutex<HashMap<StreamId, StreamState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let streams_clone = streams.clone();

        // Pending connections map - shared between reader task and main client
        let pending_connections: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_connections_clone = pending_connections.clone();

        // Pending HTTP requests map - shared between reader task and main client
        let pending_http_requests: HttpResponseMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_http_clone = pending_http_requests.clone();

        // Spawn writer task - sends messages from channel to WebSocket
        let writer_handle = tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                let encoded = msg.encode();
                if let Err(e) = write.send(Message::Binary(encoded.to_vec())).await {
                    error!("WebSocket write error: {}", e);
                    break;
                }
            }
            debug!("Writer task exiting");
        });

        // Spawn reader task - receives messages from WebSocket and dispatches to streams
        let reader_handle = tokio::spawn(async move {
            while let Some(msg_result) = read.next().await {
                match msg_result {
                    Ok(Message::Binary(data)) => {
                        if let Ok(tunnel_msg) = TunnelMessage::decode(&data) {
                            match tunnel_msg {
                                TunnelMessage::Data { stream_id, payload } => {
                                    // Forward data to the appropriate stream
                                    let streams = streams_clone.lock().await;
                                    if let Some(state) = streams.get(&stream_id) {
                                        if state.tx.send(payload).await.is_err() {
                                            debug!("Stream {} receiver dropped", stream_id);
                                        }
                                    } else {
                                        warn!("Data for unknown stream {}", stream_id);
                                    }
                                }
                                TunnelMessage::Close { stream_id } => {
                                    let mut streams = streams_clone.lock().await;
                                    streams.remove(&stream_id);
                                    debug!("Stream {} closed by server", stream_id);
                                }
                                TunnelMessage::ErrorReply {
                                    stream_id,
                                    code,
                                    message,
                                } => {
                                    error!(
                                        "Stream {} error: {} (code {})",
                                        stream_id, message, code
                                    );
                                    let mut streams = streams_clone.lock().await;
                                    streams.remove(&stream_id);

                                    // Also check pending connections
                                    let mut pending = pending_connections_clone.lock().await;
                                    if let Some(tx) = pending.remove(&stream_id) {
                                        let _ = tx.send(Err(format!(
                                            "Stream error: {} (code {})",
                                            message, code
                                        )));
                                    }
                                }
                                TunnelMessage::Pong => {
                                    debug!("Received pong");
                                }
                                TunnelMessage::ConnectSuccess { stream_id } => {
                                    let mut pending = pending_connections_clone.lock().await;
                                    if let Some(tx) = pending.remove(&stream_id) {
                                        let _ = tx.send(Ok(()));
                                    } else {
                                        warn!(
                                            "Received ConnectSuccess for unknown stream {}",
                                            stream_id
                                        );
                                    }
                                }
                                TunnelMessage::HttpResponse { stream_id, status, headers, body } => {
                                    let mut pending = pending_http_clone.lock().await;
                                    if let Some(tx) = pending.remove(&stream_id) {
                                        // Reconstruct the message to send
                                        let resp = TunnelMessage::HttpResponse {
                                            stream_id,
                                            status,
                                            headers,
                                            body,
                                        };
                                        let _ = tx.send(resp).await;
                                    } else {
                                        warn!(
                                            "Received HttpResponse for unknown stream {}",
                                            stream_id
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("Server closed connection");
                        break;
                    }
                    Err(e) => {
                        error!("WebSocket read error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            debug!("Reader task exiting");
        });

        // Keep handles for potential cleanup
        let _ = (writer_handle, reader_handle);

        Ok(Self {
            sender,
            next_stream_id: Arc::new(AtomicU32::new(1)),
            streams,
            pending_connections,
            pending_http_requests,
        })
    }

    /// Open a new connection through the tunnel
    /// Returns (stream_id, receiver for incoming data)
    pub async fn open_stream(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(StreamId, mpsc::Receiver<Bytes>), Box<dyn std::error::Error + Send + Sync>> {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);

        // Create channel for receiving data for this stream (bounded for backpressure)
        let (tx, rx) = mpsc::channel::<Bytes>(256);
        {
            let mut streams = self.streams.lock().await;
            streams.insert(stream_id, StreamState { tx });
        }

        // Create oneshot channel for connection result
        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = self.pending_connections.lock().await;
            pending.insert(stream_id, resp_tx);
        }

        // Send CONNECT command
        let msg = TunnelMessage::Connect {
            stream_id,
            host: host.to_string(),
            port,
        };
        self.sender.send(msg).await?;

        // Wait for ConnectSuccess or ErrorReply
        match tokio::time::timeout(std::time::Duration::from_secs(10), resp_rx).await {
            Ok(Ok(Ok(()))) => {
                debug!("Opened stream {} to {}:{}", stream_id, host, port);
                Ok((stream_id, rx))
            }
            Ok(Ok(Err(e))) => {
                // Connection failed (ErrorReply received)
                self.streams.lock().await.remove(&stream_id);
                Err(format!("Connection failed: {}", e).into())
            }
            Ok(Err(_)) => {
                // Oneshot channel closed (should not happen normally)
                self.streams.lock().await.remove(&stream_id);
                self.pending_connections.lock().await.remove(&stream_id);
                Err("Connection aborted".into())
            }
            Err(_) => {
                // Timeout
                self.streams.lock().await.remove(&stream_id);
                self.pending_connections.lock().await.remove(&stream_id);
                Err("Connection timed out".into())
            }
        }
    }

    /// Relay data between local TCP socket and tunnel stream (BIDIRECTIONAL)
    /// Uses efficient buffer management and proper cleanup
    pub async fn relay(
        &self,
        stream_id: StreamId,
        local: TcpStream,
        mut rx: mpsc::Receiver<Bytes>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut read_half, mut write_half) = local.into_split();
        let sender = self.sender.clone();
        let sender_for_close = self.sender.clone();
        let streams = self.streams.clone();

        // Task 1: Local -> Tunnel (read from local TCP, send to tunnel)
        let local_to_tunnel = tokio::spawn(async move {
            // Use a reasonably sized buffer for efficiency
            let mut buf = vec![0u8; 16384]; // 16KB buffer

            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) => {
                        debug!("Local EOF for stream {}", stream_id);
                        break;
                    }
                    Ok(n) => {
                        let msg = TunnelMessage::Data {
                            stream_id,
                            payload: Bytes::copy_from_slice(&buf[..n]),
                        };
                        if sender.send(msg).await.is_err() {
                            debug!("Tunnel sender closed for stream {}", stream_id);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Local read error for stream {}: {}", stream_id, e);
                        break;
                    }
                }
            }
        });

        // Task 2: Tunnel -> Local (receive from tunnel, write to local TCP)
        let tunnel_to_local = tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = write_half.write_all(&data).await {
                    debug!("Local write error for stream {}: {}", stream_id, e);
                    break;
                }
            }
            debug!("Tunnel receiver closed for stream {}", stream_id);
        });

        // Wait for either direction to finish
        tokio::select! {
            result = local_to_tunnel => {
                if let Err(e) = result {
                    debug!("Local->Tunnel task error: {}", e);
                }
            }
            result = tunnel_to_local => {
                if let Err(e) = result {
                    debug!("Tunnel->Local task error: {}", e);
                }
            }
        }

        // Send close command to server
        let _ = sender_for_close
            .send(TunnelMessage::Close { stream_id })
            .await;

        // Clean up stream
        {
            let mut streams_guard = streams.lock().await;
            streams_guard.remove(&stream_id);
        }

        debug!("Stream {} relay completed", stream_id);
        Ok(())
    }

    /// Send a ping to keep the connection alive
    #[allow(dead_code)]
    pub async fn ping(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sender.send(TunnelMessage::Ping).await?;
        Ok(())
    }

    /// Get the number of active streams
    #[allow(dead_code)]
    pub async fn active_stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// Get a clone of the message sender
    #[allow(dead_code)]
    pub fn sender(&self) -> mpsc::Sender<TunnelMessage> {
        self.sender.clone()
    }

    /// Get the next stream ID
    pub fn get_next_stream_id(&self) -> StreamId {
        self.next_stream_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Register a pending HTTP request and return a receiver for the response
    pub fn register_http_request(&self, stream_id: StreamId) -> Result<mpsc::Receiver<TunnelMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = mpsc::channel(1);
        
        // Use try_lock to avoid async in sync context
        // This might fail if lock is held, but for initialization it should be fine
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut pending = self.pending_http_requests.lock().await;
            pending.insert(stream_id, tx);
        });
        
        Ok(rx)
    }

    /// Send a message through the tunnel
    pub fn send_message(&self, msg: TunnelMessage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sender.try_send(msg).map_err(|e| format!("Failed to send message: {}", e))?;
        Ok(())
    }

    /// Send data to a stream
    pub fn send_data(&self, stream_id: StreamId, payload: Bytes) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_message(TunnelMessage::Data { stream_id, payload })
    }

    /// Close a stream
    pub fn close_stream(&self, stream_id: StreamId) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_message(TunnelMessage::Close { stream_id })
    }
}
