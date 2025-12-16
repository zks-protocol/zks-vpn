//! TunnelSession - Durable Object for persistent WebSocket connections
//!
//! Uses channel-based architecture where spawned task owns Socket exclusively

use bytes::Bytes;
use futures::channel::mpsc;
use futures::{FutureExt, SinkExt, StreamExt};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasm_bindgen_futures::spawn_local;
use worker::*;
use worker::{Method, Url};
use zks_tunnel_proto::{StreamId, TunnelMessage};

/// Stream state - holds a sender for write requests to the socket task
struct StreamInfo {
    /// Channel to send data to be written to the socket
    write_tx: mpsc::Sender<Bytes>,
}

#[durable_object]
pub struct TunnelSession {
    state: State,
    #[allow(dead_code)]
    env: Env,
    active_streams: Rc<RefCell<HashMap<StreamId, StreamInfo>>>,
    connection_count: Rc<RefCell<u32>>,
}

impl DurableObject for TunnelSession {
    fn new(state: State, env: Env) -> Self {
        console_log!("[TunnelSession] Initializing new session");
        Self {
            state,
            env,
            active_streams: Rc::new(RefCell::new(HashMap::new())),
            connection_count: Rc::new(RefCell::new(0)),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let upgrade = req.headers().get("Upgrade")?;

        if upgrade.as_deref() != Some("websocket") {
            return Response::error("Expected WebSocket upgrade", 426);
        }

        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        self.state.accept_web_socket(&server);

        *self.connection_count.borrow_mut() += 1;
        console_log!(
            "[TunnelSession] Connection #{} established",
            self.connection_count.borrow()
        );

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        match message {
            WebSocketIncomingMessage::Binary(data) => {
                self.handle_binary_message(&ws, &data).await?;
            }
            WebSocketIncomingMessage::String(text) => {
                console_log!(
                    "[TunnelSession] Text message received: {} bytes",
                    text.len()
                );
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        code: usize,
        reason: String,
        was_clean: bool,
    ) -> Result<()> {
        console_log!(
            "[TunnelSession] Connection closed: code={}, reason={}, clean={}",
            code,
            reason,
            was_clean
        );

        // Clean up all streams - dropping senders will signal tasks to stop
        self.active_streams.borrow_mut().clear();
        Ok(())
    }
}

impl TunnelSession {
    async fn handle_binary_message(&self, ws: &WebSocket, data: &[u8]) -> Result<()> {
        let msg = match TunnelMessage::decode(data) {
            Ok(m) => m,
            Err(e) => {
                console_error!("[TunnelSession] Failed to decode message: {:?}", e);
                return Ok(());
            }
        };

        match msg {
            TunnelMessage::Connect {
                stream_id,
                host,
                port,
            } => {
                if !Self::is_valid_host(&host) {
                    console_warn!("[TunnelSession] Blocked connection to: {}", host);
                    Self::send_error(ws, stream_id, 403, &format!("Blocked host: {}", host));
                    return Ok(());
                }
                self.handle_connect(ws, stream_id, &host, port).await?;
            }
            TunnelMessage::Data { stream_id, payload } => {
                self.handle_data(stream_id, &payload).await?;
            }
            TunnelMessage::Close { stream_id } => {
                // Remove from map - dropping the sender signals the task to stop
                self.active_streams.borrow_mut().remove(&stream_id);
                console_log!("[TunnelSession] Stream {} closed by client", stream_id);
            }
            TunnelMessage::DnsQuery { request_id, query } => {
                self.handle_dns(ws, request_id as u16, &query).await;
            }
            _ => {}
        }

        Ok(())
    }

    fn is_valid_host(host: &str) -> bool {
        let blocked = [
            "127.",
            "10.",
            "192.168.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "169.254.",
            "0.",
            "localhost",
            "::1",
        ];

        let host_lower = host.to_lowercase();
        for prefix in blocked {
            if host_lower.starts_with(prefix) {
                return false;
            }
        }
        !host.is_empty() && host.len() <= 253
    }

    fn send_error(ws: &WebSocket, stream_id: StreamId, code: u16, message: &str) {
        let error_msg = TunnelMessage::ErrorReply {
            stream_id,
            code,
            message: message.to_string(),
        };
        let _ = ws.send_with_bytes(&error_msg.encode());
    }

    async fn handle_connect(
        &self,
        ws: &WebSocket,
        stream_id: StreamId,
        host: &str,
        port: u16,
    ) -> Result<()> {
        if self.active_streams.borrow().contains_key(&stream_id) {
            Self::send_error(ws, stream_id, 409, "Stream ID already in use");
            return Ok(());
        }

        // Cloudflare blocks connect() to ports 80 and 443 on standard plans.
        // For Port 80 (HTTP), we can use fetch() as a fallback proxy.
        if port == 80 {
            console_log!("[TunnelSession] Port 80 detected - using Fetch Fallback for {}", host);
            return self.handle_http_fetch(ws, stream_id, host).await;
        }

        let address = format!("{}:{}", host, port);
        console_log!("[TunnelSession] Connecting to {}", address);

        match Socket::builder().connect(host, port) {
            Ok(socket) => {
                // Wait for socket to be opened
                if let Err(e) = socket.opened().await {
                    console_error!("[TunnelSession] Socket open failed: {:?}", e);
                    Self::send_error(ws, stream_id, 502, &format!("Connection failed: {:?}", e));
                    return Ok(());
                }

                console_log!("[TunnelSession] Connected to {}", address);

                // Send ConnectSuccess to client
                let success_msg = TunnelMessage::ConnectSuccess { stream_id };
                if let Err(e) = ws.send_with_bytes(&success_msg.encode()) {
                    console_error!("[TunnelSession] Failed to send ConnectSuccess: {:?}", e);
                    return Ok(());
                }

                // Create channel for write requests (bounded to prevent memory issues)
                let (write_tx, write_rx) = mpsc::channel::<Bytes>(64);

                // Store the write sender in active streams
                self.active_streams
                    .borrow_mut()
                    .insert(stream_id, StreamInfo { write_tx });

                // Spawn socket handler task - it EXCLUSIVELY owns the socket
                let ws_clone = ws.clone();
                let active_streams = self.active_streams.clone();

                spawn_local(async move {
                    Self::run_socket_loop(socket, write_rx, ws_clone, stream_id, active_streams)
                        .await;
                });

                console_log!("[TunnelSession] Stream {} ready", stream_id);
            }
            Err(e) => {
                console_error!("[TunnelSession] Connect failed to {}: {:?}", address, e);
                Self::send_error(ws, stream_id, 502, &format!("Connection failed: {:?}", e));
            }
        }

        Ok(())
    }

    /// Handle HTTP requests via fetch() instead of raw TCP connect()
    /// This is a "Blind Proxy" - it opens a stream, reads the HTTP request from the client,
    /// parses it (roughly), sends a fetch(), and streams the response back.
    async fn handle_http_fetch(
        &self,
        ws: &WebSocket,
        stream_id: StreamId,
        host: &str,
    ) -> Result<()> {
        // 1. Send ConnectSuccess immediately (we pretend we connected)
        let success_msg = TunnelMessage::ConnectSuccess { stream_id };
        ws.send_with_bytes(&success_msg.encode())?;

        // 2. Create channel to receive data from client (the HTTP request)
        let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(64);
        self.active_streams
            .borrow_mut()
            .insert(stream_id, StreamInfo { write_tx });

        let ws_clone = ws.clone();
        let host_owned = host.to_string();
        let active_streams = self.active_streams.clone();

        spawn_local(async move {
            // Buffer to accumulate the initial request headers
            let mut buffer = Vec::new();
            let mut request_sent = false;

            // We need to read from write_rx (data from client)
            while let Some(chunk) = write_rx.next().await {
                if request_sent {
                    // If we already sent the request, we can't easily pipe more data 
                    // into the fetch body unless we used a TransformStream (complex).
                    // For simple HTTP GET, this is usually fine. POST might be tricky.
                    // For now, ignore extra data or TODO: implement streaming upload.
                    continue;
                }

                buffer.extend_from_slice(&chunk);

                // Check if we have a full HTTP header (double newline)
                // or just try to send what we have if it looks like a request
                // Simple heuristic: assume the first chunk(s) contain the method and path.
                
                // Parse method and path from buffer
                let req_str = String::from_utf8_lossy(&buffer);
                let lines: Vec<&str> = req_str.lines().collect();
                if lines.is_empty() { continue; }

                let first_line = lines[0];
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if parts.len() < 2 { continue; }

                let method = parts[0]; // GET, POST, etc.
                let path = parts[1];   // /, /foo, etc.

                // Construct full URL
                let url = format!("http://{}{}", host_owned, path);
                console_log!("[TunnelSession] Fetching URL: {}", url);

                // Prepare Fetch
                let mut init = RequestInit::new();
                init.method = match method {
                    "GET" => Method::Get,
                    "POST" => Method::Post,
                    "HEAD" => Method::Head,
                    "PUT" => Method::Put,
                    "DELETE" => Method::Delete,
                    _ => Method::Get,
                };
                
                // TODO: Copy headers from client request
                // For now, basic fetch
                
                let url_parsed = match Url::parse(&url) {
                    Ok(u) => u,
                    Err(e) => {
                        console_error!("[TunnelSession] Invalid URL {}: {:?}", url, e);
                        continue;
                    }
                };

                match Fetch::Url(url_parsed).send().await {
                    Ok(mut response) => {
                        request_sent = true;
                        
                        // Reconstruct HTTP Response Status Line
                        // worker::Response doesn't always expose status_text, so we use a default
                        let status_code = response.status_code();
                        let status_text = match status_code {
                            200 => "OK",
                            201 => "Created",
                            204 => "No Content",
                            400 => "Bad Request",
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            404 => "Not Found",
                            500 => "Internal Server Error",
                            502 => "Bad Gateway",
                            503 => "Service Unavailable",
                            _ => "Unknown",
                        };
                        let status_line = format!("HTTP/1.1 {} {}\r\n", status_code, status_text);
                        let mut head = status_line.into_bytes();

                        // Reconstruct Headers
                        // response.headers() returns &Headers
                        let headers = response.headers();
                        // headers.entries() returns an iterator of (String, String)
                        for (k, v) in headers.entries() {
                            if k.to_lowercase() != "transfer-encoding" { // Chunked handled by us
                                head.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
                            }
                        }
                        head.extend_from_slice(b"\r\n"); // End of headers

                        // Send Headers
                        let msg = TunnelMessage::Data {
                            stream_id,
                            payload: Bytes::from(head),
                        };
                        let _ = ws_clone.send_with_bytes(&msg.encode());

                        // Stream Body
                        // Use response.stream() to get a Stream<Item = Result<Vec<u8>, Error>>
                        if let Ok(mut stream) = response.stream() {
                            while let Some(chunk_res) = stream.next().await {
                                match chunk_res {
                                    Ok(chunk) => {
                                        // chunk is Vec<u8>
                                        let msg = TunnelMessage::Data {
                                            stream_id,
                                            payload: Bytes::from(chunk),
                                        };
                                        let _ = ws_clone.send_with_bytes(&msg.encode());
                                    }
                                    Err(e) => {
                                        console_error!("[TunnelSession] Body read error: {:?}", e);
                                        break;
                                    }
                                }
                            }
                        }
                        
                        // Close stream
                        let close_msg = TunnelMessage::Close { stream_id };
                        let _ = ws_clone.send_with_bytes(&close_msg.encode());
                        active_streams.borrow_mut().remove(&stream_id);
                        break;
                    }
                    Err(e) => {
                        console_error!("[TunnelSession] Fetch failed: {:?}", e);
                        let close_msg = TunnelMessage::Close { stream_id };
                        let _ = ws_clone.send_with_bytes(&close_msg.encode());
                        active_streams.borrow_mut().remove(&stream_id);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Socket handler loop - exclusively owns the Socket
    /// Handles both reading from socket and writing client data to socket
    async fn run_socket_loop(
        mut socket: Socket,
        mut write_rx: mpsc::Receiver<Bytes>,
        ws: WebSocket,
        stream_id: StreamId,
        active_streams: Rc<RefCell<HashMap<StreamId, StreamInfo>>>,
    ) {
        let mut read_buffer = vec![0u8; 16384];

        loop {
            // Use select! to handle both read and write operations
            // Since we're in WASM without full tokio, we'll use a simpler approach:
            // Try to read with a small yield, and check for write requests

            futures::select! {
                // Check for data to write to socket
                write_data = write_rx.next() => {
                    match write_data {
                        Some(data) => {
                            if let Err(e) = socket.write_all(&data).await {
                                console_error!("[TunnelSession] Write error on stream {}: {:?}", stream_id, e);
                                break;
                            }
                        }
                        None => {
                            // Channel closed, client requested close
                            console_log!("[TunnelSession] Write channel closed for stream {}", stream_id);
                            break;
                        }
                    }
                }
                // Read from socket
                read_result = socket.read(&mut read_buffer).fuse() => {
                    match read_result {
                        Ok(0) => {
                            // EOF from remote
                            console_log!("[TunnelSession] Stream {} EOF", stream_id);
                            break;
                        }
                        Ok(n) => {
                            let msg = TunnelMessage::Data {
                                stream_id,
                                payload: Bytes::copy_from_slice(&read_buffer[..n]),
                            };
                            if ws.send_with_bytes(&msg.encode()).is_err() {
                                console_error!("[TunnelSession] Failed to send data to client");
                                break;
                            }
                        }
                        Err(e) => {
                            console_error!("[TunnelSession] Read error on stream {}: {:?}", stream_id, e);
                            break;
                        }
                    }
                }
            }
        }

        // Cleanup
        let close_msg = TunnelMessage::Close { stream_id };
        let _ = ws.send_with_bytes(&close_msg.encode());
        active_streams.borrow_mut().remove(&stream_id);

        // Close the socket
        let _ = socket.close().await;

        console_log!(
            "[TunnelSession] Socket loop exiting for stream {}",
            stream_id
        );
    }

    async fn handle_data(&self, stream_id: StreamId, payload: &[u8]) -> Result<()> {
        // Get a clone of the write sender (quick borrow, no await)
        let write_tx_opt = {
            let streams = self.active_streams.borrow();
            streams.get(&stream_id).map(|info| info.write_tx.clone())
        };

        if let Some(mut write_tx) = write_tx_opt {
            // Send data to the socket task via channel
            if write_tx
                .send(Bytes::copy_from_slice(payload))
                .await
                .is_err()
            {
                // Channel closed, clean up
                self.active_streams.borrow_mut().remove(&stream_id);
                console_error!(
                    "[TunnelSession] Write channel closed for stream {}",
                    stream_id
                );
            }
        } else {
            console_warn!("[TunnelSession] Data for unknown stream {}", stream_id);
        }

        Ok(())
    }

    async fn handle_dns(&self, ws: &WebSocket, query_id: u16, query: &[u8]) {
        console_log!("[TunnelSession] DNS query id={}", query_id);

        match self.resolve_dns_via_doh(query).await {
            Ok(response) => {
                let msg = TunnelMessage::DnsResponse {
                    request_id: query_id as u32,
                    response: Bytes::from(response),
                };
                let _ = ws.send_with_bytes(&msg.encode());
            }
            Err(e) => {
                console_error!("[TunnelSession] DNS failed: {:?}", e);
            }
        }
    }

    async fn resolve_dns_via_doh(&self, query: &[u8]) -> Result<Vec<u8>> {
        let query_b64 = base64_url_encode(query);
        let url = format!("https://cloudflare-dns.com/dns-query?dns={}", query_b64);

        let mut init = RequestInit::new();
        init.method = Method::Get;

        let headers = Headers::new();
        headers.set("Accept", "application/dns-message")?;
        init.headers = headers;

        let request = Request::new_with_init(&url, &init)?;
        let mut response = Fetch::Request(request).send().await?;

        let bytes = response.bytes().await?;
        Ok(bytes)
    }
}

fn base64_url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        }

        i += 3;
    }

    result
}
