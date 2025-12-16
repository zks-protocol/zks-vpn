//! TunnelSession - Durable Object for persistent WebSocket connections
//!
//! Uses Socket with Rc<RefCell> for concurrent read/write access

use bytes::Bytes;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasm_bindgen_futures::spawn_local;
use worker::*;
use zks_tunnel_proto::{StreamId, TunnelMessage};

/// Stream state - holds the full socket
struct StreamInfo {
    socket: Rc<RefCell<Socket>>,
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

        // Clean up all streams
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
                    Self::send_error(ws, stream_id, 403, "Blocked host");
                    return Ok(());
                }
                self.handle_connect(ws, stream_id, &host, port).await?;
            }
            TunnelMessage::Data { stream_id, payload } => {
                self.handle_data(ws, stream_id, &payload).await?;
            }
            TunnelMessage::Close { stream_id } => {
                self.active_streams.borrow_mut().remove(&stream_id);
                console_log!("[TunnelSession] Stream {} closed", stream_id);
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

                // Wrap socket in Rc<RefCell>
                let socket = Rc::new(RefCell::new(socket));

                // Store in active streams
                self.active_streams.borrow_mut().insert(
                    stream_id,
                    StreamInfo {
                        socket: socket.clone(),
                    },
                );

                // Spawn reader task
                let ws_clone = ws.clone();
                let active_streams = self.active_streams.clone();
                let socket_clone = socket.clone();

                spawn_local(async move {
                    let mut buffer = vec![0u8; 16384];

                    loop {
                        // Read from socket - must scope the borrow carefully
                        let read_result = {
                            let mut socket_guard = socket_clone.borrow_mut();
                            socket_guard.read(&mut buffer).await
                        };

                        match read_result {
                            Ok(0) => {
                                // EOF
                                console_log!("[TunnelSession] Stream {} EOF", stream_id);
                                break;
                            }
                            Ok(n) => {
                                let msg = TunnelMessage::Data {
                                    stream_id,
                                    payload: Bytes::copy_from_slice(&buffer[..n]),
                                };

                                if ws_clone.send_with_bytes(&msg.encode()).is_err() {
                                    console_error!("[TunnelSession] Failed to send data to client");
                                    break;
                                }
                            }
                            Err(e) => {
                                console_error!("[TunnelSession] Read error: {:?}", e);
                                break;
                            }
                        }
                    }

                    // Send close notification
                    let close_msg = TunnelMessage::Close { stream_id };
                    let _ = ws_clone.send_with_bytes(&close_msg.encode());
                    active_streams.borrow_mut().remove(&stream_id);

                    console_log!("[TunnelSession] Reader exiting for stream {}", stream_id);
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

    async fn handle_data(&self, ws: &WebSocket, stream_id: StreamId, payload: &[u8]) -> Result<()> {
        let socket_opt = {
            let streams = self.active_streams.borrow();
            streams.get(&stream_id).map(|info| info.socket.clone())
        };

        if let Some(socket) = socket_opt {
            // Write to socket
            let write_result = {
                let mut socket_borrowed = socket.borrow_mut();
                socket_borrowed.write_all(payload).await
            };

            match write_result {
                Ok(_) => {
                    console_log!(
                        "[TunnelSession] Wrote {} bytes to stream {}",
                        payload.len(),
                        stream_id
                    );
                }
                Err(e) => {
                    console_error!("[TunnelSession] Write error: {:?}", e);
                    self.active_streams.borrow_mut().remove(&stream_id);
                    Self::send_error(ws, stream_id, 500, "Write failed");
                }
            }
        } else {
            Self::send_error(ws, stream_id, 404, "Stream not found");
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
