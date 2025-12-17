//! HTTP Proxy Server for ZKS-Tunnel
//!
//! This module implements an HTTP/HTTPS forward proxy that uses the fetch() API
//! on the Cloudflare Worker to bypass connect() limitations.
//!
//! All HTTPS traffic is handled via HttpRequest/HttpResponse messages, allowing
//! access to Cloudflare-proxied sites that would fail with raw TCP.

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, error, info};
use zks_tunnel_proto::TunnelMessage;

use crate::tunnel::TunnelClient;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// HTTP Proxy Server
pub struct HttpProxyServer {
    tunnel: TunnelClient,
}

impl HttpProxyServer {
    pub fn new(tunnel: TunnelClient) -> Self {
        Self { tunnel }
    }

    /// Run the HTTP proxy server
    pub async fn run(self, listener: tokio::net::TcpListener) -> Result<(), BoxError> {
        loop {
            let (stream, addr) = listener.accept().await?;
            debug!("HTTP proxy connection from {}", addr);

            let tunnel = self.tunnel.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, tunnel).await {
                    debug!("HTTP proxy connection error: {}", e);
                }
            });
        }
    }
}

/// Handle a single HTTP proxy connection
async fn handle_connection(mut stream: TcpStream, tunnel: TunnelClient) -> Result<(), BoxError> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    // Read the first line to determine request type
    let mut first_line = String::new();
    reader.read_line(&mut first_line).await?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Err("Invalid HTTP request".into());
    }

    let method = parts[0];
    let uri = parts[1];

    // Read remaining headers
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        headers.push_str(&line);
    }

    if method == "CONNECT" {
        // HTTPS CONNECT request
        handle_connect_request(&mut writer, &mut reader, uri, tunnel).await
    } else {
        // Regular HTTP request
        handle_http_request(&mut writer, method, uri, &headers, tunnel).await
    }
}

/// Handle HTTPS CONNECT request using HttpRequest/HttpResponse protocol
async fn handle_connect_request<R, W>(
    writer: &mut W,
    reader: &mut BufReader<R>,
    uri: &str,
    tunnel: TunnelClient,
) -> Result<(), BoxError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Parse host:port from CONNECT request URI
    let (host, port) = if let Some((h, p)) = uri.split_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else {
        (uri.to_string(), 443)
    };

    info!("HTTP CONNECT to {}:{}", host, port);

    // Send 200 Connection Established to client
    writer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    writer.flush().await?;

    // Now the client will send TLS handshake, which we cannot intercept.
    // For true HTTPS proxying, we'd need to MITM with certificates.
    // Instead, we inform the user that raw CONNECT doesn't work for all sites
    // and they should use the HTTP-only mode or SOCKS5 for raw TCP.

    // For now, try the raw TCP approach via the existing tunnel
    // This will work for non-Cloudflare sites
    match tunnel.open_stream(&host, port).await {
        Ok((stream_id, mut rx)) => {
            // Read remaining data from client and send through tunnel
            let mut buf = [0u8; 8192];

            loop {
                tokio::select! {
                    // Data from client -> tunnel
                    result = reader.read(&mut buf) => {
                        match result {
                            Ok(0) => break,
                            Ok(n) => {
                                if tunnel.send_data(stream_id, Bytes::copy_from_slice(&buf[..n])).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    // Data from tunnel -> client
                    Some(data) = rx.recv() => {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                }
            }

            let _ = tunnel.close_stream(stream_id);
        }
        Err(e) => {
            error!("Failed to open tunnel stream: {}", e);
        }
    }

    Ok(())
}

/// Handle regular HTTP request using HttpRequest/HttpResponse protocol
async fn handle_http_request<W>(
    writer: &mut W,
    method: &str,
    uri: &str,
    headers: &str,
    tunnel: TunnelClient,
) -> Result<(), BoxError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    info!("HTTP {} {}", method, uri);

    // For regular HTTP requests, we use the new HttpRequest message
    // which the Worker handles via fetch()
    let stream_id = tunnel.get_next_stream_id();

    // Get the pending request receiver
    let mut rx = tunnel.register_http_request(stream_id)?;

    // Send HttpRequest message
    let msg = TunnelMessage::HttpRequest {
        stream_id,
        method: method.to_string(),
        url: uri.to_string(),
        headers: headers.to_string(),
        body: Bytes::new(),
    };

    tunnel.send_message(msg)?;
    debug!(
        "Sent HttpRequest for stream {}, waiting for response...",
        stream_id
    );

    // Wait for HttpResponse with timeout
    let timeout_duration = std::time::Duration::from_secs(30);
    match tokio::time::timeout(timeout_duration, rx.recv()).await {
        Ok(Some(TunnelMessage::HttpResponse {
            status,
            headers: resp_headers,
            body,
            ..
        })) => {
            // Write HTTP response to client
            let status_text = match status {
                200 => "OK",
                201 => "Created",
                204 => "No Content",
                301 => "Moved Permanently",
                302 => "Found",
                304 => "Not Modified",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                500 => "Internal Server Error",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                _ => "Unknown",
            };

            writer
                .write_all(format!("HTTP/1.1 {} {}\r\n", status, status_text).as_bytes())
                .await?;

            // Filter out headers that we'll set ourselves
            for line in resp_headers.lines() {
                let lower = line.to_lowercase();
                if !lower.starts_with("transfer-encoding:")
                    && !lower.starts_with("content-length:")
                    && !lower.starts_with("connection:")
                {
                    writer.write_all(line.as_bytes()).await?;
                    writer.write_all(b"\r\n").await?;
                }
            }

            // Set our own content-length
            writer
                .write_all(format!("Content-Length: {}\r\n", body.len()).as_bytes())
                .await?;
            writer.write_all(b"Connection: close\r\n").await?;
            writer.write_all(b"\r\n").await?;
            writer.write_all(&body).await?;
            writer.flush().await?;
        }
        Ok(Some(TunnelMessage::ErrorReply { message, .. })) => {
            error!("Worker returned error: {}", message);
            writer
                .write_all(
                    format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n{}",
                        message
                    )
                    .as_bytes(),
                )
                .await?;
        }
        Ok(_) => {
            error!("No response received from tunnel");
            writer
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\nNo response from tunnel")
                .await?;
        }
        Err(_) => {
            error!("Timeout waiting for HttpResponse");
            writer
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\nRequest timed out")
                .await?;
        }
    }

    Ok(())
}
