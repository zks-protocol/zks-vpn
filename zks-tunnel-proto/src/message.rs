//! ZKS-Tunnel Protocol Messages
//!
//! Binary protocol for efficient tunneling:
//! - CONNECT: Request to open a TCP connection to a target
//! - DATA: Tunneled data (ZKS-encrypted payload)
//! - CLOSE: Close a stream
//! - ERROR: Error response

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

/// Maximum size of a single frame (1MB)
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Command types for the tunnel protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandType {
    /// Request to connect to a target address (TCP)
    Connect = 0x01,
    /// Data frame (bidirectional, for TCP streams)
    Data = 0x02,
    /// Close a stream
    Close = 0x03,
    /// Error response
    ErrorReply = 0x04,
    /// Ping/keepalive
    Ping = 0x05,
    /// Pong response
    Pong = 0x06,
    /// UDP datagram (stateless)
    UdpDatagram = 0x07,
    /// DNS query (special handling via DoH)
    DnsQuery = 0x08,
    /// DNS response
    DnsResponse = 0x09,
    /// Connection established successfully
    ConnectSuccess = 0x0A,
    /// HTTP Request (for fetch-based proxying)
    HttpRequest = 0x0B,
    /// HTTP Response (from fetch)
    HttpResponse = 0x0C,
}

impl TryFrom<u8> for CommandType {
    type Error = crate::ProtoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Close),
            0x04 => Ok(Self::ErrorReply),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::UdpDatagram),
            0x08 => Ok(Self::DnsQuery),
            0x09 => Ok(Self::DnsResponse),
            0x0A => Ok(Self::ConnectSuccess),
            0x0B => Ok(Self::HttpRequest),
            0x0C => Ok(Self::HttpResponse),
            _ => Err(crate::ProtoError::InvalidCommand(value)),
        }
    }
}

/// Stream identifier for multiplexing connections
pub type StreamId = u32;

/// Protocol message types
#[derive(Debug, Clone)]
pub enum TunnelMessage {
    /// Connect to target: hostname:port (TCP)
    Connect {
        stream_id: StreamId,
        host: String,
        port: u16,
    },
    /// Data payload for a stream (TCP)
    Data { stream_id: StreamId, payload: Bytes },
    /// Close a stream
    Close { stream_id: StreamId },
    /// Error on a stream
    ErrorReply {
        stream_id: StreamId,
        code: u16,
        message: String,
    },
    /// Ping
    Ping,
    /// Pong
    Pong,
    /// UDP datagram (stateless, no connection tracking)
    /// Used for general UDP traffic
    UdpDatagram {
        /// Request ID for matching responses
        request_id: u32,
        /// Destination host
        host: String,
        /// Destination port
        port: u16,
        /// Payload data
        payload: Bytes,
    },
    /// DNS query - will be resolved via DoH
    DnsQuery {
        /// Request ID for matching responses
        request_id: u32,
        /// Raw DNS query packet
        query: Bytes,
    },
    /// DNS response
    DnsResponse {
        /// Request ID matching the query
        request_id: u32,
        /// Raw DNS response packet
        response: Bytes,
    },
    /// Connection established successfully
    ConnectSuccess { stream_id: StreamId },
    /// HTTP Request for fetch-based proxying (bypasses Cloudflare connect() limitations)
    /// Worker will use fetch() API to make the request
    HttpRequest {
        /// Stream ID for response correlation
        stream_id: StreamId,
        /// HTTP method (GET, POST, etc.)
        method: String,
        /// Full URL (e.g., "https://google.com/path")
        url: String,
        /// Request headers as "Key: Value\r\n" concatenated
        headers: String,
        /// Optional request body
        body: Bytes,
    },
    /// HTTP Response from fetch
    HttpResponse {
        /// Stream ID matching the request
        stream_id: StreamId,
        /// HTTP status code
        status: u16,
        /// Response headers as "Key: Value\r\n" concatenated
        headers: String,
        /// Response body
        body: Bytes,
    },
}

impl TunnelMessage {
    /// Encode message to binary format
    ///
    /// Format:
    /// - CONNECT:      [cmd:1][stream_id:4][port:2][host_len:2][host:N]
    /// - DATA:         [cmd:1][stream_id:4][payload_len:4][payload:N]
    /// - CLOSE:        [cmd:1][stream_id:4]
    /// - ERROR:        [cmd:1][stream_id:4][code:2][msg_len:2][msg:N]
    /// - PING:         [cmd:1]
    /// - PONG:         [cmd:1]
    /// - UDP_DATAGRAM: [cmd:1][request_id:4][port:2][host_len:2][host:N][payload_len:4][payload:N]
    /// - DNS_QUERY:    [cmd:1][request_id:4][query_len:4][query:N]
    /// - DNS_RESPONSE: [cmd:1][request_id:4][response_len:4][response:N]
    /// - CONNECT_SUCCESS: [cmd:1][stream_id:4]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256);

        match self {
            TunnelMessage::Connect {
                stream_id,
                host,
                port,
            } => {
                buf.put_u8(CommandType::Connect as u8);
                buf.put_u32(*stream_id);
                buf.put_u16(*port);
                buf.put_u16(host.len() as u16);
                buf.put_slice(host.as_bytes());
            }
            TunnelMessage::Data { stream_id, payload } => {
                buf.put_u8(CommandType::Data as u8);
                buf.put_u32(*stream_id);
                buf.put_u32(payload.len() as u32);
                buf.put_slice(payload);
            }
            TunnelMessage::Close { stream_id } => {
                buf.put_u8(CommandType::Close as u8);
                buf.put_u32(*stream_id);
            }
            TunnelMessage::ErrorReply {
                stream_id,
                code,
                message,
            } => {
                buf.put_u8(CommandType::ErrorReply as u8);
                buf.put_u32(*stream_id);
                buf.put_u16(*code);
                buf.put_u16(message.len() as u16);
                buf.put_slice(message.as_bytes());
            }
            TunnelMessage::Ping => {
                buf.put_u8(CommandType::Ping as u8);
            }
            TunnelMessage::Pong => {
                buf.put_u8(CommandType::Pong as u8);
            }
            TunnelMessage::UdpDatagram {
                request_id,
                host,
                port,
                payload,
            } => {
                buf.put_u8(CommandType::UdpDatagram as u8);
                buf.put_u32(*request_id);
                buf.put_u16(*port);
                buf.put_u16(host.len() as u16);
                buf.put_slice(host.as_bytes());
                buf.put_u32(payload.len() as u32);
                buf.put_slice(payload);
            }
            TunnelMessage::DnsQuery { request_id, query } => {
                buf.put_u8(CommandType::DnsQuery as u8);
                buf.put_u32(*request_id);
                buf.put_u32(query.len() as u32);
                buf.put_slice(query);
            }
            TunnelMessage::DnsResponse {
                request_id,
                response,
            } => {
                buf.put_u8(CommandType::DnsResponse as u8);
                buf.put_u32(*request_id);
                buf.put_u32(response.len() as u32);
                buf.put_slice(response);
            }
            TunnelMessage::ConnectSuccess { stream_id } => {
                buf.put_u8(CommandType::ConnectSuccess as u8);
                buf.put_u32(*stream_id);
            }
            TunnelMessage::HttpRequest {
                stream_id,
                method,
                url,
                headers,
                body,
            } => {
                buf.put_u8(CommandType::HttpRequest as u8);
                buf.put_u32(*stream_id);
                buf.put_u16(method.len() as u16);
                buf.put_slice(method.as_bytes());
                buf.put_u16(url.len() as u16);
                buf.put_slice(url.as_bytes());
                buf.put_u16(headers.len() as u16);
                buf.put_slice(headers.as_bytes());
                buf.put_u32(body.len() as u32);
                buf.put_slice(body);
            }
            TunnelMessage::HttpResponse {
                stream_id,
                status,
                headers,
                body,
            } => {
                buf.put_u8(CommandType::HttpResponse as u8);
                buf.put_u32(*stream_id);
                buf.put_u16(*status);
                buf.put_u16(headers.len() as u16);
                buf.put_slice(headers.as_bytes());
                buf.put_u32(body.len() as u32);
                buf.put_slice(body);
            }
        }

        buf.freeze()
    }

    /// Decode message from binary format
    pub fn decode(data: &[u8]) -> Result<Self, crate::ProtoError> {
        if data.is_empty() {
            return Err(crate::ProtoError::EmptyMessage);
        }

        let mut cursor = Cursor::new(data);
        let cmd = CommandType::try_from(cursor.get_u8())?;

        match cmd {
            CommandType::Connect => {
                if cursor.remaining() < 8 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let stream_id = cursor.get_u32();
                let port = cursor.get_u16();
                let host_len = cursor.get_u16() as usize;

                if cursor.remaining() < host_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let mut host_bytes = vec![0u8; host_len];
                cursor.copy_to_slice(&mut host_bytes);
                let host =
                    String::from_utf8(host_bytes).map_err(|_| crate::ProtoError::InvalidUtf8)?;

                Ok(TunnelMessage::Connect {
                    stream_id,
                    host,
                    port,
                })
            }
            CommandType::Data => {
                if cursor.remaining() < 8 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let stream_id = cursor.get_u32();
                let payload_len = cursor.get_u32() as usize;

                if cursor.remaining() < payload_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let payload =
                    Bytes::copy_from_slice(&data[cursor.position() as usize..][..payload_len]);

                Ok(TunnelMessage::Data { stream_id, payload })
            }
            CommandType::Close => {
                if cursor.remaining() < 4 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let stream_id = cursor.get_u32();
                Ok(TunnelMessage::Close { stream_id })
            }
            CommandType::ErrorReply => {
                if cursor.remaining() < 8 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let stream_id = cursor.get_u32();
                let code = cursor.get_u16();
                let msg_len = cursor.get_u16() as usize;

                if cursor.remaining() < msg_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let mut msg_bytes = vec![0u8; msg_len];
                cursor.copy_to_slice(&mut msg_bytes);
                let message =
                    String::from_utf8(msg_bytes).map_err(|_| crate::ProtoError::InvalidUtf8)?;

                Ok(TunnelMessage::ErrorReply {
                    stream_id,
                    code,
                    message,
                })
            }
            CommandType::Ping => Ok(TunnelMessage::Ping),
            CommandType::Pong => Ok(TunnelMessage::Pong),
            CommandType::UdpDatagram => {
                if cursor.remaining() < 8 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let request_id = cursor.get_u32();
                let port = cursor.get_u16();
                let host_len = cursor.get_u16() as usize;

                if cursor.remaining() < host_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let mut host_bytes = vec![0u8; host_len];
                cursor.copy_to_slice(&mut host_bytes);
                let host =
                    String::from_utf8(host_bytes).map_err(|_| crate::ProtoError::InvalidUtf8)?;

                if cursor.remaining() < 4 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let payload_len = cursor.get_u32() as usize;

                if cursor.remaining() < payload_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let payload =
                    Bytes::copy_from_slice(&data[cursor.position() as usize..][..payload_len]);

                Ok(TunnelMessage::UdpDatagram {
                    request_id,
                    host,
                    port,
                    payload,
                })
            }
            CommandType::DnsQuery => {
                if cursor.remaining() < 8 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let request_id = cursor.get_u32();
                let query_len = cursor.get_u32() as usize;

                if cursor.remaining() < query_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let query =
                    Bytes::copy_from_slice(&data[cursor.position() as usize..][..query_len]);

                Ok(TunnelMessage::DnsQuery { request_id, query })
            }
            CommandType::DnsResponse => {
                if cursor.remaining() < 8 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let request_id = cursor.get_u32();
                let response_len = cursor.get_u32() as usize;

                if cursor.remaining() < response_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let response =
                    Bytes::copy_from_slice(&data[cursor.position() as usize..][..response_len]);

                Ok(TunnelMessage::DnsResponse {
                    request_id,
                    response,
                })
            }
            CommandType::ConnectSuccess => {
                if cursor.remaining() < 4 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let stream_id = cursor.get_u32();
                Ok(TunnelMessage::ConnectSuccess { stream_id })
            }
            CommandType::HttpRequest => {
                if cursor.remaining() < 6 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let stream_id = cursor.get_u32();
                
                let method_len = cursor.get_u16() as usize;
                if cursor.remaining() < method_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let mut method_bytes = vec![0u8; method_len];
                cursor.copy_to_slice(&mut method_bytes);
                let method = String::from_utf8(method_bytes)
                    .map_err(|_| crate::ProtoError::InvalidUtf8)?;

                if cursor.remaining() < 2 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let url_len = cursor.get_u16() as usize;
                if cursor.remaining() < url_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let mut url_bytes = vec![0u8; url_len];
                cursor.copy_to_slice(&mut url_bytes);
                let url = String::from_utf8(url_bytes)
                    .map_err(|_| crate::ProtoError::InvalidUtf8)?;

                if cursor.remaining() < 2 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let headers_len = cursor.get_u16() as usize;
                if cursor.remaining() < headers_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let mut headers_bytes = vec![0u8; headers_len];
                cursor.copy_to_slice(&mut headers_bytes);
                let headers = String::from_utf8(headers_bytes)
                    .map_err(|_| crate::ProtoError::InvalidUtf8)?;

                if cursor.remaining() < 4 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let body_len = cursor.get_u32() as usize;
                if cursor.remaining() < body_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let body = Bytes::copy_from_slice(
                    &data[cursor.position() as usize..][..body_len]
                );

                Ok(TunnelMessage::HttpRequest {
                    stream_id,
                    method,
                    url,
                    headers,
                    body,
                })
            }
            CommandType::HttpResponse => {
                if cursor.remaining() < 8 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let stream_id = cursor.get_u32();
                let status = cursor.get_u16();
                
                let headers_len = cursor.get_u16() as usize;
                if cursor.remaining() < headers_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let mut headers_bytes = vec![0u8; headers_len];
                cursor.copy_to_slice(&mut headers_bytes);
                let headers = String::from_utf8(headers_bytes)
                    .map_err(|_| crate::ProtoError::InvalidUtf8)?;

                if cursor.remaining() < 4 {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let body_len = cursor.get_u32() as usize;
                if cursor.remaining() < body_len {
                    return Err(crate::ProtoError::InsufficientData);
                }
                let body = Bytes::copy_from_slice(
                    &data[cursor.position() as usize..][..body_len]
                );

                Ok(TunnelMessage::HttpResponse {
                    stream_id,
                    status,
                    headers,
                    body,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_roundtrip() {
        let msg = TunnelMessage::Connect {
            stream_id: 42,
            host: "google.com".to_string(),
            port: 443,
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();

        match decoded {
            TunnelMessage::Connect {
                stream_id,
                host,
                port,
            } => {
                assert_eq!(stream_id, 42);
                assert_eq!(host, "google.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_data_roundtrip() {
        let payload = Bytes::from("Hello, World!");
        let msg = TunnelMessage::Data {
            stream_id: 1,
            payload: payload.clone(),
        };
        let encoded = msg.encode();
        let decoded = TunnelMessage::decode(&encoded).unwrap();

        match decoded {
            TunnelMessage::Data {
                stream_id,
                payload: p,
            } => {
                assert_eq!(stream_id, 1);
                assert_eq!(p, payload);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
