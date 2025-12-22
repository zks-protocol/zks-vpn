//! Secure File Transfer Module
//!
//! Implements P2P file transfer using the established secure tunnel.
//! Features:
//! - Chunked transfer
//! - Authenticated encryption (ChaCha20Poly1305) using session key
//! - Automatic reassembly

use crate::p2p_relay::{P2PRelay, PeerRole};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::info;

/// Ticket containing all info needed to receive a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTicket {
    pub r: String, // room_id
    pub p: String, // peer_id (sender)
    pub f: String, // filename
    pub s: u64,    // size
    pub h: String, // hash (BLAKE3 hex)
}

impl TransferTicket {
    pub fn new(room_id: &str, peer_id: &str, filename: &str, size: u64, hash: &str) -> Self {
        Self {
            r: room_id.to_string(),
            p: peer_id.to_string(),
            f: filename.to_string(),
            s: size,
            h: hash.to_string(),
        }
    }

    pub fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let b64 = s.strip_prefix("zks://").ok_or("Invalid ticket format")?;
        let json_bytes = URL_SAFE_NO_PAD.decode(b64)?;
        let ticket = serde_json::from_slice(&json_bytes)?;
        Ok(ticket)
    }
}

impl std::fmt::Display for TransferTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        let b64 = URL_SAFE_NO_PAD.encode(json);
        write!(f, "zks://{}", b64)
    }
}

/// Message types for file transfer protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FileTransferMessage {
    /// Request to send a file
    Metadata {
        filename: String,
        size: u64,
        id: u32,
    },
    /// File data chunk
    Chunk {
        id: u32,
        offset: u64,
        data: Vec<u8>, // Encrypted data
        nonce: Vec<u8>,
    },
    /// Acknowledge chunk received
    Ack { id: u32, offset: u64 },
    /// Transfer complete
    Complete { id: u32 },
    /// Error during transfer
    Error { id: u32, message: String },
    /// Request to resume transfer
    ResumeRequest { id: u32, offset: u64 },
}

/// Handles sending files
pub struct FileSender {
    file_path: PathBuf,
    _transfer_id: u32,
    cipher: ChaCha20Poly1305,
}

impl FileSender {
    pub fn new(path: PathBuf, transfer_id: u32, key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self {
            file_path: path,
            _transfer_id: transfer_id,
            cipher,
        }
    }

    pub async fn read_chunk(
        &self,
        offset: u64,
        size: usize,
    ) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let mut file = File::open(&self.file_path).await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;

        let mut buffer = vec![0u8; size];
        let n = file.read(&mut buffer).await?;
        buffer.truncate(n);

        if n == 0 {
            return Ok((vec![], vec![]));
        }

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per chunk
        let ciphertext = self
            .cipher
            .encrypt(&nonce, buffer.as_ref())
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        Ok((ciphertext, nonce.to_vec()))
    }
}

/// Handles receiving files
pub struct FileReceiver {
    output_dir: PathBuf,
    active_transfers: Arc<Mutex<HashMap<u32, (File, String)>>>, // ID -> (FileHandle, Filename)
    cipher: ChaCha20Poly1305,
}

impl FileReceiver {
    pub fn new(output_dir: PathBuf, key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self {
            output_dir,
            active_transfers: Arc::new(Mutex::new(HashMap::new())),
            cipher,
        }
    }

    pub async fn start_transfer(
        &self,
        id: u32,
        filename: String,
        size: u64,
    ) -> std::io::Result<u64> {
        let path = self.output_dir.join(&filename);
        let mut offset = 0;

        let file = if path.exists() {
            let metadata = tokio::fs::metadata(&path).await?;
            let current_size = metadata.len();
            if current_size < size {
                info!("Found partial file, resuming from {}", current_size);
                offset = current_size;
                let mut f = tokio::fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open(path)
                    .await?;
                f.seek(std::io::SeekFrom::Start(offset)).await?;
                f
            } else {
                // Overwrite if same size or larger (assume new transfer)
                File::create(path).await?
            }
        } else {
            File::create(path).await?
        };

        let mut transfers = self.active_transfers.lock().await;
        transfers.insert(id, (file, filename));
        Ok(offset)
    }

    pub async fn write_chunk(
        &self,
        id: u32,
        offset: u64,
        data: &[u8],
        nonce: &[u8],
    ) -> std::io::Result<()> {
        let mut transfers = self.active_transfers.lock().await;

        if let Some((file, _)) = transfers.get_mut(&id) {
            let nonce = Nonce::from_slice(nonce);
            let plaintext = self
                .cipher
                .decrypt(nonce, data)
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            file.seek(std::io::SeekFrom::Start(offset)).await?;
            file.write_all(&plaintext).await?;
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Transfer ID not found",
            ))
        }
    }

    pub async fn finish_transfer(&self, id: u32) -> std::io::Result<String> {
        let mut transfers = self.active_transfers.lock().await;
        if let Some((mut file, filename)) = transfers.remove(&id) {
            file.flush().await?;
            Ok(filename)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Transfer ID not found",
            ))
        }
    }
}

pub async fn run_send_file(
    relay_url: &str,
    vernam_url: &str,
    room_id: &str,
    file_path: &str,
    _dest_peer: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        return Err("File not found".into());
    }
    let filename = path.file_name().unwrap().to_string_lossy().to_string();
    let size = tokio::fs::metadata(&path).await?.len();

    info!("Connecting to relay...");
    let relay = P2PRelay::connect(relay_url, vernam_url, room_id, PeerRole::Client, None).await?;
    info!("Connected. Shared secret established.");

    // Use the first 32 bytes of the shared secret for encryption
    let key = relay.shared_secret;
    let sender = FileSender::new(path.clone(), 1, &key);

    // Calculate hash for ticket
    let mut hasher = Hasher::new();
    let mut file = File::open(&path).await?;
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer for hashing
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let hash = hex::encode(hasher.finalize().as_bytes());

    // Generate and print ticket
    // Note: We don't know our own peer ID easily here without querying relay,
    // but for now we'll assume the receiver knows it or we send it in metadata.
    // Actually, let's just use a placeholder or ask relay.
    // For simplicity in this iteration, we'll skip putting peer_id in ticket if we don't have it,
    // or rely on the room.

    let ticket = TransferTicket::new(room_id, "sender", &filename, size, &hash);
    info!("🎟️  Share this ticket to receive the file:");
    info!("{}", ticket.to_string());

    // Send metadata
    let metadata = FileTransferMessage::Metadata {
        filename: filename.clone(),
        size,
        id: 1,
    };
    let json = serde_json::to_string(&metadata)?;
    relay.send_raw(json.as_bytes()).await?;
    info!("Sent metadata for {}", filename);

    // Setup Progress Bar
    let pb = ProgressBar::new(size);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    // Send chunks
    let chunk_size = 1024 * 64; // 64KB chunks
                                // Wait for Resume Request or start from 0
    let mut offset = 0;

    // Simple handshake: wait a bit for resume request, otherwise start
    // In a real implementation, we'd have a specific state machine.
    // For now, let's check if we receive a ResumeRequest within 2 seconds.
    let mut waiting_for_resume = true;
    let start_wait = std::time::Instant::now();

    while waiting_for_resume && start_wait.elapsed().as_secs() < 2 {
        if let Some(data) = relay.recv_raw_timeout(100).await {
            if let Ok(FileTransferMessage::ResumeRequest {
                id: _,
                offset: req_offset,
            }) = serde_json::from_slice::<FileTransferMessage>(&data)
            {
                info!("Resuming transfer from offset {}", req_offset);
                offset = req_offset;
                waiting_for_resume = false;
            }
        }
    }

    pb.set_position(offset);

    loop {
        let (data, nonce) = sender.read_chunk(offset, chunk_size).await?;
        if data.is_empty() {
            break;
        }

        let chunk = FileTransferMessage::Chunk {
            id: 1,
            offset,
            data,
            nonce,
        };
        let json = serde_json::to_string(&chunk)?;
        relay.send_raw(json.as_bytes()).await?;

        offset += chunk_size as u64;
        pb.set_position(offset);
    }
    pb.finish_with_message("Done");

    // Send complete
    let complete = FileTransferMessage::Complete { id: 1 };
    let json = serde_json::to_string(&complete)?;
    relay.send_raw(json.as_bytes()).await?;

    info!("File transfer complete!");
    Ok(())
}

pub async fn run_receive_file(
    relay_url: &str,
    vernam_url: &str,
    room_id: &str,
    ticket_str: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (final_room_id, _ticket) = if let Some(t) = ticket_str {
        let ticket = TransferTicket::from_str(&t)?;
        info!("Using ticket for file: {}", ticket.f);
        (ticket.r.clone(), Some(ticket))
    } else {
        (room_id.to_string(), None)
    };

    info!("Connecting to relay as Receiver...");
    let relay = P2PRelay::connect(
        relay_url,
        vernam_url,
        &final_room_id,
        PeerRole::ExitPeer,
        None,
    )
    .await?;
    info!("Connected. Waiting for file...");

    let key = relay.shared_secret;
    let receiver = FileReceiver::new(PathBuf::from("."), &key);

    let mut pb = ProgressBar::hidden();

    loop {
        if let Some(data) = relay.recv_raw().await? {
            if let Ok(msg) = serde_json::from_slice::<FileTransferMessage>(&data) {
                match msg {
                    FileTransferMessage::Metadata { filename, size, id } => {
                        info!("Receiving file: {} ({} bytes)", filename, size);
                        let offset = receiver.start_transfer(id, filename, size).await?;

                        if offset > 0 {
                            let resume_msg = FileTransferMessage::ResumeRequest { id, offset };
                            let json = serde_json::to_string(&resume_msg)?;
                            relay.send_raw(json.as_bytes()).await?;
                            info!("Sent resume request for offset {}", offset);
                        }

                        pb = ProgressBar::new(size);
                        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                            .unwrap()
                            .progress_chars("#>-"));
                        pb.set_position(offset);
                    }
                    FileTransferMessage::Chunk {
                        id,
                        offset,
                        data,
                        nonce,
                    } => {
                        receiver.write_chunk(id, offset, &data, &nonce).await?;
                        pb.set_position(offset + data.len() as u64);
                    }
                    FileTransferMessage::Complete { id } => {
                        pb.finish_with_message("Done");
                        let filename = receiver.finish_transfer(id).await?;
                        info!("File received: {}", filename);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
