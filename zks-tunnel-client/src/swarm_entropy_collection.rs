//! Swarm Entropy Collection via WebSocket Relay
//!
//! Implements commitment-based entropy collection using existing relay infrastructure.

use crate::entropy_events::EntropyEvent;
use crate::entropy_tax::EntropyTax;
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use std::collections::HashSet;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info};

/// Collect Swarm Entropy from peers via WebSocket relay
///
/// This function implements the commitment-based protocol:
/// 1. Send commitment (SHA256 of local entropy)
/// 2. Wait for all peer commitments
/// 3. Reveal actual entropy
/// 4. Wait for all peer reveals
/// 5. Derive 1MB remote key
///
/// # Arguments
/// * `writer` - WebSocket sink for sending messages
/// * `reader` - WebSocket stream for receiving messages
/// * `room_id` - Room identifier for entropy derivation
/// * `peer_ids` - List of expected peer IDs
///
/// # Returns
/// * `Ok(Vec<u8>)` - 1MB remote key derived from swarm entropy
/// * `Err(String)` - Error message if collection fails
pub async fn collect_swarm_entropy_via_relay<S>(
    writer: &mut futures::stream::SplitSink<WebSocketStream<S>, Message>,
    reader: &mut SplitStream<WebSocketStream<S>>,
    room_id: &str,
    peer_ids: Vec<String>,
) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    info!(
        "🎲 Starting Swarm Entropy collection with {} peers",
        peer_ids.len()
    );

    let mut entropy_tax = EntropyTax::new();
    let our_peer_id = "self".to_string(); // TODO: Get actual peer ID from relay

    // Phase 1: Send commitment
    let commitment = entropy_tax.get_commitment();
    let commit_event = EntropyEvent::commit(our_peer_id.clone(), commitment);
    let commit_json = commit_event
        .to_json()
        .map_err(|e| format!("Failed to serialize commitment: {}", e))?;

    writer
        .send(Message::Text(commit_json))
        .await
        .map_err(|e| format!("Failed to send commitment: {}", e))?;

    entropy_tax.mark_committed();
    debug!("✅ Sent commitment to relay");

    // Phase 2: Collect peer commitments
    let mut committed_peers = HashSet::new();

    while !entropy_tax.all_committed(&peer_ids) {
        if let Some(Ok(Message::Text(msg))) = reader.next().await {
            if let Ok(EntropyEvent::Commit {
                peer_id,
                commitment: commit_hex,
            }) = EntropyEvent::from_json(&msg)
            {
                if peer_ids.contains(&peer_id) && !committed_peers.contains(&peer_id) {
                    let commit_bytes = hex::decode(&commit_hex)
                        .map_err(|e| format!("Invalid commitment hex: {}", e))?;

                    if commit_bytes.len() != 32 {
                        return Err(format!("Invalid commitment size from {}", peer_id));
                    }

                    let mut commitment = [0u8; 32];
                    commitment.copy_from_slice(&commit_bytes);

                    entropy_tax.add_peer_commitment(peer_id.clone(), commitment)?;
                    committed_peers.insert(peer_id.clone());

                    debug!(
                        "✅ Received commitment from {} ({}/{})",
                        peer_id,
                        committed_peers.len(),
                        peer_ids.len()
                    );
                }
            }
        }
    }

    info!("✅ All peers committed, revealing entropy");

    // Phase 3: Reveal entropy
    let local_entropy = entropy_tax.reveal(&peer_ids)?;
    let reveal_event = EntropyEvent::reveal(our_peer_id.clone(), local_entropy);
    let reveal_json = reveal_event
        .to_json()
        .map_err(|e| format!("Failed to serialize reveal: {}", e))?;

    writer
        .send(Message::Text(reveal_json))
        .await
        .map_err(|e| format!("Failed to send reveal: {}", e))?;

    debug!("✅ Sent entropy reveal to relay");

    // Phase 4: Collect peer reveals
    let mut revealed_peers = HashSet::new();

    while !entropy_tax.all_revealed(&peer_ids) {
        if let Some(Ok(Message::Text(msg))) = reader.next().await {
            if let Ok(EntropyEvent::Reveal {
                peer_id,
                entropy: entropy_hex,
            }) = EntropyEvent::from_json(&msg)
            {
                if peer_ids.contains(&peer_id) && !revealed_peers.contains(&peer_id) {
                    let entropy_bytes = hex::decode(&entropy_hex)
                        .map_err(|e| format!("Invalid entropy hex: {}", e))?;

                    if entropy_bytes.len() != 32 {
                        return Err(format!("Invalid entropy size from {}", peer_id));
                    }

                    let mut entropy = [0u8; 32];
                    entropy.copy_from_slice(&entropy_bytes);

                    entropy_tax.add_peer_entropy(peer_id.clone(), entropy)?;
                    revealed_peers.insert(peer_id.clone());

                    debug!(
                        "✅ Received entropy from {} ({}/{})",
                        peer_id,
                        revealed_peers.len(),
                        peer_ids.len()
                    );
                }
            }
        }
    }

    info!("✅ All peers revealed, deriving remote key");

    // Phase 5: Derive remote key
    let remote_key = entropy_tax.derive_remote_key(&our_peer_id, room_id, &peer_ids)?;

    info!("🎉 Swarm Entropy collection complete! Derived 1MB remote key");

    Ok(remote_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_event_creation() {
        let commitment = [0xAB; 32];
        let event = EntropyEvent::commit("peer1".to_string(), commitment);

        let json = event.to_json().unwrap();
        assert!(json.contains("entropy_commit"));
        assert!(json.contains("peer1"));
    }
}
