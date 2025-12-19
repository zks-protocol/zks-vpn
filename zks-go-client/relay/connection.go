// Package relay implements WebSocket connection to ZKS relay with key exchange
package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/zks-vpn/zks-go-client/protocol"
)

// PeerRole defines the role in the VPN connection
type PeerRole string

const (
	RoleClient   PeerRole = "client"
	RoleExitPeer PeerRole = "exit"
)

// KeyExchangeMessage represents key exchange JSON messages
type KeyExchangeMessage struct {
	Type      string `json:"type"`
	PublicKey string `json:"public_key,omitempty"`
	Success   bool   `json:"success,omitempty"`
}

// Connection represents a connection to the ZKS relay
type Connection struct {
	ws       *websocket.Conn
	cipher   *protocol.WasifVernam
	role     PeerRole
	roomID   string
	mu       sync.Mutex
	recvMu   sync.Mutex
}

// Connect establishes a connection to the relay and performs key exchange
func Connect(relayURL, roomID string, role PeerRole) (*Connection, error) {
	// Parse and build WebSocket URL
	u, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL: %w", err)
	}

	// Convert http(s) to ws(s)
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}

	// Build final URL: /room/{roomID}?role={role}
	u.Path = fmt.Sprintf("/room/%s", roomID)
	u.RawQuery = fmt.Sprintf("role=%s", role)

	fmt.Printf("🔌 Connecting to relay: %s\n", u.String())

	// Connect via WebSocket
	ws, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	fmt.Printf("✅ Connected to relay (status: %d)\n", resp.StatusCode)

	conn := &Connection{
		ws:     ws,
		role:   role,
		roomID: roomID,
	}

	// Perform key exchange
	if err := conn.performKeyExchange(); err != nil {
		ws.Close()
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	return conn, nil
}

// performKeyExchange implements X25519 key exchange with the peer
func (c *Connection) performKeyExchange() error {
	fmt.Println("🔑 Initiating X25519 key exchange...")

	// Generate our keypair
	ke, err := protocol.NewKeyExchange(c.roomID)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Send our public key
	ourPKMsg := KeyExchangeMessage{
		Type:      "key_exchange",
		PublicKey: ke.GetPublicKeyHex(),
	}
	ourPKJSON, _ := json.Marshal(ourPKMsg)
	if err := c.ws.WriteMessage(websocket.TextMessage, ourPKJSON); err != nil {
		return fmt.Errorf("failed to send public key: %w", err)
	}

	// Wait for peer's public key
	var peerPK []byte
	for {
		msgType, data, err := c.ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to read from relay: %w", err)
		}

		if msgType == websocket.TextMessage {
			var msg KeyExchangeMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue // Ignore malformed messages
			}

			switch msg.Type {
			case "key_exchange":
				// Parse peer's public key
				peerPK, err = protocol.ParseHexPublicKey(msg.PublicKey)
				if err != nil {
					return fmt.Errorf("invalid peer public key: %w", err)
				}
				// If we're client and received peer's key first, send ours again
				if c.role == RoleClient {
					if err := c.ws.WriteMessage(websocket.TextMessage, ourPKJSON); err != nil {
						return fmt.Errorf("failed to resend public key: %w", err)
					}
				}

			case "key_exchange_ack":
				if msg.Success && len(peerPK) == 32 {
					// Key exchange complete
					goto COMPLETE
				}
			}

			// If we have peer's key, compute shared secret and send ACK
			if len(peerPK) == 32 {
				encKey, err := ke.ComputeSharedSecret(peerPK)
				if err != nil {
					return fmt.Errorf("failed to compute shared secret: %w", err)
				}

				// Create cipher
				c.cipher, err = protocol.NewWasifVernam(encKey)
				if err != nil {
					return fmt.Errorf("failed to create cipher: %w", err)
				}

				// Send ACK
				ackMsg := KeyExchangeMessage{Type: "key_exchange_ack", Success: true}
				ackJSON, _ := json.Marshal(ackMsg)
				if err := c.ws.WriteMessage(websocket.TextMessage, ackJSON); err != nil {
					return fmt.Errorf("failed to send ack: %w", err)
				}

				fmt.Println("🔐 Key exchange complete! Encryption key derived.")
				return nil
			}
		}
	}

COMPLETE:
	if len(peerPK) != 32 {
		return errors.New("key exchange completed without peer public key")
	}

	encKey, err := ke.ComputeSharedSecret(peerPK)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	c.cipher, err = protocol.NewWasifVernam(encKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	fmt.Println("🔐 Key exchange complete! Encryption key derived.")
	return nil
}

// Send encrypts and sends a TunnelMessage
func (c *Connection) Send(msg protocol.TunnelMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Encode message
	plaintext := msg.Encode()

	// Encrypt
	ciphertext, err := c.cipher.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Send as binary WebSocket message
	return c.ws.WriteMessage(websocket.BinaryMessage, ciphertext)
}

// Recv receives and decrypts a TunnelMessage
func (c *Connection) Recv() (protocol.TunnelMessage, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for {
		msgType, data, err := c.ws.ReadMessage()
		if err != nil {
			return nil, fmt.Errorf("read error: %w", err)
		}

		// Skip text messages (key exchange messages after initial handshake)
		if msgType != websocket.BinaryMessage {
			continue
		}

		// Decrypt
		plaintext, err := c.cipher.Decrypt(data)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		// Decode message
		msg, err := protocol.Decode(plaintext)
		if err != nil {
			return nil, fmt.Errorf("decode failed: %w", err)
		}

		return msg, nil
	}
}

// Close closes the connection
func (c *Connection) Close() error {
	return c.ws.Close()
}
