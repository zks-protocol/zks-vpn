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
	
	// Write pump
	sendChan chan []byte
	done     chan struct{}
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
		ws:       ws,
		role:     role,
		roomID:   roomID,
		sendChan: make(chan []byte, 256), // Buffered channel for async writes
		done:     make(chan struct{}),
	}

	// Perform key exchange
	if err := conn.performKeyExchange(); err != nil {
		ws.Close()
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	// Start write pump
	go conn.writePump()

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
		_, msg, err := c.ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to read message: %w", err)
		}

		var keMsg KeyExchangeMessage
		if err := json.Unmarshal(msg, &keMsg); err != nil {
			continue // Ignore non-JSON messages
		}

		if keMsg.Type == "key_exchange" && keMsg.PublicKey != "" {
			peerPK, err = protocol.ParseHexPublicKey(keMsg.PublicKey)
			if err != nil {
				return fmt.Errorf("invalid peer public key: %w", err)
			}
			
			// If we are Client, we wait for Exit Peer to send first (which we just did above)
			// If we are Exit Peer, we might need to send ours after receiving (but we sent ours first above)
			// The protocol is symmetric enough here.
			
			// Send ACK
			ackMsg := KeyExchangeMessage{Type: "key_exchange_ack", Success: true}
			ackJSON, _ := json.Marshal(ackMsg)
			if err := c.ws.WriteMessage(websocket.TextMessage, ackJSON); err != nil {
				return fmt.Errorf("failed to send ack: %w", err)
			}

			break
		}
	}

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

// writePump handles outgoing messages
func (c *Connection) writePump() {
	for {
		select {
		case msg, ok := <-c.sendChan:
			if !ok {
				// Channel closed
				c.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.mu.Lock()
			err := c.ws.WriteMessage(websocket.BinaryMessage, msg)
			c.mu.Unlock()
			
			// Zero-Copy Optimization:
			// The msg buffer came from the pool (in Send).
			// We must return it now that we are done with it.
			protocol.PutBuffer(msg)

			if err != nil {
				fmt.Printf("❌ Write error: %v\n", err)
				return
			}
		case <-c.done:
			return
		}
	}
}

// Send encrypts and queues a TunnelMessage
func (c *Connection) Send(msg protocol.TunnelMessage) error {
	// Zero-Copy Optimization:
	// 1. Get a buffer for the ciphertext from the pool
	ciphertextBuf := protocol.GetBuffer()
	
	// 2. Encode the message
	// We try to use zero-copy encoding if possible
	var plaintext []byte
	var encodedBuf []byte // Keep track to return if needed

	if ipPkt, ok := msg.(*protocol.IpPacket); ok {
		// Fast path for IP packets (Zero-Copy Encode)
		encodedBuf = protocol.GetBuffer()
		n := ipPkt.EncodeTo(encodedBuf)
		if n == 0 {
			// Buffer too small? Should not happen with MTU=1420 and Pool=2048
			protocol.PutBuffer(encodedBuf)
			protocol.PutBuffer(ciphertextBuf)
			return errors.New("encoding buffer too small")
		}
		plaintext = encodedBuf[:n]
	} else {
		// Slow path for other messages (Allocating Encode)
		plaintext = msg.Encode()
	}

	// 3. Encrypt directly into the ciphertext buffer
	// EncryptTo appends to dst[:0] (or similar), so we pass ciphertextBuf
	// The result is a slice of ciphertextBuf
	encrypted, err := c.cipher.EncryptTo(ciphertextBuf, plaintext)
	
	// If we used a pooled buffer for encoding, return it now
	if encodedBuf != nil {
		protocol.PutBuffer(encodedBuf)
	}

	if err != nil {
		protocol.PutBuffer(ciphertextBuf) // Return unused ciphertext buffer
		return fmt.Errorf("encryption failed: %w", err)
	}

	// 4. Queue for sending
	select {
	case c.sendChan <- encrypted:
		return nil
	default:
		// If buffer full, we must drop the packet and return the buffer
		protocol.PutBuffer(ciphertextBuf) // Return unused ciphertext buffer
		return errors.New("send buffer full, dropping packet")
	}
}

// Recv reads and decrypts a TunnelMessage
func (c *Connection) Recv() (protocol.TunnelMessage, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for {
		msgType, msg, err := c.ws.ReadMessage()
		if err != nil {
			return nil, err
		}

		if msgType == websocket.TextMessage {
			fmt.Printf("⚠️ Received text message from relay: %s\n", string(msg))
			continue // Skip text messages (likely errors or debug info)
		}

		if msgType != websocket.BinaryMessage {
			continue // Skip other types
		}

		// Decrypt
		plaintext, err := c.cipher.Decrypt(msg)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		// Decode
		return protocol.Decode(plaintext)
	}
}

// Close closes the connection
func (c *Connection) Close() {
	close(c.done)
	c.ws.Close()
}
