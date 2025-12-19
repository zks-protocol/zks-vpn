// Package socks5 implements a SOCKS5 proxy server
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zks-vpn/zks-go-client/protocol"
	"github.com/zks-vpn/zks-go-client/relay"
)

// Server is a SOCKS5 proxy server that tunnels through Exit Peer
type Server struct {
	listener     net.Listener
	conn         *relay.Connection
	streams      map[protocol.StreamID]chan protocol.TunnelMessage
	streamsMu    sync.RWMutex
	nextStreamID uint32
	running      bool
}

// NewServer creates a new SOCKS5 server
func NewServer(conn *relay.Connection) *Server {
	return &Server{
		conn:         conn,
		streams:      make(map[protocol.StreamID]chan protocol.TunnelMessage),
		nextStreamID: 1,
	}
}

// Start starts the SOCKS5 server on the given address
func (s *Server) Start(listenAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.listener = listener
	s.running = true

	fmt.Printf("🚀 SOCKS5 proxy listening on %s\n", listenAddr)
	fmt.Println("   Configure your browser: SOCKS5 proxy =", listenAddr)

	// Start relay receiver goroutine
	go s.relayReceiver()

	// Accept connections
	for s.running {
		conn, err := listener.Accept()
		if err != nil {
			if !s.running {
				break
			}
			continue
		}
		go s.handleClient(conn)
	}

	return nil
}

// relayReceiver receives messages from relay and dispatches to streams
func (s *Server) relayReceiver() {
	for s.running {
		msg, err := s.conn.Recv()
		if err != nil {
			fmt.Printf("Relay receive error: %v\n", err)
			break
		}

		var streamID protocol.StreamID
		switch m := msg.(type) {
		case *protocol.ConnectSuccess:
			streamID = m.StreamID
		case *protocol.Data:
			streamID = m.StreamID
		case *protocol.Close:
			streamID = m.StreamID
		case *protocol.ErrorReply:
			streamID = m.StreamID
		default:
			continue
		}

		s.streamsMu.RLock()
		ch, ok := s.streams[streamID]
		s.streamsMu.RUnlock()
		if ok {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

// handleClient handles a single SOCKS5 client connection
func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)

	// Read greeting
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// Send no-auth response
	conn.Write([]byte{0x05, 0x00})

	// Read request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		// Only CONNECT supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse destination
	var host string
	var port uint16

	switch buf[3] {
	case 0x01: // IPv4
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // Domain
		hostLen := int(buf[4])
		host = string(buf[5 : 5+hostLen])
		port = binary.BigEndian.Uint16(buf[5+hostLen : 7+hostLen])
	case 0x04: // IPv6 - not supported
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	fmt.Printf("SOCKS5 CONNECT to %s:%d\n", host, port)

	// Get stream ID
	streamID := protocol.StreamID(atomic.AddUint32(&s.nextStreamID, 1))

	// Register stream
	ch := make(chan protocol.TunnelMessage, 100)
	s.streamsMu.Lock()
	s.streams[streamID] = ch
	s.streamsMu.Unlock()

	defer func() {
		s.streamsMu.Lock()
		delete(s.streams, streamID)
		s.streamsMu.Unlock()
		close(ch)
	}()

	// Send CONNECT request to Exit Peer
	connectMsg := &protocol.Connect{
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}
	if err := s.conn.Send(connectMsg); err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}

	// Wait for ConnectSuccess or Error (with timeout)
	select {
	case msg := <-ch:
		switch m := msg.(type) {
		case *protocol.ConnectSuccess:
			// Success - send SOCKS5 success response
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		case *protocol.ErrorReply:
			fmt.Printf("Connect error: %s\n", m.Message)
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		default:
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	case <-time.After(30 * time.Second):
		fmt.Printf("Connect timeout for %s:%d\n", host, port)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}

	// Start bidirectional forwarding
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Relay
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					// Connection closed, send Close message
				}
				s.conn.Send(&protocol.Close{StreamID: streamID})
				return
			}

			dataMsg := &protocol.Data{
				StreamID: streamID,
				Payload:  buf[:n],
			}
			if err := s.conn.Send(dataMsg); err != nil {
				return
			}
		}
	}()

	// Relay -> Client
	go func() {
		defer wg.Done()
		for msg := range ch {
			switch m := msg.(type) {
			case *protocol.Data:
				if _, err := conn.Write(m.Payload); err != nil {
					return
				}
			case *protocol.Close:
				return
			case *protocol.ErrorReply:
				return
			}
		}
	}()

	wg.Wait()
}

// Stop stops the SOCKS5 server
func (s *Server) Stop() error {
	s.running = false
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
