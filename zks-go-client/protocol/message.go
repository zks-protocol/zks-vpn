// Package protocol implements the ZKS tunnel message encoding/decoding.
// This matches the Rust implementation in zks-tunnel-proto/src/message.rs
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Command types for the tunnel protocol
const (
	CmdConnect        byte = 0x01
	CmdData           byte = 0x02
	CmdClose          byte = 0x03
	CmdErrorReply     byte = 0x04
	CmdPing           byte = 0x05
	CmdPong           byte = 0x06
	CmdUdpDatagram    byte = 0x07
	CmdDnsQuery       byte = 0x08
	CmdDnsResponse    byte = 0x09
	CmdConnectSuccess byte = 0x0A
	CmdHttpRequest    byte = 0x0B
	CmdHttpResponse   byte = 0x0C
	CmdChainForward   byte = 0x10
	CmdChainAck       byte = 0x11
	CmdIpPacket       byte = 0x20
)

// StreamID is the identifier for multiplexed connections
type StreamID = uint32

// TunnelMessage represents a protocol message
type TunnelMessage interface {
	Encode() []byte
	Type() byte
}

// Connect requests a TCP connection to a target
type Connect struct {
	StreamID StreamID
	Host     string
	Port     uint16
}

func (m *Connect) Type() byte { return CmdConnect }

func (m *Connect) Encode() []byte {
	hostBytes := []byte(m.Host)
	buf := make([]byte, 1+4+2+2+len(hostBytes))
	buf[0] = CmdConnect
	binary.BigEndian.PutUint32(buf[1:5], m.StreamID)
	binary.BigEndian.PutUint16(buf[5:7], m.Port)
	binary.BigEndian.PutUint16(buf[7:9], uint16(len(hostBytes)))
	copy(buf[9:], hostBytes)
	return buf
}

// Data contains payload for a stream
type Data struct {
	StreamID StreamID
	Payload  []byte
}

func (m *Data) Type() byte { return CmdData }

func (m *Data) Encode() []byte {
	buf := make([]byte, 1+4+4+len(m.Payload))
	buf[0] = CmdData
	binary.BigEndian.PutUint32(buf[1:5], m.StreamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(m.Payload)))
	copy(buf[9:], m.Payload)
	return buf
}

// Close closes a stream
type Close struct {
	StreamID StreamID
}

func (m *Close) Type() byte { return CmdClose }

func (m *Close) Encode() []byte {
	buf := make([]byte, 1+4)
	buf[0] = CmdClose
	binary.BigEndian.PutUint32(buf[1:5], m.StreamID)
	return buf
}

// ErrorReply indicates an error on a stream
type ErrorReply struct {
	StreamID StreamID
	Code     uint16
	Message  string
}

func (m *ErrorReply) Type() byte { return CmdErrorReply }

func (m *ErrorReply) Encode() []byte {
	msgBytes := []byte(m.Message)
	buf := make([]byte, 1+4+2+2+len(msgBytes))
	buf[0] = CmdErrorReply
	binary.BigEndian.PutUint32(buf[1:5], m.StreamID)
	binary.BigEndian.PutUint16(buf[5:7], m.Code)
	binary.BigEndian.PutUint16(buf[7:9], uint16(len(msgBytes)))
	copy(buf[9:], msgBytes)
	return buf
}

// Ping keepalive
type Ping struct{}

func (m *Ping) Type() byte { return CmdPing }
func (m *Ping) Encode() []byte {
	return []byte{CmdPing}
}

// Pong response
type Pong struct{}

func (m *Pong) Type() byte { return CmdPong }
func (m *Pong) Encode() []byte {
	return []byte{CmdPong}
}

// ConnectSuccess indicates successful connection
type ConnectSuccess struct {
	StreamID StreamID
}

func (m *ConnectSuccess) Type() byte { return CmdConnectSuccess }

func (m *ConnectSuccess) Encode() []byte {
	buf := make([]byte, 1+4)
	buf[0] = CmdConnectSuccess
	binary.BigEndian.PutUint32(buf[1:5], m.StreamID)
	return buf
}

// IpPacket contains raw IP packet for VPN mode
type IpPacket struct {
	Payload []byte
}

func (m *IpPacket) Type() byte { return CmdIpPacket }

func (m *IpPacket) Encode() []byte {
	buf := make([]byte, 1+4+len(m.Payload))
	buf[0] = CmdIpPacket
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(m.Payload)))
	copy(buf[5:], m.Payload)
	return buf
}

// Decode parses a binary message into a TunnelMessage
func Decode(data []byte) (TunnelMessage, error) {
	if len(data) < 1 {
		return nil, errors.New("empty message")
	}

	cmd := data[0]
	switch cmd {
	case CmdConnect:
		if len(data) < 9 {
			return nil, errors.New("insufficient data for Connect")
		}
		streamID := binary.BigEndian.Uint32(data[1:5])
		port := binary.BigEndian.Uint16(data[5:7])
		hostLen := binary.BigEndian.Uint16(data[7:9])
		if len(data) < 9+int(hostLen) {
			return nil, errors.New("insufficient data for Connect host")
		}
		host := string(data[9 : 9+hostLen])
		return &Connect{StreamID: streamID, Host: host, Port: port}, nil

	case CmdData:
		if len(data) < 9 {
			return nil, errors.New("insufficient data for Data")
		}
		streamID := binary.BigEndian.Uint32(data[1:5])
		payloadLen := binary.BigEndian.Uint32(data[5:9])
		if len(data) < 9+int(payloadLen) {
			return nil, errors.New("insufficient data for Data payload")
		}
		payload := make([]byte, payloadLen)
		copy(payload, data[9:9+payloadLen])
		return &Data{StreamID: streamID, Payload: payload}, nil

	case CmdClose:
		if len(data) < 5 {
			return nil, errors.New("insufficient data for Close")
		}
		streamID := binary.BigEndian.Uint32(data[1:5])
		return &Close{StreamID: streamID}, nil

	case CmdErrorReply:
		if len(data) < 9 {
			return nil, errors.New("insufficient data for ErrorReply")
		}
		streamID := binary.BigEndian.Uint32(data[1:5])
		code := binary.BigEndian.Uint16(data[5:7])
		msgLen := binary.BigEndian.Uint16(data[7:9])
		if len(data) < 9+int(msgLen) {
			return nil, errors.New("insufficient data for ErrorReply message")
		}
		msg := string(data[9 : 9+msgLen])
		return &ErrorReply{StreamID: streamID, Code: code, Message: msg}, nil

	case CmdPing:
		return &Ping{}, nil

	case CmdPong:
		return &Pong{}, nil

	case CmdConnectSuccess:
		if len(data) < 5 {
			return nil, errors.New("insufficient data for ConnectSuccess")
		}
		streamID := binary.BigEndian.Uint32(data[1:5])
		return &ConnectSuccess{StreamID: streamID}, nil

	case CmdIpPacket:
		if len(data) < 5 {
			return nil, errors.New("insufficient data for IpPacket")
		}
		payloadLen := binary.BigEndian.Uint32(data[1:5])
		if len(data) < 5+int(payloadLen) {
			return nil, errors.New("insufficient data for IpPacket payload")
		}
		payload := make([]byte, payloadLen)
		copy(payload, data[5:5+payloadLen])
		return &IpPacket{Payload: payload}, nil

	default:
		return nil, fmt.Errorf("invalid command byte: %d", cmd)
	}
}
