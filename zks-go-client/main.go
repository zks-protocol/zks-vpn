// ZKS-VPN Go Client - Zero Knowledge Swarm VPN
// A cross-platform VPN client with reliable Windows TUN support
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/zks-vpn/zks-go-client/relay"
	"github.com/zks-vpn/zks-go-client/socks5"
)

const (
	defaultRelayURL = "wss://zks-tunnel-relay.md-wasif-faisal.workers.dev"
	version         = "1.0.0-go"
)

func main() {
	// CLI flags
	mode := flag.String("mode", "p2p-client", "Mode: p2p-client (SOCKS5), p2p-vpn (TUN), exit-peer")
	room := flag.String("room", "", "Room ID for P2P connection")
	relayURL := flag.String("relay", defaultRelayURL, "Relay WebSocket URL")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.Parse()

	if *room == "" {
		fmt.Println("Error: --room is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║         ZKS-VPN Go Client - Zero Knowledge Swarm             ║")
	fmt.Printf("║  Version: %-51s ║\n", version)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Mode:   %-52s ║\n", *mode)
	fmt.Printf("║  Room:   %-52s ║\n", *room)
	fmt.Printf("║  Relay:  %-52s ║\n", *relayURL)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	switch *mode {
	case "p2p-client":
		runP2PClient(*relayURL, *room, *listenAddr)
	case "p2p-vpn":
		runP2PVPN(*relayURL, *room)
	case "exit-peer":
		runExitPeer(*relayURL, *room)
	default:
		fmt.Printf("Unknown mode: %s\n", *mode)
		os.Exit(1)
	}
}

func runP2PClient(relayURL, roomID, listenAddr string) {
	fmt.Println("\n🔒 Starting P2P Client (SOCKS5 Proxy Mode)...")

	// Connect to relay
	conn, err := relay.Connect(relayURL, roomID, relay.RoleClient)
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("✅ Connected to Exit Peer via ZKS relay")
	fmt.Println("   All traffic will be end-to-end encrypted")

	// Start SOCKS5 server
	server := socks5.NewServer(conn)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⏹️  Shutting down...")
		server.Stop()
		conn.Close()
		os.Exit(0)
	}()

	if err := server.Start(listenAddr); err != nil {
		fmt.Printf("❌ SOCKS5 server error: %v\n", err)
		os.Exit(1)
	}
}

func runP2PVPN(relayURL, roomID string) {
	fmt.Println("\n🔒 Starting P2P VPN (System-Wide TUN Mode)...")
	fmt.Println("⚠️  VPN mode requires Administrator privileges")

	// TODO: Implement TUN mode using WireGuard's wintun
	fmt.Println("❌ VPN mode not yet implemented in Go client")
	fmt.Println("   Use --mode p2p-client for SOCKS5 proxy mode")
	os.Exit(1)
}

func runExitPeer(relayURL, roomID string) {
	fmt.Println("\n🔒 Starting Exit Peer Mode...")

	// Connect to relay as Exit Peer
	conn, err := relay.Connect(relayURL, roomID, relay.RoleExitPeer)
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("✅ Connected to relay as Exit Peer")
	fmt.Println("⏳ Waiting for Client to connect...")

	// TODO: Implement Exit Peer message handling
	fmt.Println("❌ Exit Peer mode not yet fully implemented")
	os.Exit(1)
}
