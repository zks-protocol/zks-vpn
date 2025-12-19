package vpn

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/zks-vpn/zks-go-client/protocol"
	"github.com/zks-vpn/zks-go-client/relay"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	tunInterfaceName = "zks-tun0"
	tunIP            = "10.0.85.1"
	tunNetmask       = "255.255.255.0"
	mtu              = 1420
	batchSize        = 16 // Read multiple packets at once
)

// StartTUN creates the TUN device and starts processing packets
func StartTUN(relayConn *relay.Connection) error {
	log.Printf("🔌 Creating TUN device: %s", tunInterfaceName)

	// Create TUN device using Wintun
	dev, err := tun.CreateTUN(tunInterfaceName, mtu)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}
	defer dev.Close()

	// Get the real interface name (Wintun might rename it)
	realName, err := dev.Name()
	if err != nil {
		realName = tunInterfaceName
	}
	log.Printf("🌐 TUN device created: %s", realName)

	// Configure IP address
	log.Printf("🔧 Configuring IP: %s/%s", tunIP, tunNetmask)
	if err := configureInterface(realName, tunIP, tunNetmask); err != nil {
		return fmt.Errorf("failed to configure interface: %v", err)
	}

	// Configure Routing (The "Def1" trick)
	log.Printf("twisted_rightwards_arrows Configuring VPN routes...")
	if err := configureRouting(realName); err != nil {
		return fmt.Errorf("failed to configure routing: %v", err)
	}

	// Start packet processing loops
	errChan := make(chan error, 2)

	// Read from TUN -> Send to Relay
	go func() {
		// Buffer for reading from TUN
		// WireGuard tun.Read expects [][]byte
		// We allocate these once and reuse them for the syscall
		buffs := make([][]byte, batchSize)
		for i := 0; i < batchSize; i++ {
			buffs[i] = make([]byte, mtu)
		}
		sizes := make([]int, batchSize)

		for {
			n, err := dev.Read(buffs, sizes, 0)
			if err != nil {
				errChan <- fmt.Errorf("TUN read error: %v", err)
				return
			}

			for i := 0; i < n; i++ {
				if sizes[i] > 0 {
					// Zero-Copy Optimization:
					// Instead of allocating a new slice with make([]byte, sizes[i]),
					// we copy into a pooled buffer.
					// Ideally, we would read directly into pooled buffers, but tun.Read 
					// requires a fixed slice of slices.
					// So we copy from the static read buffer -> pooled buffer.
					// This is still better than allocating a new slice every time because
					// the pooled buffer is reused.
					
					pooledBuf := protocol.GetBuffer()
					// Copy data into pooled buffer
					copy(pooledBuf, buffs[i][:sizes[i]])
					
					// Slice it to correct length
					packet := pooledBuf[:sizes[i]]
					
					// Wrap in IpPacket
					msg := &protocol.IpPacket{Payload: packet}
					
					// Send to relay (async)
					if err := relayConn.Send(msg); err != nil {
						// If send fails, we must return the buffer manually
						// If send succeeds, the writePump is responsible for returning it
						protocol.PutBuffer(pooledBuf)
					}
				}
			}
		}
	}()

	// Read from Relay -> Write to TUN
	go func() {
		for {
			msg, err := relayConn.Recv()
			if err != nil {
				errChan <- fmt.Errorf("relay recv error: %v", err)
				return
			}

			// Check if it's an IP packet
			if ipPacket, ok := msg.(*protocol.IpPacket); ok {
				// Write to TUN
				if len(ipPacket.Payload) > 0 {
					_, err := dev.Write([][]byte{ipPacket.Payload}, 0)
					if err != nil {
						log.Printf("❌ TUN write error: %v", err)
					}
				}
			}
		}
	}()

	log.Printf("✅ VPN tunnel established! Traffic should now flow through %s", tunIP)
	
	// Wait for error
	return <-errChan
}

func configureInterface(ifaceName, ip, netmask string) error {
	// netsh interface ip set address "zks-tun0" static 10.0.85.1 255.255.255.0
	cmd := exec.Command("netsh", "interface", "ip", "set", "address", ifaceName, "static", ip, netmask)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address failed: %v, output: %s", err, out)
	}
	return nil
}

func configureRouting(ifaceName string) error {
	// 1. Get Interface Index
	// powershell -Command "(Get-NetAdapter -Name 'zks-tun0').InterfaceIndex"
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf("(Get-NetAdapter -Name '%s').InterfaceIndex", ifaceName))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get interface index: %v", err)
	}
	ifIndex := strings.TrimSpace(string(out))
	log.Printf("🔢 TUN Interface Index: %s", ifIndex)

	// 2. Get the original default gateway (before we mess with routes)
	cmd = exec.Command("powershell", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1).NextHop")
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("⚠️ Could not get default gateway: %v", err)
	}
	originalGateway := strings.TrimSpace(string(out))
	log.Printf("🌐 Original gateway: %s", originalGateway)

	// 3. Add bypass routes for relay server IPs (Cloudflare Workers)
	// These routes ensure the WebSocket connection to the relay stays on the local network
	// Cloudflare anycast IPs - we route these to the original gateway
	bypassIPs := []string{
		"104.16.0.0/12",    // Cloudflare main range
		"172.64.0.0/13",    // Cloudflare range
		"131.0.72.0/22",    // Cloudflare range
	}

	if originalGateway != "" {
		for _, bypassIP := range bypassIPs {
			log.Printf("🔓 Adding bypass route: %s -> %s (original gateway)", bypassIP, originalGateway)
			cmd := exec.Command("netsh", "interface", "ipv4", "add", "route", bypassIP, "nexthop="+originalGateway, "metric=1")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("⚠️ Bypass route add info: %s", strings.TrimSpace(string(out)))
			}
		}
	}

	// 4. Add VPN routes (0.0.0.0/1 and 128.0.0.0/1) pointing to TUN interface
	routes := []string{
		"0.0.0.0/1",
		"128.0.0.0/1",
	}

	for _, route := range routes {
		// Delete existing if any (ignore error)
		exec.Command("route", "delete", route).Run()

		// Add new route
		parts := strings.Split(route, "/")
		network := parts[0]
		mask := "128.0.0.0" 

		log.Printf("🛣️ Adding route: %s -> Interface %s", route, ifIndex)
		cmd := exec.Command("netsh", "interface", "ipv4", "add", "route", route, "interface="+ifIndex, "metric=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("⚠️ netsh route add failed: %v, output: %s. Trying route.exe...", err, out)
			
			// Fallback to route.exe
			cmd = exec.Command("route", "add", network, "mask", mask, tunIP, "IF", ifIndex)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("route add failed: %v, output: %s", err, out)
			}
		}
	}

	return nil
}

