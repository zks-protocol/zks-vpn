package vpn

import (
	"fmt"
	"log"
	"net"
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
	batchSize        = 8000 // Ultra Mode: ~1TB/day on Cloudflare Free Tier
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

			// Collect packets into a batch
			batch := make([][]byte, 0, n)
			for i := 0; i < n; i++ {
				if sizes[i] > 0 {
					// Zero-Copy Optimization:
					// Copy into pooled buffer for batch sending
					pooledBuf := protocol.GetBuffer()
					copy(pooledBuf, buffs[i][:sizes[i]])
					packet := pooledBuf[:sizes[i]]
					batch = append(batch, packet)
				}
			}

			// Send entire batch as a single WebSocket message
			// This reduces overhead by 16x compared to individual sends
			if len(batch) > 0 {
				msg := &protocol.BatchIpPacket{Packets: batch}
				if err := relayConn.Send(msg); err != nil {
					// If send fails, return all buffers in batch
					for _, pkt := range batch {
						protocol.PutBuffer(pkt)
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

			// Handle BatchIpPacket (multiple packets in one message)
			if batchPacket, ok := msg.(*protocol.BatchIpPacket); ok {
				// Write all packets in batch to TUN
				if len(batchPacket.Packets) > 0 {
					_, err := dev.Write(batchPacket.Packets, 0)
					if err != nil {
						log.Printf("❌ TUN batch write error: %v", err)
					}
				}
				continue
			}

			// Handle single IpPacket (backwards compatibility)
			if ipPacket, ok := msg.(*protocol.IpPacket); ok {
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

	// Set Interface Metric to 1 to ensure our routes take precedence
	// Windows Automatic Metric can assign high values (e.g. 25-50) which overrides our route metric
	log.Printf("📉 Setting TUN interface metric to 1...")
	exec.Command("netsh", "interface", "ipv4", "set", "interface", ifIndex, "metric=1").Run()

	// 2. Get the original default gateway (robust method)
	// We get all NextHops for 0.0.0.0/0 and filter in Go to avoid PowerShell syntax issues
	cmd = exec.Command("powershell", "-Command", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop")
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("⚠️ Could not get default gateway: %v", err)
	}
	
	gatewayOutput := strings.TrimSpace(string(out))
	originalGateway := ""
	for _, line := range strings.Split(gatewayOutput, "\r\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != "0.0.0.0" && line != "::" {
			originalGateway = line
			break
		}
	}
	log.Printf("🌐 Original gateway: %s", originalGateway)

	// 3. Add bypass routes for relay server IPs
	// Resolve relay hostname to get exact IPs
	relayHost := "zks-tunnel-relay.md-wasif-faisal.workers.dev"
	ips, err := net.LookupHost(relayHost)
	if err != nil {
		log.Printf("⚠️ Failed to resolve relay host %s: %v", relayHost, err)
	}

	bypassIPs := []string{
		"104.16.0.0/12",    // Cloudflare main range
		"172.64.0.0/13",    // Cloudflare range
		"131.0.72.0/22",    // Cloudflare range
	}
	// Add resolved IPs to bypass list
	for _, ip := range ips {
		if strings.Contains(ip, ".") { // IPv4 only
			bypassIPs = append(bypassIPs, ip+"/32")
		}
	}

	if originalGateway != "" {
		for _, bypassIP := range bypassIPs {
			log.Printf("🔓 Adding bypass route: %s -> %s", bypassIP, originalGateway)
			// Use route.exe for reliability
			// route add <IP> mask <MASK> <GATEWAY> metric 1
			parts := strings.Split(bypassIP, "/")
			ip := parts[0]
			// Calculate mask from prefix length (simple lookup for common ones)
			mask := "255.255.255.255" // Default for /32
			if len(parts) > 1 {
				switch parts[1] {
				case "12": mask = "255.240.0.0"
				case "13": mask = "255.248.0.0"
				case "22": mask = "255.255.252.0"
				}
			}
			
			exec.Command("route", "add", ip, "mask", mask, originalGateway, "metric", "1").Run()
		}
	} else {
		log.Printf("❌ CRITICAL: No default gateway found! VPN routing loop likely!")
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

