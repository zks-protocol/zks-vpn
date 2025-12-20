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
	// BatchSize = 1024: Optimized for Cloudflare WebSocket Relay architecture
	// - WireGuard uses 128 for direct kernel reads (latency-optimized)
	// - We use 1024 for WebSocket relay (quota-optimized: 100k req/day limit)
	// - Opportunistic batching means latency is NOT affected (sends immediately)
	// - Daily limit: ~136 GB, RAM/user: ~1.5 MB, Max users: ~85
	batchSize = 1024
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
	
	// Configure DNS to prevent DNS leaks
	if err := configureDNS(ifaceName); err != nil {
		log.Printf("⚠️ DNS configuration warning: %v", err)
		// Non-fatal - VPN will work but may have DNS leaks
	}
	
	return nil
}

// configureDNS implements modern Windows DNS leak prevention using NRPT
func configureDNS(ifaceName string) error {
	log.Printf("🔒 Configuring DNS leak prevention (NRPT)...")
	
	// Step 1: Set DNS servers on TUN interface to Cloudflare/Google DNS
	dnsServers := []string{"1.1.1.1", "8.8.8.8"}
	
	for i, dns := range dnsServers {
		var cmd *exec.Cmd
		if i == 0 {
			// Primary DNS
			cmd = exec.Command("powershell", "-NoProfile", "-Command", 
				fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses '%s'", ifaceName, dns))
		} else {
			// Add secondary DNS
			cmd = exec.Command("netsh", "interface", "ipv4", "add", "dns", ifaceName, dns, "index="+fmt.Sprint(i+1))
		}
		
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("⚠️ Failed to set DNS server %s: %v, output: %s", dns, err, out)
		}
	}
	
	// Step 2: Add NRPT rule to route ALL DNS queries through VPN interface
	// This is the modern Windows approach used by Always On VPN
	// NRPT = Name Resolution Policy Table
	nrptCmd := fmt.Sprintf(`
		# Remove existing NRPT rules for this namespace
		Get-DnsClientNrptRule | Where-Object {$_.Namespace -eq '.'} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
		
		# Add NRPT rule for all DNS queries (namespace = '.')
		# This forces ALL DNS through the VPN's DNS servers
		Add-DnsClientNrptRule -Namespace '.' -NameServers '%s','%s' -Comment 'ZKS-VPN DNS Leak Prevention'
	`, dnsServers[0], dnsServers[1])
	
	cmd := exec.Command("powershell", "-NoProfile", "-Command", nrptCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("⚠️ NRPT rule failed (non-fatal): %v, output: %s", err, out)
		// Fallback approach: Clear DNS cache
		exec.Command("ipconfig", "/flushdns").Run()
		return fmt.Errorf("NRPT not supported, using basic DNS config")
	}
	
	log.Printf("✅ DNS leak prevention configured (NRPT active)")
	
	// Flush DNS cache to apply changes immediately
	exec.Command("ipconfig", "/flushdns").Run()
	
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

	// NOTE: Relay bypass routes are now handled in main.go BEFORE TUN creation
	// This is done by addRelayBypassRoutes() which resolves the relay hostname
	// and adds specific /32 routes for only those IPs.
	// DO NOT add broad Cloudflare bypass routes here (104.16.0.0/12 etc.)
	// as they cause IP leaks by bypassing IP check sites.

	// 3. Add VPN routes (0.0.0.0/1 and 128.0.0.0/1) pointing to TUN interface
	routes := []string{
		"0.0.0.0/1",
		"128.0.0.0/1",
	}

	for _, route := range routes {
		log.Printf("🛣️ Adding route: %s -> Interface %s", route, ifIndex)
		
		// Modern Windows approach: Use PowerShell's New-NetRoute cmdlet
		// This is the most reliable method for Windows 10/11
		// Format: New-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceIndex <idx> -RouteMetric 1
		psCmd := fmt.Sprintf(
			"if (Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -ErrorAction SilentlyContinue) { Remove-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -Confirm:$false -ErrorAction SilentlyContinue }; New-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -RouteMetric 1 -ErrorAction Stop",
			route, ifIndex, route, ifIndex, route, ifIndex,
		)
		
		cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
		out, err := cmd.CombinedOutput()
		
		if err != nil {
			log.Printf("⚠️ PowerShell New-NetRoute failed for %s: %v, output: %s", route, err, out)
			
			// Fallback 1: Try netsh
			log.Printf("   Trying netsh fallback...")
			cmd = exec.Command("netsh", "interface", "ipv4", "add", "route", route, "interface="+ifIndex, "metric=1")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("   ⚠️ netsh also failed: %v, output: %s", err, out)
				
				// Fallback 2: Try route.exe
				log.Printf("   Trying route.exe fallback...")
				parts := strings.Split(route, "/")
				network := parts[0]
				mask := "128.0.0.0"
				cmd = exec.Command("route", "add", network, "mask", mask, "0.0.0.0", "IF", ifIndex, "METRIC", "1")
				if out, err := cmd.CombinedOutput(); err != nil {
					log.Printf("   ❌ route.exe also failed: %v, output: %s", err, out)
					log.Printf("   ⚠️ WARNING: Route %s could not be added! VPN may leak traffic!", route)
					continue
				}
				log.Printf("   ✅ route.exe succeeded for %s", route)
			} else {
				log.Printf("   ✅ netsh succeeded for %s", route)
			}
		} else {
			log.Printf("✅ Successfully added route %s via PowerShell", route)
		}
	}
	
	log.Printf("🎯 Route configuration complete")
	return nil
}

