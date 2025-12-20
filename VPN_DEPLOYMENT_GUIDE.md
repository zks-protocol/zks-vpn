# ZKS VPN Deployment Guide

> **Critical Lessons Learned from Deployment 2025-12-20**

## ⚠️ Common Mistakes Made (& How to Avoid Them)

### 1. **Binary Confusion** ❌
**Mistake:** Used wrong binary name (`zks-tunnel-client` vs `zks-vpn`)  
**Solution:** Always check binary names with `find ./target/release -type f -executable`

### 2. **Missing VPN Feature Flag** ❌  
**Mistake:** Compiled without `--features vpn`, so TUN device wasn't created  
**Solution:** Always build with `cargo build --release --package zks-tunnel-client --features vpn`

### 3. **Wrong Mode Flag** ❌
**Mistake:** Used `-m exit-peer` instead of `-m exit-peer-vpn`  
**Solution:** Use `--help` to verify correct modes

### 4. **SOCKS5 vs VPN Mode** ❌
**Mistake:** Started Go client in `p2p-client` mode (SOCKS5) instead of `p2p-vpn` mode (TUN)  
**Solution:** Always use `-mode p2p-vpn` for system-wide VPN

### 5. **Admin Privileges** ❌
**Mistake:** Ran Go client without Administrator rights, TUN creation failed  
**Solution:** Use `Start-Process -Verb RunAs` on Windows, `sudo` on Linux/VPS

---

## ✅ Correct Deployment Steps

### **VPS (Exit Peer) - Ubuntu**
```bash
# 1. Navigate to repo
cd ~/ZKS-Tunnel-VPN

# 2. Pull latest code
git pull

# 3. Build with VPN features
source ~/.cargo/env
cargo build --release --package zks-tunnel-client --features vpn

# 4. Kill old processes
sudo pkill -9 zks-vpn

# 5. Start Exit Peer with TUN
sudo ./target/release/zks-vpn -m exit-peer-vpn --room zks-vpn-main

# Verify TUN device created:
ip link show tun0
ip addr show tun0
# Expected: 10.0.85.2/24
```

### **Windows Client - PowerShell (Admin)**
```powershell
# 1. Navigate to repo
cd d:\BuzzU\ZKS_VPN\zks-go-client

# 2. Pull latest code
git pull

# 3. Build Go client
go build -o zks-go-client.exe .

# 4. Kill old client
taskkill /F /IM zks-go-client.exe

# 5. Start VPN client (Admin required!)
Start-Process -Verb RunAs -FilePath ".\zks-go-client.exe" -ArgumentList "-mode","p2p-vpn","-room","zks-vpn-main"

# OR run directly in Admin PowerShell:
.\zks-go-client.exe -mode p2p-vpn -room zks-vpn-main
```

---

## 🔍 Troubleshooting Routing Leaks

### **Symptom:** Some sites show VPN IP, others show real IP

### **Root Causes:**
1. **DNS Leak** - DNS queries bypass VPN
2. **Timing** - Routes take time to apply
3. **IPv6 Leak** - IPv6 traffic bypasses VPN
4. **Application Binding** - Some apps hardcoded to physical interface

### **Fixes:**

#### 1. DNS Leak Fix (Windows)
```powershell
# Set DNS to VPN's DNS (public DNS for now)
netsh interface ipv4 set dns "zks-tun0" static 1.1.1.1
netsh interface ipv4 add dns "zks-tun0" 8.8.8.8 index=2

# Disable DNS over other interfaces
Get-NetAdapter | Where-Object Name -ne "zks-tun0" | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses @()
}
```

#### 2. Disable IPv6 (Prevent IPv6 Leak)
```powershell
# Disable IPv6 on all physical adapters
Get-NetAdapter | Where-Object Name -ne "zks-tun0" | ForEach-Object {
    Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6
}
```

#### 3. Verify Routes Are Applied
```powershell
route print 0.0.0.0

# Should see:
# 0.0.0.0/1 → Interface zks-tun0
# 128.0.0.0/1 → Interface zks-tun0
```

#### 4. Wait 5-10 Seconds After Connection
Routes and DNS changes take time to propagate. Wait before testing.

---

## 🧪 Testing VPN

### 1. Check Public IP
```powershell
curl.exe https://ipinfo.io/ip
# Expected: 213.35.103.204 (VPS IP)
```

### 2. Test DNS Leak
```powershell
curl.exe https://www.dnsleaktest.com
# Should show VPS location, not your real location
```

### 3. Ping Test
```powershell
ping -n 4 8.8.8.8
# Should have ~30-50ms latency (VPS route)
```

### 4. Traceroute
```powershell
tracert -d -h 10 8.8.8.8
# First hop should be 10.0.85.2 (Exit Peer TUN IP)
```

---

## 📊 Performance Benchmarks (Batch Size 1024)

| Metric | Value |
| :--- | :--- |
| **Ping (VPS)** | 27-43ms |
| **Throughput** | ~50 Mbps (VPS hardware limit) |
| **Daily Data Limit** | ~136 GB (Cloudflare Free Tier) |
| **Packet Loss** | 0% |
| **RAM (Client)** | ~15 MB |
| **RAM (Exit Peer)** | ~20 MB |

---

## 🔧 Key Exchange Issues

### **Symptom:** Stuck at "🔑 Initiating X25519 key exchange..."

### **Causes:**
1. Exit Peer not running
2. Wrong room ID
3. Firewall blocking relay connection
4. Both client and exit peer in same "role"

### **Fix:**
1. Verify Exit Peer is running: `ps aux | grep zks-vpn`
2. Verify TUN device exists on VPS: `ip link show tun0`
3. Ensure same room ID on both sides
4. Restart both client and exit peer FRESH

---

## 📝 Deployment Checklist

- [ ] VPS: Pull latest code (`git pull`)
- [ ] VPS: Build with `--features vpn`
- [ ] VPS: Start with `-m exit-peer-vpn`
- [ ] VPS: Verify TUN device (`ip link show tun0`)
- [ ] VPS: Verify IP is 10.0.85.2/24
- [ ] Windows: Pull latest code
- [ ] Windows: Build Go client
- [ ] Windows: Run with `-mode p2p-vpn`
- [ ] Windows: Run as Administrator
- [ ] Windows: Wait 10 seconds for routes to apply
- [ ] Test: Check IP (`curl ipinfo.io/ip`)
- [ ] Test: Check DNS leak
- [ ] Test: Ping test (should be ~30-50ms)

---

## 🛠️ Quick Commands Reference

| Action | Command |
| :--- | :--- |
| **Check VPS TUN** | `ip link show \| grep tun` |
| **Check VPS Routes** | `ip route` |
| **Check Windows TUN** | `ipconfig \| findstr zks` |
| **Check Windows Routes** | `route print 0.0.0.0` |
| **Kill VPS Exit Peer** | `sudo pkill -9 zks-vpn` |
| **Kill Windows Client** | `taskkill /F /IM zks-go-client.exe` |
| **Check Public IP** | `curl.exe https://ipinfo.io/ip` |
| **Test Ping** | `ping 8.8.8.8` |

---

## 🎯 What the Code Does (Routing)

The Go client (`tun.go:configureRouting()`) implements the **"Def1 Trick"** used by OpenVPN and WireGuard:

1. **Add bypass routes** for Cloudflare relay IPs (104.16.0.0/12, etc.) → Original gateway
   - This ensures the VPN tunnel itself can connect
2. **Add two /1 routes** (instead of one 0.0.0.0/0):
   - `0.0.0.0/1` → TUN interface (covers 0.0.0.0 to 127.255.255.255)
   - `128.0.0.0/1` → TUN interface (covers 128.0.0.0 to 255.255.255.255)
3. **Why /1 instead of /0?**
   - /1 routes have higher priority than the default /0 route
   - This forces ALL traffic through VPN without deleting the original default route
   - If VPN disconnects, the original route is still there (graceful fallback)

This is the industry-standard approach recommended by WireGuard documentation.
