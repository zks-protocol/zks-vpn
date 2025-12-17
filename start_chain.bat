@echo off
echo ===================================================
echo   ZKS TRIPLE-BLIND CHAIN LAUNCHER
echo ===================================================
echo.
echo [1/2] Establishing SSH Tunnel to VM 1 (Entry Node)...
echo       (This creates a SOCKS5 proxy at localhost:9050)
start "SSH Tunnel (VM1)" ssh -D 9050 -N -i "d:\BuzzU\Oracle\md.wasif.faisal@g.bracu.ac.bd-2025-11-21T09_12_08.635Z.pem" -o StrictHostKeyChecking=no ubuntu@140.245.127.45

echo.
echo Waiting 5 seconds for tunnel to stabilize...
timeout /t 5 /nobreak >nul

echo.
echo [2/2] Starting ZKS VPN Client...
echo       (Routing: You -> Proxy(VM1) -> Relay -> VM2)
cd zks-tunnel-client
if not exist zks-vpn.exe (
    echo ERROR: zks-vpn.exe not found in %CD%
    echo Please download it from GitHub Actions and place it here.
    pause
    exit /b
)
zks-vpn.exe --mode p2p-vpn --room triple-blind-test --proxy 127.0.0.1:9050 --relay wss://zks-tunnel-relay.md-wasif-faisal.workers.dev

pause
