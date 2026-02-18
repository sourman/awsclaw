#!/bin/bash

echo "=========================================="
echo "SSH/Network Diagnostic Script"
echo "Run this on BOTH WSL machines to compare"
echo "=========================================="
echo ""

echo "1. SYSTEM INFO"
echo "   WSL Version & Windows Build:"
wsl.exe --version 2>/dev/null || echo "   WSL info unavailable"
echo ""

echo "2. NETWORK CONFIG"
echo "   Network Interfaces:"
ip addr show eth0 2>/dev/null | grep "inet " || ip a | grep "inet "
echo "   Default Gateway:"
ip route | grep default
echo "   Public IP:"
curl -s --max-time 5 ifconfig.me || echo "   Unable to determine"
echo ""

echo "3. WSL CONFIGURATION"
echo "   /etc/wsl.conf contents:"
cat /etc/wsl.conf 2>/dev/null || echo "   No wsl.conf found"
echo "   .wslconfig (Windows side):"
cat /mnt/c/Users/*/\.wslconfig 2>/dev/null | head -20 || echo "   No .wslconfig found"
echo ""

echo "4. SSH CLIENT INFO"
echo "   Linux SSH version:"
ssh -V 2>&1
echo "   Windows SSH version:"
/mnt/c/Windows/System32/OpenSSH/ssh.exe -V 2>&1
echo ""

echo "5. FIREWALL STATUS (Windows)"
echo "   Firewall Profiles:"
powershell.exe -Command "Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize" 2>/dev/null || echo "   Unable to check"
echo ""
echo "   SSH-related Firewall Rules:"
powershell.exe -Command "Get-NetFirewallRule | Where-Object {\$_.Enabled -eq \$true -and (\$_.DisplayName -like '*ssh*' -or \$_.DisplayName -like '*port 22*' -or \$_.LocalPort -eq 22)} | Select-Object DisplayName, Direction, Action, Enabled | Format-Table -AutoSize" 2>/dev/null || echo "   Unable to check"
echo ""

echo "6. VPN STATUS"
echo "   VPN Connections:"
powershell.exe -Command "Get-VpnConnection | Select-Object Name, ConnectionStatus, TunnelType" 2>/dev/null || echo "   Unable to check"
echo "   Active Network Adapters:"
powershell.exe -Command "Get-NetAdapter | Where-Object {\$_.Status -eq 'Up'} | Select-Object Name, InterfaceDescription, Status" 2>/dev/null || echo "   Unable to check"
echo ""

echo "7. PROXY SETTINGS"
echo "   Windows HTTP Proxy:"
powershell.exe -Command "netsh winhttp show proxy" 2>/dev/null || echo "   Unable to check"
echo "   Environment Proxy:"
env | grep -i proxy || echo "   No proxy environment variables"
echo ""

echo "8. NETWORK PROFILE"
echo "   Windows Network Profile:"
powershell.exe -Command "Get-NetConnectionProfile | Select-Object Name, NetworkCategory, IPv4Connectivity, IPv6Connectivity" 2>/dev/null || echo "   Unable to check"
echo ""

echo "9. SECURITY SOFTWARE"
echo "   Security-related Services:"
powershell.exe -Command "Get-Service | Where-Object {\$_.DisplayName -match 'antivirus|firewall|security|defense|threat|protect| McAfee|Norton|Bitdefender|Kaspersky|Sophos|Trend|ESET' -and \$_.Status -eq 'Running'} | Select-Object DisplayName, Status | Format-Table -AutoSize" 2>/dev/null || echo "   Unable to check"
echo ""

echo "10. CONNECTIVITY TEST TO EC2"
echo "    Ping test:"
ping -c 2 -W 3 44.212.64.104 2>&1 | tail -2 || echo "    Ping failed"
echo "    Port 22 test:"
timeout 3 bash -c "cat < /dev/null > /dev/tcp/44.212.64.104/22" 2>&1 && echo "    Port 22: REACHABLE" || echo "    Port 22: BLOCKED"
echo ""

echo "11. SSH CONFIG"
echo "    /etc/ssh/ssh_config relevant lines:"
grep -v "^#" /etc/ssh/ssh_config | grep -v "^$" | head -20 || echo "    Unable to read"
echo ""

echo "12. ROUTING TABLE"
echo "    Full routing table:"
ip route
echo ""

echo "=========================================="
echo "Diagnostic complete! Compare outputs from both machines."
echo "=========================================="
