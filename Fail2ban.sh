#!/bin/sh
set -e

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root."
    exit 1
fi

echo "[+] Updating repositories and installing packages..."
apk update
apk add fail2ban iptables ip6tables rsyslog

echo "[+] Enabling and starting rsyslog service for log tracking..."
rc-update add rsyslog default 2>/dev/null || true
rc-service rsyslog start 2>/dev/null || true

echo "[+] Pre-creating log files so Fail2ban does not throw errors..."
touch /var/log/xrdp.log /var/log/messages

echo "[+] Configuring iptables logging for common beacon/C2 ports..."
# Common C2/Beacon ports: 4444 (Metasploit), 8080, 8443, 1337, 9001
BEACON_PORTS="4444,8080,8443,1337,9001"

# Flush old setup chain if exists and recreate
iptables -N C2_MONITOR 2>/dev/null || iptables -F C2_MONITOR
iptables -D INPUT -p tcp -m multiport --dports $BEACON_PORTS -j C2_MONITOR 2>/dev/null || true
iptables -A INPUT -p tcp -m multiport --dports $BEACON_PORTS -j C2_MONITOR

# Log unauthorized incoming probes to beacon ports so Fail2ban can catch them
iptables -A C2_MONITOR -m state --state NEW -j LOG --log-prefix "C2_PROBE_BLOCKED: " --log-level 4
iptables -A C2_MONITOR -j DROP

echo "[+] Creating Fail2ban filter for C2/Beacon probes..."
cat << 'EOF' > /etc/fail2ban/filter.d/c2-beacons.conf
[Definition]
failregex = ^.*C2_PROBE_BLOCKED: .* SRC=<HOST> DST=.*$
ignoreregex =
EOF

echo "[+] Creating Fail2ban filter for RDP (xrdp)..."
cat << 'EOF' > /etc/fail2ban/filter.d/xrdp.conf
[Definition]
failregex = ^.*\[INFO \] login failed for display.*ip <HOST>.*$
            ^.*\[ERROR\] VNC error before security handshake.*ip <HOST>.*$
ignoreregex =
EOF

echo "[+] Creating /etc/fail2ban/jail.local configuration..."
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
backend  = polling
banaction = iptables-multiport
ignoreip = 127.0.0.1/8 192.168.1.0/24

# --- SSH Jail ---
[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/messages
maxretry = 3
bantime  = 2h

# --- RDP Jail ---
[xrdp]
enabled  = true
port     = 3389
filter   = xrdp
logpath  = /var/log/xrdp.log
maxretry = 3
bantime  = 4h

# --- C2 & Beacon Ports Jail ---
[c2-beacons]
enabled  = true
port     = 4444,8080,8443,1337,9001
filter   = c2-beacons
logpath  = /var/log/messages
maxretry = 1
bantime  = 24h
EOF

echo "[+] Enabling and starting Fail2ban service..."
rc-update add fail2ban default
rc-service fail2ban restart

# Commit changes if running Alpine in diskless/RAM mode
if command -v lbu >/dev/null 2>&1; then
    echo "[+] Persistent Alpine system detected. Saving configuration with lbu..."
    lbu commit
fi

echo "[+] Setup Complete! Fail2ban is active and linked to iptables."