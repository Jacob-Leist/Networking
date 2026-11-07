#!/bin/sh
# ==============================================================================
# Cyber Testing Lab - iptables Security & Traffic Baseline Script
# Runs on the VyOS 1.4 router's underlying Debian OS (as root / sudo).
#
# Packet flow this script assumes:
#   1. VyOS NAT (nftables, PREROUTING) translates public 172.25.(20+TEAM).x
#      -> private 172.20.240.x BEFORE the FORWARD hook.
#   2. iptables FORWARD therefore sees the PRIVATE address, so every rule
#      below matches 172.20.240.x.
#   3. VyOS routes the packet on toward the Palo Alto (172.16.0.1), which
#      fronts the server LAN.
#
# Note: Modifies ONLY the iptables 'filter' table. VyOS's own NAT and firewall
# (nftables) are never touched, and the iptables 'nat' table is never used.
# ==============================================================================

# --- PATH & BACKUP CONFIGURATION ---
# /config survives reboots on VyOS; /etc does not.
BACKUP_DIR="/config/iptables"
DEFAULT_BACKUP="${BACKUP_DIR}/rules.v4.backup"
AUTO_PRE_RESTORE="${BACKUP_DIR}/auto_pre_restore.v4"

# --- NETWORK CONFIGURATION ---
# TEAM: your team number. Public/NAT range is 172.25.(20+TEAM).0/24
TEAM="${TEAM:-4}"

# Who may SSH to this VyOS box (default: the workstation subnet incl. Kali)
WKST_NET="172.17.0.0/24"
MGMT_SRC="${MGMT_SRC:-$WKST_NET}"

# Let the server subnet start its own outbound connections (updates, DNS, NTP,
# Splunk forwarding, etc.). Set to 0 for fully locked-down strict mode.
ALLOW_SERVER_EGRESS="${ALLOW_SERVER_EGRESS:-1}"

# Fixed lab addressing
INT_NET="172.20.240"              # Server LAN behind the Palo Alto
SERVER_SUBNET="${INT_NET}.0/24"
PALO_MGMT="172.20.240.200"        # Palo Alto management IP

# Server last octets
ECOM_ID=10      # Rocky Linux 9   - Ecom
EMAIL_ID=15     # Ubuntu 22.04    - Email
SPLUNK_ID=20    # Debian 12       - Splunk 10.0.2
AD_ID=100       # Server 2022     - Active Directory
MSSQL_ID=120    # Server 2019     - MSSQL

# --- PERMISSIVE BASELINE TOGGLE ---
PERMISSIVE_BASELINE=1

# --- ENVIRONMENT CHECKS ---
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run as root (sudo $0 ...)"
    exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "[!] iptables not found on this VyOS image."
    echo "    Install it (sudo apt install iptables) or convert the rules to nftables."
    exit 1
fi

mkdir -p "${BACKUP_DIR}"
modprobe nf_conntrack 2>/dev/null
modprobe ip_tables 2>/dev/null

# Address of a server (private, post-NAT)
host_ip() {
    echo "${INT_NET}.$1"
}

# allow_tcp <last-octet> <ports>   |   allow_udp <last-octet> <ports>
allow_tcp() {
    iptables -A FORWARD -d "$(host_ip "$1")" -p tcp -m multiport --dports "$2" -j ACCEPT
}
allow_udp() {
    iptables -A FORWARD -d "$(host_ip "$1")" -p udp -m multiport --dports "$2" -j ACCEPT
}

validate_team() {
    case "$TEAM" in
        ''|*[!0-9]*) echo "[!] TEAM must be a number (got '$TEAM')"; exit 1 ;;
    esac
}

show_rules() {
    echo "iptables backend: $(iptables -V)"
    echo "==================== CURRENT IPTABLES FILTER RULES ===================="
    iptables -L -v -n --line-numbers
}

save_rules() {
    TARGET_FILE="${1:-$DEFAULT_BACKUP}"
    echo "[+] Saving current iptables ruleset to ${TARGET_FILE}..."
    iptables-save > "${TARGET_FILE}"
    if [ $? -eq 0 ]; then
        echo "[+] Successfully saved configuration."
    else
        echo "[!] Error saving iptables rules."
        exit 1
    fi
}

restore_rules() {
    TARGET_FILE="${1:-$DEFAULT_BACKUP}"

    if [ ! -f "${TARGET_FILE}" ]; then
        echo "[!] Restore failed: Backup file '${TARGET_FILE}' does not exist."
        exit 1
    fi

    printf "Are you sure you want to restore rules from '%s'? (y/N): " "${TARGET_FILE}"
    read -r choice
    case "$choice" in
        y|Y)
            iptables-save > "${AUTO_PRE_RESTORE}"
            echo "[+] Created pre-restore snapshot at ${AUTO_PRE_RESTORE}"

            echo "[+] Restoring iptables configuration from ${TARGET_FILE}..."
            iptables-restore < "${TARGET_FILE}"
            if [ $? -eq 0 ]; then
                echo "[+] Rules restored successfully."
            else
                echo "[!] Error restoring rules. Reverting to pre-restore snapshot..."
                iptables-restore < "${AUTO_PRE_RESTORE}"
                exit 1
            fi
            ;;
        *)
            echo "Restore operation cancelled."
            ;;
    esac
}

clear_filter_rules() {
    echo "[!] Clearing iptables FILTER rules only. VyOS NAT/firewall (nftables) remain intact..."

    # Reset policies to ACCEPT to prevent lockout while flushing
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # Flush filter table chains and user-defined chains
    iptables -F
    iptables -X
    iptables -Z

    echo "[+] Filter table reset complete. NAT rules were not modified."
}

apply_firewall() {
    validate_team
    PUB_NET="172.25.$((20 + TEAM)).0/24"
    echo "[+] Applying rules: servers ${SERVER_SUBNET} (post-NAT), public range ${PUB_NET}"
    echo "[+] Backend: $(iptables -V)"

    # 1. Safely reset filter table
    clear_filter_rules > /dev/null 2>&1

    # 2. Set Default Policies (Default Deny for Inbound & Forwarded traffic)
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # --------------------------------------------------------------------------
    # 3. GLOBAL STATEFUL & LOOPBACK RULES
    # --------------------------------------------------------------------------
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow all ICMP (Ping / Diagnostics) across all interfaces
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A FORWARD -p icmp -j ACCEPT

    # --------------------------------------------------------------------------
    # 4. LOCAL LOCKDOWN OF THE VYOS ROUTER ITSELF
    # --------------------------------------------------------------------------
    # SSH only from the management source
    iptables -A INPUT -s "${MGMT_SRC}" -p tcp --dport 22 -j ACCEPT

    # Services VyOS provides to the workstation subnet (DHCP + DNS forwarding)
    iptables -A INPUT -p udp --dport 67 -j ACCEPT
    iptables -A INPUT -s "${WKST_NET}" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -s "${WKST_NET}" -p tcp --dport 53 -j ACCEPT

    iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix "FW-VYOS-SSH-DENIED: "
    iptables -A INPUT -p tcp --dport 22 -j DROP

    # --------------------------------------------------------------------------
    # 5. FORWARDED SERVICE RULES (destination = private IP after VyOS NAT)
    # --------------------------------------------------------------------------
    # Anything still addressed to the public range at this point was NOT
    # translated by VyOS NAT (no matching port-forward), so drop it rather than
    # let it route out the default path.
    iptables -A FORWARD -d "${PUB_NET}" -j DROP

    # Rocky Ecom (.10)
    allow_tcp "$ECOM_ID"  "80,443"

    # Ubuntu Email (.15)
    allow_tcp "$EMAIL_ID" "25,22,143,443,80"

    # Debian Splunk (.20): SSH, web UI, mgmt API, forwarder input; NTP
    allow_tcp "$SPLUNK_ID" "22,8000,8089,9997"
    allow_udp "$SPLUNK_ID" "123"

    # Server 2022 AD (.100): WinRM; DNS
    allow_tcp "$AD_ID"  "5985,5986"
    allow_udp "$AD_ID"  "53"

    # Server 2019 MSSQL (.120): RDP, SMB, SQL
    allow_tcp "$MSSQL_ID" "3389,445,1433"

    # Palo Alto management (reached from the management source only)
    iptables -A FORWARD -s "${MGMT_SRC}" -d "${PALO_MGMT}" -p tcp -m multiport --dports 22,443 -j ACCEPT

    # Servers may start their own outbound connections (VyOS SNATs them)
    if [ "$ALLOW_SERVER_EGRESS" -eq 1 ]; then
        iptables -A FORWARD -s "${SERVER_SUBNET}" -m conntrack --ctstate NEW -j ACCEPT
    fi

    # --------------------------------------------------------------------------
    # 6. PERMISSIVE BASELINE PASS (FOR DISCOVERY)
    # --------------------------------------------------------------------------
    if [ "$PERMISSIVE_BASELINE" -eq 1 ]; then
        echo "[!] PERMISSIVE BASELINE ACTIVE: Logging & passing unclassified traffic..."
        iptables -A FORWARD -m conntrack --ctstate NEW -m limit --limit 10/min -j LOG --log-prefix "FW-BASELINE-PASS: "
        iptables -A FORWARD -j ACCEPT
    else
        echo "[+] STRICT ENFORCEMENT ACTIVE: Dropping unclassified traffic."
        iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "FW-FORWARD-DROPPED: "
        iptables -A FORWARD -j DROP
    fi

    echo "[+] Firewall rules successfully loaded!"
    echo "[i] Rules are not persistent across a VyOS reboot. To reapply at boot, add"
    echo "    '$0 apply ${TEAM}' to /config/scripts/vyos-postconfig-bootup.script"
}

# ------------------------------------------------------------------------------
# 7. INTERACTIVE RULE GENERATOR & POSITION PLACEMENT
# ------------------------------------------------------------------------------
interactive_rule_generator() {
    echo "================================================="
    echo " Interactive iptables Rule Generator (Multiport)"
    echo "================================================="

    while true; do
        echo
        echo "Choose chain:"
        echo "1) INPUT"
        echo "2) OUTPUT"
        echo "3) FORWARD"
        printf "Selection [1-3]: "
        read CHOICE

        case "$CHOICE" in
            1) CHAIN="INPUT" ;;
            2) CHAIN="OUTPUT" ;;
            3) CHAIN="FORWARD" ;;
            *) echo "ERROR: Invalid chain"; continue ;;
        esac

        # --- RULE POSITION SELECTION ---
        echo
        echo "Current rules in $CHAIN chain:"
        iptables -L "$CHAIN" -v -n --line-numbers | head -n 12
        echo "..."
        printf "Enter line number to INSERT rule (leave blank to APPEND to end of chain): "
        read POS

        if [ -z "$POS" ]; then
            TARGET_ACTION="-A $CHAIN"
        else
            case "$POS" in
                ''|*[!0-9]*) echo "ERROR: Position must be a valid line number"; continue ;;
                *) TARGET_ACTION="-I $CHAIN $POS" ;;
            esac
        fi

        printf "Enter IP address (use the PRIVATE 172.20.240.x address for FORWARD rules): "
        read IPADDR
        [ -z "$IPADDR" ] && { echo "ERROR: IP required"; continue; }

        printf "Protocol (tcp/udp): "
        read PROTO
        PROTO=$(echo "$PROTO" | tr 'A-Z' 'a-z')

        if [ "$PROTO" != "tcp" ] && [ "$PROTO" != "udp" ]; then
            echo "ERROR: Protocol must be tcp or udp"
            continue
        fi

        printf "Is the IP source or destination? (s/d): "
        read DIR
        case "$DIR" in
            s) IPFLAG="-s $IPADDR" ;;
            d) IPFLAG="-d $IPADDR" ;;
            *) echo "ERROR: Must be s or d"; continue ;;
        esac

        echo
        echo "Port selection:"
        echo "1) Single port"
        echo "2) Multiple ports (comma separated, max 15)"
        printf "Choice [1-2]: "
        read PORTMODE

        if [ "$PORTMODE" = "1" ]; then
            printf "Enter port number: "
            read PORT
            case "$PORT" in
                ''|*[!0-9]*) echo "ERROR: Invalid port"; continue ;;
            esac
            PORTFLAG="--dport $PORT"
            MODULES=""
        elif [ "$PORTMODE" = "2" ]; then
            printf "Enter ports (e.g. 22,80,443): "
            read PORTS
            case "$PORTS" in
                ''|*[!0-9,]*) echo "ERROR: Invalid port list"; continue ;;
            esac
            MODULES="-m multiport"
            PORTFLAG="--dports $PORTS"
        else
            echo "ERROR: Invalid port mode"
            continue
        fi

        CMD="iptables $TARGET_ACTION -p $PROTO $MODULES $IPFLAG $PORTFLAG -j ACCEPT"

        echo "---------------------------------------------------------------------------------"
        echo "Executing:"
        echo "$CMD"
        echo "---------------------------------------------------------------------------------"

        if $CMD; then
            echo "[+] Rule successfully added!"
            echo "Updated rules for $CHAIN chain:"
            iptables -L "$CHAIN" -v -n --line-numbers
        else
            echo "ERROR: Failed to add rule"
        fi

        echo
        printf "Add another rule? (y/n): "
        read AGAIN
        case "$AGAIN" in
            y|Y) ;;
            *) break ;;
        esac
    done

    echo
    echo "Done adding rules."
}

# --- CLI OPTION HANDLER ---
case "$1" in
    apply)
        [ -n "$2" ] && TEAM="$2"
        apply_firewall
        ;;
    strict)
        PERMISSIVE_BASELINE=0
        [ -n "$2" ] && TEAM="$2"
        apply_firewall
        ;;
    add|interactive)
        interactive_rule_generator
        ;;
    save)
        save_rules "$2"
        ;;
    restore|rollback)
        restore_rules "$2"
        ;;
    clear)
        printf "Are you sure you want to clear iptables FILTER rules? VyOS NAT will not be touched. (y/N): "
        read -r choice
        case "$choice" in
            y|Y) clear_filter_rules ;;
            *) echo "Aborted." ;;
        esac
        ;;
    show)
        show_rules
        ;;
    *)
        echo "Usage: sudo $0 {apply|strict|add|save|restore|clear|show} [ARGUMENT]"
        echo ""
        echo "Commands:"
        echo "  apply [TEAM#]      : Apply firewall with permissive discovery pass (Default team: 4)"
        echo "  strict [TEAM#]     : Apply firewall with strict drop policy"
        echo "  add | interactive  : Launch interactive rule builder (supports line insertion position)"
        echo "  save [FILE_PATH]   : Save active iptables state to file"
        echo "  restore [FILE_PATH]: Restore iptables state from file"
        echo "  show               : Display active filter rules with line numbers"
        echo "  clear              : Reset iptables FILTER table without touching VyOS NAT"
        echo ""
        echo "Environment overrides: TEAM, MGMT_SRC, ALLOW_SERVER_EGRESS (1|0)"
        echo ""
        echo "Examples:"
        echo "  sudo $0 apply 4"
        echo "  sudo MGMT_SRC=172.17.0.2 $0 strict 4"
        echo "  sudo $0 save"
        exit 1
        ;;
esac