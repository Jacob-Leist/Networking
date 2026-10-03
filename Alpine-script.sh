#!/bin/sh
# ==============================================================================
# Alpine Linux (pangea) Master iptables Security & Traffic Baseline Script
# Target Node: PANGEA (.2) - Router / Firewall[cite: 1, 2]
# Note: Modifies ONLY the 'filter' table. NAT table remains completely untouched.
# ==============================================================================

# --- PATH & BACKUP CONFIGURATION ---
BACKUP_DIR="/etc/iptables"
DEFAULT_BACKUP="${BACKUP_DIR}/rules.v4.backup"
AUTO_PRE_RESTORE="${BACKUP_DIR}/auto_pre_restore.v4"

# --- NETWORK CONFIGURATION ---
NET_PREFIX="${NET_PREFIX:-192.168.1}"

# Host Definitions
PANGEA="${NET_PREFIX}.2"      # Alpine Router/Firewall (ntopng)[cite: 1, 2]
TREX="${NET_PREFIX}.12"       # AD, DNS (Win Server 2016)[cite: 1, 2]
FOSSIL="${NET_PREFIX}.20"     # Admin Workstation (Win 10 RDP/SSH)[cite: 1, 2]
FERNBANK="${NET_PREFIX}.37"   # Web Server (Win Server 2022)[cite: 1, 2]
LABORATORY="${NET_PREFIX}.70" # DevOps (Gitea, JFrog)[cite: 1, 2]
HATCHERY="${NET_PREFIX}.76"   # DB / Storage (MySQL, MinIO)[cite: 1, 2]
HELLCREEK="${NET_PREFIX}.103" # SSO / Backend (Keycloak, APIs)[cite: 1, 2]
BADLANDS="${NET_PREFIX}.104"  # Front-facing Web (Fedora 42)[cite: 1, 2]
TARPIT="${NET_PREFIX}.170"    # Centralized Logging (Graylog)[cite: 1, 2]

# --- PERMISSIVE BASELINE TOGGLE ---
PERMISSIVE_BASELINE=1

# Ensure required system directories and kernel modules exist
mkdir -p "${BACKUP_DIR}"
modprobe ip_tables 2>/dev/null

show_rules() {
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
    echo "[!] Clearing FILTER table rules only. NAT table remains intact..."
    
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
    echo "[+] Applying firewall and protection rules for network ${NET_PREFIX}.0/24..."

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

    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j DROP

    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow all ICMP (Ping / Diagnostics) across all interfaces
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A FORWARD -p icmp -j ACCEPT

    # --------------------------------------------------------------------------
    # 4. HARDENING PANGEA (.2) - LOCAL LOCKDOWN[cite: 1, 2]
    # --------------------------------------------------------------------------
    # Allow management (SSH & ntopng) only from Admin Workstation (FOSSIL .20)[cite: 1, 2]
    iptables -A INPUT -s "${FOSSIL}" -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -s "${FOSSIL}" -p tcp --dport 3000 -j ACCEPT
    
    iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix "FW-PANGEA-SSH-DENIED: "
    iptables -A INPUT -p tcp --dport 22 -j DROP
    iptables -A INPUT -p tcp --dport 3000 -j DROP

    # --------------------------------------------------------------------------
    # 5. INTER-VM & SERVICE TRAFFIC RULES[cite: 1, 2]
    # --------------------------------------------------------------------------
    # Active Directory & DNS (TREX .12)[cite: 1, 2]
    iptables -A FORWARD -d "${TREX}" -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -d "${TREX}" -p tcp --dport 53 -j ACCEPT
    iptables -A FORWARD -d "${TREX}" -p tcp -m multiport --dports 88,135,389,445,636,3268,3269 -j ACCEPT

    # Remote Management Workstation (FOSSIL .20)[cite: 1, 2]
    iptables -A FORWARD -d "${FOSSIL}" -p tcp --dport 3389 -j ACCEPT
    iptables -A FORWARD -d "${FOSSIL}" -p tcp --dport 22 -j ACCEPT

    # Centralized Logging (TARPIT .170)[cite: 1, 2]
    iptables -A FORWARD -d "${TARPIT}" -p udp -m multiport --dports 514,12201 -j ACCEPT
    iptables -A FORWARD -d "${TARPIT}" -p tcp -m multiport --dports 514,12201,9000 -j ACCEPT

    # Web Services (FERNBANK .37 & BADLANDS .104)[cite: 1, 2]
    iptables -A FORWARD -d "${FERNBANK}" -p tcp -m multiport --dports 80,443 -j ACCEPT
    iptables -A FORWARD -d "${BADLANDS}" -p tcp -m multiport --dports 80,443 -j ACCEPT

    # DevOps Services (LABORATORY .70)[cite: 1, 2]
    iptables -A FORWARD -d "${LABORATORY}" -p tcp -m multiport --dports 22,80,443,3000,8081,8082 -j ACCEPT

    # Backend APIs & Auth (HELLCREEK .103)[cite: 1, 2]
    iptables -A FORWARD -d "${HELLCREEK}" -p tcp -m multiport --dports 80,443,8080,8443 -j ACCEPT

    # Database & Storage (HATCHERY .76)[cite: 1, 2]
    iptables -A FORWARD -d "${HATCHERY}" -p tcp -m multiport --dports 3306,9000,9001 -j ACCEPT

    # --------------------------------------------------------------------------
    # 6. PERMISSIVE BASELINE PASS (FOR DISCOVERY)
    # --------------------------------------------------------------------------
    if [ "$PERMISSIVE_BASELINE" -eq 1 ]; then
        echo "[!] PERMISSIVE BASELINE ACTIVE: Logging & passing unclassified traffic..."
        iptables -A FORWARD -m state --state NEW -m limit --limit 10/min -j LOG --log-prefix "FW-BASELINE-PASS: "
        iptables -A FORWARD -j ACCEPT
    else
        echo "[+] STRICT ENFORCEMENT ACTIVE: Dropping unclassified traffic."
        iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "FW-FORWARD-DROPPED: "
        iptables -A FORWARD -j DROP
    fi

    echo "[+] Firewall rules successfully loaded!"
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

        printf "Enter IP address: "
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
        [ -n "$2" ] && NET_PREFIX="$2"
        apply_firewall
        ;;
    strict)
        PERMISSIVE_BASELINE=0
        [ -n "$2" ] && NET_PREFIX="$2"
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
        printf "Are you sure you want to clear FILTER rules? NAT will not be touched. (y/N): "
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
        echo "Usage: $0 {apply|strict|add|save|restore|clear|show} [ARGUMENT]"
        echo ""
        echo "Commands:"
        echo "  apply [PREFIX]     : Apply firewall with permissive discovery pass (Default prefix: 192.168.1)"
        echo "  strict [PREFIX]    : Apply firewall with strict drop policy"
        echo "  add | interactive  : Launch interactive rule builder (supports line insertion position)"
        echo "  save [FILE_PATH]   : Save active iptables state to file"
        echo "  restore [FILE_PATH]: Restore iptables state from file"
        echo "  show               : Display active filter rules with line numbers"
        echo "  clear              : Reset FILTER table safely without touching NAT"
        echo ""
        echo "Examples:"
        echo "  $0 add"
        echo "  $0 apply 10.0.50"
        echo "  $0 save"
        exit 1
        ;;
esac