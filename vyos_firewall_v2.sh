#!/bin/vbash
# ==============================================================================
# VyOS Master Firewall & Traffic Baseline Script
# Target Node: main VyOS router
#   External 172.16.1.0/24  <->  VyOS  <->  Alpine (172.20.10.0/24)
#                                      <->  OPNsense (172.20.11.0/24)
# Touches ONLY: firewall ipv4 input filter / forward filter
# The 'nat' tree is NEVER modified.
# Syntax: VyOS 1.4+ (sagitta / circinus). 1.3 uses "firewall name ..." instead.
#
# Run as the 'vyos' user (NOT with sudo). If you are root:
#   sg vyattacfg -c "/config/scripts/vyos_firewall.sh apply"
# ==============================================================================

source /opt/vyatta/etc/functions/script-template

# --- PATH & BACKUP CONFIGURATION ---
WRAP=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper
OPCMD=/opt/vyatta/bin/vyatta-op-cmd-wrapper
BACKUP_DIR="/config/fw-backups"
DEFAULT_BACKUP="${BACKUP_DIR}/fw-baseline.config"
AUTO_PRE_APPLY="${BACKUP_DIR}/auto_pre_apply.config"
AUTO_PRE_RESTORE="${BACKUP_DIR}/auto_pre_restore.config"
PENDING="/tmp/fw_revert_pending"
WATCHDOG="/tmp/fw_watchdog.sh"
CONFIRM_SECS="${CONFIRM_SECS:-90}"     # auto-revert timer after apply/strict

# --- NETWORK CONFIGURATION (AD domain: horrorhouse.local) ---
EXT_NET="172.16.1.0/24"        # External: scoring engine + red team, 1:1 NAT range
ALPINE_NET="172.20.10.0/24"    # Internal Linux segment
OPN_NET="172.20.11.0/24"       # Internal Windows segment

# Which address do the rules match on?
#   internal = post-DNAT internal IPs. Correct when VyOS does the 1:1 NAT,
#              because the forward chain runs AFTER destination NAT.
#   nat      = 172.16.1.x NAT IPs. Use if the NAT happens downstream
#              (on Alpine-FW / OPNsense-FW) so VyOS only ever sees NAT IPs.
# Usage:  ADDR_MODE=nat ./vyos_firewall.sh apply
ADDR_MODE="${ADDR_MODE:-internal}"

# Host table:            INTERNAL IP                NAT IP
ECOMM_INT="172.20.10.30";   ECOMM_NAT="172.16.1.30"     # Ubuntu-Ecomm   (Ubuntu Server 24.04)
WEBMAIL_INT="172.20.10.40"; WEBMAIL_NAT="172.16.1.40"   # Rocky-Webmail  (Rocky 9)
SPLUNK_INT="172.20.10.20";  SPLUNK_NAT="172.16.1.20"    # Splunk         (Rocky 9)
UBU_WS_INT="172.20.10.50";  UBU_WS_NAT="172.16.1.50"    # Ubuntu-Wkst    (Ubuntu 24.04)
ADDNS_INT="172.20.11.102";  ADDNS_NAT="172.16.1.102"    # AD-DNS         (Server 2016)
IIS_INT="172.20.11.101";    IIS_NAT="172.16.1.101"      # IIS-Web        (Server 2019)
FTP_INT="172.20.11.104";    FTP_NAT="172.16.1.104"      # IIS-FTP        (Server 2019)
WIN_WS_INT="172.20.11.100"; WIN_WS_NAT="172.16.1.100"   # Win10-Wkst     (Windows 10)

# Segment gateways (their 172.16.1.x addresses are what VyOS sees them as)
ALPINE_FW_NAT="172.16.1.1"     # Alpine-FW   (internal 172.20.10.1)
OPN_FW_NAT="172.16.1.2"        # OPNsense-FW (internal 172.20.11.1)

if [ "$ADDR_MODE" = "nat" ]; then
    ECOMM="$ECOMM_NAT"; WEBMAIL="$WEBMAIL_NAT"; SPLUNK="$SPLUNK_NAT"; UBU_WS="$UBU_WS_NAT"
    ADDNS="$ADDNS_NAT"; IIS="$IIS_NAT"; FTP="$FTP_NAT"; WIN_WS="$WIN_WS_NAT"
else
    ECOMM="$ECOMM_INT"; WEBMAIL="$WEBMAIL_INT"; SPLUNK="$SPLUNK_INT"; UBU_WS="$UBU_WS_INT"
    ADDNS="$ADDNS_INT"; IIS="$IIS_INT"; FTP="$FTP_INT"; WIN_WS="$WIN_WS_INT"
fi

# Hosts allowed to SSH into the VyOS router itself (space separated).
# If SSH gets blocked because the workstations appear as their NAT IPs, add
# them to ADMIN_EXTRA (but note anyone on 172.16.1.0/24 could spoof those).
ADMIN_EXTRA=""
ADMIN_HOSTS="${UBU_WS_INT} ${WIN_WS_INT} ${ADMIN_EXTRA}"

# Neighbours allowed to speak routing protocols to the router
ROUTING_PEERS="${ALPINE_FW_NAT} ${OPN_FW_NAT}"

# Service port lists
FTP_PASV_RANGE="49152-65535"   # narrow this to your FTP server's passive range

# Extra app ports for scored web apps that may not sit on 80/443 (comma list, "" = none).
# Run '$0 discover' in permissive mode to find the real ones, then fix these.
IIS_APP_PORTS="8080,8443"          # 2019-Web-api-inventory, 2019-Web-Tickets-ticket-form
ECOMM_APP_PORTS="8080,8443,3000"   # Ubuntu-Ecomm phpmyadmin, product-designer

# ---- SCOREBOARD CHECK -> RULE MAP (what must stay green) -------------------
# 2016-AD-DNS : dns 53, kerberos 88, ldap 389, ldaps 636, smb 445, rdp 3389, ping
# 2019-FTP    : ftp 21 (+passive range), rdp 3389, ping
# 2019-Web    : HTTP 80, HTTPS 443, api-inventory + ticket-form (IIS_APP_PORTS), rdp, ping
# Rocky-Webmail: imap 143/993, pop3 110/995, smtp + smtp-banner 25, roundcube(+login) 80/443,
#                ssh + ssh-ad 22, ping
# splunk      : HTTP 8000, splunkd-mgmt 8089, ssh + ssh-ad 22, ping
# Ubuntu-Ecomm: web 80, HTTPS 443, mysql 3306, phpmyadmin + product-designer
#                (80/443/ECOMM_APP_PORTS), ssh + ssh-ad 22, ping
# NOTE: every "ssh-ad" check logs in with AD creds, so the Linux boxes must keep
#       reaching AD-DNS (53/88/389/445...). Those rules allow any source -> ADDNS.
# ---------------------------------------------------------------------------

# helper: append an optional comma list to a base port list
join_ports() { if [ -n "$2" ]; then echo "$1,$2"; else echo "$1"; fi; }
ALLOW_AD_DYN_RPC=1             # 1 = allow AD dynamic RPC (49152-65535) to AD-DNS
PERMIT_ROUTING=1               # 1 = allow OSPF/VRRP/BGP from ROUTING_PEERS (avoid breaking routing)
ALLOW_MGMT_TO_SERVERS=1        # 1 = SSH to Linux servers, RDP/WinRM to Windows servers (scoring may need these)
ALLOW_OUTBOUND_EXT=1           # 1 = internal nets may reach EXT_NET

# --- PERMISSIVE BASELINE TOGGLE ---
PERMISSIVE_BASELINE=1

mkdir -p "${BACKUP_DIR}"
ERR=0
RULE=0

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
cfg() {
    "$WRAP" "$@" || { echo "[!] FAILED: $*"; ERR=1; }
}

op() {
    "$OPCMD" "$@"
}

# fw_rule <chain> <action> <desc-no-spaces> <proto|-> <src|-> <dst|-> <dports|->
fw_rule() {
    chain="$1"; action="$2"; desc="$3"; proto="$4"; src="$5"; dst="$6"; ports="$7"
    RULE=$((RULE + 10))
    B="firewall ipv4 ${chain} filter rule ${RULE}"
    cfg set $B action "$action"
    cfg set $B description "$desc"
    [ "$proto" != "-" ] && cfg set $B protocol "$proto"
    [ "$src"   != "-" ] && cfg set $B source address "$src"
    [ "$dst"   != "-" ] && cfg set $B destination address "$dst"
    [ "$ports" != "-" ] && cfg set $B destination port "$ports"
}

# Stateful + ICMP rules every chain gets first
std_rules() {
    chain="$1"
    RULE=$((RULE + 10)); B="firewall ipv4 ${chain} filter rule ${RULE}"
    cfg set $B action accept
    cfg set $B description Established-Related
    cfg set $B state established
    cfg set $B state related

    RULE=$((RULE + 10)); B="firewall ipv4 ${chain} filter rule ${RULE}"
    cfg set $B action drop
    cfg set $B description Drop-Invalid
    cfg set $B state invalid

    RULE=$((RULE + 10)); B="firewall ipv4 ${chain} filter rule ${RULE}"
    cfg set $B action accept
    cfg set $B description Allow-ICMP
    cfg set $B protocol icmp
}

save_rules() {
    TARGET_FILE="${1:-$DEFAULT_BACKUP}"
    echo "[+] Saving current running config to ${TARGET_FILE}..."
    "$WRAP" begin >/dev/null 2>&1
    if "$WRAP" save "${TARGET_FILE}" >/dev/null; then
        "$WRAP" end >/dev/null 2>&1
        echo "[+] Successfully saved configuration."
        return 0
    fi
    "$WRAP" end >/dev/null 2>&1
    echo "[!] Error saving config."
    return 1
}

persist_config() {
    # Writes the running config to /config/config.boot so it survives reboot
    "$WRAP" begin >/dev/null 2>&1
    "$WRAP" save >/dev/null
    "$WRAP" end >/dev/null 2>&1
    echo "[+] Config persisted to boot config."
}

show_rules() {
    echo "==================== VyOS FIREWALL: FORWARD ===================="
    op show firewall ipv4 forward filter
    echo "==================== VyOS FIREWALL: INPUT ======================"
    op show firewall ipv4 input filter
}

# ------------------------------------------------------------------------------
# Safety net: auto-revert unless you confirm (survives a dropped SSH session)
# ------------------------------------------------------------------------------
start_watchdog() {
    touch "$PENDING"
    cat > "$WATCHDOG" <<EOF
#!/bin/vbash
source /opt/vyatta/etc/functions/script-template
sleep ${CONFIRM_SECS}
if [ -f "${PENDING}" ]; then
    ${WRAP} begin
    ${WRAP} load "${AUTO_PRE_APPLY}"
    ${WRAP} commit
    ${WRAP} end
    rm -f "${PENDING}"
fi
EOF
    chmod +x "$WATCHDOG"
    nohup setsid "$WATCHDOG" >/tmp/fw_watchdog.log 2>&1 &
}

revert_now() {
    echo "[!] Reverting to pre-apply snapshot..."
    "$WRAP" begin >/dev/null 2>&1
    "$WRAP" load "$AUTO_PRE_APPLY"
    "$WRAP" commit
    "$WRAP" end >/dev/null 2>&1
    rm -f "$PENDING"
    echo "[+] Reverted."
}

confirm_or_revert() {
    start_watchdog
    echo
    printf "Rules are LIVE. Still reachable? Keep them? Auto-revert in %s seconds. (y/N): " "$CONFIRM_SECS"
    if read -r -t "$CONFIRM_SECS" ans; then
        case "$ans" in
            y|Y) rm -f "$PENDING"; persist_config; echo "[+] Rules kept." ;;
            *)   revert_now ;;
        esac
    else
        echo
        revert_now
    fi
}

# ------------------------------------------------------------------------------
# Rule builders
# ------------------------------------------------------------------------------
build_input() {
    RULE=0
    cfg set firewall ipv4 input filter default-action drop

    # Loopback
    RULE=$((RULE + 10)); B="firewall ipv4 input filter rule ${RULE}"
    cfg set $B action accept
    cfg set $B description Loopback
    cfg set $B inbound-interface name lo

    std_rules input

    # Management (SSH) only from admin workstations
    for h in $ADMIN_HOSTS; do
        fw_rule input accept Mgmt-SSH-from-admin tcp "$h" - 22
    done

    # Keep routing alive (OSPF / VRRP / BGP)
    if [ "$PERMIT_ROUTING" -eq 1 ]; then
        for peer in $ROUTING_PEERS; do
            fw_rule input accept Routing-OSPF ospf "$peer" - -
            fw_rule input accept Routing-VRRP vrrp "$peer" - -
            fw_rule input accept Routing-BGP  tcp  "$peer" - 179
        done
    fi

    # Log + drop all other SSH attempts at the router
    RULE=$((RULE + 10)); B="firewall ipv4 input filter rule ${RULE}"
    cfg set $B action drop
    cfg set $B description PANGEA-SSH-DENIED
    cfg set $B protocol tcp
    cfg set $B destination port 22
    cfg set $B log
}

build_forward() {
    RULE=0
    if [ "$PERMISSIVE_BASELINE" -eq 1 ]; then
        cfg set firewall ipv4 forward filter default-action accept
    else
        cfg set firewall ipv4 forward filter default-action drop
    fi

    std_rules forward

    # Internal nets -> External
    if [ "$ALLOW_OUTBOUND_EXT" -eq 1 ] && [ "$ADDR_MODE" = "internal" ]; then
        fw_rule forward accept Alpine-to-External - "$ALPINE_NET" "$EXT_NET" -
        fw_rule forward accept OPN-to-External    - "$OPN_NET"    "$EXT_NET" -
    fi

    # Active Directory & DNS (ADDNS)
    fw_rule forward accept AD-DNS-udp53   udp - "$ADDNS" 53
    fw_rule forward accept AD-DNS-tcp53   tcp - "$ADDNS" 53
    fw_rule forward accept AD-core-tcp    tcp - "$ADDNS" 88,135,139,389,445,464,636,3268,3269
    fw_rule forward accept AD-core-udp    udp - "$ADDNS" 88,123,389,464
    [ "$ALLOW_AD_DYN_RPC" -eq 1 ] && \
        fw_rule forward accept AD-dynamic-RPC tcp - "$ADDNS" 49152-65535

    # Admin workstations (RDP / SSH)
    fw_rule forward accept WinWS-RDP-SSH  tcp - "$WIN_WS" 22,3389
    fw_rule forward accept UbuWS-RDP-SSH  tcp - "$UBU_WS" 22,3389

    # Management / scoring access to servers
    if [ "$ALLOW_MGMT_TO_SERVERS" -eq 1 ]; then
        for h in $ECOMM $WEBMAIL $SPLUNK; do
            fw_rule forward accept Linux-SSH tcp - "$h" 22
        done
        for h in $ADDNS $IIS $FTP; do
            fw_rule forward accept Win-RDP-WinRM tcp - "$h" 3389,5985,5986
        done
    fi

    # Splunk (web, HEC, mgmt, forwarders, syslog)
    fw_rule forward accept Splunk-tcp tcp - "$SPLUNK" 514,8000,8088,8089,9997
    fw_rule forward accept Splunk-udp udp - "$SPLUNK" 514

    # Web services (IIS, Ecomm)
    fw_rule forward accept IIS-web   tcp - "$IIS"   "$(join_ports 80,443 "$IIS_APP_PORTS")"
    fw_rule forward accept Ecomm-web tcp - "$ECOMM" "$(join_ports 80,443 "$ECOMM_APP_PORTS")"
    fw_rule forward accept Ecomm-mysql tcp - "$ECOMM" 3306

    # Webmail (web + mail protocols)
    fw_rule forward accept Webmail-web  tcp - "$WEBMAIL" 80,443
    fw_rule forward accept Webmail-mail tcp - "$WEBMAIL" 25,110,143,465,587,993,995

    # FTP (control + passive range)
    fw_rule forward accept FTP-control tcp - "$FTP" 21
    fw_rule forward accept FTP-passive tcp - "$FTP" "$FTP_PASV_RANGE"

    # Baseline catch-all (always the highest rule number)
    B="firewall ipv4 forward filter rule 9000"
    if [ "$PERMISSIVE_BASELINE" -eq 1 ]; then
        echo "[!] PERMISSIVE BASELINE ACTIVE: logging & passing unclassified traffic..."
        cfg set $B action accept
        cfg set $B description FW-BASELINE-PASS
        cfg set $B state new
        cfg set $B limit rate 30/minute
        cfg set $B log
    else
        echo "[+] STRICT ENFORCEMENT ACTIVE: dropping unclassified traffic."
        cfg set $B action drop
        cfg set $B description FW-FORWARD-DROPPED
        cfg set $B limit rate 5/minute
        cfg set $B log
    fi
}

apply_firewall() {
    echo "[+] Applying firewall rules (input + forward filter only; NAT untouched)..."

    save_rules "$AUTO_PRE_APPLY" || return 1

    ERR=0
    "$WRAP" begin >/dev/null 2>&1

    # Reset ONLY the filter chains we manage
    "$WRAP" delete firewall ipv4 input filter   >/dev/null 2>&1
    "$WRAP" delete firewall ipv4 forward filter >/dev/null 2>&1

    build_input
    build_forward

    if [ "$ERR" -ne 0 ]; then
        echo "[!] One or more commands failed - discarding changes. Nothing was applied."
        "$WRAP" discard >/dev/null 2>&1
        "$WRAP" end >/dev/null 2>&1
        return 1
    fi

    if ! "$WRAP" commit; then
        echo "[!] Commit failed - discarding changes."
        "$WRAP" discard >/dev/null 2>&1
        "$WRAP" end >/dev/null 2>&1
        return 1
    fi
    "$WRAP" end >/dev/null 2>&1
    echo "[+] Firewall rules committed!"

    confirm_or_revert
}

restore_rules() {
    TARGET_FILE="${1:-$DEFAULT_BACKUP}"

    if [ ! -f "${TARGET_FILE}" ]; then
        echo "[!] Restore failed: Backup file '${TARGET_FILE}' does not exist."
        return 1
    fi

    printf "Are you sure you want to restore config from '%s'? (y/N): " "${TARGET_FILE}"
    read -r choice
    case "$choice" in
        y|Y)
            save_rules "${AUTO_PRE_RESTORE}" || return 1
            echo "[+] Restoring ${TARGET_FILE}..."
            "$WRAP" begin >/dev/null 2>&1
            if "$WRAP" load "${TARGET_FILE}" && "$WRAP" commit; then
                "$WRAP" end >/dev/null 2>&1
                echo "[+] Config restored successfully. Run '$0 save' / persist if you want it permanent."
            else
                echo "[!] Error restoring. Reverting to pre-restore snapshot..."
                "$WRAP" discard >/dev/null 2>&1
                "$WRAP" load "${AUTO_PRE_RESTORE}" && "$WRAP" commit
                "$WRAP" end >/dev/null 2>&1
                return 1
            fi
            ;;
        *) echo "Restore operation cancelled." ;;
    esac
}

clear_filter_rules() {
    echo "[!] Clearing input + forward FILTER rules only. NAT remains intact..."
    "$WRAP" begin >/dev/null 2>&1
    "$WRAP" delete firewall ipv4 input filter   >/dev/null 2>&1
    "$WRAP" delete firewall ipv4 forward filter >/dev/null 2>&1
    "$WRAP" commit
    "$WRAP" end >/dev/null 2>&1
    echo "[+] Filter reset complete (VyOS default = accept). NAT rules were not modified."
}

# ------------------------------------------------------------------------------
# Interactive rule generator (VyOS uses rule NUMBERS, not line positions)
# ------------------------------------------------------------------------------
next_free_rule() {
    max=$(op show configuration commands 2>/dev/null \
          | grep "firewall ipv4 $1 filter rule " \
          | awk '{print $7}' | sort -n | awk '$1<9000' | tail -n1)
    echo $(( ${max:-0} + 10 ))
}

rule_exists() {
    op show configuration commands 2>/dev/null \
        | grep -q "firewall ipv4 $1 filter rule $2 "
}

interactive_rule_generator() {
    echo "================================================="
    echo " Interactive VyOS Rule Generator (multi-port)"
    echo "================================================="

    while true; do
        echo
        echo "Choose chain:"
        echo "1) input   (to the router)"
        echo "2) output  (from the router)"
        echo "3) forward (through the router)"
        printf "Selection [1-3]: "
        read -r CHOICE

        case "$CHOICE" in
            1) CHAIN="input" ;;
            2) CHAIN="output" ;;
            3) CHAIN="forward" ;;
            *) echo "ERROR: Invalid chain"; continue ;;
        esac

        # --- RULE NUMBER SELECTION ---
        echo
        echo "Current rules in $CHAIN chain:"
        op show firewall ipv4 "$CHAIN" filter | head -n 25
        echo "..."
        NEXT=$(next_free_rule "$CHAIN")
        printf "Rule number to use (blank = %s; lower number = evaluated earlier): " "$NEXT"
        read -r NUM
        [ -z "$NUM" ] && NUM="$NEXT"
        case "$NUM" in
            ''|*[!0-9]*) echo "ERROR: Rule number must be numeric"; continue ;;
        esac
        if rule_exists "$CHAIN" "$NUM"; then
            echo "ERROR: Rule $NUM already exists in $CHAIN - pick a free number"
            continue
        fi

        printf "Action (accept/drop) [accept]: "
        read -r ACTION
        [ -z "$ACTION" ] && ACTION="accept"
        case "$ACTION" in
            accept|drop) ;;
            *) echo "ERROR: Action must be accept or drop"; continue ;;
        esac

        printf "Enter IP address (or CIDR): "
        read -r IPADDR
        [ -z "$IPADDR" ] && { echo "ERROR: IP required"; continue; }

        printf "Protocol (tcp/udp): "
        read -r PROTO
        PROTO=$(echo "$PROTO" | tr 'A-Z' 'a-z')
        if [ "$PROTO" != "tcp" ] && [ "$PROTO" != "udp" ]; then
            echo "ERROR: Protocol must be tcp or udp"
            continue
        fi

        printf "Is the IP source or destination? (s/d): "
        read -r DIR
        case "$DIR" in
            s) IPKEY="source address" ;;
            d) IPKEY="destination address" ;;
            *) echo "ERROR: Must be s or d"; continue ;;
        esac

        echo
        echo "Port selection:"
        echo "1) Single port"
        echo "2) Multiple ports (comma separated, ranges like 5000-5100 ok, max 15)"
        printf "Choice [1-2]: "
        read -r PORTMODE

        if [ "$PORTMODE" = "1" ]; then
            printf "Enter port number: "
            read -r PORTS
            case "$PORTS" in
                ''|*[!0-9]*) echo "ERROR: Invalid port"; continue ;;
            esac
        elif [ "$PORTMODE" = "2" ]; then
            printf "Enter ports (e.g. 22,80,443): "
            read -r PORTS
            case "$PORTS" in
                ''|*[!0-9,-]*) echo "ERROR: Invalid port list"; continue ;;
            esac
        else
            echo "ERROR: Invalid port mode"
            continue
        fi

        B="firewall ipv4 $CHAIN filter rule $NUM"
        echo "---------------------------------------------------------------------------------"
        echo "Applying:"
        echo "  set $B action $ACTION"
        echo "  set $B protocol $PROTO"
        echo "  set $B $IPKEY $IPADDR"
        echo "  set $B destination port $PORTS"
        echo "---------------------------------------------------------------------------------"

        ERR=0
        "$WRAP" begin >/dev/null 2>&1
        cfg set $B action "$ACTION"
        cfg set $B protocol "$PROTO"
        cfg set $B $IPKEY "$IPADDR"
        cfg set $B destination port "$PORTS"

        if [ "$ERR" -eq 0 ] && "$WRAP" commit; then
            "$WRAP" end >/dev/null 2>&1
            echo "[+] Rule successfully added! (live, not yet saved to boot config)"
            op show firewall ipv4 "$CHAIN" filter | head -n 25
        else
            "$WRAP" discard >/dev/null 2>&1
            "$WRAP" end >/dev/null 2>&1
            echo "ERROR: Failed to add rule (changes discarded)"
        fi

        echo
        printf "Add another rule? (y/n): "
        read -r AGAIN
        case "$AGAIN" in
            y|Y) ;;
            *) break ;;
        esac
    done

    echo
    printf "Persist changes to boot config now? (y/N): "
    read -r P
    case "$P" in y|Y) persist_config ;; esac
    echo "Done adding rules."
}

# ------------------------------------------------------------------------------
# Discovery: which unclassified flows is the permissive baseline passing?
# Use this to find the real scoring ports, then add them to the rules above.
# ------------------------------------------------------------------------------
discover() {
    echo "Top unclassified flows hit by the baseline rule (count  proto  dst:port)"
    echo "Tip: also shows the scoring engine - look at the SRC counts with '$0 discover src'."
    LOGSRC=$( { sudo journalctl -k --no-pager 2>/dev/null || sudo cat /var/log/messages 2>/dev/null; } )
    if [ "$1" = "src" ]; then
        echo "$LOGSRC" | grep -E -- '-9000-' | \
            awk '{ s=""; for(i=1;i<=NF;i++){ if($i ~ /^SRC=/) s=substr($i,5) } if (s!="") print s }' \
            | sort | uniq -c | sort -rn | head -n 20
    else
        echo "$LOGSRC" | grep -E -- '-9000-' | \
            awk '{ p="";d="";t="";
                   for(i=1;i<=NF;i++){
                       if($i ~ /^PROTO=/) p=substr($i,7);
                       if($i ~ /^DST=/)   d=substr($i,5);
                       if($i ~ /^DPT=/)   t=substr($i,5);
                   }
                   if (d!="") print p, d ":" t }' \
            | sort | uniq -c | sort -rn | head -n 40
    fi
}

# --- CLI OPTION HANDLER ---
case "$1" in
    apply)
        apply_firewall
        ;;
    strict)
        PERMISSIVE_BASELINE=0
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
        printf "Clear input+forward FILTER rules? NAT will not be touched. (y/N): "
        read -r choice
        case "$choice" in
            y|Y) clear_filter_rules ;;
            *) echo "Aborted." ;;
        esac
        ;;
    show)
        show_rules
        ;;
    discover)
        discover "$2"
        ;;
    *)
        echo "Usage: $0 {apply|strict|add|save|restore|clear|show|discover} [ARGUMENT]"
        echo ""
        echo "Commands:"
        echo "  apply              : Apply firewall with permissive discovery pass (logs unclassified traffic)"
        echo "  strict             : Apply firewall with strict drop policy"
        echo "  add | interactive  : Launch interactive rule builder (by rule number)"
        echo "  save [FILE_PATH]   : Save running config snapshot (default ${DEFAULT_BACKUP})"
        echo "  restore [FILE_PATH]: Load a config snapshot and commit"
        echo "  show               : Display active input/forward filter rules"
        echo "  discover [src]     : Summarise flows hitting the permissive baseline (find scoring ports / source)"
        echo "  clear              : Remove input+forward filter rules (NAT untouched)"
        echo ""
        echo "Env: CONFIRM_SECS=120 $0 apply   # change the auto-revert timer"
        echo "     ADDR_MODE=nat $0 apply      # match on 172.16.1.x NAT IPs instead of internal IPs"
        exit 1
        ;;
esac
