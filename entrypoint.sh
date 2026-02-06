#!/bin/bash
set -eo pipefail

# === CONFIGURATION & DEFAULTS ===
ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
PSK_FILE="${ZBX_TLSPSKFILE:-/etc/zabbix/netvaktin.psk}"
SERVER_HOST="${ZBX_SERVER_HOST:-monitor.logbirta.is}"
ID_FILE="/var/lib/zabbix/data/probe_id"

# GitHub Sources (The Single Source of Truth)
URL_DOMESTIC="https://raw.githubusercontent.com/hoddiv/netvaktin-probe/main/netvaktin_signatures.json"
URL_EXTERNAL="https://raw.githubusercontent.com/hoddiv/netvaktin-probe/main/signatures_inbound.json"

# Local Fallbacks (Baked into Image)
LOCAL_DOMESTIC="/usr/local/share/netvaktin/netvaktin_signatures.json"
LOCAL_EXTERNAL="/usr/local/share/netvaktin/signatures_inbound.json"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

# === DYNAMIC SIGNATURE LOGIC ===
download_signatures() {
    local url="$1"
    local fallback="$2"
    local target="/etc/zabbix/signatures.json"

    log "⬇️  Attempting to fetch latest signatures from GitHub..."
    
    # Try download with 5s timeout
    if curl -s --max-time 5 -o "${target}.tmp" "$url"; then
        # Validate JSON integrity
        if jq empty "${target}.tmp" >/dev/null 2>&1; then
            mv "${target}.tmp" "$target"
            log "✅  Signatures updated from GitHub."
            return 0
        else
            log "⚠️  Downloaded file is invalid JSON. Ignoring."
        fi
    else
        log "⚠️  GitHub unreachable or timeout. Using local fallback."
    fi

    # Fallback to baked-in file
    log "ℹ️  Reverting to baked-in signatures."
    cp "$fallback" "$target"
}

# === ROLE SWITCHING ===
ROLE="${NETVAKTIN_ROLE:-Domestic}"

if [ "$ROLE" == "External" ]; then
    echo "[Init] 🌍 Mode: EXTERNAL (Inbound Monitoring)"
    download_signatures "$URL_EXTERNAL" "$LOCAL_EXTERNAL"
    
    export ZBX_HOSTGROUP_NAME="Netvaktin External Probes"
    export ZBX_TEMPLATE_NAME="Template Netvaktin Inbound"
else
    echo "[Init] 🏠 Mode: DOMESTIC (Outbound Monitoring)"
    download_signatures "$URL_DOMESTIC" "$LOCAL_DOMESTIC"
    
    export ZBX_HOSTGROUP_NAME="Netvaktin Probes"
    export ZBX_TEMPLATE_NAME="Template Netvaktin"
fi

log "Starting Netvaktin Probe (Role: $ROLE)..."

# 0. Runtime Fixes
mkdir -p /var/run/zabbix
if [ "$(id -u)" -eq 0 ]; then chown zabbix:zabbix /var/run/zabbix; fi

if [ ! -d "$(dirname "$ID_FILE")" ]; then
    mkdir -p "$(dirname "$ID_FILE")"
    if [ "$(id -u)" -eq 0 ]; then chown zabbix:zabbix "$(dirname "$ID_FILE")"; fi
fi

# 1. Connectivity Check
if ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    log "WARN: Cloudflare unreachable. Checking Google..."
    if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log "FATAL: No internet connectivity."
        exit 1
    fi
fi

# 2. Hostname Logic
if [ -n "$ZBX_HOSTNAME" ]; then
    HOSTNAME="$ZBX_HOSTNAME"
    DETECTED_ISP="ManualOverride" 
else
    if [ -f "$ID_FILE" ]; then
        HOSTNAME=$(cat "$ID_FILE")
        DETECTED_ISP=$(echo "$HOSTNAME" | cut -d'_' -f2)
    else
        DETECTED_ISP=$(curl -s --max-time 5 http://ip-api.com/json/ | jq -r .isp | sed 's/[^a-zA-Z0-9]//g')
        [ -z "$DETECTED_ISP" ] || [ "$DETECTED_ISP" == "null" ] && DETECTED_ISP="Unknown"
        RAND_SUFFIX=$(head /dev/urandom | tr -dc A-Z0-9 | head -c 4)
        HOSTNAME="Probe_${DETECTED_ISP}_${RAND_SUFFIX}"
        echo "$HOSTNAME" > "$ID_FILE"
    fi
fi

# 2.5 Metadata Construction
METADATA="ISP:${DETECTED_ISP};Role:${ROLE}"
log "Probe Identity: $HOSTNAME ($METADATA)"

# 2.9 API Self-Registration
if [ -n "$ZBX_API_TOKEN" ]; then
    log "🤖 Performing API Self-Registration..."
    if [ -f "$PSK_FILE" ]; then
        export ZBX_TLSPSKVALUE=$(cat "$PSK_FILE")
        python3 /usr/bin/register_probe.py
    fi
fi

# 3. Agent Config
cat > "$ZABBIX_CONF" <<EOF
PidFile=/var/run/zabbix/zabbix_agent2.pid
Timeout=30
LogFile=/dev/stdout
LogFileSize=0
ServerActive=${SERVER_HOST}:10051
Hostname=${HOSTNAME}
HostMetadata=${METADATA}
TLSConnect=psk
TLSPSKIdentity=${ZBX_TLSPSKIDENTITY:-CommunityProbe}
TLSPSKFile=${PSK_FILE}
ControlSocket=/tmp/agent.sock
Include=/etc/zabbix/zabbix_agent2.d/*.conf
EOF

# 4. User Parameters
echo 'UserParameter=netvaktin.mtr[*],/usr/bin/route_check.sh $1 $2' > /etc/zabbix/zabbix_agent2.d/netvaktin.conf

log "Handing off to Zabbix Agent..."
exec /usr/sbin/zabbix_agent2 -c "$ZABBIX_CONF" -f
