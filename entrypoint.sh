#!/bin/bash
set -eo pipefail

ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
PSK_FILE="${ZBX_TLSPSKFILE:-/etc/zabbix/netvaktin.psk}"
SERVER_HOST="${ZBX_SERVER_HOST:-monitor.logbirta.is}"
# 1. PERSISTENCE FILE LOCATION (The Memory)
ID_FILE="/var/lib/zabbix/data/probe_id"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

log "Starting Netvaktin Probe..."

# 0. Runtime Fixes (PID Directory & Data Directory)
if [ ! -d "/var/run/zabbix" ]; then
    mkdir -p /var/run/zabbix
    if [ "$(id -u)" -eq 0 ]; then chown zabbix:zabbix /var/run/zabbix; fi
fi

# Ensure data dir exists for persistence
if [ ! -d "$(dirname "$ID_FILE")" ]; then
    mkdir -p "$(dirname "$ID_FILE")"
    if [ "$(id -u)" -eq 0 ]; then chown zabbix:zabbix "$(dirname "$ID_FILE")"; fi
fi

# 1. Connectivity Check
if ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    log "WARN: Cloudflare (1.1.1.1) unreachable. Retrying Google..."
    if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log "FATAL: No internet connectivity."
        exit 1
    fi
fi

# 2. Hostname Logic (The Sticky Fix)
if [ -n "$ZBX_HOSTNAME" ]; then
    # CASE A: Manual Override (Highest Priority)
    HOSTNAME="$ZBX_HOSTNAME"
    DETECTED_ISP="ManualOverride" 
    log "✅ Manual Hostname Detected: $HOSTNAME"
else
    # CASE B: Check for Saved Identity (The Memory)
    if [ -f "$ID_FILE" ]; then
        HOSTNAME=$(cat "$ID_FILE")
        # Try to guess ISP from the saved name (e.g. Probe_Vodafone_AB12 -> Vodafone)
        DETECTED_ISP=$(echo "$HOSTNAME" | cut -d'_' -f2)
        log "♻️  Restored Sticky Identity: $HOSTNAME"
    else
        # CASE C: First Boot - Generate New
        log "✨ First boot detected. Generating Identity..."
        if [ -n "${PROBE_MANUAL_ISP:-}" ]; then
            DETECTED_ISP="$PROBE_MANUAL_ISP"
            log "Using Manual ISP Override: $DETECTED_ISP"
        else
            DETECTED_ISP=$(curl -s --max-time 5 http://ip-api.com/json/ | jq -r .isp | sed 's/[^a-zA-Z0-9]//g')
            [ -z "$DETECTED_ISP" ] || [ "$DETECTED_ISP" == "null" ] && DETECTED_ISP="Unknown"
        fi
        
        RAND_SUFFIX=$(head /dev/urandom | tr -dc A-Z0-9 | head -c 4)
        HOSTNAME="Probe_${DETECTED_ISP}_${RAND_SUFFIX}"
        
        # SAVE IT FOR NEXT TIME
        echo "$HOSTNAME" > "$ID_FILE"
        log "💾 Identity Saved to $ID_FILE"
    fi
fi

METADATA="ISP:${DETECTED_ISP}"
log "Identity Established: $HOSTNAME [$METADATA]"

# 2.5 Signature Updates
SIGNATURE_URL="${ZBX_SIGNATURE_URL:-https://raw.githubusercontent.com/hoddiv/netvaktin-probe/main/netvaktin_signatures.json}"
SIGNATURE_DEST="/etc/zabbix/signatures.json"

log "⬇️ Checking for Cable Signature updates..."
if curl -s -f -o "$SIGNATURE_DEST" --max-time 10 "$SIGNATURE_URL"; then
    log "✅ Signatures updated successfully."
else
    log "⚠️ Signature download failed (or no URL set). Using baked-in heuristics."
    if [ ! -f "$SIGNATURE_DEST" ]; then echo "{}" > "$SIGNATURE_DEST"; fi
fi

# 2.9 API Self-Registration (The New Feature)
# If an API token is provided, we register ourselves before starting the agent
if [ -n "$ZBX_API_TOKEN" ]; then
    log "🤖 Performing API Self-Registration..."
    # We export the PSK content so Python can read it easily
    if [ -f "$PSK_FILE" ]; then
        export ZBX_TLSPSKVALUE=$(cat "$PSK_FILE")
        # Run the registration script
        python3 /usr/bin/register_probe.py
    else
        log "⚠️  Cannot register: PSK file missing at $PSK_FILE"
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

if [ -n "$ZBX_USERPARAMETER" ]; then
    echo "UserParameter=$ZBX_USERPARAMETER" >> /etc/zabbix/zabbix_agent2.d/custom_params.conf
fi

log "Handing off to Zabbix Agent..."
exec /usr/sbin/zabbix_agent2 -c "$ZABBIX_CONF" -f
