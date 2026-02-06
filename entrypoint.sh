#!/bin/bash
set -eo pipefail

ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
PSK_FILE="${ZBX_TLSPSKFILE:-/etc/zabbix/netvaktin.psk}"
SERVER_HOST="${ZBX_SERVER_HOST:-monitor.logbirta.is}"
ID_FILE="/var/lib/zabbix/data/probe_id"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

log "Starting Netvaktin Probe (Bulletproof v2.3)..."

# 0. Runtime Fixes
if [ ! -d "/var/run/zabbix" ]; then
    mkdir -p /var/run/zabbix
    if [ "$(id -u)" -eq 0 ]; then chown zabbix:zabbix /var/run/zabbix; fi
fi

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

METADATA="ISP:${DETECTED_ISP}"

# 2.5 Signature Updates
SIGNATURE_URL="${ZBX_SIGNATURE_URL:-https://raw.githubusercontent.com/hoddiv/netvaktin-probe/main/netvaktin_signatures.json}"
SIGNATURE_DEST="/etc/zabbix/signatures.json"
curl -s -f -o "$SIGNATURE_DEST" --max-time 10 "$SIGNATURE_URL" || log "⚠️ Using baked-in signatures."
if [ ! -f "$SIGNATURE_DEST" ]; then echo "{}" > "$SIGNATURE_DEST"; fi

# 2.9 API Self-Registration (The PSK Sync logic)
if [ -n "$ZBX_API_TOKEN" ]; then
    log "🤖 Performing API Self-Registration..."
    if [ -f "$PSK_FILE" ]; then
        export ZBX_TLSPSKVALUE=$(cat "$PSK_FILE")
        python3 /usr/bin/register_probe.py
    fi
fi

# 3. Agent Config - UNIVERSAL TIMEOUTS
cat > "$ZABBIX_CONF" <<EOF
PidFile=/var/run/zabbix/zabbix_agent2.pid
Timeout=60
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
