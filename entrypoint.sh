#!/bin/bash
set -eo pipefail

ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
PSK_FILE="${ZBX_TLSPSKFILE:-/etc/zabbix/netvaktin.psk}"
SERVER_HOST="${ZBX_SERVER_HOST:-monitor.logbirta.is}"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

log "Starting Netvaktin Probe..."

# 0. Runtime Fixes (PID Directory)
# This prevents the "cannot open PID file" crash
if [ ! -d "/var/run/zabbix" ]; then
    mkdir -p /var/run/zabbix
    # Try to set ownership if running as root
    if [ "$(id -u)" -eq 0 ]; then
        chown zabbix:zabbix /var/run/zabbix
    fi
fi

# 1. Connectivity Check
if ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    log "WARN: Cloudflare (1.1.1.1) unreachable. Retrying Google..."
    if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log "FATAL: No internet connectivity."
        exit 1
    fi
fi

# 2. Hostname Logic (The Identity Fix)
if [ -n "$ZBX_HOSTNAME" ]; then
    # CASE A: Manual Override (This enables your specific naming)
    HOSTNAME="$ZBX_HOSTNAME"
    DETECTED_ISP="ManualOverride" 
    log "✅ Manual Hostname Detected: $HOSTNAME"
else
    # CASE B: Auto-Generation (Default behavior for volunteers)
    if [ -n "${PROBE_MANUAL_ISP:-}" ]; then
        DETECTED_ISP="$PROBE_MANUAL_ISP"
        log "Using Manual ISP Override: $DETECTED_ISP"
    else
        DETECTED_ISP=$(curl -s --max-time 5 http://ip-api.com/json/ | jq -r .isp | sed 's/[^a-zA-Z0-9]//g')
        [ -z "$DETECTED_ISP" ] || [ "$DETECTED_ISP" == "null" ] && DETECTED_ISP="Unknown"
    fi
    
    RAND_SUFFIX=$(head /dev/urandom | tr -dc A-Z0-9 | head -c 4)
    HOSTNAME="Probe_${DETECTED_ISP}_${RAND_SUFFIX}"
    log "ℹ️ Auto-Generated Hostname: $HOSTNAME"
fi

METADATA="ISP:${DETECTED_ISP}"
log "Identity Established: $HOSTNAME [$METADATA]"

# 2.5 Signature Updates (Community Intelligence)
# This pulls the latest "Gatekeeper IPs" from GitHub so we don't have to rebuild Docker for every new cable.
SIGNATURE_URL="${ZBX_SIGNATURE_URL:-https://raw.githubusercontent.com/hoddiv/netvaktin-probe/main/netvaktin_signatures.json}"
SIGNATURE_DEST="/etc/zabbix/signatures.json"

log "⬇️ Checking for Cable Signature updates..."
if curl -s -f -o "$SIGNATURE_DEST" --max-time 10 "$SIGNATURE_URL"; then
    log "✅ Signatures updated successfully."
else
    log "⚠️ Signature download failed (or no URL set). Using baked-in heuristics."
    # Optional: Create an empty JSON array if missing to prevent jq errors later
    if [ ! -f "$SIGNATURE_DEST" ]; then echo "{}" > "$SIGNATURE_DEST"; fi
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

# 4. User Parameters (The Magic Word)
# Always ensure the core route_check function is present
# Allow IP ($1) and Label ($2)
echo 'UserParameter=netvaktin.mtr[*],/usr/bin/route_check.sh $1 $2' > /etc/zabbix/zabbix_agent2.d/netvaktin.conf

# Support for extra parameters passed via ENV if needed
if [ -n "$ZBX_USERPARAMETER" ]; then
    echo "UserParameter=$ZBX_USERPARAMETER" >> /etc/zabbix/zabbix_agent2.d/custom_params.conf
fi

log "Handing off to Zabbix Agent..."
exec /usr/sbin/zabbix_agent2 -c "$ZABBIX_CONF" -f
