#!/bin/bash
set -eo pipefail

ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
PSK_FILE="${ZBX_TLSPSKFILE:-/etc/zabbix/netvaktin.psk}"
SERVER_HOST="${ZBX_SERVER_HOST:-monitor.logbirta.is}"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

log "Starting Netvaktin Probe..."

# 1. Connectivity Check
if ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    log "WARN: Cloudflare (1.1.1.1) unreachable. Retrying Google..."
    if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        log "FATAL: No internet connectivity."
        exit 1
    fi
fi

# 2. ISP Detection
if [ -n "${PROBE_MANUAL_ISP:-}" ]; then
    DETECTED_ISP="$PROBE_MANUAL_ISP"
    log "Using Manual ISP Override: $DETECTED_ISP"
else
    # Fetch ISP, sanitize to alphanumeric
    DETECTED_ISP=$(curl -s --max-time 5 http://ip-api.com/json/ | jq -r .isp | sed 's/[^a-zA-Z0-9]//g')
    [ -z "$DETECTED_ISP" ] || [ "$DETECTED_ISP" == "null" ] && DETECTED_ISP="Unknown"
fi

# 3. Identity Setup
RAND_SUFFIX=$(head /dev/urandom | tr -dc A-Z0-9 | head -c 4)
HOSTNAME="Probe_${DETECTED_ISP}_${RAND_SUFFIX}"
METADATA="ISP:${DETECTED_ISP}"

log "Identity Established: $HOSTNAME [$METADATA]"

# 4. Agent Config
cat > "$ZABBIX_CONF" <<EOF
PidFile=/var/run/zabbix/zabbix_agent2.pid
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

# Register Magic Word
echo 'UserParameter=netvaktin.mtr[*],/usr/bin/route_check.sh "$1"' > /etc/zabbix/zabbix_agent2.d/netvaktin.conf

log "Handing off to Zabbix Agent..."
exec /usr/sbin/zabbix_agent2 -c "$ZABBIX_CONF" -f
