#!/bin/bash
set -eo pipefail

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

# === CONFIGURATION ===
ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
PSK_FILE="${ZBX_TLSPSKFILE:-/etc/zabbix/netvaktin.psk}"
HOSTNAME="${ZBX_HOSTNAME:-UnknownProbe}"

# === 1. ROLE SWITCHING ===
ROLE="${NETVAKTIN_ROLE:-Domestic}"

if [ "$ROLE" == "External" ]; then
    log "🌍 Mode: EXTERNAL (Inbound Monitoring)"
    export ZBX_HOSTGROUP_NAME="Netvaktin Dev External Probes"
    export ZBX_TEMPLATE_NAME="Template Netvaktin Inbound"
else
    log "🏠 Mode: DOMESTIC (Outbound Monitoring)"
    export ZBX_HOSTGROUP_NAME="Netvaktin Dev Probes"
    export ZBX_TEMPLATE_NAME="Template Netvaktin"
fi

# === 2. API SELF-REGISTRATION ===
if [ -n "$ZBX_API_TOKEN" ]; then
    log "🤖 Performing API Self-Registration..."
    # This executes your register_probe.py!
    python3 /usr/bin/register_probe.py
else
    log "⚠️ No ZBX_API_TOKEN provided. Skipping registration."
fi

# === 3. ZABBIX AGENT CONFIGURATION ===
log "⚙️ Generating Zabbix Agent configuration..."
cat > "$ZABBIX_CONF" <<EOF
PidFile=/var/run/zabbix/zabbix_agent2.pid
Timeout=30
LogFile=/dev/stdout
LogFileSize=0
ServerActive=${ZBX_SERVER_HOST}
Hostname=${HOSTNAME}
TLSConnect=psk
TLSAccept=psk
TLSPSKIdentity=${ZBX_TLSPSKIDENTITY}
TLSPSKFile=${PSK_FILE}
UserParameter=netvaktin.mtr[*],/usr/bin/route_check.sh "\$1" "\$2"
EOF

# === 4. START THE AGENT ===
log "🚀 Starting Zabbix Agent 2..."
exec /usr/sbin/zabbix_agent2 -c "$ZABBIX_CONF"
