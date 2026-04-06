#!/bin/bash
set -eo pipefail

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

# === CONFIGURATION ===
ZABBIX_CONF="/etc/zabbix/zabbix_agent2.conf"
PSK_FILE="${ZBX_TLSPSKFILE:-/etc/zabbix/netvaktin.psk}"
HOSTNAME="${ZBX_HOSTNAME:-UnknownProbe}"

# === 1. ROLE SWITCHING ===
# NETVAKTIN_ROLE controls prod/dev routing:
#   Domestic  → prod group "Netvaktin Probes"           + "Template Netvaktin"
#   External  → prod group "Netvaktin External Probes"  + "Template Netvaktin Inbound"
#   Dev       → dev group  "Netvaktin Dev Probes"       + "Template Netvaktin Dev"
#   DevExt    → dev group  "Netvaktin Dev External Probes" + "Template Netvaktin Inbound Dev"
#
# Override at any time by setting ZBX_HOSTGROUP_NAME and ZBX_TEMPLATE_NAME directly.
ROLE="${NETVAKTIN_ROLE:-Domestic}"

if [ "$ROLE" == "External" ]; then
    log "🌍 Mode: EXTERNAL (Inbound Monitoring) — PRODUCTION"
    export ZBX_HOSTGROUP_NAME="${ZBX_HOSTGROUP_NAME:-Netvaktin External Probes}"
    export ZBX_TEMPLATE_NAME="${ZBX_TEMPLATE_NAME:-Template Netvaktin Inbound}"
elif [ "$ROLE" == "Dev" ]; then
    log "🧪 Mode: DEV DOMESTIC (Outbound Monitoring) — DEV"
    export ZBX_HOSTGROUP_NAME="${ZBX_HOSTGROUP_NAME:-Netvaktin Dev Probes}"
    export ZBX_TEMPLATE_NAME="${ZBX_TEMPLATE_NAME:-Template Netvaktin Dev}"
elif [ "$ROLE" == "DevExt" ]; then
    log "🧪 Mode: DEV EXTERNAL (Inbound Monitoring) — DEV"
    export ZBX_HOSTGROUP_NAME="${ZBX_HOSTGROUP_NAME:-Netvaktin Dev External Probes}"
    export ZBX_TEMPLATE_NAME="${ZBX_TEMPLATE_NAME:-Template Netvaktin Inbound Dev}"
else
    log "🏠 Mode: DOMESTIC (Outbound Monitoring) — PRODUCTION"
    export ZBX_HOSTGROUP_NAME="${ZBX_HOSTGROUP_NAME:-Netvaktin Probes}"
    export ZBX_TEMPLATE_NAME="${ZBX_TEMPLATE_NAME:-Template Netvaktin}"
fi

# === 2. API SELF-REGISTRATION ===
if [ -n "$ZBX_API_TOKEN" ]; then
    log "🤖 Performing API Self-Registration..."
    python3 /usr/bin/register_probe.py
else
    log "⚠️ No ZBX_API_TOKEN provided. Skipping registration."
fi

# === 3. ZABBIX AGENT CONFIGURATION ===
if command -v getcap >/dev/null 2>&1; then
    for bin in /usr/local/bin/scamper "$(command -v mtr 2>/dev/null || true)" "$(command -v mtr-packet 2>/dev/null || true)"; do
        [ -n "$bin" ] || continue
        if [ -x "$bin" ]; then
            log "🔎 Trace binary: $bin $(getcap "$bin" 2>/dev/null | sed "s#^$bin##")"
        fi
    done
fi

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
UserParameter=netvaktin.v5.mtr[*],/usr/bin/route_check_v5.py "\$1" "\$2" "\$3" "\$4" "\$5" "\$6" "\$7"
EOF

# === 4. START THE AGENT ===
log "🚀 Starting Zabbix Agent 2..."
exec /usr/sbin/zabbix_agent2 -c "$ZABBIX_CONF"
