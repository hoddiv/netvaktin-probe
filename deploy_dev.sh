#!/bin/bash
# Netvaktin Dev Probe Deployment
# Registers to "Netvaktin Dev Probes" / "Template Netvaktin Dev" — never touches production.
#
# Usage:
#   ./deploy_dev.sh <HOSTNAME> [ext]
#   ./deploy_dev.sh Probe-Dev-01        # domestic dev probe
#   ./deploy_dev.sh Probe-DevExt-01 ext # external dev probe

SERVER="monitor.logbirta.is"
PORT="10051"
API="https://monitor.logbirta.is/api_jsonrpc.php"
PSK_FILE="netvaktin-dev.psk"

if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker not found."
    exit 1
fi

if [ -z "${ZBX_API_TOKEN:-}" ]; then
    read -sp "🔑 Zabbix API Token: " ZBX_API_TOKEN
    echo ""
fi

if [ -z "$ZBX_API_TOKEN" ]; then
    echo "❌ Error: Token required."
    exit 1
fi

HOSTNAME="${1:-}"
if [ -z "$HOSTNAME" ]; then
    read -p "🖥️  Dev Hostname (e.g., Probe-Dev-01): " HOSTNAME
fi
if [ -z "$HOSTNAME" ]; then
    echo "❌ Error: Hostname required."
    exit 1
fi

ROLE_ARG="${2:-domestic}"
if [ "$ROLE_ARG" == "ext" ] || [ "$ROLE_ARG" == "external" ]; then
    NETVAKTIN_ROLE="DevExt"
    echo ">> Dev mode: EXTERNAL (DevExt)"
else
    NETVAKTIN_ROLE="Dev"
    echo ">> Dev mode: DOMESTIC (Dev)"
fi

PSK_ID="DevProbe-${HOSTNAME}"
CONTAINER="netvaktin-dev-${HOSTNAME}"

echo "🧪 Deploying dev probe: $CONTAINER ..."
# Stop old container FIRST so it releases any bind-mount hold on the PSK path
sudo docker rm -f "$CONTAINER" 2>/dev/null || true

# Separate PSK file from prod to avoid overwriting it
if [ -d "$PSK_FILE" ]; then
    echo "⚠️  $PSK_FILE is a directory (Docker volume artifact). Removing it..."
    sudo rm -rf "$PSK_FILE"
fi
if [ -f "$PSK_FILE" ]; then
    echo "Using existing dev PSK."
    PSK=$(cat "$PSK_FILE")
else
    echo "Generating new dev PSK..."
    PSK=$(openssl rand -hex 32)
    echo "$PSK" > "$PSK_FILE"
    chmod 600 "$PSK_FILE"
fi

sudo docker run -d \
  --name "$CONTAINER" \
  --net=host \
  --cap-add NET_RAW \
  --restart always \
  --init \
  --pids-limit 2000 \
  --memory="512m" \
  --health-cmd="ls /usr/bin/route_check_v5.py > /dev/null || exit 1" \
  --health-interval=1m \
  --health-retries=3 \
  -e ZBX_HOSTNAME="$HOSTNAME" \
  -e ZBX_SERVER_HOST="$SERVER" \
  -e ZBX_SERVER_PORT="$PORT" \
  -e ZBX_API_URL="$API" \
  -e ZBX_API_TOKEN="$ZBX_API_TOKEN" \
  -e ZBX_TLSPSKIDENTITY="$PSK_ID" \
  -e ZBX_TLSPSKVALUE="$PSK" \
  -e NETVAKTIN_ROLE="$NETVAKTIN_ROLE" \
  netvaktin-probe

if [ $? -eq 0 ]; then
    echo "✅ Dev probe deployed: $CONTAINER"
    echo "   Role: $NETVAKTIN_ROLE"
    echo "   Host group: $([ "$NETVAKTIN_ROLE" == "DevExt" ] && echo "Netvaktin Dev External Probes" || echo "Netvaktin Dev Probes")"
    echo "   Template:   $([ "$NETVAKTIN_ROLE" == "DevExt" ] && echo "Template Netvaktin Inbound Dev" || echo "Template Netvaktin Dev")"
    echo ""
    echo "Verify in Zabbix: Configuration → Hosts → $HOSTNAME should appear under dev group."
    echo "Check dev exporter output: curl http://localhost:8081/status.json"
else
    echo "❌ Failed to start dev probe container."
    exit 1
fi
