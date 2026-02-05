#!/bin/bash
# Netvaktin Probe Deployment v2.2 - Hardened Edition

SERVER="monitor.logbirta.is"
PORT="10051"
API="https://monitor.logbirta.is/api_jsonrpc.php"
PSK_FILE="netvaktin.psk"

# 1. Environment Checks
if ! command -v docker &> /dev/null; then
    echo "Error: Docker not found."
    exit 1
fi

# 2. Credential Handling
if [ -z "${ZBX_API_TOKEN:-}" ]; then
    read -sp "Zabbix API Token: " ZBX_API_TOKEN
    echo ""
fi

if [ -z "$ZBX_API_TOKEN" ]; then
    echo "Error: Token required."
    exit 1
fi

# 3. Host Identity
if [ -n "${1:-}" ]; then
    HOSTNAME="$1"
else
    read -p "Hostname (e.g. Probe-Garage-01): " HOSTNAME
fi

if [ -z "$HOSTNAME" ]; then
    echo "Error: Hostname required."
    exit 1
fi

# 4. Key Management
if [ -f "$PSK_FILE" ]; then
    echo "Using existing PSK."
    PSK=$(cat "$PSK_FILE")
else
    echo "Generating new PSK..."
    PSK=$(openssl rand -hex 32)
    echo "$PSK" > "$PSK_FILE"
    chmod 600 "$PSK_FILE"
fi

PSK_ID="CommunityProbe-${HOSTNAME}"
CONTAINER="netvaktin-${HOSTNAME}"

# 5. Deployment
echo "Deploying $CONTAINER..."
sudo docker rm -f "$CONTAINER" 2>/dev/null || true

# INCREASED PIDS-LIMIT AND FORK-BASED HEALTHCHECK
sudo docker run -d \
  --name "$CONTAINER" \
  --net=host \
  --restart always \
  --init \
  --pids-limit 2000 \
  --memory="512m" \
  --health-cmd="ls /usr/bin/route_check.sh > /dev/null || exit 1" \
  --health-interval=1m \
  --health-retries=3 \
  -v "$(pwd)/$PSK_FILE":/etc/zabbix/netvaktin.psk \
  -e ZBX_HOSTNAME="$HOSTNAME" \
  -e ZBX_SERVER_HOST="$SERVER" \
  -e ZBX_SERVER_PORT="$PORT" \
  -e ZBX_API_URL="$API" \
  -e ZBX_API_TOKEN="$ZBX_API_TOKEN" \
  -e ZBX_TLSPSKIDENTITY="$PSK_ID" \
  -e ZBX_TLSPSKVALUE="$PSK" \
  netvaktin-probe

if [ $? -eq 0 ]; then
    echo "Done. Container ID: $(sudo docker ps -q -f name=$CONTAINER)"
else
    echo "Failed to start container."
    exit 1
fi
