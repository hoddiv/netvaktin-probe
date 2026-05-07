#!/bin/bash
# Netvaktin Probe Deployment v3.0 - Unified Architecture

SERVER="monitor.logbirta.is"
PORT="10051"
API="https://monitor.logbirta.is/api_jsonrpc.php"
PSK_FILE="netvaktin.psk"
CONTAINER_PSK_FILE="/etc/zabbix/netvaktin.psk"
IMAGE_NAME="netvaktin-probe"
AUTO_BUILD_ON_INVALID="${NETVAKTIN_BUILD_IF_INVALID:-0}"
DOCKER_CMD=()
DOCKER_PREFIX_DISPLAY="docker"

setup_docker_access() {
    if docker info >/dev/null 2>&1; then
        DOCKER_CMD=(docker)
        DOCKER_PREFIX_DISPLAY="docker"
        return 0
    fi

    if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
        DOCKER_CMD=(sudo docker)
        DOCKER_PREFIX_DISPLAY="sudo docker"
        return 0
    fi

    echo "❌ Error: Docker is installed but this shell cannot access the Docker daemon."
    echo "   Use an account with Docker access, or verify that 'sudo docker info' works on this host."
    return 1
}

run_docker() {
    "${DOCKER_CMD[@]}" "$@"
}

remove_local_path() {
    local target="$1"
    if rm -rf "$target" 2>/dev/null; then
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        sudo rm -rf "$target"
        return $?
    fi
    echo "❌ Error: Unable to remove '$target'. Remove it manually and rerun."
    return 1
}

print_image_refresh_help() {
    echo "❌ Local Docker image '$IMAGE_NAME' is missing or does not contain the current PSK bootstrap logic."
    echo "   Refresh it with one of the following options:"
    echo "   A) docker pull ghcr.io/hoddiv/netvaktin-probe:latest && docker tag ghcr.io/hoddiv/netvaktin-probe:latest $IMAGE_NAME"
    echo "   B) $DOCKER_PREFIX_DISPLAY build --pull --no-cache -t $IMAGE_NAME ."
    echo "   Optional: set NETVAKTIN_BUILD_IF_INVALID=1 to let this script rebuild locally when validation fails."
}

validate_probe_image() {
    if ! run_docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        if [ "$AUTO_BUILD_ON_INVALID" = "1" ]; then
            echo "⚠️  Local image '$IMAGE_NAME' not found. Building it now because NETVAKTIN_BUILD_IF_INVALID=1..."
            run_docker build --pull --no-cache -t "$IMAGE_NAME" . || return 1
        else
            print_image_refresh_help
            return 1
        fi
    fi

    if run_docker run --rm --entrypoint sh "$IMAGE_NAME" -c \
        "grep -q 'ZBX_TLSPSKVALUE' /usr/bin/entrypoint.sh && \
         grep -q 'TLSPSKFile' /usr/bin/entrypoint.sh && \
         grep -q 'TLS PSK file ready' /usr/bin/entrypoint.sh"; then
        echo "✅ Image preflight passed: '$IMAGE_NAME' contains PSK bootstrap support."
        return 0
    fi

    if [ "$AUTO_BUILD_ON_INVALID" = "1" ]; then
        echo "⚠️  Local image '$IMAGE_NAME' is stale. Rebuilding it now because NETVAKTIN_BUILD_IF_INVALID=1..."
        run_docker build --pull --no-cache -t "$IMAGE_NAME" . || return 1
        if run_docker run --rm --entrypoint sh "$IMAGE_NAME" -c \
            "grep -q 'ZBX_TLSPSKVALUE' /usr/bin/entrypoint.sh && \
             grep -q 'TLSPSKFile' /usr/bin/entrypoint.sh && \
             grep -q 'TLS PSK file ready' /usr/bin/entrypoint.sh"; then
            echo "✅ Image preflight passed after local rebuild."
            return 0
        fi
        print_image_refresh_help
        return 1
    fi

    print_image_refresh_help
    return 1
}

# 1. Environment Checks
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker not found."
    exit 1
fi

if ! setup_docker_access; then
    exit 1
fi

if ! validate_probe_image; then
    exit 1
fi

# 2. Credential Handling
if [ -z "${ZBX_API_TOKEN:-}" ]; then
    read -sp "🔑 Zabbix API Token: " ZBX_API_TOKEN
    echo ""
fi

if [ -z "$ZBX_API_TOKEN" ]; then
    echo "❌ Error: Token required."
    exit 1
fi

# 3. Host Identity & Role Selection
# Usage: ./deploy.sh [HOSTNAME] [ROLE]

# A. Hostname
if [ -n "${1:-}" ]; then
    HOSTNAME="$1"
else
    read -p "🖥️  Hostname (e.g., Probe-Garage-01): " HOSTNAME
fi

if [ -z "$HOSTNAME" ]; then
    echo "❌ Error: Hostname required."
    exit 1
fi

# B. Role (New Logic)
if [ -n "${2:-}" ]; then
    ROLE="$2"
else
    echo "Select Probe Role:"
    echo "  1) Domestic (Outbound Monitoring - Default)"
    echo "  2) External (Inbound Monitoring - e.g., Hetzner)"
    read -p "Choice [1]: " ROLE_CHOICE
    
    case "$ROLE_CHOICE" in
        2) ROLE="External" ;;
        *) ROLE="Domestic" ;;
    esac
fi

echo ">> Configured as: $ROLE Probe"

PSK_ID="CommunityProbe-${HOSTNAME}"
CONTAINER="netvaktin-${HOSTNAME}"

# 4. Key Management
# Stop old container FIRST so it releases any bind-mount hold on the PSK path
echo "🚀 Deploying $CONTAINER..."
run_docker rm -f "$CONTAINER" 2>/dev/null || true

if [ -d "$PSK_FILE" ]; then
    echo "⚠️  $PSK_FILE is a directory (Docker volume artifact). Removing it..."
    remove_local_path "$PSK_FILE" || exit 1
fi
if [ -f "$PSK_FILE" ]; then
    echo "Using existing PSK."
    PSK=$(cat "$PSK_FILE")
else
    echo "Generating new PSK..."
    PSK=$(openssl rand -hex 32)
    echo "$PSK" > "$PSK_FILE"
    chmod 600 "$PSK_FILE"
fi

# 5. Deployment

# INCREASED PIDS-LIMIT AND FORK-BASED HEALTHCHECK
run_docker run -d \
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
  -e ZBX_TLSPSKFILE="$CONTAINER_PSK_FILE" \
  -e ZBX_TLSPSKVALUE="$PSK" \
  -e NETVAKTIN_ROLE="$ROLE" \
  "$IMAGE_NAME"

if [ $? -eq 0 ]; then
    echo "✅ Success. Container ID: $(run_docker ps -q -f name=$CONTAINER)"
    echo "   Role: $ROLE"
    echo "   Mode: Active"
else
    echo "❌ Failed to start container."
    exit 1
fi
