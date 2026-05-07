#!/bin/bash
# Netvaktin Probe Deployment v3.0 - Unified Architecture

SERVER="monitor.logbirta.is"
PORT="10051"
API="https://monitor.logbirta.is/api_jsonrpc.php"
PSK_FILE="netvaktin.psk"
CONTAINER_PSK_FILE="/etc/zabbix/netvaktin.psk"
IMAGE_NAME="netvaktin-probe"
AUTO_BUILD_ON_INVALID="${NETVAKTIN_BUILD_IF_INVALID:-0}"
SKIP_REMOTE_PREFLIGHT="${NETVAKTIN_SKIP_REMOTE_PREFLIGHT:-0}"
DOCKER_CMD=()
DOCKER_PREFIX_DISPLAY="docker"
DOCTOR_MODE=0
PREFLIGHT_WARNINGS=()
PREFLIGHT_FAILURES=()
HOSTNAME=""
ROLE=""
HOSTNAME_PATTERN='^ProbeV5-[A-Z]{2}-[A-Za-z0-9._-]+$'

if [ "${1:-}" = "--doctor" ]; then
    DOCTOR_MODE=1
    shift
fi

record_warning() {
    PREFLIGHT_WARNINGS+=("$*")
    echo "⚠️  $*"
}

record_failure() {
    PREFLIGHT_FAILURES+=("$*")
    echo "❌ $*"
}

setup_docker_access() {
    if docker info >/dev/null 2>&1; then
        DOCKER_CMD=(docker)
        DOCKER_PREFIX_DISPLAY="docker"
        return 0
    fi

    if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null; then
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

resolve_hostname_and_role() {
    if [ -n "${1:-}" ]; then
        HOSTNAME="$1"
    elif [ "$DOCTOR_MODE" = "1" ]; then
        HOSTNAME=""
    else
        read -p "🖥️  Hostname (e.g., ProbeV5-IS-Hringdu): " HOSTNAME
    fi

    if [ "$DOCTOR_MODE" != "1" ] && [ -z "$HOSTNAME" ]; then
        echo "❌ Error: Hostname required."
        exit 1
    fi

    if [ -n "${2:-}" ]; then
        ROLE="$2"
    elif [ "$DOCTOR_MODE" = "1" ]; then
        ROLE="Domestic"
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

check_docker_environment() {
    local server_version operating_system architecture security_options docker_root_dir docker_bin docker_major

    server_version="$(run_docker info --format '{{.ServerVersion}}' 2>/dev/null || echo unknown)"
    operating_system="$(run_docker info --format '{{.OperatingSystem}}' 2>/dev/null || echo unknown)"
    architecture="$(run_docker info --format '{{.Architecture}}' 2>/dev/null || echo unknown)"
    docker_root_dir="$(run_docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo unknown)"
    security_options="$(run_docker info --format '{{json .SecurityOptions}}' 2>/dev/null || echo '[]')"
    docker_bin="$(command -v docker 2>/dev/null || echo docker)"

    echo "ℹ️  Docker access mode: $DOCKER_PREFIX_DISPLAY"
    echo "ℹ️  Docker binary: $docker_bin"
    echo "ℹ️  Docker server: $server_version | OS: $operating_system | Arch: $architecture"
    echo "ℹ️  Docker root dir: $docker_root_dir"

    docker_major="$(printf '%s' "$server_version" | awk -F. '{print $1}')"
    if [ -n "$docker_major" ] && [ "$docker_major" != "unknown" ] 2>/dev/null && [ "$docker_major" -lt 24 ] 2>/dev/null; then
        record_warning "Docker server version $server_version is older than the recommended baseline. Upgrade if networking or capability issues appear."
    fi

    if echo "$security_options" | grep -qi rootless; then
        record_warning "Docker appears rootless. Linux Docker Engine is recommended because the probe depends on host networking and NET_RAW."
    fi

    if printf '%s\n%s\n' "$docker_bin" "$docker_root_dir" | grep -qi '/snap/'; then
        record_warning "Docker appears to come from a snap-style install. Host networking and capabilities can behave differently across snap packaging."
    fi

    case "$operating_system" in
        *"Docker Desktop"*|*"Rancher Desktop"*|*"Colima"*|*"OrbStack"*)
            record_warning "Docker Desktop-like environments may not support host networking and NET_RAW the same way as Linux Docker Engine."
            ;;
    esac
}

check_disk_space() {
    local avail_kb
    avail_kb="$(df -Pk . | awk 'NR==2 {print $4}')"
    if [ -n "$avail_kb" ] && [ "$avail_kb" -lt 1048576 ] 2>/dev/null; then
        record_warning "Less than 1 GiB of free disk space is available in $(pwd). Local builds or container writes may fail."
    fi
}

check_existing_containers() {
    local existing
    existing="$(run_docker ps -a --format '{{.Names}}' 2>/dev/null | grep '^netvaktin' || true)"
    if [ -n "$existing" ]; then
        record_warning "Existing Netvaktin containers detected:"
        printf '%s\n' "$existing"
    fi
}

check_hostname_guidance() {
    if [ -z "$HOSTNAME" ]; then
        record_warning "No hostname supplied. Skipping hostname-format check in doctor mode."
        return 0
    fi

    if ! [[ "$HOSTNAME" =~ $HOSTNAME_PATTERN ]]; then
        record_warning "Hostname '$HOSTNAME' does not match the recommended format ProbeV5-<CC>-<ISP>."
    fi
}

check_local_psk_path() {
    if [ -d "$PSK_FILE" ]; then
        record_failure "Local PSK path '$PSK_FILE' is a directory. Remove it before deploying."
        return 1
    fi

    if [ -e "$PSK_FILE" ] && [ ! -r "$PSK_FILE" ]; then
        record_failure "Local PSK file '$PSK_FILE' exists but is not readable by this user."
        return 1
    fi

    if [ -f "$PSK_FILE" ] && [ ! -s "$PSK_FILE" ]; then
        record_failure "Local PSK file '$PSK_FILE' exists but is empty. Remove it before deploying so a new PSK can be generated."
        return 1
    fi

    if [ -f "$PSK_FILE" ]; then
        echo "ℹ️  Local PSK file present and will be reused: $PSK_FILE"
    else
        echo "ℹ️  Local PSK file not present. A new PSK will be generated during deploy: $PSK_FILE"
    fi

    return 0
}

check_local_psk_generation_dependency() {
    if [ -f "$PSK_FILE" ] && [ -s "$PSK_FILE" ]; then
        return 0
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        record_failure "openssl is required to generate a local PSK; install openssl or provide an existing $PSK_FILE file."
        return 1
    fi

    return 0
}

check_server_connectivity() {
    local dns_output tcp_output

    if [ "$SKIP_REMOTE_PREFLIGHT" = "1" ]; then
        record_warning "Skipping DNS/TCP preflight for $SERVER because NETVAKTIN_SKIP_REMOTE_PREFLIGHT=1."
        return 0
    fi

    dns_output="$(run_docker run --rm --net=host --entrypoint python3 "$IMAGE_NAME" -c '
import socket, sys
host = sys.argv[1]
try:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
except Exception as exc:
    print(f"error:{exc}")
    sys.exit(1)
seen = []
for item in infos:
    addr = item[4][0]
    if addr not in seen:
        seen.append(addr)
print(" ".join(seen))
' "$SERVER" 2>&1)"
    if [ $? -ne 0 ]; then
        record_failure "DNS resolution failed for $SERVER."
        echo "$dns_output"
        return 1
    fi

    echo "ℹ️  $SERVER resolves to: $dns_output"

    tcp_output="$(run_docker run --rm --net=host --entrypoint python3 "$IMAGE_NAME" -c '
import socket, sys
host = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=5):
        pass
except Exception as exc:
    print(f"error:{exc}")
    sys.exit(1)
print("connected")
' "$SERVER" "$PORT" 2>&1)"
    if [ $? -ne 0 ]; then
        record_failure "Outbound TCP connectivity test to $SERVER:$PORT failed."
        echo "$tcp_output"
        return 1
    fi

    echo "✅ Outbound TCP connectivity to $SERVER:$PORT succeeded."
    return 0
}

validate_probe_image() {
    if ! run_docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        if [ "$AUTO_BUILD_ON_INVALID" = "1" ]; then
            echo "⚠️  Local image '$IMAGE_NAME' not found. Building it now because NETVAKTIN_BUILD_IF_INVALID=1..."
            run_docker build --pull --no-cache -t "$IMAGE_NAME" . || return 1
        else
            record_failure "Local Docker image '$IMAGE_NAME' is missing."
            print_image_refresh_help
            return 1
        fi
    fi

    if run_docker run --rm --entrypoint sh "$IMAGE_NAME" -c \
        "test -x /usr/bin/entrypoint.sh && \
         grep -q 'ZBX_TLSPSKVALUE' /usr/bin/entrypoint.sh && \
         grep -q 'TLSPSKFile' /usr/bin/entrypoint.sh && \
         grep -q 'TLS PSK file ready' /usr/bin/entrypoint.sh"; then
        echo "✅ Image preflight passed: '$IMAGE_NAME' contains PSK bootstrap support."
        return 0
    fi

    if [ "$AUTO_BUILD_ON_INVALID" = "1" ]; then
        echo "⚠️  Local image '$IMAGE_NAME' is stale. Rebuilding it now because NETVAKTIN_BUILD_IF_INVALID=1..."
        run_docker build --pull --no-cache -t "$IMAGE_NAME" . || return 1
        if run_docker run --rm --entrypoint sh "$IMAGE_NAME" -c \
            "test -x /usr/bin/entrypoint.sh && \
             grep -q 'ZBX_TLSPSKVALUE' /usr/bin/entrypoint.sh && \
             grep -q 'TLSPSKFile' /usr/bin/entrypoint.sh && \
             grep -q 'TLS PSK file ready' /usr/bin/entrypoint.sh"; then
            echo "✅ Image preflight passed after local rebuild."
            return 0
        fi
        record_failure "Local Docker image '$IMAGE_NAME' is still stale after local rebuild."
        print_image_refresh_help
        return 1
    fi

    record_failure "Local Docker image '$IMAGE_NAME' is stale."
    print_image_refresh_help
    return 1
}

run_runtime_preflight() {
    local runtime_output runtime_status

    runtime_output="$(
        run_docker run --rm --net=host --cap-add NET_RAW --entrypoint sh "$IMAGE_NAME" -c '
            set -eu

            entrypoint_path=/usr/bin/entrypoint.sh
            scamper_path=/usr/local/bin/scamper
            zabbix_agent2_path=/usr/sbin/zabbix_agent2
            mtr_path="$(command -v mtr 2>/dev/null || true)"
            mtr_packet_path="$(command -v mtr-packet 2>/dev/null || true)"

            test -x "$entrypoint_path"
            test -x "$scamper_path"
            test -x "$zabbix_agent2_path"

            if [ -z "$mtr_path" ]; then
                if [ -x /usr/sbin/mtr ]; then
                    mtr_path=/usr/sbin/mtr
                else
                    echo "missing:mtr"
                    exit 21
                fi
            fi

            if ! command -v getcap >/dev/null 2>&1; then
                echo "missing:getcap"
                exit 22
            fi

            scamper_cap="$(getcap "$scamper_path" 2>/dev/null || true)"
            echo "entrypoint:$entrypoint_path"
            echo "scamper:$scamper_path"
            echo "mtr:$mtr_path"
            echo "zabbix_agent2:$zabbix_agent2_path"
            echo "scamper_cap:${scamper_cap:-missing}"
            echo "$scamper_cap" | grep -q "cap_net_raw"

            if [ -n "$mtr_packet_path" ]; then
                mtr_packet_cap="$(getcap "$mtr_packet_path" 2>/dev/null || true)"
                echo "mtr_packet:$mtr_packet_path"
                echo "mtr_packet_cap:${mtr_packet_cap:-missing}"
                echo "$mtr_packet_cap" | grep -q "cap_net_raw"
            else
                echo "mtr_packet:(not present)"
            fi
        ' 2>&1
    )"
    runtime_status=$?

    if [ $runtime_status -ne 0 ]; then
        if echo "$runtime_output" | grep -qi "exec format error"; then
            record_failure "Selected image '$IMAGE_NAME' cannot run on this host architecture. Pull a current multi-arch image or build locally on this machine."
        else
            record_failure "Docker runtime preflight failed for '$IMAGE_NAME' with --net=host --cap-add NET_RAW."
            echo "   Linux Docker Engine is recommended for this probe."
        fi
        if [ -n "$runtime_output" ]; then
            echo "$runtime_output"
        fi
        return 1
    fi

    echo "✅ Runtime preflight passed: host networking, NET_RAW, and probe tools are available."
    if [ "$DOCTOR_MODE" = "1" ] && [ -n "$runtime_output" ]; then
        echo "$runtime_output"
    fi
    return 0
}

run_all_preflights() {
    check_docker_environment
    check_disk_space
    check_existing_containers
    check_hostname_guidance

    if ! check_local_psk_path; then
        return 1
    fi

    if ! check_local_psk_generation_dependency; then
        return 1
    fi

    if ! validate_probe_image; then
        return 1
    fi

    if ! run_runtime_preflight; then
        return 1
    fi

    if ! check_server_connectivity; then
        return 1
    fi

    return 0
}

print_doctor_summary() {
    local warning_count failure_count
    warning_count="${#PREFLIGHT_WARNINGS[@]}"
    failure_count="${#PREFLIGHT_FAILURES[@]}"

    if [ "$failure_count" -eq 0 ]; then
        echo "✅ Doctor summary: all preflight checks passed."
        if [ "$warning_count" -gt 0 ]; then
            echo "⚠️  Doctor summary: $warning_count warning(s) noted."
        fi
        return 0
    fi

    echo "❌ Doctor summary: $failure_count failure(s), $warning_count warning(s)."
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

resolve_hostname_and_role "${1:-}" "${2:-}"

if [ "$DOCTOR_MODE" = "1" ]; then
    echo "🩺 Running deploy doctor checks..."
fi

if ! run_all_preflights; then
    if [ "$DOCTOR_MODE" = "1" ]; then
        print_doctor_summary
    fi
    exit 1
fi

if [ "$DOCTOR_MODE" = "1" ]; then
    print_doctor_summary
    exit 0
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
