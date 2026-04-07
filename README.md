# Netvaktin Community Probe — V5

**Network monitoring probe for the [Netvaktin](https://netvaktin.is) project.**

Runs a Zabbix Agent 2 (active mode) container that performs route measurements to national endpoints. Uses `scamper` Paris-traceroutes as primary engine with automatic fallback to `mtr`. Designed to work behind residential routers with no port forwarding required.

- **Auto-registration:** Registers itself in Zabbix via API on first boot, including PSK key exchange.
- **Self-healing:** Detects and updates its own public IP in Zabbix on every restart.
- **No inbound ports needed:** Active (push) mode only.
- **Multi-arch:** Supports AMD64 and ARM64 (Raspberry Pi, NAS).

---

## Quick Start — Production Probe

### 1. Get the code

```bash
git clone https://github.com/hoddiv/netvaktin-probe.git netvaktin-probe-v5
cd netvaktin-probe-v5
```

### 2. Get the image

**Option A — Pull from registry (recommended):**
```bash
docker pull ghcr.io/hoddiv/netvaktin-probe:latest
docker tag ghcr.io/hoddiv/netvaktin-probe:latest netvaktin-probe
```

**Option B — Build locally** (if you prefer or are on an unusual architecture):
```bash
sudo docker build -t netvaktin-probe .
```

### 3. Deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

Enter a hostname using the `ProbeV5-<Country>-<ISP>` convention (e.g. `ProbeV5-IS-Hringdu`) and your API token when prompted. Select role:
- `1` Domestic — outbound monitoring from your ISP
- `2` External — inbound monitoring (for external/foreign locations)

---

## Dev Probe Deployment

For deploying to the dev environment (registers into `Netvaktin Dev Probes`, never touches production):

```bash
chmod +x deploy_dev.sh
./deploy_dev.sh DEV-ProbeV5-IS-Hringdu          # domestic
./deploy_dev.sh DEV-ProbeV5-FI-Hetzner ext      # external/inbound
```

Hostname convention for dev: `DEV-ProbeV5-<Country>-<ISP>`

---

## Naming Convention

| Phase | Format | Example |
|-------|--------|---------|
| Dev testing | `DEV-ProbeV5-<CC>-<ISP>` | `DEV-ProbeV5-IS-Hringdu` |
| Production | `ProbeV5-<CC>-<ISP>` | `ProbeV5-IS-Hringdu` |

`ProbeV5` is kept permanently — V4 and V5 probes use different Zabbix item schemas so history is never continuous between generations. Keeping the suffix makes the generation unambiguous in Zabbix at all times.

On promotion from dev to prod: reconfigure the container hostname (strip `DEV-`), change role to `Domestic`/`External`, and move the host to the prod Zabbix group.

---

## How It Works

- **Engine:** `route_check_v5.py` is the universal runner. Scamper gets the first slice of the time budget; MTR gets the fallback window if Scamper fails or is blocked.
- **Schema:** Both engines emit the same structured V5 JSON payload including `probe_engine`, `was_fallback`, `runner_errors`, and `engine_attempts`.
- **Budget:** Hard 30-second wall-clock limit (`NETVAKTIN_TRACE_BUDGET_MS=27000` by default).
- **Hashing:** Route fingerprinting is done server-side — the probe only emits normalized measurement data.

### Debug overrides

```bash
# Force a specific engine
-e NETVAKTIN_FORCE_ENGINE=scamper
-e NETVAKTIN_FORCE_ENGINE=mtr

# Adjust budget
-e NETVAKTIN_TRACE_BUDGET_MS=20000
-e NETVAKTIN_TRACE_FALLBACK_RESERVE_MS=5000
```

---

## Debugging

```bash
# View startup and registration logs
sudo docker logs netvaktin-ProbeV5-IS-Hringdu

# Check running containers
sudo docker ps | grep netvaktin

# Verify Zabbix registration
# Look for "[Auto-Register] REGISTRATION SUCCESSFUL" or "Host exists. Syncing PSK and IP"
```
