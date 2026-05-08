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

### 2. Run doctor mode first

```bash
chmod +x deploy.sh
./deploy.sh --doctor ProbeV5-IS-Nova
```

### 3. Deploy

```bash
./deploy.sh ProbeV5-IS-Nova
```

Then enter the API token when prompted.

The normal production hostname format is `ProbeV5-<CC>-<ISP>`, for example:
- `ProbeV5-IS-Nova`
- `ProbeV5-IS-Hringdu`

Most Icelandic public participants should omit the role and use the default `Domestic` mode. Only use `External` if you were explicitly asked to.

### 4. If it fails

```bash
./deploy.sh --support ProbeV5-IS-Nova
```

Send the `--support` output back. Do not resend the API token.

---

## Dev Probe Deployment

For deploying to the dev environment (registers into `Netvaktin Dev Probes`, never touches production):

```bash
chmod +x deploy_dev.sh
./deploy_dev.sh DEV-ProbeV5-IS-Hringdu          # domestic
./deploy_dev.sh DEV-ProbeV5-FI-Hetzner ext      # external/inbound
```

Hostname convention for dev: `DEV-ProbeV5-<CC>-<ISP>`

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

## Troubleshooting

Linux Docker Engine on a normal Linux host is the recommended environment for this probe. Rootless Docker, Docker Desktop, and Docker Desktop-like environments may not support host networking and `NET_RAW` the same way as Linux Docker Engine.

### Run doctor mode first

```bash
./deploy.sh --doctor ProbeV5-IS-Example
./deploy_dev.sh --doctor
```

If doctor mode fails, send back:
- the full doctor output
- whether you normally use `docker` or `sudo docker`
- the output of `docker version` or `sudo docker version`

If doctor mode passes but deployment later fails after you enter the API token, do not resend the token. Send back the last 80 lines of container logs instead, because template/group/API-permission errors appear there.

Doctor mode uses the probe image itself for Docker runtime and connectivity checks. `openssl` is only required when the script needs to generate a new local PSK file.

### Useful helper commands

```bash
./deploy.sh --status ProbeV5-IS-Example
./deploy.sh --logs ProbeV5-IS-Example
./deploy.sh --support ProbeV5-IS-Example
```

### What to send if it fails

```bash
./deploy.sh --support ProbeV5-IS-Example
docker ps -a | grep netvaktin
docker logs netvaktin-<hostname> --tail 80
uname -a
docker version
```

### `invalid TLSPSKFile configuration parameter: open /etc/zabbix/netvaktin.psk: no such file or directory`

This means the container image being run does not contain the current entrypoint logic that writes `/etc/zabbix/netvaktin.psk` from `ZBX_TLSPSKVALUE`, or that PSK file creation failed before `zabbix_agent2` started.

By default `deploy.sh` uses `ghcr.io/hoddiv/netvaktin-probe:latest` and pulls it automatically. If you disabled pulling with `NETVAKTIN_NO_PULL=1`, rerun without that override first:

```bash
./deploy.sh ProbeV5-IS-Nova
```

If you prefer a local developer build instead:

```bash
docker build --pull --no-cache -t netvaktin-probe:local .
NETVAKTIN_IMAGE=netvaktin-probe:local ./deploy.sh ProbeV5-IS-Nova
```

If you want the deploy scripts to rebuild automatically when they detect a missing or stale local image, opt in explicitly:

```bash
NETVAKTIN_IMAGE=netvaktin-probe:local NETVAKTIN_BUILD_IF_INVALID=1 ./deploy.sh ProbeV5-IS-Nova
NETVAKTIN_BUILD_IF_INVALID=1 ./deploy_dev.sh DEV-ProbeV5-IS-Hringdu
```

When the container is current, startup logs should show both of these lines before `Starting Zabbix Agent 2...`:

```text
PSK written from environment to /etc/zabbix/netvaktin.psk.
TLS PSK file ready at /etc/zabbix/netvaktin.psk.
```

If you want to inspect the local image directly before redeploying, this doctor command should print the PSK bootstrap markers from the image entrypoint:

```bash
docker run --rm --entrypoint sh ghcr.io/hoddiv/netvaktin-probe:latest -c "grep -n 'ZBX_TLSPSKVALUE\\|TLSPSKFile\\|TLS PSK file ready' /usr/bin/entrypoint.sh"
```

## Release Notes

The GitHub Container Registry image `ghcr.io/hoddiv/netvaktin-probe:latest` is intended to be published from `main`. If you are testing unpublished local changes, build locally and set `NETVAKTIN_IMAGE=netvaktin-probe:local`.

After publishing `latest`, verify that an anonymous pull works:

```bash
docker pull ghcr.io/hoddiv/netvaktin-probe:latest
```

IPv6 probing is intentionally out of scope for this V5 community probe rollout. If added later, it should ship as a separate, explicitly labeled measurement family rather than being mixed into the current IPv4-oriented route set.
