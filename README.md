# Netvaktin Probe

**Network monitoring probe for the [Netvaktin](https://netvaktin.is) project.**

A probe is a small container, run by a volunteer or operator, that performs network
measurements and reports the results to Netvaktin's Zabbix collector(s). It runs Zabbix
Agent 2 in active (push) mode plus a custom measurement script — it does not run any
Netvaktin server-side logic itself.

---

## What the probe measures

- **Route/latency measurements:** `route_check_v5.py` runs Paris-traceroute measurements via
  `scamper` (primary engine), with automatic fallback to `mtr` if scamper fails or is
  blocked. Both engines emit the same structured JSON payload (`probe_engine`,
  `was_fallback`, `runner_errors`, `engine_attempts`, hop-level results) under a hard
  wall-clock time budget (27 seconds by default).
- **Service reachability checks:** standard Zabbix Agent 2 TCP checks (e.g.
  `net.tcp.service`, `net.tcp.service.perf`) against endpoints defined by the Zabbix item
  configuration assigned to the host.
- Exactly which targets and check types run against this probe is controlled by the Zabbix
  templates assigned to its host record on the server side, not by anything in this
  repository — the repo only implements the measurement engine and the agent bootstrap.

## What the probe does not do

- Does not inspect, capture, or proxy user traffic — it only originates its own outbound
  measurement probes (traceroutes, TCP connection checks).
- Does not scan or monitor other devices on the local network.
- Does not require any inbound ports to be opened or forwarded. It only makes outbound
  connections to its configured Zabbix server(s); nothing needs to reach it from the
  internet for it to function.
- Does not provide shell access, a management API, or any remote-control surface to
  Netvaktin operators or anyone else.
- Does not execute arbitrary commands from the network. The measurement script only runs
  with a fixed, bounded set of parameters (target, method, probe count, timing) supplied
  through the Zabbix item configuration on the server — it does not accept commands from
  arbitrary network input.

## Data sent

- Measurement results (route hops, latency, reachability) for the targets configured on the
  Zabbix server side.
- Hostname and role/group metadata used to classify the probe in Zabbix (as set via
  `ZBX_HOSTNAME` / `NETVAKTIN_ROLE`).
- On first boot, if an API token is supplied, the probe registers itself via the Zabbix API:
  this includes its detected public IP address and a PSK identity/key used to authenticate
  future connections. No PSK value is ever printed to logs or written anywhere other than
  the local PSK file and the one-time API registration call.
- Nothing else. No packet captures, no file contents, no other host's traffic.

---

## Requirements

- A Linux host with Docker (Linux Docker Engine is recommended — see
  [Troubleshooting](#troubleshooting) for why).
- Outbound network access from the probe host.
- Network reachability from the probe host to every configured active Zabbix endpoint (see
  [Multiple active Zabbix servers](#multiple-active-zabbix-servers)).
- A PSK file, provisioned separately from this repository (generated locally by `deploy.sh`
  on first run, or provided by the Netvaktin operator) — never commit a PSK file or its
  value anywhere.
- The `NET_RAW` Linux capability, used by `scamper`/`mtr` to send raw ICMP/UDP probes for
  traceroute measurements. `deploy.sh`/`deploy_dev.sh` add this automatically
  (`--cap-add NET_RAW`).

---

## Configuration

Real, supported environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `ZBX_HOSTNAME` | This probe's identity in Zabbix. Must match a host record on every configured server. | none — required |
| `NETVAKTIN_ROLE` | `Domestic`, `External`, `Dev`, or `DevExt` — selects the Zabbix host group/template pairing. | `Domestic` |
| `NETVAKTIN_ZABBIX_ACTIVE_SERVERS` | Deploy-script-level: comma-separated active Zabbix servers. See below. | `monitor.logbirta.is:10051,monitor.netvaktin.is:10051` |
| `ZBX_SERVER_ACTIVE` | Container-level equivalent — set directly to the full `ServerActive` value. No default; if unset, falls back to `ZBX_SERVER_HOST`/`ZBX_SERVER_PORT`. | unset |
| `ZBX_SERVER_HOST` / `ZBX_SERVER_PORT` | Single-server fallback used only when `ZBX_SERVER_ACTIVE` is unset. | `monitor.logbirta.is` / `10051` |
| `ZBX_TLSPSKIDENTITY` | PSK identity string, paired with the PSK file. | derived from hostname by `deploy.sh` |
| `ZBX_TLSPSKFILE` | Path to the PSK file inside the container. | `/etc/zabbix/netvaktin.psk` |
| `ZBX_TLSPSKVALUE` | PSK value written to `ZBX_TLSPSKFILE` on startup, if set. Never log or commit this. | unset (existing PSK file is reused) |
| `ZBX_API_URL` / `ZBX_API_TOKEN` | Used only for one-time self-registration with the Zabbix API. | unset — registration skipped if absent |

`deploy.sh` and `deploy_dev.sh` set sensible values for all of these automatically; most
volunteers never need to set environment variables directly.

---

## Multiple active Zabbix servers

A probe can report the same measurement data to one or more independent Zabbix servers. The
probe generates a normal Zabbix `ServerActive` value — a comma-separated list of `host:port`
endpoints — from a single configuration variable.

**Default Netvaktin deployment** (`./deploy.sh`/`./deploy_dev.sh` enable this automatically,
no extra flags needed):

```bash
NETVAKTIN_ZABBIX_ACTIVE_SERVERS="monitor.logbirta.is:10051,monitor.netvaktin.is:10051"
```

generates:

```text
ServerActive=monitor.logbirta.is:10051,monitor.netvaktin.is:10051
```

**Primary-only override** (useful for testing, bootstrap, rollback, or special
deployments):

```bash
NETVAKTIN_ZABBIX_ACTIVE_SERVERS="monitor.logbirta.is:10051" ./deploy.sh ProbeV5-IS-Nova
```

generates:

```text
ServerActive=monitor.logbirta.is:10051
```

**Future multi-server expansion** works the same way — just add more entries:

```bash
NETVAKTIN_ZABBIX_ACTIVE_SERVERS="monitor.logbirta.is:10051,monitor.netvaktin.is:10051,third.example.net:10051" ./deploy.sh ProbeV5-IS-Nova
```

Notes:

- **Every configured endpoint must resolve and be reachable from the probe host** on its
  configured port. Routing, firewalling, DNS, and exposure of those endpoints are
  deployment-specific and managed entirely outside the probe container — this software has
  no opinion on transport.
- An unreachable endpoint is retried by Zabbix Agent 2 on its own (each entry in the list is
  maintained independently) and does not block, delay, or degrade delivery to the other,
  reachable endpoints.
- Every Zabbix server that receives data from a given probe must already have a matching
  host entry for that probe's `Hostname`, with the same PSK identity/key and a compatible
  item/template configuration. This setting only controls how many servers the probe
  *sends* to — it does not provision the receiving side.
- The underlying container-level variable is `ZBX_SERVER_ACTIVE`; set it directly if running
  the container without `deploy.sh`/`deploy_dev.sh`. Leaving it unset/empty falls back to the
  original single-server config built from `ZBX_SERVER_HOST`/`ZBX_SERVER_PORT`.

---

## Deploy

```bash
git clone https://github.com/hoddiv/netvaktin-probe.git netvaktin-probe-v5
cd netvaktin-probe-v5
chmod +x deploy.sh
./deploy.sh --doctor ProbeV5-IS-Nova
./deploy.sh ProbeV5-IS-Nova
```

Enter the API token when prompted (provided separately by the Netvaktin operator — see
[docs/VOLUNTEER_PROBE_SETUP.md](docs/VOLUNTEER_PROBE_SETUP.md) for the full volunteer flow).

The normal production hostname format is `ProbeV5-<CC>-<ISP>`, for example `ProbeV5-IS-Nova`
or `ProbeV5-IS-Hringdu`. Most participants should omit the role and use the default
`Domestic` mode; only use `External` if explicitly asked to.

**What `deploy.sh` does:** pulls/validates the probe image, generates or reuses a local PSK
file, registers the probe with the Zabbix API if a token is supplied, and starts the
container with the active Zabbix server list, PSK, and role baked in as environment
variables.

**What it does not do:** it does not touch any other container on the host, does not modify
firewall/network configuration, and does not require or request access to anything outside
the probe's own container and PSK file.

For dev-environment deployment (registers into a separate dev group, never touches
production):

```bash
chmod +x deploy_dev.sh
./deploy_dev.sh DEV-ProbeV5-IS-Hringdu          # domestic
./deploy_dev.sh DEV-ProbeV5-FI-Provider01 ext   # external/inbound
```

### Naming convention

| Phase | Format | Example |
|-------|--------|---------|
| Dev testing | `DEV-ProbeV5-<CC>-<ISP>` | `DEV-ProbeV5-IS-Hringdu` |
| Production | `ProbeV5-<CC>-<ISP>` | `ProbeV5-IS-Hringdu` |

`ProbeV5` is kept permanently — different probe generations use different Zabbix item
schemas, so history is never continuous across generations; keeping the suffix makes the
generation unambiguous in Zabbix at all times.

---

## Update

```bash
cd netvaktin-probe-v5
git pull --ff-only
./deploy.sh --doctor ProbeV5-IS-Nova
./deploy.sh ProbeV5-IS-Nova
```

This pulls the latest published image, recreates the container, and reuses the existing
local PSK file (it is never regenerated or discarded on update). After updating, verify:

```bash
./deploy.sh --status ProbeV5-IS-Nova
./deploy.sh --logs ProbeV5-IS-Nova
```

and confirm fresh measurement data is arriving in Zabbix for this host.

---

## Rollback

If an update causes problems:

```bash
NETVAKTIN_IMAGE=ghcr.io/hoddiv/netvaktin-probe:<previous-tag-or-sha> ./deploy.sh ProbeV5-IS-Nova
```

using a previously known-good tag or `sha-<digest>` tag from the container registry. The PSK
file and hostname are unaffected by this — only the image changes.

To fall back to primary-only reporting without changing anything else (e.g. while
diagnosing a problem with one of the additional endpoints):

```bash
NETVAKTIN_ZABBIX_ACTIVE_SERVERS="monitor.logbirta.is:10051" ./deploy.sh ProbeV5-IS-Nova
```

---

## Debug overrides

```bash
# Force a specific measurement engine
-e NETVAKTIN_FORCE_ENGINE=scamper
-e NETVAKTIN_FORCE_ENGINE=mtr

# Adjust the measurement time budget
-e NETVAKTIN_TRACE_BUDGET_MS=20000
-e NETVAKTIN_TRACE_FALLBACK_RESERVE_MS=5000
```

---

## Troubleshooting

Linux Docker Engine on a normal Linux host is the recommended environment for this probe.
Rootless Docker, Docker Desktop, and Docker Desktop-like environments may not support host
networking and `NET_RAW` the same way as Linux Docker Engine.

### Run doctor mode first

```bash
./deploy.sh --doctor ProbeV5-IS-Example
./deploy_dev.sh --doctor
```

If doctor mode fails, send back the full doctor output, whether you normally use `docker` or
`sudo docker`, and the output of `docker version`.

If doctor mode passes but deployment later fails after you enter the API token, do not
resend the token. Send back the last 80 lines of container logs instead.

### DNS resolution failure for a configured Zabbix endpoint

Confirm the hostname resolves from the probe host:

```bash
getent hosts monitor.netvaktin.is
```

If it doesn't resolve, that endpoint will simply stay unreachable — this does not stop the
probe from reporting to any other configured endpoint that does resolve.

### One of several active servers is unreachable

This is expected to be non-fatal. Zabbix Agent 2 retries each configured server
independently; check container logs for a `cannot connect to [...]` message naming the
specific unreachable endpoint, and confirm other endpoints are still receiving data before
treating it as a real problem.

### PSK mismatch

If logs show a TLS/PSK authentication error, the PSK identity/key the probe is using does
not match what a given Zabbix server has on file for this hostname. This is provisioned
out of band — contact the operator of that Zabbix server rather than editing the PSK file
yourself.

### Hostname mismatch

If a probe's `ZBX_HOSTNAME` doesn't exactly match an existing host record on a given Zabbix
server, that server will not accept active-check data from it. Use one canonical hostname
per physical probe.

### Container unhealthy

The healthcheck only confirms the measurement script is present in the image — it does not
run a live measurement. An unhealthy container usually means the container failed to start
correctly; check `docker logs` for the actual startup error.

### Missing `NET_RAW` / permission issues

If traceroute measurements fail but TCP checks still work, the container may be missing the
`NET_RAW` capability. `deploy.sh`/`deploy_dev.sh` add this automatically; if running the
container manually, add `--cap-add NET_RAW`.

### `invalid TLSPSKFile configuration parameter: ... no such file or directory`

This means the running image predates the entrypoint logic that writes the PSK file from
`ZBX_TLSPSKVALUE`. Re-run `./deploy.sh ProbeV5-IS-Nova` to pull the current image, or build
locally:

```bash
docker build --pull --no-cache -t netvaktin-probe:local .
NETVAKTIN_IMAGE=netvaktin-probe:local ./deploy.sh ProbeV5-IS-Nova
```

When the image is current, startup logs show both of these lines before
`Starting Zabbix Agent 2...`:

```text
PSK written from environment to /etc/zabbix/netvaktin.psk.
TLS PSK file ready at /etc/zabbix/netvaktin.psk.
```

### Clean reinstall for legacy leftovers

See [docs/VOLUNTEER_PROBE_SETUP.md](docs/VOLUNTEER_PROBE_SETUP.md) — use this only if asked
to by the operator, or if normal deploy keeps failing.

### Support bundle

```bash
./deploy.sh --support ProbeV5-IS-Example
```

Send the full output to the Netvaktin operator. Do not resend an API token or PSK value if
asked for logs.

---

## Security notes

- **PSK handling:** the PSK file is provisioned out of band (generated locally on first
  deploy, or supplied by the operator) — never commit a `.psk` file, an `.env` file, or any
  PSK/token value to this repository. `.gitignore` excludes `*.psk`, `.env`, `*.key`, and
  `*.pem` by default.
- **Outbound-only:** the probe only makes outbound connections to its configured Zabbix
  server(s) and, during one-time self-registration, to the Zabbix API and a public-IP lookup
  service. It does not listen for or accept inbound connections.
- **Least privilege:** the container requests only the `NET_RAW` capability needed for raw
  ICMP/UDP traceroute probes — no other elevated privileges are required.
- **Reporting issues:** if you find a security issue in this repository, contact the
  Netvaktin operator directly rather than filing a public issue with sensitive details.

---

## Release notes

The GitHub Container Registry image `ghcr.io/hoddiv/netvaktin-probe:latest` is published
from `main`. If testing unpublished local changes, build locally and set
`NETVAKTIN_IMAGE=netvaktin-probe:local`:

```bash
docker build --pull --no-cache -t netvaktin-probe:local .
NETVAKTIN_IMAGE=netvaktin-probe:local ./deploy.sh ProbeV5-IS-Nova
```

If you want the deploy scripts to rebuild automatically when they detect a missing or stale
local image, opt in explicitly:

```bash
NETVAKTIN_IMAGE=netvaktin-probe:local NETVAKTIN_BUILD_IF_INVALID=1 ./deploy.sh ProbeV5-IS-Nova
```

IPv6 probing is intentionally out of scope for this probe rollout. If added later, it should
ship as a separate, explicitly labeled measurement family rather than being mixed into the
current IPv4-oriented route set.
