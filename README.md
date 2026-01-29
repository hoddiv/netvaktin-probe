# Netvaktin Community Probe

Distributed network latency & path analyzer for the **Netvaktin** project.

## Overview
This container runs a lightweight Zabbix Agent that performs `mtr` (traceroute) checks against defined national endpoints. It uses heuristic fingerprinting to identify upstream carriers (e.g., Level3, Arelion, Cogent) and detects route deviations in real-time.

## Architecture
* **Base:** `zabbix/zabbix-agent2:alpine-7.0`
* **Logic:** Bash-based path analysis (`route_check.sh`)
* **Security:** * No incoming ports opened.
    * TLS-PSK encryption for all metric uploads.
    * Runs in unprivileged mode (privileged capability only required for `mtr` raw sockets).

## Usage (Volunteer)
If you have been issued a PSK, run the following:

```bash
docker run -d --name netvaktin-probe \
  --restart unless-stopped \
  --privileged \
  --net=host \
  -e ZBX_SERVER_HOST=monitor.logbirta.is \
  -e ZBX_TLSPSKIDENTITY=CommunityProbe \
  -e ZBX_TLSPSKFILE=/etc/zabbix/key.psk \
  -v $(pwd)/key.psk:/etc/zabbix/key.psk \
  ghcr.io/YOUR_GITHUB_USER/netvaktin-probe:latest


