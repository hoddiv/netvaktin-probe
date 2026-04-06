# Netvaktin Community Probe v2

**Network monitoring probe for the Netvaktin project.**

### Overview
Runs a **Zabbix Agent 2** (Active Mode) container that performs deadline-aware route measurements to national endpoints. The probe now prefers precise `scamper` Paris-traceroutes (TCP/UDP/ICMP) and automatically falls back to `mtr` when Scamper is unavailable, blocked, or too slow for the remaining budget. It is designed to work behind residential routers seamlessly.

* **Auto-Registration:** Registers itself via Zabbix API on boot.
* **Encryption:** Generates its own TLS-PSK keys automatically.
* **No Port Forwarding:** Uses active (push) checks only. No inbound firewall rules needed.

### Architecture
* **Base:** `zabbix/zabbix-agent2:alpine-7.0`
* **Scripts:** `route_check_v5.py` is now the universal runner. It enforces a hard time budget, tries Scamper first, falls back to MTR, and emits one normalized V5 JSON payload regardless of engine. Legacy `route_check.sh` is preserved for manual compatibility and emergency rollback.
* **Security:**
    * Traffic encrypted via TLS-PSK.
    * Binary capabilities `cap_net_raw+ep` are applied to the `scamper` binary directly during build for raw socket access.


### Universal Runner Behavior
* **Hard time budget:** The V5 runner stays under the Zabbix agent's 30-second wall by default (`NETVAKTIN_TRACE_BUDGET_MS=27000`).
* **Smart fallback:** Scamper gets the first slice of the budget, and MTR gets the reserved fallback window.
* **Single schema:** Both engines emit the same structured V5 payload shape, including `probe_engine`, `was_fallback`, and `runner_errors` metadata.
* **Debug override:** Set `NETVAKTIN_FORCE_ENGINE=scamper` or `NETVAKTIN_FORCE_ENGINE=mtr` to force one engine during testing.

### Installation

**Requirements:** Docker, Internet access.

1.  **Get the code**
    ```bash
    git clone https://github.com/hoddiv/netvaktin-probe.git
    cd netvaktin-probe
    ```

2.  **Build image**
    (Builds locally to support both AMD64 and ARM64/Pi).
    ```bash
    sudo docker build -t netvaktin-probe .
    ```

3.  **Deploy**
    Run the wrapper script to generate keys and start the container.
    ```bash
    chmod +x deploy.sh
    ./deploy.sh
    ```
    *Enter a unique hostname (e.g., `Probe-Garage`) and your API Token when prompted.*

### Debugging
```bash
# View startup logs
sudo docker logs netvaktin-Probe-Name

# Check status
sudo docker ps
```
