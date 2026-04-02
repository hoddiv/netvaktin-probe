# Netvaktin Community Probe v2

**Network monitoring probe for the Netvaktin project.**

### Overview
Runs a **Zabbix Agent 2** (Active Mode) container that performs precise `scamper` Paris-traceroutes (TCP/UDP/ICMP) to national endpoints. It is designed to work behind residential routers seamlessly.

* **Auto-Registration:** Registers itself via Zabbix API on boot.
* **Encryption:** Generates its own TLS-PSK keys automatically.
* **No Port Forwarding:** Uses active (push) checks only. No inbound firewall rules needed.

### Architecture
* **Base:** `zabbix/zabbix-agent2:alpine-7.0`
* **Scripts:** `route_check_v5.py` performs scamper execution and trace parsing. Legacy `route_check.sh` is preserved for raw MTR fallback logic.
* **Security:**
    * Traffic encrypted via TLS-PSK.
    * Binary capabilities `cap_net_raw+ep` are applied to the `scamper` binary directly during build for raw socket access.

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
