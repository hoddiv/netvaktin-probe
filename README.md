# Netvaktin Community Probe v2

**Network monitoring probe for the Netvaktin project.**

### Overview
Runs a **Zabbix Agent 2** (Active Mode) container that performs `mtr` traceroutes to national endpoints. It is designed to work behind residential routers without configuration.

* **Auto-Registration:** Registers itself via Zabbix API on boot.
* **Encryption:** Generates its own TLS-PSK keys automatically.
* **No Port Forwarding:** Uses active (push) checks only. No inbound firewall rules needed.

### Architecture
* **Base:** `zabbix/zabbix-agent2:alpine-7.0`
* **Scripts:** Python (`exporter.py`) handles registration and MTR parsing.
* **Security:**
    * Traffic encrypted via TLS-PSK.
    * Container requires `--privileged` flag solely for `mtr` raw socket access.

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
