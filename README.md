# Netvaktin Community Probe v2

**Distributed network latency & path analyzer for the Netvaktin project.**

### Overview
This container runs a specialized **Zabbix Agent 2** in "Active Mode" to perform deep-packet path analysis (`mtr`) against defined national endpoints. Unlike standard agents, this probe is **autonomous**:
* **Auto-Registration:** Automatically registers itself with the central server using the Zabbix API.
* **Self-Provisioning:** Generates its own TLS-PSK encryption keys on first launch.
* **NAT-Piercing:** Uses a "Push-Only" architecture, requiring **zero inbound firewall ports** or router configuration.

### Architecture
* **Base:** `zabbix/zabbix-agent2:alpine-7.0` (Modified)
* **Logic:** Python-based Auto-Registrar & Path Analyzer (`exporter.py` / `arris_stats.py`)
* **Security:**
    * Strict TLS-PSK Encryption for all data transport.
    * No incoming ports opened (Active Agent).
    * Runs in privileged mode (required *only* for raw socket access by `mtr`).

### Deployment (Volunteer)

**Prerequisites:** Docker and Internet access.

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/YOUR_USER/netvaktin-probe.git
    cd netvaktin-probe
    ```

2.  **Build the Image**
    *We build locally to ensure compatibility with your CPU architecture (AMD64/ARM64).*
    ```bash
    sudo docker build -t netvaktin-probe .
    ```

3.  **Run the Installer**
    This script handles key generation and container startup automatically.
    ```bash
    chmod +x deploy.sh
    ./deploy.sh
    ```
    *You will be prompted to enter a unique name (e.g., `Probe-Garage`) and the API Token.*

### Manual Debugging
To check the status of your probe:
```bash
# Check logs
sudo docker logs netvaktin-Probe-Name

# Verify container is running
sudo docker ps
```
