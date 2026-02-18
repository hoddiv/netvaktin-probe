# Netvaktin Community Probe v3.0

This is the community probe for **[Netvaktin.is](https://netvaktin.is)**.

It is a lightweight Docker container that helps map how Iceland connects to the rest of the world. By running this on your home connection, company network, or VPS, you help us detect if traffic is being routed via **Farice-1** (UK), **Danice** (Denmark), or **Iris** (Ireland).

### What it does
1.  **Starts up:** Checks internet connectivity and downloads the latest route signatures from this repo.
2.  **Registers:** Auto-registers with the Netvaktin central server using an API token.
3.  **Traces:** Receives a list of targets (like Google, Cloudflare, or University networks) and runs `mtr` (traceroute) to them.
4.  **Reports:** Sends the path data back to the dashboard to visualize latency and routing changes.

### Security / Privacy
* **No Inbound Ports:** It acts as an Active Zabbix Agent. It pushes data out; you do not need to open firewall ports.
* **Encryption:** It generates its own TLS-PSK keys on first boot.
* **Scope:** It *only* runs traceroutes (ICMP). It does not inspect other traffic on your network.

---

### Quick Start (The Script)

The easiest way to get running. Supports x86_64 and ARM64 (Raspberry Pi).

**1. Clone & Build**
We build locally to ensure architecture compatibility.
```bash
git clone [https://github.com/hoddiv/netvaktin-probe.git](https://github.com/hoddiv/netvaktin-probe.git)
cd netvaktin-probe
sudo docker build -t netvaktin-probe .

2. Deploy Run the helper script. It handles the keys and Docker flags for you.
chmod +x deploy.sh
./deploy.sh

The script will ask for:
Zabbix Token: email admin@netvaktin.is to get one
Hostname: Name your probe (e.g., Probe-Nova-Rvk or Probe-Hringdu-Akureyri).

Role:
Domestic: You are in Iceland (monitoring the way out).
External: You are hosting this on a VPS abroad (monitoring the way in).

Manual Run (Docker Compose / Custom)
If you prefer running this without the wrapper script, here is the docker run command equivalent.
Note: mtr requires raw socket access. You must use --net=host (recommended for accurate latency) or explicitly add NET_ADMIN/NET_RAW capabilities.
docker run -d \
  --name netvaktin-probe \
  --net=host \
  --restart unless-stopped \
  -e ZBX_SERVER_HOST="monitor.logbirta.is" \
  -e ZBX_API_TOKEN="YOUR_TOKEN_HERE" \
  -e ZBX_HOSTNAME="Probe-MyHost" \
  -e NETVAKTIN_ROLE="Domestic" \
  netvaktin-probe

File Structure
route_check.sh: The logic that runs the traceroute and matches it against known submarine cable signatures.
entrypoint.sh: Startup logic that fetches updates and configures the agent.
register_probe.py: Handles the API handshake to register the probe automatically.


+-----------------------------------------+                 +--------------------------------+
|       Community Node (Docker)           |                 |    Netvaktin Infrastructure    |
|                                         |                 |                                |
|  1. Initialization (entrypoint.sh)      |                 |                                |
|     - Fetches latest cable signatures   |                 |                                |
|     - Generates local TLS-PSK keys      |                 |                                |
|                                         |                 |                                |
|  2. Auto-Discovery (register_probe.py)  |   API Token     |      monitor.netvaktin.is       |
|     - Authenticates via Zabbix API      | ---------------->      (Zabbix Backend)          |
|     - Registers Hostname & Role         |                 |      - Host Inventory          |
|                                         |                 |      - Route Hash Analysis     |
|  3. Execution (route_check.sh)          |                 |      - Alerting / Triggers     |
|     - Runs `mtr` to external targets    |                 |                                |
|     - Parses logical paths              |                 |                                |
|     - Matches against known signatures  |   TLS-PSK       |                                |
|                                         |   Encrypted     |                                |
|  4. Data Delivery (Zabbix Active Agent) |   Push Data     |                                |
|     - Pushes routing state metrics      | ---------------->      netvaktin.is              |
|     - Pushes latency data               |  (Port 10051)   |      (Public Dashboard)        |
+-----------------------------------------+                 +--------------------------------+
