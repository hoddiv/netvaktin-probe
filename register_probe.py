import os
import sys
import socket
import requests
import json

# === CONFIGURATION ===
ZABBIX_URL = os.getenv("ZBX_API_URL")
API_TOKEN = os.getenv("ZBX_API_TOKEN") 
HOSTNAME = os.getenv("ZBX_HOSTNAME")
PSK_IDENTITY = os.getenv("ZBX_TLSPSKIDENTITY", "CommunityProbe")
PSK_VALUE = os.getenv("ZBX_TLSPSKVALUE") 

# Dynamic Configuration via Env (Defaults to Domestic)
TEMPLATE_NAME = os.getenv("ZBX_TEMPLATE_NAME", "Template Netvaktin")
HOST_GROUP_NAME = os.getenv("ZBX_HOSTGROUP_NAME", "Netvaktin Probes")

def log(msg):
    print(f"[Auto-Register] {msg}")

def get_public_ip():
    """Detect the probe's public IP via external lookup, fall back to outbound socket."""
    try:
        r = requests.get("https://api.ipify.org", timeout=5)
        ip = r.text.strip()
        if ip:
            return ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""

def zapi(method, params):
    payload = {
        "jsonrpc": "2.0", "method": method, "params": params,
        "auth": API_TOKEN, "id": 1
    }
    try:
        r = requests.post(ZABBIX_URL, json=payload, timeout=10)
        r.raise_for_status()
        resp = r.json()
        if "error" in resp:
            log(f"!! API Error ({method}): {resp['error']['data']}")
            return None
        return resp.get("result")
    except Exception as e:
        log(f"!! Network Error: {e}")
        return None

def get_id(resource_type, name):
    method = f"{resource_type}.get"
    filter_key = "host" if resource_type == "template" else "name"
    res = zapi(method, {"filter": {filter_key: [name]}})
    if res:
        id_key = f"{resource_type}id"
        if resource_type == "hostgroup": id_key = "groupid"
        return res[0][id_key]
    return None

def register():
    if not API_TOKEN or not ZABBIX_URL:
        log("No API Token/URL provided. Skipping API registration.")
        return

    if not HOSTNAME or not PSK_VALUE:
        log("Missing Hostname or PSK. Cannot register.")
        return

    # 1. Resolve IDs dynamically
    log(f"Resolving configuration for '{TEMPLATE_NAME}'...")
    template_id = get_id("template", TEMPLATE_NAME)
    group_id = get_id("hostgroup", HOST_GROUP_NAME)

    if not template_id or not group_id:
        log(f"❌ CRITICAL: Template '{TEMPLATE_NAME}' or Host Group '{HOST_GROUP_NAME}' not found on server!")
        sys.exit(1)

    # 2. Check if Host Exists
    log(f"Checking status of '{HOSTNAME}'...")
    hosts = zapi("host.get", {"filter": {"host": [HOSTNAME]}})
    
    if hosts:
        host_id = hosts[0]['hostid']
        log(f"✅ Host exists (ID: {host_id}). Syncing PSK and IP to server...")

        probe_ip = get_public_ip()
        log(f"Detected probe IP: {probe_ip or '(unknown)'}")

        update_params = {
            "hostid": host_id,
            "tls_psk_identity": PSK_IDENTITY,
            "tls_psk": PSK_VALUE
        }
        res = zapi("host.update", update_params)
        if res:
            log("🔄 PSK updated successfully.")
        else:
            log("❌ Failed to update PSK on server.")

        # Update interface IP if we have one
        if probe_ip:
            interfaces = zapi("hostinterface.get", {"hostids": host_id})
            if interfaces:
                iface_id = interfaces[0]["interfaceid"]
                iface_res = zapi("hostinterface.update", {
                    "interfaceid": iface_id,
                    "ip": probe_ip,
                    "dns": "",
                    "useip": 1
                })
                if iface_res:
                    log(f"🔄 Interface IP updated to {probe_ip}.")
                else:
                    log("⚠️ Failed to update interface IP.")
        return

    # 3. Create Host (New Probe)
    probe_ip = get_public_ip()
    log(f"Detected probe IP: {probe_ip or '(unknown)'}")
    log(f"Registering new probe in group '{HOST_GROUP_NAME}'...")
    create_params = {
        "host": HOSTNAME,
        "interfaces": [{
            "type": 1, "main": 1, "useip": 1, "ip": probe_ip, "dns": "", "port": "10050"
        }],
        "groups": [{"groupid": group_id}],
        "templates": [{"templateid": template_id}],
        "tls_connect": 2, 
        "tls_accept": 2,  
        "tls_psk_identity": PSK_IDENTITY,
        "tls_psk": PSK_VALUE
    }
    
    res = zapi("host.create", create_params)
    if res:
        log(f"✅ REGISTRATION SUCCESSFUL (Host ID: {res['hostids'][0]})")
    else:
        log("❌ Registration Failed.")
        sys.exit(1)

if __name__ == "__main__":
    register()
