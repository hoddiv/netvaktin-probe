import os
import sys
import requests
import json

# === CONFIGURATION (From Docker Env) ===
ZABBIX_URL = os.getenv("ZBX_API_URL")
API_TOKEN = os.getenv("ZBX_API_TOKEN") 
HOSTNAME = os.getenv("ZBX_HOSTNAME")
PSK_IDENTITY = os.getenv("ZBX_TLSPSKIDENTITY", "CommunityProbe")
PSK_VALUE = os.getenv("ZBX_TLSPSKVALUE") 

# Target names from Zabbix Setup
TEMPLATE_NAME = "Template Netvaktin"
HOST_GROUP_NAME = "Netvaktin Probes"

def log(msg):
    print(f"[Auto-Register] {msg}")

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
    """Looks up an ID by name (Template or Host Group)"""
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
        log(f"❌ CRITICAL: Template or Host Group not found on server!")
        sys.exit(1)

    # 2. Check if Host Exists
    log(f"Checking status of '{HOSTNAME}'...")
    hosts = zapi("host.get", {"filter": {"host": [HOSTNAME]}})
    
    if hosts:
        host_id = hosts[0]['hostid']
        log(f"✅ Host exists (ID: {host_id}). Syncing current PSK to server...")
        
        # --- THE SYNC FIX ---
        # If the host exists, we OVERWRITE the PSK on the server with our current local PSK
        update_params = {
            "hostid": host_id,
            "tls_psk_identity": PSK_IDENTITY,
            "tls_psk": PSK_VALUE
        }
        
        res = zapi("host.update", update_params)
        if res:
            log("🔄 PSK updated successfully. Handshake should now recover.")
        else:
            log("❌ Failed to update PSK on server.")
        return

    # 3. Create Host (New Probe)
    log(f"Registering new probe...")
    create_params = {
        "host": HOSTNAME,
        "interfaces": [{
            "type": 1, "main": 1, "useip": 0, "ip": "", "dns": "0.0.0.0", "port": "10050"
        }],
        "groups": [{"groupid": group_id}],
        "templates": [{"templateid": template_id}],
        "tls_connect": 2, # 2 = PSK
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
