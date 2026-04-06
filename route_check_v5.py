#!/usr/bin/env python3
import hashlib, json, math, os, re, shutil, subprocess, sys, time
from datetime import datetime, timezone

PROBE_ID = os.getenv("ZBX_HOSTNAME", "unknown-probe")
PROBE_ROLE = "external" if "ext" in os.getenv("NETVAKTIN_ROLE", "").lower() else "domestic"
MTR_RAW_HOST_RE = re.compile(r"^h\s+(?P<ttl>\d+)\s+(?P<host>.+?)\s*$")
MTR_RAW_RTT_RE = re.compile(r"^p\s+(?P<ttl>\d+)\s+(?P<rtt>\d+)(?:\s+\d+)?\s*$")
MTR_RAW_DNS_RE = re.compile(r"^d\s+(?P<ttl>\d+)\s+(?P<hostname>.+?)\s*$")

def now_utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def emit_failure(m, e, s):
    print(json.dumps({"error": m, "status": "failed", "runner_errors": e, "duration_ms": int((time.monotonic()-s)*1000), "timestamp_utc": now_utc()}))
    sys.exit(0)
def token_to_float(t):
    try: return float(t.strip()) if t and t.strip() not in {"", "?", "*", "nan", "-"} else None
    except: return None
def normalize_ip(t):
    t = t.strip()
    if t in {"", "???", "*", "???*"}: return None
    if t.startswith("AS"): t = t.split(maxsplit=1)[1] if len(t.split()) > 1 else ""
    if t.endswith(")") and "(" in t: t = t[t.rfind("(")+1:-1].strip()
    return t or None
def resolve_bin(e, *c):
    o = os.getenv(e, "").strip()
    if o: return o
    for x in c:
        r = shutil.which(x)
        if r: return r
    return None

def run_scamper(ip, meth, count, wait, ttl, budget):
    b = resolve_bin("NETVAKTIN_SCAMPER_BIN", "scamper", "/usr/local/bin/scamper", "/usr/bin/scamper")
    if not b: return None, "scamper_not_found"
    try:
        r = subprocess.run([b, "-O", "json", "-I", f"trace -P {meth} -q {count} -w {max(1, wait//1000)} -m {ttl} {ip}"], capture_output=True, text=True, timeout=budget/1000.0)
        for l in r.stdout.splitlines():
            obj = json.loads(l)
            if obj.get("type") == "trace": return obj, None
        return None, "no_trace"
    except: return None, "scamper_error"

def parse_scamper(obj, target, silence, count):
    raw, ttl_res = obj.get("hops", []), {}
    for h in raw:
        t, pid = h.get("probe_ttl"), h.get("probe_id", 1)
        if t: ttl_res.setdefault(int(t), {})[int(pid)] = (h.get("addr"), token_to_float(str(h.get("rtt"))), h.get("asn"), h.get("hostname") or h.get("rdns"))
    hops = []
    if ttl_res:
        for t in range(1, max(ttl_res.keys())+1):
            p = ttl_res.get(t, {})
            vals = [v for v in p.values() if v[0]]
            hops.append({"ttl": t, "ip": vals[0][0] if vals else None, "rtt_ms": [p[i][1] if i in p else None for i in range(1, count+1)], "responding": bool(vals), "asn": vals[0][2] if vals else None, "hostname": vals[0][3] if vals else None})
    return hops

def run_mtr(ip, meth, count, wait, ttl, budget):
    b = resolve_bin("NETVAKTIN_MTR_BIN", "mtr", "/usr/sbin/mtr", "/usr/bin/mtr")
    if not b: return None, "mtr_not_found"
    f = ["-u"] if meth == "udp-paris" else (["-T"] if meth == "tcp" else [])
    try:
        r = subprocess.run([b, "--raw", "--no-dns", "-c", str(max(1, count)), "-m", str(ttl), "--timeout", str(max(1, wait//1000))] + f + [ip], capture_output=True, text=True, timeout=budget/1000.0)
        return (r.stdout.strip(), None) if r.returncode == 0 else (None, "mtr_failed")
    except: return None, "mtr_timeout"

def parse_mtr(raw, target, silence, count):
    h_data = {}
    for l in raw.splitlines():
        m_h, m_p, m_d = MTR_RAW_HOST_RE.match(l), MTR_RAW_RTT_RE.match(l), MTR_RAW_DNS_RE.match(l)
        if m_h: h_data.setdefault(int(m_h.group("ttl")), {})["ip"] = normalize_ip(m_h.group("host"))
        if m_p: h_data.setdefault(int(m_p.group("ttl")), {}).setdefault("rtt", []).append(round(float(m_p.group("rtt"))/1000.0, 3))
        if m_d: h_data.setdefault(int(m_d.group("ttl")), {})["dns"] = m_d.group("hostname")
    hops = []
    if h_data:
        off = 1 if min(h_data.keys()) == 0 else 0
        for t in range(1, max(h_data.keys()) + off + 1):
            d = h_data.get(t - off, {})
            rtts = d.get("rtt", [])
            while len(rtts) < count: rtts.append(None)
            hops.append({"ttl": t, "ip": d.get("ip"), "rtt_ms": rtts[:count], "responding": bool(d.get("ip")), "asn": None, "hostname": d.get("dns")})
    return hops

def build_res(tid, tip, meth, engine, was_fb, hops, start, errs):
    final = next((h for h in reversed(hops) if h["responding"]), None)
    reached = final["ip"] == tip if final else False
    visible = [h["ip"] for h in hops if h["responding"] and h["ip"]]
    return {
        "schema_version": "1.0", "probe_id": PROBE_ID, "probe_role": PROBE_ROLE, "target_id": tid, "target_ip": tip, "method": meth, "probe_engine": engine, "was_fallback": was_fb,
        "timestamp_utc": now_utc(), "duration_ms": int((time.monotonic() - start) * 1000), "hops": hops,
        "terminal": {"reached": reached, "final_responding_ip": final["ip"] if final else None, "status": "complete" if reached else "incomplete"},
        "path_fingerprint": {"value": hashlib.sha256(",".join(visible).encode()).hexdigest()[:16]},
        "evidence_quality": {"score": 0.93 if reached else 0.35}, "runner_errors": errs
    }

def main():
    _, tid, tip, meth, pc_s, w_s, mt_s, sil_s = sys.argv
    start, pc, wait, mt = time.monotonic(), int(pc_s), int(w_s), int(mt_s)
    errs = []
    
    # Try Scamper
    obj, sc_err = run_scamper(tip, meth, pc, wait, mt, 15000)
    if obj:
        hops = parse_scamper(obj, tip, False, pc)
        if any(h["responding"] for h in hops):
            print(json.dumps(build_res(tid, tip, meth, "scamper", False, hops, start, errs)))
            return
        errs.append({"engine": "scamper", "error": "zero_hops_visible"})
    else: errs.append({"engine": "scamper", "error": sc_err})

    # Fallback to MTR
    raw, m_err = run_mtr(tip, meth, pc, wait, mt, 10000)
    if raw:
        hops = parse_mtr(raw, tip, False, pc)
        print(json.dumps(build_res(tid, tip, meth, "mtr", True, hops, start, errs)))
    else: emit_failure("all_engines_failed", errs + [{"engine": "mtr", "error": m_err}], start)

if __name__ == "__main__": main()
