#!/usr/bin/env python3
"""
Netvaktin V5 Probe Runner — dumb edge, no local config.
Usage: route_check_v5.py <target_id> <target_ip> <method> <packet_count> <wait_ms> <max_ttl> <silence_acceptable>
Emits:  JSON conforming to probe_measurement.schema.json v1.0
"""

import sys
import os
import json
import subprocess
import hashlib
import time
from datetime import datetime, timezone

PROBE_ID   = os.getenv("ZBX_HOSTNAME", "unknown-probe")
PROBE_ROLE = "external" if "ext" in os.getenv("NETVAKTIN_ROLE", "").lower() else "domestic"

METHOD_STRENGTH = {"icmp-paris": 1.0, "udp-paris": 0.85, "tcp": 0.7}

W_METHOD   = 0.35
W_TERMINAL = 0.35
W_PATH     = 0.30


def fail(msg):
    print(json.dumps({"error": msg, "status": "failed"}))
    sys.exit(0)


def run_scamper(ip, method, packet_count, wait_ms, max_ttl):
    wait_sec  = max(1, -(-wait_ms // 1000))  # ceiling division, minimum 1s
    trace_cmd = f"trace -P {method} -q {packet_count} -w {wait_sec} -m {max_ttl} {ip}"
    timeout_sec = int(packet_count * max_ttl * wait_sec) + 10
    timeout_sec = max(timeout_sec, 35)

    try:
        result = subprocess.run(
            ["scamper", "-O", "json", "-I", trace_cmd],
            capture_output=True, text=True, timeout=timeout_sec
        )
        if result.returncode != 0:
            return None, f"scamper_exit_{result.returncode}"

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "trace":
                    return obj, None
            except json.JSONDecodeError:
                continue

        return None, "no_trace_in_output"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except FileNotFoundError:
        return None, "scamper_not_found"
    except Exception as e:
        return None, str(e)


def parse_trace(trace_obj, target_ip, silence_acceptable, packet_count):
    raw_hops = trace_obj.get("hops", [])
    attempts = trace_obj.get("attempts", packet_count)

    # ttl_responses[ttl][probe_id] = (addr, rtt_ms)
    ttl_responses: dict[int, dict[int, tuple]] = {}
    for h in raw_hops:
        ttl      = h.get("probe_ttl")
        probe_id = h.get("probe_id", 1)
        addr     = h.get("addr")
        rtt      = h.get("rtt")
        if ttl is None:
            continue
        ttl_responses.setdefault(ttl, {})[probe_id] = (addr, rtt)

    if not ttl_responses:
        return [], {
            "reached": False,
            "final_responding_ip": None,
            "final_responding_ttl": None,
            "silence_acceptable": silence_acceptable,
            "status": "incomplete",
        }

    max_ttl_seen = max(ttl_responses.keys())
    hops = []

    for ttl in range(1, max_ttl_seen + 1):
        if ttl in ttl_responses:
            probes     = ttl_responses[ttl]
            ips        = {addr for addr, _ in probes.values() if addr}
            ip_at_ttl  = next(iter(ips)) if ips else None
            rtt_ms     = [probes[pid][1] if pid in probes else None
                          for pid in range(1, attempts + 1)]
            responding = ip_at_ttl is not None
        else:
            ip_at_ttl  = None
            rtt_ms     = [None] * attempts
            responding = False

        hops.append({"ttl": ttl, "ip": ip_at_ttl, "rtt_ms": rtt_ms, "responding": responding})

    final_ttl = None
    final_ip  = None
    reached   = False
    for hop in reversed(hops):
        if hop["responding"]:
            final_ttl = hop["ttl"]
            final_ip  = hop["ip"]
            reached   = (hop["ip"] == target_ip)
            break

    status = "complete" if reached else ("terminal_silent" if final_ip else "incomplete")

    terminal = {
        "reached": reached,
        "final_responding_ip": final_ip,
        "final_responding_ttl": final_ttl,
        "silence_acceptable": silence_acceptable,
        "status": status,
    }
    return hops, terminal


def compute_fingerprint(hops):
    visible = [h["ip"] for h in hops if h["responding"] and h["ip"]]
    digest  = hashlib.sha256(",".join(visible).encode()).hexdigest()
    return {
        "algorithm": "sha256-visible-hops",
        "value": digest[:16],
        "visible_hop_count": len(visible),
        "hop_sequence": visible,
    }


def compute_quality(method, terminal, hops):
    method_strength = METHOD_STRENGTH.get(method, 0.5)

    if terminal["reached"]:
        terminal_response = 1.0
    elif terminal["status"] == "terminal_silent" and terminal["silence_acceptable"]:
        terminal_response = 0.7
    elif terminal["status"] == "terminal_silent":
        terminal_response = 0.3
    else:
        terminal_response = 0.0

    frt = terminal["final_responding_ttl"]
    if frt and frt > 0:
        responding        = sum(1 for h in hops if h["responding"] and h["ttl"] <= frt)
        path_completeness = responding / frt
    else:
        path_completeness = 0.0

    score = round(min(
        W_METHOD * method_strength + W_TERMINAL * terminal_response + W_PATH * path_completeness,
        1.0
    ), 3)

    grade = "strong" if score >= 0.75 else "adequate" if score >= 0.50 else "weak" if score >= 0.25 else "unusable"

    return {
        "score": score,
        "grade": grade,
        "factors": {
            "method_strength":      method_strength,
            "terminal_response":    terminal_response,
            "path_completeness":    round(path_completeness, 3),
            "fingerprint_stability": None,
        },
    }


def main():
    if len(sys.argv) != 8:
        fail("usage: route_check_v5.py <target_id> <target_ip> <method> <packet_count> <wait_ms> <max_ttl> <silence_acceptable>")

    _, target_id, target_ip, method, packet_count_s, wait_ms_s, max_ttl_s, silence_s = sys.argv

    try:
        packet_count      = int(packet_count_s)
        wait_ms           = int(wait_ms_s)
        max_ttl           = int(max_ttl_s)
        silence_acceptable = silence_s.lower() == "true"
    except ValueError as e:
        fail(f"bad_arg:{e}")

    if method not in METHOD_STRENGTH:
        fail(f"unknown_method:{method}")

    ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0     = time.time()

    trace_obj, err = run_scamper(target_ip, method, packet_count, wait_ms, max_ttl)
    duration_ms    = int((time.time() - t0) * 1000)

    if trace_obj is None:
        fail(f"scamper_failed:{err}")

    hops, terminal  = parse_trace(trace_obj, target_ip, silence_acceptable, packet_count)
    fingerprint     = compute_fingerprint(hops)
    quality         = compute_quality(method, terminal, hops)

    print(json.dumps({
        "schema_version":   "1.0",
        "probe_id":         PROBE_ID,
        "probe_role":       PROBE_ROLE,
        "target_id":        target_id,
        "target_ip":        target_ip,
        "method":           method,
        "method_port":      None,
        "was_fallback":     False,
        "timestamp_utc":    ts_utc,
        "duration_ms":      duration_ms,
        "hops":             hops,
        "terminal":         terminal,
        "path_fingerprint": fingerprint,
        "evidence_quality": quality,
    }))


if __name__ == "__main__":
    main()
