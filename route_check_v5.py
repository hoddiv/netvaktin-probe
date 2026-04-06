#!/usr/bin/env python3
"""
Netvaktin V5 Universal Probe Runner.
Features: Explicit Fallback Logic, MTR Raw Parsing, and Robust Binary Resolution.
"""

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

PROBE_ID = os.getenv("ZBX_HOSTNAME", "unknown-probe")
PROBE_ROLE = "external" if "ext" in os.getenv("NETVAKTIN_ROLE", "").lower() else "domestic"

METHOD_STRENGTH = {"icmp-paris": 1.0, "udp-paris": 0.85, "tcp": 0.7}
ENGINE_STRENGTH = {"scamper": 1.0, "mtr": 0.8}

W_METHOD = 0.35
W_TERMINAL = 0.35
W_PATH = 0.30

DEFAULT_TOTAL_BUDGET_MS = 27000
DEFAULT_SCAMPER_BUDGET_MS = 18000
DEFAULT_MTR_RESERVE_MS = 8000
MIN_ENGINE_BUDGET_MS = 4000

MTR_RAW_HOST_RE = re.compile(r"^h\s+(?P<ttl>\d+)\s+(?P<host>.+?)\s*$")
# Captures the TTL and the first number (microseconds), ignoring the optional sequence number at the end
MTR_RAW_RTT_RE = re.compile(r"^p\s+(?P<ttl>\d+)\s+(?P<rtt>\d+)(?:\s+\d+)?\s*$")
MTR_RAW_DNS_RE = re.compile(r"^d\s+(?P<ttl>\d+)\s+(?P<hostname>.+?)\s*$")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit_failure(message: str, errors: List[Dict[str, object]], started_at: float) -> None:
    print(
        json.dumps(
            {
                "error": message,
                "status": "failed",
                "runner_errors": errors,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
                "timestamp_utc": now_utc(),
            }
        )
    )
    sys.exit(0)


def parse_int_arg(name: str, value: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"bad_{name}:{exc}") from exc


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class Budget:
    def __init__(self, total_ms: int) -> None:
        self.started = time.monotonic()
        self.deadline = self.started + (max(total_ms, MIN_ENGINE_BUDGET_MS) / 1000.0)

    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.started) * 1000)

    def remaining_ms(self) -> int:
        return max(0, int((self.deadline - time.monotonic()) * 1000))


def bounded_timeout_seconds(budget_ms: int) -> float:
    return max(1.0, budget_ms / 1000.0)


def token_to_float(token: Optional[str]) -> Optional[float]:
    if token is None:
        return None
    token = token.strip()
    if token in {"", "?", "*", "nan", "-"}:
        return None
    try:
        return float(token)
    except ValueError:
        return None


def normalize_ip(token: str) -> Optional[str]:
    token = token.strip()
    if token in {"", "???", "*", "???*"}:
        return None
    if token.startswith("AS"):
        parts = token.split(maxsplit=1)
        token = parts[1] if len(parts) > 1 else ""
    if token.endswith(")") and "(" in token:
        token = token[token.rfind("(") + 1 : -1].strip()
    return token or None


def resolve_executable(env_var: str, *candidates: str) -> Optional[str]:
    override = os.getenv(env_var, "").strip()
    if override:
        return override

    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def classify_mtr_error(returncode: int, stderr: str) -> str:
    normalized = stderr.lower()
    if "mtr-packet" in normalized and ("permission" in normalized or "not permitted" in normalized):
        return f"mtr_permission_error:{stderr}"
    if "operation not permitted" in normalized or "permission denied" in normalized:
        return f"mtr_permission_error:{stderr}"
    return f"mtr_exit_{returncode}:{stderr or 'no_stderr'}"


def planned_mtr_cycles(packet_count: int, budget_ms: int) -> int:
    requested = max(packet_count, 1)
    usable_seconds = max(1, int(math.floor(max(budget_ms, MIN_ENGINE_BUDGET_MS) / 1000.0)) - 1)
    return max(1, min(requested, usable_seconds))


def plan_engine_budgets(total_remaining_ms: int) -> Tuple[int, int]:
    preferred_scamper_ms = env_int("NETVAKTIN_SCAMPER_BUDGET_MS", DEFAULT_SCAMPER_BUDGET_MS)
    mtr_reserve_ms = env_int("NETVAKTIN_MTR_RESERVE_MS", DEFAULT_MTR_RESERVE_MS)

    scamper_ms = max(
        MIN_ENGINE_BUDGET_MS,
        min(preferred_scamper_ms, max(MIN_ENGINE_BUDGET_MS, total_remaining_ms - mtr_reserve_ms)),
    )
    mtr_ms = max(MIN_ENGINE_BUDGET_MS, total_remaining_ms - scamper_ms)
    return scamper_ms, mtr_ms


def run_scamper(
    ip: str,
    method: str,
    packet_count: int,
    wait_ms: int,
    max_ttl: int,
    budget_ms: int,
) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    wait_sec = max(1, -(-wait_ms // 1000))
    trace_cmd = f"trace -P {method} -q {packet_count} -w {wait_sec} -m {max_ttl} {ip}"

    try:
        scamper_bin = resolve_executable("NETVAKTIN_SCAMPER_BIN", "scamper", "/usr/local/bin/scamper", "/usr/bin/scamper")
        if not scamper_bin:
            return None, "scamper_not_found"

        result = subprocess.run(
            [scamper_bin, "-O", "json", "-I", trace_cmd],
            capture_output=True,
            text=True,
            timeout=bounded_timeout_seconds(budget_ms),
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return None, f"scamper_exit_{result.returncode}:{stderr or 'no_stderr'}"

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "trace":
                return obj, None
        return None, "no_trace_in_output"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except Exception as exc:  
        return None, f"exec_error:{exc}"


def parse_scamper_trace(
    trace_obj: Dict[str, object],
    target_ip: str,
    silence_acceptable: bool,
    packet_count: int,
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    raw_hops = trace_obj.get("hops", []) if isinstance(trace_obj, dict) else []
    attempts = int(trace_obj.get("attempts", packet_count)) if isinstance(trace_obj, dict) else packet_count

    ttl_responses: Dict[int, Dict[int, Tuple[Optional[str], Optional[float], Optional[int], Optional[str]]]] = {}
    for hop in raw_hops:
        if not isinstance(hop, dict):
            continue
        ttl = hop.get("probe_ttl")
        probe_id = hop.get("probe_id", 1)
        if ttl is None:
            continue
        asn = hop.get("asn")
        if isinstance(asn, str) and asn.upper().startswith("AS"):
            asn = asn[2:]
        try:
            normalized_asn = int(asn) if asn is not None else None
        except (TypeError, ValueError):
            normalized_asn = None
        ttl_responses.setdefault(int(ttl), {})[int(probe_id)] = (
            hop.get("addr"),
            token_to_float(str(hop.get("rtt"))) if hop.get("rtt") is not None else None,
            normalized_asn,
            hop.get("hostname") or hop.get("rdns"),
        )

    if not ttl_responses:
        return [], build_terminal([], target_ip, silence_acceptable)

    max_ttl_seen = max(ttl_responses.keys())
    hops: List[Dict[str, object]] = []

    for ttl in range(1, max_ttl_seen + 1):
        if ttl in ttl_responses:
            probes = ttl_responses[ttl]
            responding_values = [value for value in probes.values() if value[0]]
            ip_at_ttl = responding_values[0][0] if responding_values else None
            asn_at_ttl = responding_values[0][2] if responding_values else None
            hostname_at_ttl = responding_values[0][3] if responding_values else None
            rtt_ms = [probes[pid][1] if pid in probes else None for pid in range(1, attempts + 1)]
            responding = ip_at_ttl is not None
        else:
            ip_at_ttl = None
            asn_at_ttl = None
            hostname_at_ttl = None
            rtt_ms = [None] * attempts
            responding = False

        hops.append(
            {
                "ttl": ttl,
                "ip": ip_at_ttl,
                "rtt_ms": rtt_ms,
                "responding": responding,
                "asn": asn_at_ttl,
                "hostname": hostname_at_ttl,
            }
        )

    return hops, build_terminal(hops, target_ip, silence_acceptable)


def mtr_method_flags(method: str) -> List[str]:
    if method == "udp-paris":
        return ["-u"]
    if method == "tcp":
        return ["-T"]
    return []


def run_mtr(
    ip: str,
    method: str,
    packet_count: int,
    wait_ms: int,
    max_ttl: int,
    budget_ms: int,
) -> Tuple[Optional[str], Optional[str]]:
    mtr_bin = resolve_executable("NETVAKTIN_MTR_BIN", "mtr", "/usr/sbin/mtr", "/usr/bin/mtr")
    if not mtr_bin:
        return None, "mtr_not_found"

    report_cycles = planned_mtr_cycles(packet_count, budget_ms)
    per_probe_timeout_s = max(1, int(math.ceil(max(wait_ms, 1) / 1000.0)))

    cmd = [
        mtr_bin,
        "--raw",
        "--no-dns",
        "-c", str(report_cycles),
        "-m", str(max(max_ttl, 1)),
        "--gracetime", "1",
        "--timeout", str(per_probe_timeout_s),
    ]
    cmd.extend(mtr_method_flags(method))
    cmd.append(ip)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=bounded_timeout_seconds(budget_ms),
        )
    except subprocess.TimeoutExpired:
        return None, f"timeout:cycles={report_cycles}"
    except Exception as exc:
        return None, f"exec_error:{exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return None, classify_mtr_error(result.returncode, stderr)

    output = result.stdout.strip()
    if not output:
        return None, f"empty_output:cycles={report_cycles}"
    return output, None


def parse_mtr_trace(
    raw_output: str,
    target_ip: str,
    silence_acceptable: bool,
    packet_count: int,
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    raw_hops: Dict[int, Dict[str, object]] = {}

    def ensure_hop(raw_ttl: int) -> Dict[str, object]:
        return raw_hops.setdefault(
            raw_ttl,
            {
                "ip": None,
                "hostname": None,
                "rtt_ms": [],
            },
        )

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        host_match = MTR_RAW_HOST_RE.match(line)
        if host_match:
            raw_ttl = int(host_match.group("ttl"))
            hop = ensure_hop(raw_ttl)
            hop["ip"] = normalize_ip(host_match.group("host"))
            continue

        rtt_match = MTR_RAW_RTT_RE.match(line)
        if rtt_match:
            raw_ttl = int(rtt_match.group("ttl"))
            hop = ensure_hop(raw_ttl)
            # RTT is in microseconds, convert to milliseconds
            val = token_to_float(rtt_match.group("rtt"))
            hop["rtt_ms"].append(round(val / 1000.0, 3) if val is not None else None)
            continue

        dns_match = MTR_RAW_DNS_RE.match(line)
        if dns_match:
            raw_ttl = int(dns_match.group("ttl"))
            hop = ensure_hop(raw_ttl)
            hop["hostname"] = dns_match.group("hostname").strip() or None

    if not raw_hops:
        return [], build_terminal([], target_ip, silence_acceptable)

    ttl_offset = 1 if min(raw_hops.keys()) == 0 else 0
    hops_by_ttl: Dict[int, Dict[str, object]] = {}

    for raw_ttl, raw_hop in raw_hops.items():
        ttl = raw_ttl + ttl_offset
        rtt_values = list(raw_hop.get("rtt_ms", []))[: max(packet_count, 1)]
        while len(rtt_values) < max(packet_count, 1):
            rtt_values.append(None)

        ip_value = raw_hop.get("ip")
        hops_by_ttl[ttl] = {
            "ttl": ttl,
            "ip": ip_value,
            "rtt_ms": rtt_values,
            "responding": ip_value is not None,
            "asn": None,
            "hostname": raw_hop.get("hostname"),
        }

    max_ttl_seen = max(hops_by_ttl.keys())
    hops: List[Dict[str, object]] = []
    for ttl in range(1, max_ttl_seen + 1):
        if ttl in hops_by_ttl:
            hops.append(hops_by_ttl[ttl])
        else:
            hops.append(
                {
                    "ttl": ttl,
                    "ip": None,
                    "rtt_ms": [None] * max(packet_count, 1),
                    "responding": False,
                    "asn": None,
                    "hostname": None,
                }
            )

    return hops, build_terminal(hops, target_ip, silence_acceptable)


def build_terminal(hops: List[Dict[str, object]], target_ip: str, silence_acceptable: bool) -> Dict[str, object]:
    final_ttl: Optional[int] = None
    final_ip: Optional[str] = None
    reached = False

    for hop in reversed(hops):
        if hop.get("responding"):
            final_ttl = int(hop["ttl"])
            final_ip = hop.get("ip")
            reached = final_ip == target_ip
            break

    status = "complete" if reached else ("terminal_silent" if final_ip else "incomplete")
    return {
        "reached": reached,
        "final_responding_ip": final_ip,
        "final_responding_ttl": final_ttl,
        "silence_acceptable": silence_acceptable,
        "status": status,
    }


def compute_fingerprint(hops: List[Dict[str, object]]) -> Dict[str, object]:
    visible = [hop["ip"] for hop in hops if hop.get("responding") and hop.get("ip")]
    digest = hashlib.sha256(",".join(visible).encode("utf-8")).hexdigest()
    return {
        "algorithm": "sha256-visible-hops",
        "value": digest[:16],
        "visible_hop_count": len(visible),
        "hop_sequence": visible,
    }


def compute_quality(engine: str, method: str, terminal: Dict[str, object], hops: List[Dict[str, object]]) -> Dict[str, object]:
    method_strength = METHOD_STRENGTH.get(method, 0.5) * ENGINE_STRENGTH.get(engine, 0.6)

    if terminal["reached"]:
        terminal_response = 1.0
    elif terminal["status"] == "terminal_silent" and terminal["silence_acceptable"]:
        terminal_response = 0.7
    elif terminal["status"] == "terminal_silent":
        terminal_response = 0.3
    else:
        terminal_response = 0.0

    final_responding_ttl = terminal["final_responding_ttl"]
    if isinstance(final_responding_ttl, int) and final_responding_ttl > 0:
        responding = sum(1 for hop in hops if hop.get("responding") and int(hop["ttl"]) <= final_responding_ttl)
        path_completeness = responding / final_responding_ttl
    else:
        path_completeness = 0.0

    score = round(min(W_METHOD * method_strength + W_TERMINAL * terminal_response + W_PATH * path_completeness, 1.0), 3)
    if score >= 0.75:
        grade = "strong"
    elif score >= 0.50:
        grade = "adequate"
    elif score >= 0.25:
        grade = "weak"
    else:
        grade = "unusable"

    return {
        "score": score,
        "grade": grade,
        "factors": {
            "method_strength": round(method_strength, 3),
            "terminal_response": terminal_response,
            "path_completeness": round(path_completeness, 3),
            "fingerprint_stability": None,
            "probe_engine": engine,
        },
    }


def build_measurement(
    *,
    target_id: str,
    target_ip: str,
    method: str,
    engine: str,
    was_fallback: bool,
    fallback_from: Optional[str],
    hops: List[Dict[str, object]],
    terminal: Dict[str, object],
    started_at_monotonic: float,
    runner_errors: List[Dict[str, object]],
) -> Dict[str, object]:
    return {
        "schema_version": "1.0",
        "probe_id": PROBE_ID,
        "probe_role": PROBE_ROLE,
        "target_id": target_id,
        "target_ip": target_ip,
        "method": method,
        "method_port": None,
        "probe_engine": engine,
        "was_fallback": was_fallback,
        "fallback_from": fallback_from,
        "fallback_to": engine if was_fallback else None,
        "timestamp_utc": now_utc(),
        "duration_ms": int((time.monotonic() - started_at_monotonic) * 1000),
        "hops": hops,
        "terminal": terminal,
        "path_fingerprint": compute_fingerprint(hops),
        "evidence_quality": compute_quality(engine, method, terminal, hops),
        "runner_errors": runner_errors,
    }


def main() -> None:
    if len(sys.argv) != 8:
        emit_failure(
            "usage: route_check_v5.py <target_id> <target_ip> <method> <packet_count> <wait_ms> <max_ttl> <silence_acceptable>",
            [],
            time.monotonic(),
        )

    _, target_id, target_ip, method, packet_count_s, wait_ms_s, max_ttl_s, silence_s = sys.argv
    started_at = time.monotonic()

    try:
        packet_count = parse_int_arg("packet_count", packet_count_s)
        wait_ms = parse_int_arg("wait_ms", wait_ms_s)
        max_ttl = parse_int_arg("max_ttl", max_ttl_s)
        silence_acceptable = silence_s.lower() == "true"
    except ValueError as exc:
        emit_failure(str(exc), [], started_at)
        return

    if method not in METHOD_STRENGTH:
        emit_failure(f"unknown_method:{method}", [], started_at)
        return

    total_budget_ms = env_int("NETVAKTIN_TRACE_BUDGET_MS", DEFAULT_TOTAL_BUDGET_MS)
    budget = Budget(total_budget_ms)
    runner_errors: List[Dict[str, object]] = []

    force_engine = os.getenv("NETVAKTIN_FORCE_ENGINE", "auto").strip().lower()
    if force_engine not in {"auto", "scamper", "mtr"}:
        force_engine = "auto"

    scamper_slice_ms, mtr_slice_ms = plan_engine_budgets(budget.remaining_ms())

    if force_engine != "mtr" and budget.remaining_ms() >= MIN_ENGINE_BUDGET_MS:
        scamper_budget_ms = min(scamper_slice_ms, budget.remaining_ms())
        trace_obj, err = run_scamper(target_ip, method, packet_count, wait_ms, max_ttl, scamper_budget_ms)
        
        if trace_obj is not None:
            hops, terminal = parse_scamper_trace(trace_obj, target_ip, silence_acceptable, packet_count)
            print(
                json.dumps(
                    build_measurement(
                        target_id=target_id,
                        target_ip=target_ip,
                        method=method,
                        engine="scamper",
                        was_fallback=False,
                        fallback_from=None,
                        hops=hops,
                        terminal=terminal,
                        started_at_monotonic=started_at,
                        runner_errors=runner_errors,
                    )
                )
            )
            return
        
        runner_errors.append({"engine": "scamper", "error": err or "unknown", "budget_ms": scamper_budget_ms})

    if force_engine == "scamper":
        emit_failure("scamper_failed", runner_errors, started_at)
        return

    if budget.remaining_ms() < MIN_ENGINE_BUDGET_MS and force_engine != "mtr":
        emit_failure("budget_exhausted_before_mtr", runner_errors, started_at)
        return

    mtr_budget_ms = min(max(mtr_slice_ms, MIN_ENGINE_BUDGET_MS), budget.remaining_ms())
    raw_mtr, mtr_err = run_mtr(target_ip, method, packet_count, wait_ms, max_ttl, mtr_budget_ms)
    
    if raw_mtr is None:
        runner_errors.append({"engine": "mtr", "error": mtr_err, "budget_ms": mtr_budget_ms})
        emit_failure("all_engines_failed", runner_errors, started_at)
        return

    hops, terminal = parse_mtr_trace(raw_mtr, target_ip, silence_acceptable, packet_count)
    if not hops:
        runner_errors.append({"engine": "mtr", "error": "no_hops_parsed", "budget_ms": mtr_budget_ms})
        emit_failure("all_engines_failed", runner_errors, started_at)
        return
        
    print(
        json.dumps(
            build_measurement(
                target_id=target_id,
                target_ip=target_ip,
                method=method,
                engine="mtr",
                was_fallback=(force_engine != "mtr"),
                fallback_from="scamper" if force_engine != "mtr" else None,
                hops=hops,
                terminal=terminal,
                started_at_monotonic=started_at,
                runner_errors=runner_errors,
            )
        )
    )

if __name__ == "__main__":
    main()
