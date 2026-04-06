#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"
DEFAULT_TRACE_BUDGET_MS = 27000
DEFAULT_FALLBACK_RESERVE_MS = 10000
MIN_ENGINE_BUDGET_MS = 1500
STDERR_TAIL_BYTES = 1200
STDOUT_TAIL_BYTES = 1200

PROBE_ID = os.getenv("ZBX_HOSTNAME", "unknown-probe")
ROLE_RAW = os.getenv("NETVAKTIN_ROLE", "")
PROBE_ROLE = "external" if "ext" in ROLE_RAW.lower() else "domestic"
FORCE_ENGINE = os.getenv("NETVAKTIN_FORCE_ENGINE", "").strip().lower()

_TRACE_LINE_RE = re.compile(r"^(?P<prefix>[hdp])\s+(?P<ttl>-?\d+)\s*(?P<body>.*)$")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.%]+\b")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def tail_text(data: bytes | None, limit: int = STDERR_TAIL_BYTES) -> str:
    if not data:
        return ""
    clipped = data[-limit:]
    return clipped.decode("utf-8", errors="replace")


def token_to_float(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in {"", "?", "*", "nan", "-", "none", "null"}:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def normalize_hostname(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    try:
        ipaddress.ip_address(text)
        return None
    except ValueError:
        return text or None


def _valid_ip(candidate: str) -> str | None:
    text = candidate.strip().strip("[]()")
    if not text:
        return None
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def normalize_ip(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in {"*", "???", "???*"}:
        return None

    direct = _valid_ip(text)
    if direct:
        return direct

    for pattern in (_IPV4_RE, _IPV6_RE):
        for match in pattern.findall(text):
            parsed = _valid_ip(match)
            if parsed:
                return parsed

    if text.startswith("AS"):
        parts = text.split(maxsplit=1)
        if len(parts) == 2:
            parsed = normalize_ip(parts[1])
            if parsed:
                return parsed

    if text.endswith(")") and "(" in text:
        parsed = normalize_ip(text[text.rfind("(") + 1 : -1])
        if parsed:
            return parsed

    return None


def resolve_bin(env_name: str, *candidates: str) -> str | None:
    override = os.getenv(env_name, "").strip()
    if override:
        return override
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def remaining_ms(deadline: float) -> int:
    return max(0, int((deadline - time.monotonic()) * 1000))


def base_payload(target_id: str, target_ip: str, method: str, started_at: float) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "probe_id": PROBE_ID,
        "probe_role": PROBE_ROLE,
        "target_id": target_id,
        "target_ip": target_ip,
        "method": method,
        "timestamp_utc": now_utc(),
        "duration_ms": int((time.monotonic() - started_at) * 1000),
    }


def emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, separators=(",", ":"), sort_keys=False))


def emit_failure(
    target_id: str,
    target_ip: str,
    method: str,
    started_at: float,
    runner_errors: list[dict[str, Any]],
    engine_attempts: list[dict[str, Any]],
    *,
    error: str,
    budget_ms: int,
) -> None:
    payload = base_payload(target_id, target_ip, method, started_at)
    payload.update(
        {
            "status": "failed",
            "error": error,
            "budget_ms": budget_ms,
            "runner_errors": runner_errors,
            "engine_attempts": engine_attempts,
            "hops": [],
            "terminal": {
                "reached": False,
                "final_responding_ip": None,
                "status": "failed",
            },
            "path_fingerprint": {
                "value": "",
                "mode": "legacy-visible-hop-sha256",
                "diagnostic_only": True,
            },
        }
    )
    emit_json(payload)
    sys.exit(0)


class EngineResult(dict):
    pass


def run_command(engine: str, argv: list[str], timeout_ms: int) -> EngineResult:
    started = time.monotonic()
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            start_new_session=True,
        )
        stdout_b, stderr_b = proc.communicate(timeout=max(timeout_ms, 1) / 1000.0)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return EngineResult(
            {
                "ok": proc.returncode == 0,
                "engine": engine,
                "argv": argv,
                "returncode": proc.returncode,
                "stdout": stdout_b,
                "stderr": stderr_b,
                "elapsed_ms": elapsed_ms,
                "timeout_ms": timeout_ms,
                "timed_out": False,
            }
        )
    except subprocess.TimeoutExpired as exc:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except Exception:
                proc.kill()
            try:
                stdout_b, stderr_b = proc.communicate(timeout=0.5)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except Exception:
                    proc.kill()
                stdout_b, stderr_b = proc.communicate()
        else:
            stdout_b = exc.stdout or b""
            stderr_b = exc.stderr or b""
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return EngineResult(
            {
                "ok": False,
                "engine": engine,
                "argv": argv,
                "returncode": None,
                "stdout": stdout_b or b"",
                "stderr": stderr_b or b"",
                "elapsed_ms": elapsed_ms,
                "timeout_ms": timeout_ms,
                "timed_out": True,
                "exception_type": "TimeoutExpired",
                "exception_message": str(exc),
            }
        )
    except FileNotFoundError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return EngineResult(
            {
                "ok": False,
                "engine": engine,
                "argv": argv,
                "returncode": None,
                "stdout": b"",
                "stderr": str(exc).encode(),
                "elapsed_ms": elapsed_ms,
                "timeout_ms": timeout_ms,
                "timed_out": False,
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
            }
        )
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return EngineResult(
            {
                "ok": False,
                "engine": engine,
                "argv": argv,
                "returncode": None,
                "stdout": b"",
                "stderr": str(exc).encode(),
                "elapsed_ms": elapsed_ms,
                "timeout_ms": timeout_ms,
                "timed_out": False,
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
            }
        )


def engine_attempt_record(result: EngineResult, *, parse_status: str | None = None, responding_hops: int | None = None) -> dict[str, Any]:
    return {
        "engine": result.get("engine"),
        "argv": result.get("argv"),
        "timeout_ms": result.get("timeout_ms"),
        "elapsed_ms": result.get("elapsed_ms"),
        "returncode": result.get("returncode"),
        "timed_out": bool(result.get("timed_out", False)),
        "stdout_bytes": len(result.get("stdout") or b""),
        "stderr_tail": tail_text(result.get("stderr"), STDERR_TAIL_BYTES),
        "stdout_tail": tail_text(result.get("stdout"), STDOUT_TAIL_BYTES),
        "exception_type": result.get("exception_type"),
        "exception_message": result.get("exception_message"),
        "parse_status": parse_status,
        "responding_hops": responding_hops,
    }


def parse_scamper_trace(stdout_b: bytes, count: int) -> tuple[dict[str, Any] | None, str | None, dict[str, Any]]:
    text = stdout_b.decode("utf-8", errors="replace")
    trace_obj = None
    malformed_lines = 0
    seen_lines = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        seen_lines += 1
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            malformed_lines += 1
            continue
        if isinstance(obj, dict) and obj.get("type") == "trace":
            trace_obj = obj
            break
    meta = {
        "stdout_lines": seen_lines,
        "malformed_lines": malformed_lines,
    }
    if trace_obj is None:
        return None, "no_trace_json", meta
    hops = parse_scamper_hops(trace_obj, count)
    meta["responding_hops"] = sum(1 for hop in hops if hop.get("responding"))
    meta["hop_count"] = len(hops)
    return trace_obj, None, meta


def parse_scamper_hops(obj: dict[str, Any], count: int) -> list[dict[str, Any]]:
    ttl_map: dict[int, dict[int, dict[str, Any]]] = {}
    max_ttl = 0
    for hop in obj.get("hops", []) or []:
        if not isinstance(hop, dict):
            continue
        try:
            ttl = int(hop.get("probe_ttl", 0) or 0)
        except (TypeError, ValueError):
            continue
        if ttl <= 0:
            continue
        probe_id_raw = hop.get("probe_id", 1)
        try:
            probe_id = int(probe_id_raw or 1)
        except (TypeError, ValueError):
            probe_id = 1
        entry = ttl_map.setdefault(ttl, {})
        entry[probe_id] = {
            "ip": normalize_ip(hop.get("addr")),
            "rtt_ms": token_to_float(hop.get("rtt")),
            "asn": hop.get("asn"),
            "hostname": normalize_hostname(hop.get("hostname") or hop.get("rdns")),
        }
        max_ttl = max(max_ttl, ttl)

    hops: list[dict[str, Any]] = []
    if max_ttl <= 0:
        return hops

    ordered_probe_ids = list(range(1, max(1, count) + 1))
    for ttl in range(1, max_ttl + 1):
        probes = ttl_map.get(ttl, {})
        responders = [entry for _, entry in sorted(probes.items()) if entry.get("ip")]
        rtts: list[float | None] = []
        seen_ids: set[int] = set()
        for probe_id in ordered_probe_ids:
            entry = probes.get(probe_id)
            if entry is None:
                rtts.append(None)
            else:
                rtts.append(entry.get("rtt_ms"))
                seen_ids.add(probe_id)
        extra_ids = sorted(pid for pid in probes if pid not in seen_ids)
        for probe_id in extra_ids:
            rtts.append(probes[probe_id].get("rtt_ms"))
        hops.append(
            {
                "ttl": ttl,
                "ip": responders[0]["ip"] if responders else None,
                "rtt_ms": rtts[: max(1, count)],
                "responding": bool(responders),
                "asn": responders[0].get("asn") if responders else None,
                "hostname": responders[0].get("hostname") if responders else None,
            }
        )
    return hops


def parse_mtr_raw(stdout_b: bytes, count: int) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    text = stdout_b.decode("utf-8", errors="replace")
    hop_data: dict[int, dict[str, Any]] = {}
    malformed_lines = 0
    line_count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line_count += 1
        match = _TRACE_LINE_RE.match(line)
        if not match:
            malformed_lines += 1
            continue
        try:
            ttl = int(match.group("ttl"))
        except ValueError:
            malformed_lines += 1
            continue
        body = match.group("body").strip()
        prefix = match.group("prefix")
        bucket = hop_data.setdefault(ttl, {})
        if prefix == "h":
            bucket["ip"] = normalize_ip(body)
        elif prefix == "d":
            bucket["dns"] = normalize_hostname(body)
        elif prefix == "p":
            if not body:
                malformed_lines += 1
                continue
            parts = body.split()
            rtt_us = token_to_float(parts[0])
            if rtt_us is None:
                malformed_lines += 1
                continue
            bucket.setdefault("rtt", []).append(round(rtt_us / 1000.0, 3))

    if not hop_data:
        return [], "no_raw_hops", {"stdout_lines": line_count, "malformed_lines": malformed_lines}

    min_ttl = min(hop_data)
    offset = 1 if min_ttl == 0 else 0
    max_output_ttl = max(hop_data) + offset
    hops: list[dict[str, Any]] = []
    for output_ttl in range(1, max_output_ttl + 1):
        source_ttl = output_ttl - offset
        data = hop_data.get(source_ttl, {})
        rtts = list(data.get("rtt", []))
        while len(rtts) < max(1, count):
            rtts.append(None)
        hops.append(
            {
                "ttl": output_ttl,
                "ip": data.get("ip"),
                "rtt_ms": rtts[: max(1, count)],
                "responding": bool(data.get("ip")),
                "asn": None,
                "hostname": data.get("dns"),
            }
        )

    meta = {
        "stdout_lines": line_count,
        "malformed_lines": malformed_lines,
        "responding_hops": sum(1 for hop in hops if hop.get("responding")),
        "hop_count": len(hops),
    }
    return hops, None, meta


def build_path_fingerprint(hops: list[dict[str, Any]]) -> dict[str, Any]:
    visible = [hop.get("ip") for hop in hops if hop.get("responding") and hop.get("ip")]
    joined = ",".join(ip for ip in visible if ip)
    value = hashlib.sha256(joined.encode()).hexdigest()[:16] if joined else ""
    return {
        "value": value,
        "mode": "legacy-visible-hop-sha256",
        "diagnostic_only": True,
    }


def build_result(
    target_id: str,
    target_ip: str,
    method: str,
    engine: str,
    was_fallback: bool,
    hops: list[dict[str, Any]],
    started_at: float,
    runner_errors: list[dict[str, Any]],
    engine_attempts: list[dict[str, Any]],
    *,
    budget_ms: int,
) -> dict[str, Any]:
    payload = base_payload(target_id, target_ip, method, started_at)
    final = next((hop for hop in reversed(hops) if hop.get("responding")), None)
    reached = bool(final and final.get("ip") == target_ip)
    responding_hops = sum(1 for hop in hops if hop.get("responding"))
    if reached:
        terminal_status = "complete"
    elif responding_hops == 0:
        terminal_status = "dark"
    else:
        terminal_status = "incomplete"
    payload.update(
        {
            "probe_engine": engine,
            "was_fallback": was_fallback,
            "budget_ms": budget_ms,
            "status": "ok",
            "hops": hops,
            "terminal": {
                "reached": reached,
                "final_responding_ip": final.get("ip") if final else None,
                "status": terminal_status,
            },
            "path_fingerprint": build_path_fingerprint(hops),
            "evidence_quality": {
                "score": 0.93 if reached else (0.15 if responding_hops == 0 else 0.35)
            },
            "runner_errors": runner_errors,
            "engine_attempts": engine_attempts,
        }
    )
    return payload


def scamper_command(bin_path: str, target_ip: str, method: str, count: int, wait_ms: int, max_ttl: int) -> list[str]:
    wait_s = max(1, math.ceil(wait_ms / 1000.0))
    return [
        bin_path,
        "-O",
        "json",
        "-I",
        f"trace -P {method} -q {max(1, count)} -w {wait_s} -m {max(1, max_ttl)} {target_ip}",
    ]


def mtr_command(bin_path: str, target_ip: str, method: str, count: int, wait_ms: int, max_ttl: int) -> list[str]:
    method_flags = ["-u"] if method == "udp-paris" else (["-T"] if method == "tcp" else [])
    timeout_s = max(1, math.ceil(wait_ms / 1000.0))
    return [
        bin_path,
        "--raw",
        "--no-dns",
        "-c",
        str(max(1, count)),
        "-m",
        str(max(1, max_ttl)),
        "--timeout",
        str(timeout_s),
        *method_flags,
        target_ip,
    ]


def append_runner_error(runner_errors: list[dict[str, Any]], engine: str, error: str, **extra: Any) -> None:
    entry: dict[str, Any] = {"engine": engine, "error": error}
    entry.update({key: value for key, value in extra.items() if value is not None})
    runner_errors.append(entry)


def main() -> None:
    started_at = time.monotonic()
    try:
        if len(sys.argv) != 8:
            emit_failure(
                "unknown-target",
                "",
                "",
                started_at,
                [{"engine": "runner", "error": "invalid_argv", "argc": len(sys.argv) - 1}],
                [],
                error="invalid_arguments",
                budget_ms=env_int("NETVAKTIN_TRACE_BUDGET_MS", DEFAULT_TRACE_BUDGET_MS, minimum=1000),
            )

        _, target_id, target_ip_raw, method, probe_count_raw, wait_ms_raw, max_ttl_raw, _silence_raw = sys.argv
        target_ip = normalize_ip(target_ip_raw) or str(target_ip_raw).strip()
        probe_count = int(probe_count_raw)
        wait_ms = int(wait_ms_raw)
        max_ttl = int(max_ttl_raw)
        budget_ms = env_int("NETVAKTIN_TRACE_BUDGET_MS", DEFAULT_TRACE_BUDGET_MS, minimum=1000)
        fallback_reserve_ms = env_int(
            "NETVAKTIN_TRACE_FALLBACK_RESERVE_MS",
            DEFAULT_FALLBACK_RESERVE_MS,
            minimum=MIN_ENGINE_BUDGET_MS,
        )
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        emit_failure(
            "unknown-target",
            "",
            "",
            started_at,
            [{"engine": "runner", "error": "argument_parse_failed", "detail": str(exc)}],
            [],
            error="invalid_arguments",
            budget_ms=env_int("NETVAKTIN_TRACE_BUDGET_MS", DEFAULT_TRACE_BUDGET_MS, minimum=1000),
        )

    runner_errors: list[dict[str, Any]] = []
    engine_attempts: list[dict[str, Any]] = []
    deadline = started_at + (budget_ms / 1000.0)

    scamper_bin = resolve_bin("NETVAKTIN_SCAMPER_BIN", "scamper", "/usr/local/bin/scamper", "/usr/bin/scamper")
    mtr_bin = resolve_bin("NETVAKTIN_MTR_BIN", "mtr", "/usr/sbin/mtr", "/usr/bin/mtr")

    if FORCE_ENGINE not in {"", "scamper", "mtr"}:
        append_runner_error(runner_errors, "runner", "invalid_force_engine", value=FORCE_ENGINE)

    scamper_allowed = FORCE_ENGINE in {"", "scamper"}
    mtr_allowed = FORCE_ENGINE in {"", "mtr"}

    if scamper_allowed and scamper_bin:
        reserve_ms = 0 if FORCE_ENGINE == "scamper" else fallback_reserve_ms
        scamper_budget_ms = max(0, remaining_ms(deadline) - reserve_ms)
        if scamper_budget_ms >= MIN_ENGINE_BUDGET_MS:
            scamper_cmd = scamper_command(scamper_bin, target_ip, method, probe_count, wait_ms, max_ttl)
            scamper_result = run_command("scamper", scamper_cmd, scamper_budget_ms)
            if scamper_result.get("ok"):
                trace_obj, parse_error, parse_meta = parse_scamper_trace(scamper_result.get("stdout", b""), probe_count)
                parse_status = "ok" if parse_error is None else parse_error
                hops = parse_scamper_hops(trace_obj, probe_count) if trace_obj else []
                responding_hops = sum(1 for hop in hops if hop.get("responding"))
                engine_attempts.append(
                    engine_attempt_record(
                        scamper_result,
                        parse_status=parse_status,
                        responding_hops=responding_hops,
                    )
                    | parse_meta
                )
                if trace_obj and responding_hops > 0:
                    emit_json(
                        build_result(
                            target_id,
                            target_ip,
                            method,
                            "scamper",
                            False,
                            hops,
                            started_at,
                            runner_errors,
                            engine_attempts,
                            budget_ms=budget_ms,
                        )
                    )
                    return
                if parse_error:
                    append_runner_error(runner_errors, "scamper", parse_error, **parse_meta)
                else:
                    append_runner_error(runner_errors, "scamper", "zero_hops_visible", **parse_meta)
            else:
                error_code = "timeout" if scamper_result.get("timed_out") else "nonzero_exit"
                if scamper_result.get("exception_type") == "FileNotFoundError":
                    error_code = "not_found"
                engine_attempts.append(engine_attempt_record(scamper_result, parse_status=error_code, responding_hops=0))
                append_runner_error(
                    runner_errors,
                    "scamper",
                    error_code,
                    returncode=scamper_result.get("returncode"),
                    stderr_tail=tail_text(scamper_result.get("stderr")),
                )
        else:
            append_runner_error(runner_errors, "scamper", "budget_exhausted", remaining_ms=remaining_ms(deadline))
    elif scamper_allowed:
        append_runner_error(runner_errors, "scamper", "not_found")

    if mtr_allowed and mtr_bin:
        mtr_budget_ms = remaining_ms(deadline)
        if mtr_budget_ms >= MIN_ENGINE_BUDGET_MS:
            mtr_cmd = mtr_command(mtr_bin, target_ip, method, probe_count, wait_ms, max_ttl)
            mtr_result = run_command("mtr", mtr_cmd, mtr_budget_ms)
            if mtr_result.get("ok"):
                hops, parse_error, parse_meta = parse_mtr_raw(mtr_result.get("stdout", b""), probe_count)
                responding_hops = sum(1 for hop in hops if hop.get("responding"))
                parse_status = "ok" if parse_error is None else parse_error
                engine_attempts.append(
                    engine_attempt_record(
                        mtr_result,
                        parse_status=parse_status,
                        responding_hops=responding_hops,
                    )
                    | parse_meta
                )
                if parse_error:
                    append_runner_error(runner_errors, "mtr", parse_error, **parse_meta)
                emit_json(
                    build_result(
                        target_id,
                        target_ip,
                        method,
                        "mtr",
                        FORCE_ENGINE != "mtr",
                        hops,
                        started_at,
                        runner_errors,
                        engine_attempts,
                        budget_ms=budget_ms,
                    )
                )
                return
            error_code = "timeout" if mtr_result.get("timed_out") else "nonzero_exit"
            if mtr_result.get("exception_type") == "FileNotFoundError":
                error_code = "not_found"
            engine_attempts.append(engine_attempt_record(mtr_result, parse_status=error_code, responding_hops=0))
            append_runner_error(
                runner_errors,
                "mtr",
                error_code,
                returncode=mtr_result.get("returncode"),
                stderr_tail=tail_text(mtr_result.get("stderr")),
            )
        else:
            append_runner_error(runner_errors, "mtr", "budget_exhausted", remaining_ms=remaining_ms(deadline))
    elif mtr_allowed:
        append_runner_error(runner_errors, "mtr", "not_found")

    emit_failure(
        target_id,
        target_ip,
        method,
        started_at,
        runner_errors,
        engine_attempts,
        error="all_engines_failed",
        budget_ms=budget_ms,
    )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        started_at = time.monotonic()
        emit_failure(
            "unknown-target",
            "",
            "",
            started_at,
            [{"engine": "runner", "error": "unhandled_exception", "detail": str(exc), "type": type(exc).__name__}],
            [],
            error="runner_crashed",
            budget_ms=env_int("NETVAKTIN_TRACE_BUDGET_MS", DEFAULT_TRACE_BUDGET_MS, minimum=1000),
        )
