#!/bin/bash
# Netvaktin Probe - Legacy raw MTR helper kept for compatibility and rollback
# Usage: ./route_check.sh <TARGET_IP> [LABEL]

set -euo pipefail

# --- Watchdog: Safety net (25s) to stay under Agent's 30s limit ---
(sleep 25; kill $$ 2>/dev/null) &
WATCHDOG_PID=$!

TARGET="${1:-}"
LABEL="${2:-}"

if [[ -z "$TARGET" ]]; then
    echo '{"error": "missing_target", "status": "failed"}'
    exit 1
fi

# Run Trace with 10s timeout
if ! raw_trace=$(timeout 10 mtr -r -n -c 1 -w -G 1 "$TARGET" 2>/dev/null | tail -n +2); then
    kill $WATCHDOG_PID 2>/dev/null
    echo '{"error": "trace_failed_or_timeout", "status": "failed", "label": "'"$LABEL"'"}'
    exit 0
fi

# Clean up watchdog
kill $WATCHDOG_PID 2>/dev/null

# Safely escape the multiline raw_trace into a clean JSON payload
jq -n \
    --arg trace "$raw_trace" \
    --arg label "$LABEL" \
    '{raw_trace: $trace, label: $label}'
