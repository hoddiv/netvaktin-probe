#!/bin/bash
# Netvaktin Probe - Route Analyzer v3.1 (Hardened)
# Usage: ./route_check.sh <TARGET_IP> [LABEL]

set -euo pipefail

TARGET="${1:-}"
LABEL="${2:-}"  # Capture the Zabbix Label (e.g., "UK_janet1")

if [[ -z "$TARGET" ]]; then
    echo '{"error": "missing_target", "status": "failed"}'
    exit 1
fi

# --- Configuration ---
SIG_FILE="/etc/zabbix/signatures.json"

# --- Legacy Signatures (Context Tags) ---
readonly SIG_LINX="195.66."
readonly SIG_INEX="185.6.36."
readonly SIG_DKNET="109.105."
readonly SIG_ARELION="62.115."
readonly SIG_L3_LEGACY="4.68."
readonly SIG_L3_LUMEN="4.69."
readonly SIG_NTT="129.250."
readonly SIG_COGENT="213.248."
readonly SIG_COGENT_BB="154.54."
readonly SIG_ZAYO="64.125."
readonly SIG_TATA="80.239."
readonly SIG_HE="184.105."
readonly SIG_GOOGLE_PEER="72.14."
readonly SIG_GOOGLE_NET="172.217."
readonly SIG_JANET="146.97."
readonly SIG_VODAFONE_UK="89.10."
readonly SIG_VODAFONE_IS="217.151."

# --- Execution ---
# 1. Run Trace with Hard Timeout
if ! raw_trace=$(timeout 25 mtr -r -n -c 1 -w "$TARGET" 2>/dev/null | tail -n +2); then
    echo '{"error": "trace_failed_or_timeout", "status": "failed", "label": "'"$LABEL"'"}'
    exit 0
fi

# 2. Extract Hops (Sanitizing)
hop_list=$(echo "$raw_trace" | awk '{
    hop_num=$1;
    gsub(/[^0-9]/, "", hop_num);
    print hop_num, $2
}')

# 3. Smart Detection (JSON Source of Truth)
DETECTED_CABLE=""
if [[ -f "$SIG_FILE" ]]; then
    cables=$(jq -r '.signatures | keys[]' "$SIG_FILE" 2>/dev/null || true)
    for cable in $cables; do
        gateways=$(jq -r ".signatures[\"$cable\"].gateways[]" "$SIG_FILE")
        for gate in $gateways; do
            if [[ "$raw_trace" == *"$gate"* ]]; then
                DETECTED_CABLE="$cable"
                break 2
            fi
        done
    done
fi

# 4. Feature Detection (Combining Sources)
declare -a detected_features=()
if [[ -n "$DETECTED_CABLE" ]]; then
    detected_features+=("$DETECTED_CABLE")
fi

# Legacy Heuristics (Window Hops 6-12)
sig_window=$(echo "$hop_list" | awk '$1>=6 && $1<=12 {printf "%s:%s ", $1, $2} END{print ""}' | sed 's/ $//')

[[ "$sig_window" == *"$SIG_LINX"* ]]        && detected_features+=("LINX")
[[ "$sig_window" == *"$SIG_INEX"* ]]        && detected_features+=("INEX")
[[ "$sig_window" == *"$SIG_DKNET"* ]]       && detected_features+=("DKNET")
[[ "$sig_window" == *"$SIG_ARELION"* ]]     && detected_features+=("ARELION")
[[ "$sig_window" == *"$SIG_L3_LUMEN"* ]]    && detected_features+=("LEVEL3")
[[ "$sig_window" == *"$SIG_L3_LEGACY"* ]]   && detected_features+=("LEVEL3")
[[ "$sig_window" == *"$SIG_NTT"* ]]         && detected_features+=("NTT")
[[ "$sig_window" == *"$SIG_COGENT"* ]]      && detected_features+=("COGENT")
[[ "$sig_window" == *"$SIG_COGENT_BB"* ]]   && detected_features+=("COGENT")
[[ "$sig_window" == *"$SIG_ZAYO"* ]]        && detected_features+=("ZAYO")
[[ "$sig_window" == *"$SIG_TATA"* ]]        && detected_features+=("TATA")
[[ "$sig_window" == *"$SIG_HE"* ]]          && detected_features+=("HE")
[[ "$sig_window" == *"$SIG_VODAFONE_UK"* ]] && detected_features+=("VODAFONE")
[[ "$sig_window" == *"$SIG_VODAFONE_IS"* ]] && detected_features+=("VODAFONE_IS")
[[ "$sig_window" == *"$SIG_GOOGLE_PEER"* ]] && detected_features+=("GOOGLE")
[[ "$sig_window" == *"$SIG_GOOGLE_NET"* ]]  && detected_features+=("GOOGLE")

# 5. Final Output Formatting
if [ ${#detected_features[@]} -eq 0 ]; then
    feature_string="UNKNOWN"
else
    feature_string=$(echo "${detected_features[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')
fi

# Hashing for deduplication
hash_input=$(echo "$hop_list" | awk '$1>=6 && $1<=9 {print $2}')
route_hash=$(echo "$hash_input" | md5sum | awk '{print $1}')
domain_hash=$(echo "$feature_string" | md5sum | awk '{print $1}')

# JSON Output
jq -n \
    --arg trace "$raw_trace" \
    --arg hash "$route_hash" \
    --arg features "$feature_string" \
    --arg sig "$sig_window" \
    --arg domain "$domain_hash" \
    --arg label "$LABEL" \
    '{raw_trace: $trace, hash: $hash, features: $features, sig: $sig, domain: $domain, label: $label}'
