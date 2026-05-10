# Probe operational follow-ups

Status: **current follow-up list based on `main`**

This note tracks operational hardening, deployment hygiene, and community-support follow-ups for the Netvaktin probe after the current deploy and publishing hardening work already landed on `main`.

It is intentionally not written as a vulnerability report. The goal is to make volunteer/community probe installs easier to support and less likely to fail in confusing ways.

## 1. Current state already implemented

The following items are already in place on current `main` and should not be restated as open TODOs:

- `deploy.sh` and `deploy_dev.sh` have a doctor/support-oriented deploy flow with preflight output intended for volunteer troubleshooting.
- The deploy scripts validate the selected image before use and refuse stale images that do not contain the expected PSK bootstrap markers.
- `entrypoint.sh` bootstraps the PSK file from `ZBX_TLSPSKVALUE`, verifies that the file exists and is non-empty before starting `zabbix_agent2`, and writes `TLSPSKFile` into the generated Zabbix config.
- The deploy scripts perform Docker/runtime diagnostics for host networking, `NET_RAW`, image executability, local PSK path issues, and outbound connectivity.
- The GHCR publish workflow now validates both the pushed digest image and `ghcr.io/hoddiv/netvaktin-probe:latest` after publish.

This document only covers what still appears useful after those changes.

## 2. Registration lifecycle follow-ups

### Existing-host role and template reconciliation

`register_probe.py` currently resolves the desired template and host group from the selected role, but for an existing host it mainly updates PSK and interface IP.

Future work:

- detect when an existing host is still linked to the wrong group or template for the selected role
- warn clearly or reconcile automatically, depending on how safe that behavior is in practice
- document expected dev-to-prod and domestic-to-external transitions

Why this still matters:

- a probe can be locally configured for one role while Zabbix still links it to another
- community support is easier when role drift is surfaced explicitly

### Existing-host PSK sync failure behavior

For existing hosts, PSK update failures should be reviewed as a lifecycle decision:

- decide whether PSK sync failure should become fatal before agent startup
- or keep the current behavior but make the failure much more explicit in support guidance

Why this still matters:

- “container started” is not the same as “probe can authenticate and deliver active checks”

### Volunteer cleanup and troubleshooting guidance

The current support flow is much better than before, but there is still room for clearer operator-facing docs on:

- what to send after doctor mode fails
- how to distinguish image drift from API registration issues
- when to reuse a local PSK versus regenerate it
- how to clean up stale local artifacts without touching runtime secrets unnecessarily

## 3. PSK/runtime follow-ups still open

### PSK path/type/format validation

Current `main` already checks a lot:

- local deploy-side PSK path readability and emptiness
- entrypoint-side missing/empty PSK detection

Possible further hardening, if it proves worthwhile:

- explicitly reject a directory at the container PSK path before write/use
- explicitly require a regular readable file when booting without `ZBX_TLSPSKVALUE`
- optionally validate hex format in the entrypoint before starting the agent

This is a smaller follow-up now, not a broad PSK redesign.

### Non-root runtime investigation

The image still performs setup as root and starts the agent from that context. If this is revisited later, it should be treated as a compatibility exercise, not a cosmetic change.

Future work:

- test whether setup can remain privileged while steady-state runtime is reduced
- preserve `scamper` and `mtr-packet` raw-socket capability behavior
- avoid breaking simple volunteer deployments behind normal residential routers

## 4. Image reproducibility and release follow-ups

The release/publish validation gap that blocked volunteers has now been fixed. Remaining work is narrower and should focus on reproducibility rather than basic publish correctness.

Possible future work:

- pin the base image more tightly than `zabbix/zabbix-agent2:alpine-7.0-latest`
- record and verify the scamper source tarball checksum during build
- consider SBOM/provenance work later if distribution expands
- document expected release semantics for `latest` versus immutable SHA tags

These are supply-chain/reproducibility improvements, not emergency fixes.

## 5. Route-runner input guardrails

`route_check_v5.py` already normalizes IPs and enforces some minimum numeric bounds, but its operator/input contract could be made tighter.

Future work:

- explicitly allowlist supported methods such as `icmp-paris`, `udp-paris`, and `tcp`
- decide whether non-IP targets should be rejected or deliberately supported
- clamp probe count, wait timeout, and max TTL to safe upper/lower ranges
- document the intended item-parameter contract for Zabbix maintainers

Why this still matters:

- bad item parameters should fail predictably
- volunteer probes should not be made noisy or expensive by configuration mistakes

## 6. Healthcheck and observability follow-ups

The current healthcheck is intentionally cheap and stable, but it does not prove that active checks are succeeding.

Possible future work:

- investigate a slightly stronger healthcheck that stays low-impact
- expose clearer support signals without running route measurements
- document what “healthy container” does and does not guarantee for operators

This should remain lightweight. Expensive or stateful healthchecks would be counterproductive on community probes.

## 7. Suggested future PR slices

To keep changes reviewable, future work should stay split into narrow branches.

Suggested slices:

### `docs/probe-operations-followups-refresh`

- docs-only updates for volunteer troubleshooting, role transitions, and release semantics

### `fix/register-probe-lifecycle-reconciliation`

- existing-host group/template mismatch handling
- explicit decision on PSK sync failure behavior
- public-IP/interface update guardrails

### `fix/route-runner-input-guardrails`

- method allowlist
- parameter bounds/clamping
- clearer invalid-input output contract

### `build/probe-image-reproducibility`

- pinned base image or digest strategy
- scamper checksum verification
- any future provenance additions

## 8. Explicitly obsolete items from earlier hardening drafts

The earlier hardening drafts were useful during investigation, but the following should now be treated as obsolete framing:

- treating doctor/support mode as future work
- treating image preflight validation as future work
- treating entrypoint PSK bootstrap as future work
- treating GHCR post-publish validation as future work
- describing the old release gap without noting that current `main` now validates both pushed digest and `latest`

If any older draft is revived later, it should be rewritten against the current `main` baseline first rather than merged as-is.
