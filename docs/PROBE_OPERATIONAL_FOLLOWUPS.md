# Probe operational follow-ups

Status: **prioritized roadmap based on current `main`**

This document tracks general probe follow-up work that is still useful after the current deploy and publishing hardening already landed on `main`.

It is intentionally focused on reliability, deployment hygiene, and volunteer/community support. It is not a vulnerability report and should not be used to track individual support cases.

## Completed / current baseline

The following are already in place on current `main`:

- doctor/support deploy flow in `deploy.sh` and `deploy_dev.sh`
- image preflight validation before deploy
- PSK bootstrap in `entrypoint.sh`
- GHCR validation of both pushed digest and `latest`
- volunteer setup guide

Open items below should be read as future work beyond that baseline.

## P0 — Volunteer deployment reliability

Priority goal: keep the normal volunteer path simple, predictable, and easy to support.

Checklist:

- keep the normal deploy path short and clearly documented
- maintain support-bundle-first troubleshooting instead of ad hoc manual debugging
- keep clean reinstall guidance targeted to probe leftovers only
- keep canonical hostname guidance clear for volunteers and operators
- ensure stale-image and image-drift failures remain actionable and easy to explain

Notes:

- the public docs should continue to bias toward copy/paste guidance rather than internals
- troubleshooting paths should avoid pushing volunteers toward local image builds unless explicitly needed

## P1 — Registration lifecycle

Priority goal: reduce confusion when a probe already exists in Zabbix but local runtime state changes.

Checklist:

- make existing-host PSK sync failure fatal or explicitly handled
- detect existing-host group/template mismatch
- decide whether role/template drift should warn or reconcile
- document dev/prod and domestic/external transitions clearly

Notes:

- “container is running” should not be treated as equivalent to “probe is correctly registered”
- role and template drift should be visible enough that operator support does not depend on guesswork

## P2 — Route runner guardrails

Priority goal: make route-runner inputs predictable and bounded.

Checklist:

- enforce a method allowlist: `icmp-paris`, `udp-paris`, `tcp`
- clamp probe count
- clamp wait timeout
- clamp max TTL
- decide whether non-IP targets are supported or rejected
- document the expected Zabbix item parameter contract

Notes:

- bad measurement parameters should fail predictably
- volunteer probes should not become noisy or expensive because of configuration mistakes upstream

## P3 — Release reproducibility

Priority goal: make probe image rebuilds and support expectations more reproducible over time.

Checklist:

- pin the Zabbix base image more tightly than `alpine-7.0-latest`
- verify the scamper tarball checksum
- document `latest` versus SHA-tag release semantics

Notes:

- this is about reproducibility and supportability, not emergency release correctness
- the current publish validation already covers the immediate stale-image problem

## P4 — Runtime hardening

Priority goal: improve runtime safety and observability without making volunteer deployment harder.

Checklist:

- investigate non-root steady-state runtime
- improve the healthcheck without running route measurements
- document what a healthy container does and does not mean

Notes:

- any runtime privilege changes need to preserve current networking and raw-socket requirements
- healthcheck work should stay low-impact for community probes

## Out of repo / operator-side

These are important, but they should remain generic operator guidance rather than repo-side implementation work.

Checklist:

- clean stale Zabbix host records when probe names change
- use one canonical hostname per physical or logical probe
- handle API token distribution outside the public repo

## Suggested future PR slices

To keep review scope small, future work should stay split into narrow branches.

Possible slices:

- `docs/volunteer-deploy-guidance-refresh`
- `fix/register-probe-lifecycle-reconciliation`
- `fix/route-runner-input-guardrails`
- `build/probe-image-reproducibility`

## Obsolete framing to avoid

Earlier drafts are now outdated if they describe these as still missing:

- doctor/support deploy flow
- image preflight validation
- entrypoint PSK bootstrap
- GHCR post-publish validation of pushed digest and `latest`

Any future refresh of this document should continue from the current `main` baseline rather than from older incident-specific drafts.
