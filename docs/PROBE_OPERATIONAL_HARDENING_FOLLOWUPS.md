# Probe operational hardening follow-ups

Status: **further investigation warranted**

This note captures operational hardening and maintainability follow-ups for the Netvaktin community probe. It is intentionally framed as reliability and deployment hygiene work, not as a vulnerability report.

The current probe design remains intentionally low-friction:

- active Zabbix Agent 2 mode only
- no inbound ports required
- bounded route measurements
- scamper first, MTR fallback
- structured V5 JSON output
- no local route classification or cable judgment in the probe

These follow-ups are about making community deployment more predictable as more probes are installed.

## 1. Deployment script strict mode

Investigate adding stricter shell behavior to `deploy.sh` and `deploy_dev.sh`:

```bash
set -euo pipefail
```

Also check required local tools before deployment:

```bash
command -v docker >/dev/null
command -v openssl >/dev/null
```

Goal:

- fail early on missing prerequisites
- avoid continuing after partial setup failures
- keep PSK generation and container launch behavior predictable

## 2. Hostname and role validation

Add explicit validation for probe hostnames and roles before using them for:

- Docker container names
- Zabbix host names
- PSK identity strings
- role/template/group selection

Possible hostname rule:

```text
^[A-Za-z0-9_.-]{3,64}$
```

Preferred naming conventions:

```text
ProbeV5-<CC>-<ISP>
DEV-ProbeV5-<CC>-<ISP>
```

Role values should be constrained to the expected set:

```text
Domestic
External
Dev
DevExt
```

Goal:

- avoid accidental malformed Docker names
- avoid messy Zabbix host records
- keep dev/prod and domestic/external roles explicit

## 3. PSK handling tradeoff

Today the deployment scripts pass the PSK into the container through an environment variable so the entrypoint can write the PSK file.

This is simple and works, but a future hardening pass should consider a host-side PSK file bind mount instead:

```text
host generates PSK
host registers/syncs Zabbix PSK
container receives read-only PSK file mount
container does not receive PSK value as an environment variable
```

Goal:

- keep setup easy
- reduce accidental exposure through local container inspection tools
- document the tradeoff clearly for community probe operators

This is not urgent if probe hosts are trusted, but it is worth revisiting before wider distribution.

## 4. Existing-host role reconciliation

`register_probe.py` resolves the desired template and host group from the selected role. For existing hosts, future work should verify whether the existing Zabbix host already matches the desired role.

Investigate reconciling or warning on:

- host group mismatch
- template mismatch
- domestic/external role changes
- dev/prod promotion

Goal:

- avoid a container saying it is running one role while Zabbix still links it to another template/group
- make dev-to-prod promotion less error-prone
- keep V5 item schema expectations clear

## 5. Existing-host PSK sync failure behavior

For existing hosts, if PSK update fails in Zabbix, the probe container can continue starting even though the server may reject active checks.

Future work should consider treating PSK sync failure as fatal before starting the agent.

Goal:

- avoid “container is running” while the probe cannot actually authenticate to Zabbix
- make registration failures obvious to the operator

## 6. Non-root runtime investigation

The image currently performs setup as root and starts `zabbix_agent2` from the entrypoint. Because scamper/MTR need raw socket capability, this should be changed only after testing.

Investigate whether the runtime can be reduced to a non-root user after setup:

```text
entrypoint runs setup
PSK/config ownership fixed
zabbix_agent2 starts as zabbix user
scamper and mtr-packet retain only required capabilities
```

Goal:

- reduce container runtime privileges where practical
- preserve scamper/MTR functionality
- avoid breaking community probes behind simple residential routers

## 7. Image reproducibility

Future image hardening should consider:

- using a fixed Zabbix Agent 2 image tag or digest instead of a floating `latest` tag
- recording or verifying the scamper source tarball checksum
- adding basic image build validation in GitHub Actions
- considering SBOM/provenance later if the image becomes widely distributed

Goal:

- make rebuilds reproducible
- reduce surprises from upstream image changes
- make community deployment easier to support

## 8. Runner input guardrails

`route_check_v5.py` receives target, method, probe count, wait, and max TTL from Zabbix item parameters.

Future work should add explicit validation/clamping for:

- method allowlist: `icmp-paris`, `udp-paris`, `tcp`
- target IP validity, unless hostname targets are intentionally supported
- probe count safe range
- wait timeout safe range
- max TTL safe range

Goal:

- protect against bad Zabbix item parameters
- keep output predictable
- avoid unnecessary probe-side load

## 9. Public IP/interface update behavior

`register_probe.py` detects a public IP through an external lookup and has a socket fallback. The fallback can produce a local/private address depending on the network.

Future work should consider updating the Zabbix interface only when the detected address is public/routable, or otherwise storing local fallback information only as diagnostic metadata.

Goal:

- avoid misleading interface IPs in Zabbix
- keep active-mode behavior clear: inbound reachability is not required for community probes

## 10. Healthcheck usefulness

The current Docker healthcheck verifies that the runner script exists. That is stable and low-cost, but it does not verify that Zabbix Agent 2 is connected or that active checks are flowing.

Future work could investigate a slightly stronger healthcheck that remains low-impact and does not run route measurements.

Goal:

- improve operator feedback
- avoid expensive healthchecks
- keep healthcheck safe for low-power probes

## Suggested first implementation branch

Start with a small, low-risk branch:

```text
fix/deploy-input-and-registration-hardening
```

Suggested scope:

- add strict shell mode to deploy scripts
- validate hostname and role
- require `openssl`
- reject empty PSK values
- make existing-host PSK update failure fatal
- detect or reconcile existing-host group/template mismatch
- update README with neutral PSK handling and role lifecycle notes

Avoid changing the traceroute runner in the same branch.

## Suggested second branch

```text
fix/route-runner-input-guardrails
```

Suggested scope:

- validate method allowlist
- reject or explicitly handle non-IP targets
- clamp probe count, wait, and max TTL
- add tests or documented sample invocations if a test harness is added

## Wording guardrail

For public documentation and PR titles, prefer:

```text
operational hardening
deployment hygiene
reliability follow-ups
lifecycle reconciliation
input guardrails
```

Avoid framing these as confirmed vulnerabilities unless there is a specific, tested vulnerability and a coordinated disclosure reason to do so.
