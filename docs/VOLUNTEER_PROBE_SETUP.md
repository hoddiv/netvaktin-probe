# Volunteer Probe Setup

## Purpose

This guide is for Netvaktin community probes.

- the probe sends active outbound-only checks to Netvaktin/Zabbix
- no inbound ports are required
- volunteers should mostly just copy, paste, and report results back if something fails

## Requirements

- a Linux VM or server
- Docker installed and working
- outbound internet access
- a probe hostname provided by the Netvaktin operator
- a Zabbix API token provided separately if the deploy script asks for one

Replace `ProbeV5-IS-Provider01` below with the hostname assigned to you.

## Fresh install / normal deploy

```bash
if [ ! -d ~/netvaktin-probe-v5/.git ]; then
  git clone https://github.com/hoddiv/netvaktin-probe.git ~/netvaktin-probe-v5
fi
cd ~/netvaktin-probe-v5
git pull --ff-only
chmod +x deploy.sh
./deploy.sh --doctor ProbeV5-IS-Provider01
./deploy.sh ProbeV5-IS-Provider01
```

If prompted for an API token, paste the one provided by the Netvaktin operator.

## Update existing probe

```bash
cd ~/netvaktin-probe-v5
git pull --ff-only
./deploy.sh --doctor ProbeV5-IS-Provider01
./deploy.sh ProbeV5-IS-Provider01
```

## Clean reinstall for legacy leftovers

Use this only if the operator asks you to do a clean reinstall, or if normal deploy keeps failing and you were told to clear old local leftovers first.

The Docker container name follows:

```text
netvaktin-<hostname>
```

Example:

If your assigned hostname is `ProbeV5-IS-Provider01`, the container name is `netvaktin-ProbeV5-IS-Provider01`.

```bash
cd ~/netvaktin-probe-v5
docker rm -f netvaktin-ProbeV5-IS-Provider01 2>/dev/null || true
docker rmi -f ghcr.io/hoddiv/netvaktin-probe:latest netvaktin-probe:latest netvaktin-probe:local 2>/dev/null || true
rm -f netvaktin.psk
docker image prune -f
git pull --ff-only
./deploy.sh --doctor ProbeV5-IS-Provider01
./deploy.sh ProbeV5-IS-Provider01
```

## Support bundle

If anything fails, run:

```bash
./deploy.sh --support ProbeV5-IS-Provider01
```

Send the full output to the Netvaktin operator.

## What not to do

- do not wipe the VM unless asked
- do not manually edit the PSK unless asked
- do not build a local image unless asked
- do not expose inbound ports for the probe

## Operator note

- old Zabbix host names may need cleanup on the operator side
- one canonical hostname should be used for the probe
