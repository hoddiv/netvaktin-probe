FROM zabbix/zabbix-agent2:alpine-7.0-latest

LABEL maintainer="Netvaktin <admin@netvaktin.is>"
LABEL description="Universal Network Probe for Netvaktin.is"

USER root
# Ensure PID directory exists for stability
RUN mkdir -p /var/run/zabbix && chown -R zabbix:zabbix /var/run/zabbix

# Install dependencies
RUN apk add --no-cache \
    bash \
    curl \
    mtr \
    iputils \
    jq \
    python3 \
    py3-requests \
    && rm -rf /var/cache/apk/*

# Create staging area for assets
RUN mkdir -p /usr/local/share/netvaktin

# Copy Scripts & Assets
COPY route_check.sh /usr/bin/route_check.sh
COPY entrypoint.sh /usr/bin/entrypoint.sh
COPY register_probe.py /usr/bin/register_probe.py
COPY netvaktin_signatures.json /usr/local/share/netvaktin/netvaktin_signatures.json
COPY signatures_inbound.json /usr/local/share/netvaktin/signatures_inbound.json

# Set Permissions
RUN chmod +x /usr/bin/route_check.sh \
             /usr/bin/entrypoint.sh \
             /usr/bin/register_probe.py

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
