FROM zabbix/zabbix-agent2:alpine-7.0-latest

LABEL maintainer="Netvaktin <admin@netvaktin.is>"
LABEL description="Community Network Probe for Netvaktin.is"

USER root

# Install dependencies (grouped for layer caching)
RUN apk add --no-cache \
    bash \
    curl \
    mtr \
    iputils \
    jq \
    && rm -rf /var/cache/apk/*

# Copy Scripts
COPY route_check.sh /usr/bin/route_check.sh
COPY entrypoint.sh /usr/bin/entrypoint.sh

# Permissions
RUN chmod +x /usr/bin/route_check.sh /usr/bin/entrypoint.sh

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
