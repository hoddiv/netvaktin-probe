# Stage 1: Build scamper from source on Alpine
FROM alpine:3.19 AS scamper-builder

RUN apk add --no-cache \
    build-base \
    autoconf \
    automake \
    libtool \
    openssl-dev \
    linux-headers \
    wget

RUN wget -qLO /tmp/scamper.tar.gz \
    "https://github.com/alistairking/scamper/archive/refs/tags/20260204.03-a6r.tar.gz" \
 && cd /tmp \
 && tar xzf scamper.tar.gz \
 && cd scamper-* \
 && autoreconf -vfi \
 && ./configure --prefix=/usr/local \
 && make -j$(nproc) \
 && make install \
 && strip /usr/local/bin/scamper

# Stage 2: Probe image
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
    py3-requests

# Copy scamper binary from builder stage + add runtime deps
COPY --from=scamper-builder /usr/local/bin/scamper /usr/local/bin/scamper
RUN apk add --no-cache openssl libcap \
 && setcap cap_net_raw+ep /usr/local/bin/scamper \
 && MTR_PACKET="$(command -v mtr-packet || true)" \
 && if [ -n "$MTR_PACKET" ]; then setcap cap_net_raw+ep "$MTR_PACKET"; fi

# Create staging area for assets
RUN mkdir -p /usr/local/share/netvaktin

# Copy Scripts & Assets
COPY route_check_v5.py /usr/bin/route_check_v5.py
COPY entrypoint.sh /usr/bin/entrypoint.sh
COPY register_probe.py /usr/bin/register_probe.py

# Set Permissions
RUN chmod +x /usr/bin/route_check.sh \
             /usr/bin/route_check_v5.py \
             /usr/bin/entrypoint.sh \
             /usr/bin/register_probe.py

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
