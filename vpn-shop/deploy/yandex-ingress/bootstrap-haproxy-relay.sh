#!/usr/bin/env bash
set -euo pipefail

# SilentConnect Yandex ingress relay.
# This VM only forwards encrypted TCP streams to the Amsterdam node.
# Xray/REALITY still terminates on the Amsterdam node.

AMS_HOST="${AMS_HOST:-192.0.2.1}"
AMS_TCP_PORT="${AMS_TCP_PORT:-23385}"
AMS_XHTTP_PORT="${AMS_XHTTP_PORT:-8443}"
RELAY_TCP_PORT="${RELAY_TCP_PORT:-443}"
RELAY_XHTTP_PORT="${RELAY_XHTTP_PORT:-8443}"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y haproxy ca-certificates curl

cat >/etc/sysctl.d/99-silentconnect-ingress.conf <<'SYSCTL'
net.core.somaxconn = 65535
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_congestion_control = bbr
SYSCTL
sysctl --system >/dev/null || true

cat >/etc/haproxy/haproxy.cfg <<EOF
global
    log /dev/log local0
    log /dev/log local1 notice
    maxconn 50000
    daemon

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client 2h
    timeout server 2h
    timeout tunnel 2h

frontend silentconnect_tcp_reality
    bind *:${RELAY_TCP_PORT}
    default_backend amsterdam_tcp_reality

backend amsterdam_tcp_reality
    option tcp-check
    server ams ${AMS_HOST}:${AMS_TCP_PORT} check inter 10s fall 3 rise 2

frontend silentconnect_xhttp_reality
    bind *:${RELAY_XHTTP_PORT}
    default_backend amsterdam_xhttp_reality

backend amsterdam_xhttp_reality
    option tcp-check
    server ams ${AMS_HOST}:${AMS_XHTTP_PORT} check inter 10s fall 3 rise 2
EOF

systemctl enable haproxy
systemctl restart haproxy

echo "SilentConnect ingress relay is ready."
echo "TCP+REALITY: 0.0.0.0:${RELAY_TCP_PORT} -> ${AMS_HOST}:${AMS_TCP_PORT}"
echo "XHTTP+REALITY: 0.0.0.0:${RELAY_XHTTP_PORT} -> ${AMS_HOST}:${AMS_XHTTP_PORT}"
ss -tulpn | grep -E ":(${RELAY_TCP_PORT}|${RELAY_XHTTP_PORT})\\b" || true
