#!/usr/bin/env bash
set -euo pipefail

# SilentConnect Yandex Xray ingress.
# Client traffic terminates on this VM, then goes to the Amsterdam exit through
# a dedicated encrypted VLESS+REALITY backhaul client.

: "${INGRESS_CLIENT_ID:?set INGRESS_CLIENT_ID}"
: "${INGRESS_REALITY_PRIVATE_KEY:?set INGRESS_REALITY_PRIVATE_KEY}"
: "${INGRESS_REALITY_SHORT_ID:?set INGRESS_REALITY_SHORT_ID}"
: "${AMS_BACKHAUL_ID:?set AMS_BACKHAUL_ID}"
: "${AMS_BACKHAUL_ENCRYPTION:?set AMS_BACKHAUL_ENCRYPTION}"

AMS_HOST="${AMS_HOST:-192.0.2.1}"
AMS_PORT="${AMS_PORT:-23385}"
AMS_REALITY_SERVER_NAME="${AMS_REALITY_SERVER_NAME:-www.kernel.org}"
AMS_REALITY_PUBLIC_KEY="${AMS_REALITY_PUBLIC_KEY:-mock_reality_public_key_ams_00000000000000000=}"
AMS_REALITY_SHORT_ID="${AMS_REALITY_SHORT_ID:-0123456789abcdef}"
INGRESS_PORT="${INGRESS_PORT:-443}"
INGRESS_REALITY_SERVER_NAME="${INGRESS_REALITY_SERVER_NAME:-www.yandex.ru}"
INGRESS_REALITY_DEST="${INGRESS_REALITY_DEST:-www.yandex.ru:443}"
INGRESS_CLIENT_EMAIL="${INGRESS_CLIENT_EMAIL:-yc-ingress-test}"

cat >/usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "none",
    "error": "/var/log/xray/error.log"
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "inbounds": [
    {
      "tag": "yc-ingress",
      "listen": "0.0.0.0",
      "port": ${INGRESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${INGRESS_CLIENT_ID}",
            "email": "${INGRESS_CLIENT_EMAIL}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${INGRESS_REALITY_DEST}",
          "xver": 0,
          "serverNames": [
            "${INGRESS_REALITY_SERVER_NAME}"
          ],
          "privateKey": "${INGRESS_REALITY_PRIVATE_KEY}",
          "shortIds": [
            "${INGRESS_REALITY_SHORT_ID}"
          ]
        },
        "tcpSettings": {
          "acceptProxyProtocol": false,
          "header": {
            "type": "none"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": false
      }
    }
  ],
  "outbounds": [
    {
      "tag": "ams-exit",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${AMS_HOST}",
            "port": ${AMS_PORT},
            "users": [
              {
                "id": "${AMS_BACKHAUL_ID}",
                "email": "yandex-backhaul",
                "flow": "xtls-rprx-vision",
                "encryption": "${AMS_BACKHAUL_ENCRYPTION}"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "${AMS_REALITY_SERVER_NAME}",
          "fingerprint": "chrome",
          "publicKey": "${AMS_REALITY_PUBLIC_KEY}",
          "shortId": "${AMS_REALITY_SHORT_ID}",
          "spiderX": "/"
        },
        "tcpSettings": {
          "header": {
            "type": "none"
          }
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "direct"
      }
    ]
  }
}
EOF

/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
systemctl disable --now haproxy 2>/dev/null || true
systemctl enable xray
systemctl restart xray
systemctl is-active xray
ss -tulpn | grep -E ":${INGRESS_PORT}\\b" || true
