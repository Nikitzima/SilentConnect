# SilentConnect Yandex Ingress

This folder contains the first, reversible implementation of a Russian ingress
node for SilentConnect.

Public wording: use "Yandex ingress", "Russian entry node", "stable entry
point", or "traffic package". Do not use wording about block bypass or
third-party whitelist bypass in public product texts.

## What This Does

MVP mode is an L4 TCP relay:

```text
client -> Yandex Cloud VM:443 -> Amsterdam node:23385 -> internet
client -> Yandex Cloud VM:8443 -> Amsterdam node:8443 -> internet
```

The relay does not decrypt user traffic. Xray/REALITY still terminates on the
Amsterdam node. This keeps the first test small and easy to remove.

## Why It Is A Separate Product

Yandex Cloud charges for outgoing traffic from public IP addresses after the
included free monthly allowance. In this relay design, billed Yandex traffic is
approximately equal to user download plus user upload through the ingress node:

- user download: Amsterdam -> Yandex is inbound to Yandex, Yandex -> user is
  outgoing from Yandex;
- user upload: user -> Yandex is inbound to Yandex, Yandex -> Amsterdam is
  outgoing from Yandex.

So this mode should be sold as traffic packages, not as the current unlimited
3/6/9-device plans.

## MVP Limitations

- `limitIp` is less useful through an L4 relay because Amsterdam sees the
  Yandex VM as the source IP.
- Xray per-client traffic accounting on Amsterdam should still work because
  the VLESS client identity is unchanged.
- If a network validates both destination IP and TLS SNI strictly, this simple
  relay may be insufficient: the client connects to a Yandex IP, but the REALITY
  SNI remains whatever is configured in the Amsterdam inbound. In that case the
  next version should terminate Xray on Yandex and tunnel to Amsterdam as an
  upstream.

## VM Shape

Start small:

- Ubuntu 24.04 LTS
- 2 vCPU
- 2 GB RAM
- 20-30 GB SSD
- static public IPv4
- SSH by key only

Security group:

- TCP 22 only from owner/admin IP
- TCP 443 from `0.0.0.0/0`
- TCP 8443 from `0.0.0.0/0` for XHTTP testing
- all outbound allowed

## Install Relay On VM

Copy and run:

```bash
curl -fsSL https://raw.githubusercontent.com/example/silentconnect/bootstrap-haproxy-relay.sh -o /root/bootstrap-haproxy-relay.sh
bash /root/bootstrap-haproxy-relay.sh
```

When deploying from this repo, use the local file instead:

```bash
scp vpn-shop/deploy/yandex-ingress/bootstrap-haproxy-relay.sh root@<YANDEX_IP>:/root/
ssh root@<YANDEX_IP> 'bash /root/bootstrap-haproxy-relay.sh'
```

Override defaults if needed:

```bash
AMS_HOST=192.0.2.1 \
AMS_TCP_PORT=23385 \
AMS_XHTTP_PORT=8443 \
RELAY_TCP_PORT=443 \
RELAY_XHTTP_PORT=8443 \
bash /root/bootstrap-haproxy-relay.sh
```

## Enable Relay Subscription Routes

On the Amsterdam node, set these env values in `/root/subjson-service/subjson.env`:

```text
RELAY_PUBLIC_HOST=<YANDEX_STATIC_IP_OR_DOMAIN>
RELAY_TCP_PORT=443
RELAY_XHTTP_PORT=8443
```

Restart:

```bash
systemctl restart subjson.service
```

Test routes:

```text
https://sub.example.com/my-secret-sub/json-relay/<tcp_subid>
https://sub.example.com/my-secret-sub/json-hybrid-relay/<tcp_subid>~<xhttp_subid>
```

The normal routes stay unchanged:

```text
https://sub.example.com/my-secret-sub/json/<subid>
https://sub.example.com/my-secret-sub/json-hybrid/<tcp_subid>~<xhttp_subid>
```

## Production Direction

Before selling this widely, add a separate catalog type:

- name: `Российская входная точка`
- billing: traffic packages, e.g. 50/100/250 GB
- no device-count promise in the first version
- show traffic balance and warn near quota
- use Xray `totalGB`/traffic stats for cutoff

For stricter networks, build v2 as full Yandex Xray ingress:

```text
client -> Yandex Xray inbound -> encrypted upstream tunnel -> Amsterdam exit
```

That version can enforce limits directly on Yandex and avoids relying on a pure
TCP relay.

## Full Xray Ingress

`bootstrap-xray-ingress.sh` configures the stronger production-shaped topology:

```text
client -> Yandex Xray:443 -> Amsterdam TCP+REALITY backhaul -> internet
```

This mode terminates the user profile on the Yandex VM, then uses one dedicated
service client on the Amsterdam TCP+REALITY inbound as the upstream tunnel. It is
the preferred direction for strict networks because the public client endpoint is
the Yandex VM itself, not a transparent TCP relay.

Current test VM:

```text
198.51.100.24
```

The full-ingress mode is not yet wired into the shop catalog. Do not expose it as
a public plan until per-user provisioning and traffic accounting are added on the
Yandex ingress.
