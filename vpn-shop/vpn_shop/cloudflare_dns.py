from __future__ import annotations

import json
import logging
import os
import socket
import urllib.request
from typing import Any

LOGGER = logging.getLogger("vpn_shop.cloudflare_dns")


class CloudflareDnsError(RuntimeError):
    """Raised when Cloudflare DNS API request fails or violates safety rules."""


def resolve_node_ip(node_domain: str) -> str:
    """
    Динамическое определение IP-адреса ноды по её системному домену.
    Никаких захардкоженных IP: адрес всегда берётся из текущей A-записи домена.
    Например: 'pl.<base_domain>' -> IP
    """
    clean_domain = str(node_domain or "").strip()
    if not clean_domain:
        raise CloudflareDnsError("Node domain cannot be empty")
    try:
        return socket.gethostbyname(clean_domain)
    except Exception as exc:
        raise CloudflareDnsError(f"Could not resolve IP for domain '{clean_domain}': {exc}") from exc


class CloudflareDnsClient:
    """
    Клиент Cloudflare DNS API для аварийного переключения кластера (Disaster Recovery).
    СТРОГОЕ ПРАВИЛО БЕЗОПАСНОСТИ:
    Все записи обязаны быть исключительно в режиме DNS-Only ⚪ ('proxied': False).
    Проксирование Cloudflare (🟠) запрещено ТСПУ/РКН.
    """

    def __init__(self, token: str, zone_id: str) -> None:
        self.token = str(token or "").strip()
        self.zone_id = str(zone_id or "").strip()
        if not self.token or not self.zone_id:
            # Fallback: attempt reading from /etc/cf-failover-dns.env
            env_file = "/etc/cf-failover-dns.env"
            if os.path.exists(env_file):
                try:
                    for line in open(env_file, encoding="utf-8").read().splitlines():
                        if line.startswith("CF_API_TOKEN=") and not self.token:
                            self.token = line.split("=", 1)[1].strip().strip('"').strip("'")
                        elif line.startswith("CF_ZONE_ID=") and not self.zone_id:
                            self.zone_id = line.split("=", 1)[1].strip().strip('"').strip("'")
                except Exception:
                    pass

    @property
    def is_configured(self) -> bool:
        return bool(self.token and self.zone_id)

    def _request(self, method: str, endpoint: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.is_configured:
            raise CloudflareDnsError("Cloudflare API credentials (token/zone_id) are not configured")

        url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}{endpoint}"
        body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": "SilentConnect-Failover/2.0",
        }

        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8")
                parsed = json.loads(raw)
                if not parsed.get("success"):
                    errors = parsed.get("errors") or []
                    raise CloudflareDnsError(f"Cloudflare API error: {errors}")
                return parsed
        except Exception as exc:
            if isinstance(exc, CloudflareDnsError):
                raise
            raise CloudflareDnsError(f"Cloudflare request failed [{method} {endpoint}]: {exc}") from exc

    def get_dns_status(self, managed_domains: list[str]) -> list[dict[str, Any]]:
        """Получить текущий статус A-записей доменов в Cloudflare."""
        statuses = []
        for d in managed_domains:
            clean_d = d.strip()
            res = self._request("GET", f"/dns_records?type=A&name={clean_d}")
            records = res.get("result") or []
            if records:
                rec = records[0]
                statuses.append(
                    {
                        "domain": clean_d,
                        "ip": rec.get("content", ""),
                        "proxied": rec.get("proxied", False),
                        "ttl": rec.get("ttl", 60),
                        "id": rec.get("id", ""),
                    }
                )
            else:
                statuses.append({"domain": clean_d, "ip": "NOT_FOUND", "proxied": False, "ttl": 0, "id": ""})
        return statuses

    def switch_cluster_dns(
        self,
        target_node_domain: str,
        managed_domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Переключение всех основных доменов кластера на целевой узел.
        IP узла динамически резолвится из target_node_domain (например 'pl.<domain>').
        Режим строго форсируется в proxied: False (DNS-Only ⚪).
        """
        if managed_domains is None:
            base = os.environ.get("BASE_DOMAIN", os.environ.get("DOMAIN_MAIN", "example.com"))
            managed_domains = [base, f"sub.{base}", f"edge.{base}"]

        target_ip = resolve_node_ip(target_node_domain)
        updated_records = []

        for d in managed_domains:
            clean_d = d.strip()
            # 1. Поиск ID существующей записи
            search_res = self._request("GET", f"/dns_records?type=A&name={clean_d}")
            records = search_res.get("result") or []
            if not records:
                raise CloudflareDnsError(f"DNS A-record for '{clean_d}' not found in Cloudflare zone")

            rec_id = records[0]["id"]

            # 2. Обновление A-записи со СТРОГИМ proxied: False
            payload = {
                "type": "A",
                "name": clean_d,
                "content": target_ip,
                "ttl": 60,
                "proxied": False,
            }
            update_res = self._request("PUT", f"/dns_records/{rec_id}", payload)
            rec = update_res.get("result") or {}

            # 3. Валидация отсутствия оранжевого облачка
            if rec.get("proxied") is not False:
                raise CloudflareDnsError(
                    f"Safety Violation: Cloudflare Proxied mode is forbidden! '{clean_d}' returned proxied={rec.get('proxied')}"
                )
            if rec.get("content") != target_ip:
                raise CloudflareDnsError(
                    f"Content mismatch: expected {target_ip}, got {rec.get('content')} for '{clean_d}'"
                )

            updated_records.append(
                {
                    "domain": clean_d,
                    "content": rec.get("content"),
                    "proxied": rec.get("proxied"),
                    "ttl": rec.get("ttl"),
                }
            )

        LOGGER.info(
            "Cluster DNS successfully switched to %s (%s): %s",
            target_node_domain,
            target_ip,
            [r["domain"] for r in updated_records],
        )

        return {
            "target_node_domain": target_node_domain,
            "target_ip": target_ip,
            "updated": updated_records,
        }
