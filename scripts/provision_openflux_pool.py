#!/usr/bin/env python3
"""
provision_openflux_pool.py
Automated shard pool provisioning and manager for OpenFlux Core v0.2.0 exit nodes.

Uses Yandex Disk REST API to create, upload minimal DOCX documents, publish them,
and register active shards for NL, PL, and FI exit nodes.
"""

import sys
import os
import io
import json
import time
import zipfile
import argparse
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SEEDS = {
    "nl": [
        "https://disk.yandex.ru/i/_-g0vNUuu69ffw"
    ],
    "pl": [
        "https://disk.yandex.ru/i/hb1xodFfECGL8w"
    ],
    "fi": [
        "https://yadi.sk/d/I0ULWUKv_9YzpA"
    ]
}

def create_minimal_docx() -> bytes:
    """Generate a valid, compact DOCX document for Yandex Volga sessions."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>",
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>",
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>OpenFlux Node Session Shard</w:t></w:r></w:p></w:body>"
            "</w:document>",
        )
    return buf.getvalue()


class YandexDiskProvisioner:
    BASE_URL = "https://cloud-api.yandex.net/v1/disk/resources"

    def __init__(self, oauth_token: str):
        self.token = oauth_token.strip()
        self.headers = {
            "Authorization": f"OAuth {self.token}",
            "User-Agent": "SilentConnect-OpenFlux-Provisioner/1.0",
        }

    def _request(self, method: str, url: str, data: bytes = None, headers: dict = None) -> dict:
        req_headers = dict(self.headers)
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read()
            if content:
                try:
                    return json.loads(content.decode("utf-8"))
                except Exception:
                    return {"raw": content}
            return {}

    def ensure_dir(self, dir_path: str):
        url = f"{self.BASE_URL}?path={urllib.parse.quote(dir_path)}"
        try:
            self._request("PUT", url)
        except urllib.error.HTTPError as e:
            if e.code != 409:  # 409 means directory already exists
                raise

    def upload_and_publish(self, disk_path: str, file_bytes: bytes) -> str:
        # 1. Get upload link
        upload_meta_url = (
            f"{self.BASE_URL}/upload?path={urllib.parse.quote(disk_path)}&overwrite=true"
        )
        meta = self._request("GET", upload_meta_url)
        upload_href = meta.get("href")
        if not upload_href:
            raise RuntimeError(f"Could not obtain upload URL for {disk_path}: {meta}")

        # 2. Upload file content via PUT
        upload_req = urllib.request.Request(
            upload_href, data=file_bytes, method="PUT", headers={"Content-Type": "application/octet-stream"}
        )
        with urllib.request.urlopen(upload_req, timeout=30) as upload_resp:
            if upload_resp.status not in (200, 201, 202):
                raise RuntimeError(f"Upload failed with HTTP {upload_resp.status}")

        # 3. Publish resource
        publish_url = f"{self.BASE_URL}/publish?path={urllib.parse.quote(disk_path)}"
        self._request("PUT", publish_url)

        # 4. Fetch public URL
        info_url = f"{self.BASE_URL}?path={urllib.parse.quote(disk_path)}"
        info = self._request("GET", info_url)
        public_url = info.get("public_url")
        if not public_url:
            raise RuntimeError(f"Could not retrieve public URL for {disk_path}: {info}")
        return public_url


def provision_pool(country: str, count: int, token: str | None = None, output_file: Path = None, extra_urls: list[str] = None) -> dict:
    country = country.lower().strip()
    shards = []

    # Include existing/extra URLs first
    seeds = list(extra_urls or [])
    if not seeds and country in DEFAULT_SEEDS:
        seeds = list(DEFAULT_SEEDS[country])

    for idx, s_url in enumerate(seeds, 1):
        shards.append({
            "id": f"{country}_{idx:02d}",
            "url": s_url,
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    # If OAuth token provided, create additional fresh documents via API
    if token:
        print(f"[*] Connecting to Yandex Disk API for country '{country}'...")
        prov = YandexDiskProvisioner(token)
        folder = f"/openflux_pool_{country}"
        prov.ensure_dir(folder)
        docx_data = create_minimal_docx()

        start_idx = len(shards) + 1
        needed = max(0, count - len(shards))
        for i in range(start_idx, start_idx + needed):
            fname = f"shard_{country}_{i:02d}.docx"
            disk_path = f"{folder}/{fname}"
            print(f"    -> Uploading & publishing {disk_path}...")
            try:
                pub_url = prov.upload_and_publish(disk_path, docx_data)
                print(f"       Public URL: {pub_url}")
                shards.append({
                    "id": f"{country}_{i:02d}",
                    "url": pub_url,
                    "active": True,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
                time.sleep(0.5)
            except Exception as exc:
                print(f"    [!] Error uploading {disk_path}: {exc}")

    pool_data = {
        "country": country,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total_shards": len(shards),
        "shards": shards,
    }

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(pool_data, f, ensure_ascii=False, indent=2)
        print(f"[OK] Saved pool to {output_file} with {len(shards)} shards.")

    return pool_data


def main():
    parser = argparse.ArgumentParser(description="Provision OpenFlux Yandex Document Pools")
    parser.add_argument("--country", choices=["nl", "pl", "fi"], default="nl", help="Target country code")
    parser.add_argument("--count", type=int, default=5, help="Target total shard count")
    parser.add_argument("--token", default=os.environ.get("YANDEX_DISK_TOKEN"), help="Yandex Disk OAuth token")
    parser.add_argument("--out", type=str, default=None, help="Output pool json path")
    parser.add_argument("--add-url", action="append", default=[], help="Add specific document URL(s)")

    args = parser.parse_args()
    out_path = Path(args.out) if args.out else Path(f"/etc/openflux-node/pool_{args.country}.json")

    pool = provision_pool(
        country=args.country,
        count=args.count,
        token=args.token,
        output_file=out_path,
        extra_urls=args.add_url,
    )
    print(f"Pool for {args.country.upper()}: {pool['total_shards']} shards active.")


if __name__ == "__main__":
    main()
