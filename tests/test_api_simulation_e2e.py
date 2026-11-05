from __future__ import annotations

from dataclasses import replace
import os
import pathlib
import subprocess
import sys
import time
from unittest.mock import MagicMock
import urllib.request
import urllib.error
import unittest
try:
    import pytest
except ImportError:
    raise unittest.SkipTest("pytest is not installed")

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = ROOT_DIR / "vpn-shop"
SUBJSON_DIR = ROOT_DIR / "subjson-service"

for p in (str(VPN_SHOP_DIR), str(SUBJSON_DIR), str(ROOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from vpn_shop.platega import PlategaClient, PlategaError, PlategaApiError, PlategaAuthError
from vpn_shop.web import verify_cf_turnstile, WebCheckout
from vpn_shop.store import Store
from vpn_shop.config import load_settings


SIMULATION_PORT = 4900
SIM_BASE_URL = f"http://127.0.0.1:{SIMULATION_PORT}"


@pytest.fixture(scope="module")
def postman_simulation():
    """Starts postman simulation for shop-deps on port 4900 and cleanly tears it down after tests."""
    sim_path = (ROOT_DIR / "postman" / "simulations" / "shop-deps.sim.yaml").resolve()
    assert sim_path.is_file(), f"Simulation file not found: {sim_path}"

    cmd = f'postman simulation run "{sim_path}" --port {SIMULATION_PORT} --no-history'

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=True,
    )

    healthy = False
    start_time = time.time()
    while time.time() - start_time < 12:
        try:
            req = urllib.request.Request(f"{SIM_BASE_URL}/platega/test/reset", method="POST")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    healthy = True
                    break
        except Exception:
            time.sleep(0.5)

    if not healthy:
        try:
            subprocess.run(f"taskkill /F /T /PID {proc.pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        pytest.skip(f"Postman simulation did not start on port {SIMULATION_PORT}")

    yield proc

    try:
        subprocess.run(f"taskkill /F /T /PID {proc.pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def test_platega_create_transaction_live_simulation(postman_simulation):
    """Verifies that PlategaClient communicates with simulated Platega API over real HTTP."""
    client = PlategaClient(
        merchant_id_web="test_merchant",
        secret_web="test_secret",
        base_url=f"{SIM_BASE_URL}/platega",
    )

    resp = client.create_transaction(
        amount=149,
        currency="RUB",
        description="SilentConnect VPN Test",
        payload="uuid_sim_01",
        is_bot=False,
    )

    assert resp.get("transactionId") is not None
    assert resp.get("url") is not None
    assert "preview.example.com" in resp["url"]


def test_platega_get_transaction_status_live_simulation(postman_simulation):
    """Verifies that PlategaClient checks transaction status over real HTTP."""
    client = PlategaClient(
        merchant_id_web="test_merchant",
        secret_web="test_secret",
        base_url=f"{SIM_BASE_URL}/platega",
    )

    status_resp = client.get_transaction_status("tx_sim_manual_01", is_bot=False)
    assert status_resp.get("status") in ("PENDING", "CONFIRMED")
    assert status_resp.get("transactionId") == "tx_sim_manual_01"


def test_turnstile_verify_live_simulation(postman_simulation, monkeypatch):
    """Verifies Cloudflare Turnstile token validation over real HTTP."""
    monkeypatch.setenv("CF_TURNSTILE_VERIFY_URL", f"{SIM_BASE_URL}/turnstile/turnstile/v0/siteverify")

    # 1. Valid token
    ok = verify_cf_turnstile(
        secret_key="0x4AAAAAAtestsecret",
        response_token="valid_token_pass",
        client_ip="127.0.0.1",
    )
    assert ok is True

    # 2. Invalid token
    bad = verify_cf_turnstile(
        secret_key="0x4AAAAAAtestsecret",
        response_token="fail_token_invalid",
        client_ip="127.0.0.1",
    )
    assert bad is False


def test_platega_webhook_idempotency_live_simulation(postman_simulation, tmp_path):
    """Verifies WebCheckout callback processing, status verification against simulation, and duplicate rejection."""
    db_file = tmp_path / "sim_store.db"
    store = Store(db_file)
    store.init()

    # Initialize WebCheckout with simulated Platega client
    base_settings = load_settings(VPN_SHOP_DIR)
    settings = replace(
        base_settings,
        root_dir=VPN_SHOP_DIR,
        database_path=db_file,
        platega_enabled=True,
        platega_merchant_id_web="test_merchant",
        platega_secret_web="test_secret",
        web_public_base_url="https://preview.example.com",
    )

    checkout = WebCheckout(settings, store)
    checkout.platega.base_url = f"{SIM_BASE_URL}/platega"

    # Mock bot to avoid sending real Telegram notifications during webhook processing
    mock_bot = MagicMock()
    checkout._bot = mock_bot

    # Create dummy order via WebCheckout
    order = checkout.create_order("tcp_3_30", "", customer_email="test_sim@example.com")
    order_id = order["id"]
    order_pub_id = str(order["public_id"])
    final_amount = float(order["final_price_rub"])
    tx_id = "tx_sim_live_999"

    # Link transaction ID to order metadata
    meta = order.get("meta_json") or {}
    meta["platega_transaction_id"] = tx_id
    store.update_order_meta(order_id, meta)

    # Simulate Platega sending webhook
    headers = {
        "X-MerchantId": "test_merchant",
        "X-Secret": "test_secret",
    }
    webhook_data = {
        "id": tx_id,
        "status": "CONFIRMED",
        "amount": final_amount,
        "currency": "RUB",
        "payload": order_pub_id,
    }

    # 1. Verify signature check passes
    assert checkout.platega.verify_webhook_signature(headers) is True

    # 2. Verify signature check rejects forged secret
    assert checkout.platega.verify_webhook_signature({"X-MerchantId": "test_merchant", "X-Secret": "hacked"}) is False

    # 3. First callback delivery: should process successfully
    result1, status1 = checkout.handle_platega_callback(webhook_data)
    assert status1 == 200
    assert result1.get("status") == "ok"
    assert result1.get("message") == "confirmed"
    assert mock_bot.complete_order.call_count == 1

    # 4. Duplicate callback delivery: should be detected as duplicate without side effects
    result2, status2 = checkout.handle_platega_callback(webhook_data)
    assert status2 == 200
    assert result2.get("status") == "ok"
    assert result2.get("message") == "duplicate_ignored"
    # Order must NOT be completed a second time
    assert mock_bot.complete_order.call_count == 1


def test_platega_outage_graceful_handling():
    """Verifies that when Platega is completely down / unreachable, PlategaClient raises PlategaError and WebCheckout handles it safely."""
    dead_client = PlategaClient(
        merchant_id_web="test_merchant",
        secret_web="test_secret",
        base_url="http://127.0.0.1:59999",
        timeout_seconds=3,
    )

    with pytest.raises(PlategaError):
        dead_client.create_transaction(amount=100, is_bot=False)
