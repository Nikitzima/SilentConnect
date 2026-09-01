import importlib.util
import json
import os
import queue
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure paths are importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = PROJECT_ROOT / "vpn-shop"
SUBJSON_DIR = PROJECT_ROOT / "subjson-service"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))
if str(SUBJSON_DIR) not in sys.path:
    sys.path.insert(0, str(SUBJSON_DIR))

# Test environment configuration
os.environ["SECRET_SEGMENT"] = "test-phase-p1-secret"
os.environ["INTERNAL_SECRET"] = "internal-token-p1-xyz"
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "485a96779d1ad79d0fa80ca0"
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"
os.environ["PUBLIC_HOST"] = "sub.example.com"
os.environ["WS443_PUBLIC_HOST"] = "edge.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"

# Import modules
from vpn_shop import catalog, mailer, store, web, xui_db
from vpn_shop.config import Settings
from vpn_shop.store import Store
from vpn_shop.xui_db import XuiDatabase

# Import subjson app
subjson_path = SUBJSON_DIR / "app.py"
spec_subjson = importlib.util.spec_from_file_location("subjson_app_p1", str(subjson_path))
subjson_app = importlib.util.module_from_spec(spec_subjson)
spec_subjson.loader.exec_module(subjson_app)


class TestPhaseP1Hardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.shop_db_path = self.temp_path / "vpn_shop.db"
        self.xui_db_path = self.temp_path / "x-ui.db"
        subjson_app.XUI_DB_PATH = str(self.xui_db_path)
        os.environ["STORE_DB_PATH"] = str(self.shop_db_path)
        os.environ["XUI_DB_PATH"] = str(self.xui_db_path)

        # Initialize mock shop db
        self.store = Store(self.shop_db_path)
        self.store.init()

        # Insert active profile in shop db for renewal tests
        now = int(time.time())
        with sqlite3.connect(self.shop_db_path) as conn:
            conn.execute("""
                INSERT INTO profiles (
                    public_id, xui_inbound_id, transport, profile_mode, xui_email,
                    xui_client_id, status, created_at, expires_at, notes
                )
                VALUES ('prf_test1', 1, 'tcp', 'anonymous', 'test-user@example.com', 'client-uuid-1234', 'active', ?, ?, 'standard_paid')
            """, (now, now + 30 * 86400))
            conn.commit()

        # Initialize mock x-ui db
        self._init_xui_db(self.xui_db_path)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _init_xui_db(self, path: Path):
        conn = sqlite3.connect(path)
        conn.execute("""
            CREATE TABLE inbounds (
                id INTEGER PRIMARY KEY,
                remark TEXT,
                protocol TEXT,
                port INTEGER,
                settings TEXT,
                stream_settings TEXT,
                sniffing TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE client_traffics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER,
                enable INTEGER,
                email TEXT UNIQUE,
                up INTEGER,
                down INTEGER,
                total INTEGER,
                expiry_time INTEGER,
                last_online INTEGER
            )
        """)
        inbound_settings = {
            "clients": [
                {
                    "id": "client-uuid-1234",
                    "email": "test-user@example.com",
                    "subId": "sub_test_p1_user",
                    "expiryTime": 1750000000000,
                    "enable": True,
                    "limitIp": 3,
                }
            ]
        }
        conn.execute(
            "INSERT INTO inbounds (id, remark, protocol, port, settings, stream_settings, sniffing) VALUES (1, 'VLESS-TCP', 'vless', 443, ?, '{}', '{}')",
            (json.dumps(inbound_settings),)
        )
        conn.execute(
            "INSERT INTO client_traffics (inbound_id, enable, email, up, down, total, expiry_time, last_online) VALUES (1, 1, 'test-user@example.com', 100, 200, 300, 1750000000000, 1700000000)",
        )
        conn.commit()
        conn.close()

    # =========================================================================
    # Task 1: Centralized Pricing
    # =========================================================================
    def test_quote_price_authoritative_formula(self):
        """Verify quote_price and calculate_renewal_price produce expected prices and psychological 9-ending rounding."""
        # Standard default base prices (100, 150, 200)
        with patch.dict(os.environ, {
            "MONTHLY_PRICE_3_DEVICES_RUB": "100",
            "MONTHLY_PRICE_6_DEVICES_RUB": "150",
            "MONTHLY_PRICE_9_DEVICES_RUB": "200",
        }):
            # 3 devices
            self.assertEqual(catalog.quote_price(3, 30), 99)
            self.assertEqual(catalog.quote_price(3, 90), 269)   # 100*3 - 10% = 270 -> 269
            self.assertEqual(catalog.quote_price(3, 180), 479)  # 100*6 - 20% = 480 -> 479
            self.assertEqual(catalog.quote_price(3, 360), 839)  # 100*12 - 30% = 840 -> 839

            # 6 devices
            self.assertEqual(catalog.quote_price(6, 30), 149)
            self.assertEqual(catalog.quote_price(6, 90), 409)   # 150*3 - 10% = 405 -> 409
            self.assertEqual(catalog.quote_price(6, 180), 719)  # 150*6 - 20% = 720 -> 719
            self.assertEqual(catalog.quote_price(6, 360), 1259) # 150*12 - 30% = 1260 -> 1259

            # 9 devices
            self.assertEqual(catalog.quote_price(9, 30), 199)
            self.assertEqual(catalog.quote_price(9, 90), 539)   # 200*3 - 10% = 540 -> 539
            self.assertEqual(catalog.quote_price(9, 180), 959)  # 200*6 - 20% = 960 -> 959
            self.assertEqual(catalog.quote_price(9, 360), 1679) # 200*12 - 30% = 1680 -> 1679

            # Alias check
            self.assertEqual(catalog.calculate_renewal_price(9, 90), catalog.quote_price(9, 90))

    def test_quote_price_with_custom_settings(self):
        """Verify quote_price works with explicit Settings instances."""
        mock_settings = MagicMock(spec=Settings)
        mock_settings.monthly_price_3_devices_rub = 199
        mock_settings.monthly_price_6_devices_rub = 299
        mock_settings.monthly_price_9_devices_rub = 399

        self.assertEqual(catalog.quote_price(3, 30, settings=mock_settings), 199)
        self.assertEqual(catalog.quote_price(3, 90, settings=mock_settings), 539)  # (199*3*90)//100 = 537 -> 539
        self.assertEqual(catalog.quote_price(3, 180, settings=mock_settings), 959) # (199*6*80)//100 = 955 -> 959
        self.assertEqual(catalog.quote_price(3, 360, settings=mock_settings), 1669) # (199*12*70)//100 = 1671 -> 1669

    def test_subjson_renewal_uses_centralized_pricing(self):
        """Verify create_inline_renewal_order calculates price through catalog.quote_price without price drift."""
        with patch.dict(os.environ, {
            "MONTHLY_PRICE_3_DEVICES_RUB": "100",
            "MONTHLY_PRICE_6_DEVICES_RUB": "150",
            "MONTHLY_PRICE_9_DEVICES_RUB": "200",
            "STORE_DB_PATH": str(self.shop_db_path),
            "XUI_DB_PATH": str(self.xui_db_path),
        }):
            order = subjson_app.create_inline_renewal_order(
                sub_id="sub_test_p1_user",
                device_limit=9,
                duration_days=90,
            )
            # Price must match catalog authoritative quote_price (539 RUB)
            expected_price = catalog.quote_price(9, 90)
            self.assertEqual(order["final_price_rub"], expected_price)
            self.assertEqual(order["final_price_rub"], 539)

    # =========================================================================
    # Task 2: SQLite Resilience & Context Cleanup
    # =========================================================================
    def test_store_connect_busy_timeout_pragma(self):
        """Verify Store._connect sets timeout=30.0 and executes PRAGMA busy_timeout = 30000."""
        with self.store._connect() as conn:
            row = conn.execute("PRAGMA busy_timeout;").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], 30000)

    def test_xui_db_connect_busy_timeout_pragma(self):
        """Verify XuiDatabase._connect sets timeout=30.0 and executes PRAGMA busy_timeout = 30000."""
        xdb = XuiDatabase(self.xui_db_path)
        with xdb._connect() as conn:
            row = conn.execute("PRAGMA busy_timeout;").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], 30000)

    def test_subjson_sqlite_connection_leak_prevention(self):
        """Verify create_inline_renewal_order safely closes connections even under error conditions."""
        with patch.dict(os.environ, {
            "STORE_DB_PATH": str(self.shop_db_path),
            "XUI_DB_PATH": str(self.xui_db_path),
        }):
            # Trigger ValueError on invalid subscription ID
            with self.assertRaises(ValueError):
                subjson_app.create_inline_renewal_order(
                    sub_id="nonexistent_sub_id_xyz",
                    device_limit=3,
                    duration_days=30,
                )

            # Ensure we can still perform exclusive DB operations without file lock errors
            with sqlite3.connect(self.shop_db_path, timeout=5.0) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS lock_test (id INT)")
                conn.commit()

    # =========================================================================
    # Task 3: HTTP Server Hardening (Slowloris / Socket Timeout)
    # =========================================================================
    def test_request_handler_socket_timeout_configured(self):
        """Verify both subjson RequestHandler and web RequestHandler configure socket timeout."""
        # 1. subjson RequestHandler
        self.assertEqual(subjson_app.RequestHandler.timeout, 15.0)
        
        # 2. web RequestHandler
        self.assertEqual(web.RequestHandler.timeout, 15.0)

        # 3. Test setup() method sets timeout on socket
        mock_socket = MagicMock()
        mock_server = MagicMock()
        
        # Create subjson handler instance without calling standard constructor
        handler = subjson_app.RequestHandler.__new__(subjson_app.RequestHandler)
        handler.request = mock_socket
        handler.client_address = ("127.0.0.1", 12345)
        handler.server = mock_server
        handler.rfile = MagicMock()
        handler.wfile = MagicMock()
        
        with patch.object(subjson_app.BaseHTTPRequestHandler, "setup", return_value=None):
            handler.setup()
            mock_socket.settimeout.assert_called_with(15.0)

        # Create web handler instance
        web_handler = web.RequestHandler.__new__(web.RequestHandler)
        web_handler.request = mock_socket
        web_handler.client_address = ("127.0.0.1", 12345)
        web_handler.server = mock_server
        web_handler.rfile = MagicMock()
        web_handler.wfile = MagicMock()

        with patch.object(web.BaseHTTPRequestHandler, "setup", return_value=None):
            web_handler.setup()
            mock_socket.settimeout.assert_called_with(15.0)

    # =========================================================================
    # Task 4: Bounded Email Worker Queue
    # =========================================================================
    def test_email_bounded_worker_queue_structure(self):
        """Verify email dispatcher uses a bounded Queue(maxsize=1000)."""
        self.assertIsInstance(mailer._EMAIL_QUEUE, queue.Queue)
        self.assertEqual(mailer._EMAIL_QUEUE.maxsize, 1000)

    def test_email_enqueue_and_worker_processing(self):
        """Verify tasks enqueued via enqueue_email_task are processed by background workers."""
        processed_event = threading.Event()
        received_args = []

        def dummy_email_task(arg1, kwarg1=""):
            received_args.append((arg1, kwarg1))
            processed_event.set()

        ok = mailer.enqueue_email_task(dummy_email_task, "test_arg", kwarg1="test_kwarg")
        self.assertTrue(ok)
        
        # Wait for background worker to consume item
        self.assertTrue(processed_event.wait(timeout=3.0))
        self.assertEqual(received_args, [("test_arg", "test_kwarg")])

    def test_async_email_helpers_enqueue_without_spawning_unbounded_threads(self):
        """Verify send_subscription_email_async and send_cabinet_access_email_async enqueue to bounded queue."""
        mock_settings = MagicMock(spec=Settings)
        mock_settings.smtp_host = ""  # Disables actual SMTP network call

        with patch.object(mailer, "enqueue_email_task") as mock_enqueue:
            mailer.send_subscription_email_async(
                mock_settings,
                customer_email="customer@example.com",
                order_public_id="ord_test123",
                plan_name="Standard",
                duration_days=30,
                setup_url="https://example.com/setup",
                json_url="https://example.com/json",
                cabinet_url="https://example.com/cabinet",
            )
            mock_enqueue.assert_called_once()

        with patch.object(mailer, "enqueue_email_task") as mock_enqueue:
            mailer.send_cabinet_access_email_async(
                mock_settings,
                customer_email="customer@example.com",
                profiles_data=[{"public_id": "prf_123"}],
            )
            mock_enqueue.assert_called_once()

    # =========================================================================
    # Task 5: Quiesce State Hardening
    # =========================================================================
    def test_quiesce_persists_during_maintenance_without_accidental_expiry(self):
        """Verify Quiesce remains active during long operations unless explicitly released."""
        with subjson_app.QUIESCE_LOCK:
            subjson_app.QUIESCE_ACTIVE = True
            subjson_app.QUIESCE_LEASE_UNTIL = time.time() - 100.0  # Lease expired long ago in maintenance

        # Under hardened mode, quiesce stays active to avoid split-brain writes during failover
        self.assertTrue(subjson_app.is_quiesced())

        # Explicit release should reset quiesce
        with subjson_app.QUIESCE_LOCK:
            subjson_app.QUIESCE_ACTIVE = False
            subjson_app.QUIESCE_LEASE_UNTIL = 0.0

        self.assertFalse(subjson_app.is_quiesced())


if __name__ == "__main__":
    unittest.main(verbosity=2)
