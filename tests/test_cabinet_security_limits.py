import os
import sys
import unittest
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'vpn-shop'))
sys.path.insert(0, str(ROOT / 'subjson-service'))

os.environ.setdefault('SERVER_PEPPER', 'unit-test-pepper-0123456789abcdefghijklmnop')
os.environ.setdefault('SECRET_SEGMENT', 'test-secret-sub')
os.environ.setdefault('HYSTERIA_SALAMANDER_PASSWORD', 'test-salamander-pwd-123')
os.environ.setdefault('HYSTERIA_AUTH_PASSWORD', 'test-auth-pwd-123')

from vpn_shop import security
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout
from vpn_shop.config import Settings

class CabinetSecurityLimitsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = Store(self.tmp / 'vpn_shop.db')
        self.store.init()
        self.settings = Settings(
            root_dir=self.tmp,
            data_dir=self.tmp,
            database_path=self.tmp / 'vpn_shop.db',
            telegram_bot_token='mock',
            telegram_bot_username='mock',
            brand_name='SilentConnect',
            support_tg_url='https://t.me/support',
            welcome_media='',
            quickstart_media='',
            admin_usernames=(),
            admin_user_ids=(),
            subscription_base_url='https://sub.example.com',
            payment_instructions_text='',
            payment_transfer_url='',
            payment_bank_note='',
            xui_panel_url='http://mock',
            xui_username='admin',
            xui_password='admin',
            xui_verify_tls=False,
            xui_db_path=self.tmp / 'x-ui.db',
            xui_xhttp_inbound_id=1,
            xui_tcp_inbound_id=2,
            web_listen_host='127.0.0.1',
            web_listen_port=8080,
            web_public_base_url='https://example.com',
            monthly_price_xhttp_rub=149,
            monthly_price_tcp_rub=149,
            monthly_price_3_devices_rub=149,
            monthly_price_6_devices_rub=199,
            monthly_price_9_devices_rub=235,
            default_device_limit=3,
            invite_required=False,
            terms_version='2026-04-20',
            purge_after_days=30,
            support_email='support@example.com',
            smtp_host='',
            smtp_port=465,
            smtp_user='',
            smtp_password='',
            smtp_from_email='',
            cf_turnstile_site_key='',
            cf_turnstile_secret_key='',
            cf_turnstile_enabled=False,
        )
        self.checkout = WebCheckout(settings=self.settings, store=self.store)

    def test_magic_link_invalidates_previous(self):
        email = 'user@test.com'
        tok1 = security.sign_token({'email': email}, purpose='magic_link', ttl_seconds=1800)
        self.store.create_magic_link(email=email, token=tok1, ttl_seconds=1800, request_ip='192.0.2.1')

        # Link 1 works
        self.assertEqual(self.store.consume_magic_link(tok1, single_use=False), email)

        # Generate Link 2
        tok2 = security.sign_token({'email': email}, purpose='magic_link', ttl_seconds=1800)
        self.store.create_magic_link(email=email, token=tok2, ttl_seconds=1800, request_ip='192.0.2.1')

        # Link 1 is now canceled / expired!
        self.assertIsNone(self.store.consume_magic_link(tok1, single_use=False))

        # Link 2 works!
        self.assertEqual(self.store.consume_magic_link(tok2, single_use=False), email)

    def test_magic_link_max_3_per_30_minutes(self):
        email = 'quota@test.com'
        headers = type('Headers', (), {'peer_ip': '192.0.2.1', 'get': lambda self, k, d=None: None})()

        # Request 1: OK
        res1 = self.checkout.request_cabinet_access_link(headers, email)
        self.assertTrue(res1['ok'])

        # Advance time by 25s to bypass burst cooldown
        with self.store.transaction() as conn:
            conn.execute('UPDATE magic_links SET created_at = created_at - 25 WHERE email = ?', (email,))

        # Request 2: OK
        res2 = self.checkout.request_cabinet_access_link(headers, email)
        self.assertTrue(res2['ok'])

        # Advance time by another 25s
        with self.store.transaction() as conn:
            conn.execute('UPDATE magic_links SET created_at = created_at - 25 WHERE email = ?', (email,))

        # Request 3: OK
        res3 = self.checkout.request_cabinet_access_link(headers, email)
        self.assertTrue(res3['ok'])

        # Advance time by another 25s
        with self.store.transaction() as conn:
            conn.execute('UPDATE magic_links SET created_at = created_at - 25 WHERE email = ?', (email,))

        # Request 4 (within 30m window): REJECTED!
        res4 = self.checkout.request_cabinet_access_link(headers, email)
        self.assertFalse(res4['ok'])
        self.assertIn('не более 3 ссылок за 30 минут', res4['message'])

    def test_magic_link_burst_cooldown(self):
        email = 'burst@test.com'
        headers = type('Headers', (), {'peer_ip': '192.0.2.1', 'get': lambda self, k, d=None: None})()

        # Immediate request 1
        res1 = self.checkout.request_cabinet_access_link(headers, email)
        self.assertTrue(res1['ok'])

        # Immediate request 2 (under 20s cooldown)
        res2 = self.checkout.request_cabinet_access_link(headers, email)
        self.assertFalse(res2['ok'])
        self.assertIn('уже отправляется', res2['message'])


    def test_bind_email_limit_5_per_day(self):
        import sqlite3
        import importlib
        from unittest.mock import patch

        subjson_app = importlib.import_module('app')
        
        # Setup mock subscription
        mock_client = {'email': 'client-test-sub@example.com', 'expiryTime': 0, 'id': 'sub-uuid-1'}
        mock_row = {'id': 1}
        
        with patch.object(subjson_app, 'find_subscription', return_value=(mock_row, None, None, None, mock_client)),              patch.object(subjson_app, 'find_store_db_path', return_value=str(self.tmp / 'vpn_shop.db')),              patch.object(subjson_app, 'get_shop_settings', return_value=self.settings):

            sub_id = 'test-sub-123'
            
            # First 5 changes: should succeed
            for i in range(1, 6):
                email = f'user{i}@test.com'
                res = subjson_app.bind_subscription_email(
                    sub_id=sub_id,
                    customer_email=email,
                    client_ip='10.0.0.1'
                )
                self.assertEqual(res['customer_email'], email)
                
            # Re-binding the SAME 5th email again (no-op): should succeed!
            res_same = subjson_app.bind_subscription_email(
                sub_id=sub_id,
                customer_email='user5@test.com',
                client_ip='10.0.0.1'
            )
            self.assertEqual(res_same['customer_email'], 'user5@test.com')

            # 6th distinct email change within 24h: MUST FAIL!
            with self.assertRaises(ValueError) as ctx:
                subjson_app.bind_subscription_email(
                    sub_id=sub_id,
                    customer_email='user6@test.com',
                    client_ip='10.0.0.1'
                )
            self.assertIn('Нельзя менять почту более 5 раз в день', str(ctx.exception))

if __name__ == '__main__':
    unittest.main()
