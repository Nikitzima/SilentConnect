import base64
import os
import sys

# Setup environment before importing app
os.environ['HYSTERIA_SALAMANDER_PASSWORD'] = '485a96779d1ad79d0fa80ca0'  # PLACEHOLDER
os.environ['HYSTERIA_AUTH_PASSWORD'] = 'test_auth_pass_443'  # PLACEHOLDER
os.environ['SECRET_SEGMENT'] = 'test-secret'  # PLACEHOLDER
os.environ['INTERNAL_SECRET'] = 'internal-token-xyz'  # PLACEHOLDER
os.environ['RELAY_PUBLIC_HOST'] = 'relay.example.com'
os.environ['LISTEN_PORT'] = '3088'
os.environ['PUBLIC_HOST'] = 'sub.example.com'
os.environ['PUBLIC_SUBSCRIPTION_ORIGIN'] = 'https://sub.example.com'
os.environ['WS443_PUBLIC_HOST'] = 'edge.example.com'
os.environ['FI_STANDBY_HOST'] = 'fi.example.com'

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
APP_DIR = os.path.join(PROJECT_ROOT, 'subjson-service')
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import unittest
import urllib.parse
import app as subjson_app


class PolandProfilesIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.orig_pl = os.environ.get('PL_STANDBY_HOST')
        os.environ['PL_STANDBY_HOST'] = 'pl.silentconnect.net'

    def tearDown(self):
        if self.orig_pl is not None:
            os.environ['PL_STANDBY_HOST'] = self.orig_pl
        else:
            os.environ.pop('PL_STANDBY_HOST', None)

    def test_streisand_bundle_includes_poland_5_profiles(self):
        b64_str = subjson_app.build_streisand_bundle('MainDefConf', 'sub.example.com')
        raw_text = base64.b64decode(b64_str).decode('utf-8')
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

        self.assertEqual(len(lines), 15, f'Expected 15 URIs with Poland, got {len(lines)}')
        
        pl_lines = [l for l in lines if 'pl.silentconnect.net' in l or 'Польша' in l or 'PL' in l]
        self.assertEqual(len(pl_lines), 5, f'Expected 5 Poland URIs, found: {pl_lines}')

        pl_classic = next(l for l in pl_lines if '11. Классический' in urllib.parse.unquote(l))
        self.assertIn('sni=swdist.apple.com', pl_classic)
        self.assertIn(':443', pl_classic)
        self.assertIn('security=reality', pl_classic)

        pl_fast = next(l for l in pl_lines if '12. Быстрый' in urllib.parse.unquote(l))
        self.assertIn('sni=gateway.icloud.com', pl_fast)
        self.assertIn(':443', pl_fast)

        pl_hy2 = next(l for l in pl_lines if '13. Скоростной' in urllib.parse.unquote(l))
        self.assertTrue(pl_hy2.startswith('hy2://'))

        pl_grpc = next(l for l in pl_lines if '14. Запасной' in urllib.parse.unquote(l))
        self.assertIn(':29443', pl_grpc)
        self.assertIn('type=grpc', pl_grpc)

        pl_xhttp = next(l for l in pl_lines if '15. Незаметный' in urllib.parse.unquote(l))
        self.assertIn(':8443', pl_xhttp)
        self.assertIn('type=xhttp', pl_xhttp)

    def test_four_profiles_includes_poland_5_profiles(self):
        profiles = subjson_app.build_four_profiles('MainDefConf', 'sub.example.com')
        self.assertEqual(len(profiles), 16, f'Expected 16 profiles (1 balancer + 15 nodes), got {len(profiles)}')
        
        remarks = [p.get('remarks', '') for p in profiles]
        pl_remarks = [r for r in remarks if '🇵🇱' in r]
        self.assertEqual(len(pl_remarks), 5)


if __name__ == '__main__':
    unittest.main()
