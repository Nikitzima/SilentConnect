"""Live security/regression checks against the DE staging hosts.

Skipped unless SC_LIVE_PREVIEW=1 so CI never hits the network by default.
Run: SC_LIVE_PREVIEW=1 python -m pytest tests/test_preview_live_security.py -v
"""
import json
import os
import ssl
import unittest
import urllib.error
import urllib.request

LIVE = os.environ.get("SC_LIVE_PREVIEW") == "1"
SHOP = "https://preview.example.com"
SUB = "https://previewsub.example.com"
SEG = "/my-secret-sub"
SUB_ID = os.environ.get("SC_PREVIEW_SUB_ID", "28njm8v72ruyu2he")
EVIL = {"Origin": "https://evil.example"}


def _req(method, url, data=None, headers=None):
    h = dict(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        resp = urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=20)
        return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


@unittest.skipUnless(LIVE, "set SC_LIVE_PREVIEW=1 to run live staging checks")
class TestPreviewLiveSecurity(unittest.TestCase):
    def test_security_headers_and_no_cors(self):
        status, headers, _ = _req("GET", SHOP + "/")
        self.assertEqual(status, 200)
        self.assertIn("max-age=", headers.get("Strict-Transport-Security", ""))
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

    def test_path_traversal_blocked(self):
        for path in ("/assets/../../etc/passwd", "/assets/%2e%2e/%2e%2e/etc/passwd"):
            status, _, body = _req("GET", SHOP + path)
            self.assertEqual(status, 404, path)
            self.assertNotIn(b"root:", body)

    def test_unknown_order_and_cabinet_token_404(self):
        self.assertEqual(_req("GET", SHOP + "/order/ord_nonexistent/badtoken")[0], 404)
        self.assertEqual(_req("GET", SHOP + "/cabinet/badtoken")[0], 404)

    def test_cross_origin_posts_rejected(self):
        for url, data in (
            (SHOP + "/api/check-promo", {"code": "X"}),
            (SHOP + "/api/cabinet/request-link", {"email": "a@b.co"}),
            (SHOP + "/order", None),
            (SUB + SEG + f"/awg/{SUB_ID}/slot/1/rename", {"name": "x"}),
            (SUB + f"/api/sub/openflux/{SUB_ID}/switch/cancel", {}),
        ):
            status, _, _ = _req("POST", url, data, EVIL)
            self.assertEqual(status, 403, url)

    def test_cabinet_link_requires_turnstile(self):
        status, _, body = _req("POST", SHOP + "/api/cabinet/request-link", {"email": "a@b.co"})
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])

    def test_wrong_secret_segment_and_unknown_sub_404(self):
        self.assertEqual(_req("GET", SUB + f"/wrong-secret/import/{SUB_ID}")[0], 404)
        self.assertEqual(_req("GET", SUB + SEG + "/import/doesnotexist")[0], 404)
        self.assertEqual(_req("GET", SUB + SEG + "/qr/doesnotexist")[0], 404)

    def test_slot_index_beyond_device_limit_rejected(self):
        status, _, _ = _req("GET", SUB + SEG + f"/awg/{SUB_ID}/slot/99/qr")
        self.assertEqual(status, 400)

    def test_qr_endpoints_return_png(self):
        for url in (SUB + SEG + f"/qr/{SUB_ID}", SUB + SEG + f"/awg/{SUB_ID}/slot/1/qr"):
            status, headers, body = _req("GET", url)
            self.assertEqual(status, 200, url)
            self.assertTrue(body.startswith(b"\x89PNG"), url)

    def test_branding_avatar_served(self):
        for host in (SHOP, SUB):
            status, _, _ = _req("GET", host + "/assets/branding/avatar.webp")
            self.assertEqual(status, 200, host)

    def test_promo_unknown_code_rejected(self):
        status, _, body = _req("POST", SHOP + "/api/check-promo", {"code": "NONEXISTENTPROMO", "plan": "6", "months": 12},
                               {"Origin": SHOP})
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])


if __name__ == "__main__":
    unittest.main()
