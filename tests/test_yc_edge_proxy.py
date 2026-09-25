#!/usr/bin/env python3
"""
Unit tests for SilentConnect Yandex Cloud Serverless Edge Proxy logic.
Verifies caching exclusion rules, host-aware cache keys, query parameter sanitization,
and emergency fallback handlers.
"""

import unittest
import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PROXY_JS = BASE_DIR / "sub-proxy" / "yandex-cloud" / "index.js"


class TestYCEdgeProxyLogic(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PROXY_JS.exists(), f"File {PROXY_JS} must exist.")
        self.js_code = PROXY_JS.read_text(encoding="utf-8")

    def test_cache_exclusion_rules_present(self):
        """Ensure critical dynamic routes are explicitly excluded from microcache."""
        self.assertIn("!fullPath.startsWith('/order')", self.js_code)
        self.assertIn("!fullPath.startsWith('/api/')", self.js_code)
        self.assertIn("!fullPath.startsWith('/cabinet')", self.js_code)
        self.assertIn("!fullPath.startsWith('/auth')", self.js_code)
        self.assertIn("!fullPath.includes('/renew')", self.js_code)

    def test_host_isolated_cache_key(self):
        """Ensure cache keys are isolated by incoming host to prevent cross-domain contamination."""
        self.assertIn("const cacheKey = `${incomingHost}:${httpMethod}:${fullPath}`;", self.js_code)

    def test_query_string_duplicate_protection(self):
        """Ensure query strings are not duplicated when fullPath already contains query parameters."""
        self.assertIn("if (!fullPath.includes('?'))", self.js_code)

    def test_upstream_failover_topology(self):
        """Ensure UPSTREAM_NODES contains NL, PL, and FI in correct priority order."""
        self.assertIn("const UPSTREAM_NODES = [", self.js_code)
        nl_match = re.search(r"{\s*name:\s*'NL'", self.js_code)
        pl_match = re.search(r"{\s*name:\s*'PL'", self.js_code)
        fi_match = re.search(r"{\s*name:\s*'FI'", self.js_code)
        self.assertIsNotNone(nl_match, "NL node must be primary upstream")
        self.assertIsNotNone(pl_match, "PL node must be standby upstream")
        self.assertIsNotNone(fi_match, "FI node must be second standby upstream")
        self.assertTrue(nl_match.start() < pl_match.start() < fi_match.start(), "Upstream order must be NL -> PL -> FI")

    def test_failover_status_codes(self):
        """Ensure 502-504 trigger failover to next node."""
        self.assertIn("upstreamResp.status >= 502 && upstreamResp.status <= 504", self.js_code)

    def test_emergency_fallback_syntax(self):
        """Verify emergency fallback handles fullPath and does not reference undefined variables."""
        self.assertIn("const lowerPath = (fullPath || '').toLowerCase();", self.js_code)
        self.assertIn("emergencySingbox", self.js_code)
        self.assertIn("emergencyHapp", self.js_code)
        self.assertIn("emergencyHtml", self.js_code)

    def test_forwarded_headers_propagation(self):
        """Ensure X-Forwarded-Host and X-Forwarded-Proto are explicitly propagated to upstream."""
        self.assertIn("fwdHeaders.set('X-Forwarded-Host',", self.js_code)
        self.assertIn("fwdHeaders.set('X-Forwarded-Proto', 'https');", self.js_code)
        self.assertIn("fwdHeaders.set('X-Forwarded-For', clientIp);", self.js_code)


if __name__ == "__main__":
    unittest.main()
