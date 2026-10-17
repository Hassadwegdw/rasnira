import importlib.util
import json
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("server", Path(__file__).resolve().parents[1] / "server.py")
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class URLPolicyTests(unittest.TestCase):
    def test_reject_private_dns(self):
        with patch.object(server.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                server.resolve_public("example.org")

    def test_reject_ipv6_mapped(self):
        with patch.object(server.socket, "getaddrinfo", return_value=[(10, 1, 6, "", ("::ffff:8.8.8.8", 443, 0, 0))]):
            with self.assertRaises(ValueError):
                server.resolve_public("example.org")

    def test_reject_nat64_translation(self):
        import ipaddress
        self.assertTrue(server._reject_ip(ipaddress.ip_address("64:ff9b::7f00:1")))

    def test_reject_malicious_urls(self):
        for url in ("http://example.com", "https://127.0.0.1/", "https://localhost/", "https://a/", "https://user:pw@example.com/", "https://example.com:444/", "https://a_b.example/", "https://example.com/#x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                server.validate_url(url)

    def test_accept_normal_url(self):
        self.assertEqual(server.validate_url("https://example.org/a?q=x")[:3], ("example.org", 443, "/a?q=x"))


class ScanTests(unittest.TestCase):
    @patch.object(server, "resolve_public", side_effect=[["93.184.216.34"], ["93.184.216.34"]])
    @patch.object(server, "_PinnedHTTPSConnection")
    def test_single_get_no_redirect_follow_and_headers(self, conn_cls, _dns):
        conn = conn_cls.return_value
        response = Mock(status=302, reason="Found")
        response.getheaders.return_value = [("Location", "https://elsewhere.example/"), ("Content-Type", "text/html"), ("X-Frame-Options", "bad"), ("Set-Cookie", "sid=x")]
        response.read.return_value = b'<img src="http://bad.example/x">'
        conn.getresponse.return_value = response
        result = server.scan_site("https://example.org/")
        conn.request.assert_called_once()
        self.assertEqual(conn.request.call_args.args[0], "GET")
        self.assertEqual(result["statusCode"], 302)
        self.assertEqual(result["bytesRead"], len(response.read.return_value))
        ids = {f["id"] for f in result["findings"]}
        self.assertIn("frame", ids)
        self.assertIn("secure_cookies", ids)
        self.assertIn("mixed_content", ids)
        self.assertNotIn("sid=x", json.dumps(result))
        self.assertFalse(any(c["id"] == "hsts" and c["status"] == "present" for c in result["checks"]))

    @patch.object(server, "resolve_public", side_effect=[["93.184.216.34"], ["93.184.216.34"]])
    @patch.object(server, "_PinnedHTTPSConnection")
    def test_body_limit(self, conn_cls, _dns):
        response = Mock(status=200)
        response.getheaders.return_value = []
        response.read.return_value = b"x" * (server.MAX_BODY + 1)
        conn_cls.return_value.getresponse.return_value = response
        result = server.scan_site("https://example.org/")
        self.assertEqual(result["bytesRead"], server.MAX_BODY)
        self.assertTrue(result["coverage"]["truncated"])

    @patch.object(server, "resolve_public", side_effect=[["93.184.216.34"], ["8.8.8.8"]])
    def test_dns_rebinding_rejected(self, _dns):
        with self.assertRaises(ValueError):
            server.scan_site("https://example.org/")


class HandlerTests(unittest.TestCase):
    def make_handler(self, headers):
        h = Mock()
        h.headers = headers
        h.server.server_port = 8000
        return h

    def test_origin_requires_exact_origin_host(self):
        self.assertTrue(server._same_origin(self.make_handler({"Origin": "http://127.0.0.1:8000", "Host": "127.0.0.1:8000"})))
        self.assertFalse(server._same_origin(self.make_handler({"Origin": "https://evil.example", "Host": "127.0.0.1:8000"})))
        self.assertFalse(server._same_origin(self.make_handler({"Host": "127.0.0.1:8000"})))

    def test_rebinding_origin_rejected(self):
        self.assertFalse(server._same_origin(self.make_handler({"Origin":"http://evil.example:8000","Host":"evil.example:8000"})))

    def test_capabilities_contract(self):
        class Stub(server.Handler):
            def __init__(self):
                self.path = "/api/capabilities"
                self.sent = None
            def _json(self, code, data): self.sent = (code, data)
        stub = Stub()
        stub.do_GET()
        self.assertEqual(stub.sent, (200, {"siteScan": True}))


if __name__ == "__main__":
    unittest.main()
