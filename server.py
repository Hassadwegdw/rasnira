"""خادم محلي: شغّل بـ python3 server.py [public_dir]؛ يستمع على 127.0.0.1:8000 ويقدّم الملفات من public_dir (افتراضيًا public). فحص POST /api/site-scan سلبي ومحدود ويتطلب تفويضًا صريحًا و consent=true؛ لا يثبت غياب النتائج السلامة."""
from __future__ import annotations

import http.client
import ipaddress
import json
import mimetypes
import re
import os
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

MAX_BODY = 256 * 1024
TIMEOUT = 8
RATE_WINDOW = 60
RATE_MAX = 5
_rate_lock = threading.Lock()
_rate_hits: dict[str, list[float]] = {}


def _reject_ip(ip: ipaddress._BaseAddress) -> bool:
    if not ip.is_global:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        # Block mapped and transition/embedded IPv4 mechanisms, even if globally routed.
        if ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None:
            return True
        if any(ip in ipaddress.ip_network(net) for net in ("2001::/23", "64:ff9b::/96", "64:ff9b:1::/48")):
            return True
    return False


def validate_url(raw: str) -> tuple[str, int, str, str]:
    if not isinstance(raw, str) or len(raw) > 2048:
        raise ValueError("url must be a valid HTTPS URL")
    try:
        p = urlsplit(raw)
        if p.fragment or p.scheme.lower() != "https" or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError
        host = p.hostname
        if not p.port is None and p.port != 443:
            raise ValueError
        if p.port is None and ":" in p.netloc and not p.netloc.startswith("["):
            raise ValueError
        if host.lower() == "localhost" or "." not in host or host.endswith("."):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass  # Not an IP literal; continue with DNS-name validation.
        else:
            raise ValueError  # IP literals are not accepted.
        # IDNA-normalize and validate DNS labels.
        hostname = host.encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9.-]+", hostname) or len(hostname) > 253 or any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-") for x in hostname.split(".")):
            raise ValueError
        port = p.port or 443
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return hostname, port, path, urlunsplit(("https", hostname, p.path or "/", p.query, ""))
    except (ValueError, UnicodeError) as e:
        raise ValueError("URL مرفوض: يلزم HTTPS على المنفذ 443 واسم DNS عام صالح بلا بيانات دخول أو IP حرفي") from e


def resolve_public(host: str, port: int = 443) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = sorted({item[4][0].split("%", 1)[0] for item in infos})
    if not addresses:
        raise ValueError("تعذر حل اسم المضيف")
    parsed = []
    for value in addresses:
        ip = ipaddress.ip_address(value)
        if _reject_ip(ip):
            raise ValueError("تم رفض عنوان DNS غير عام أو IPv6 انتقالي")
        parsed.append(str(ip))
    return parsed


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, ip: str):
        super().__init__(hostname, 443, timeout=TIMEOUT, context=ssl.create_default_context())
        self._pin = ip

    def connect(self):
        sock = socket.create_connection((self._pin, 443), timeout=TIMEOUT)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def scan_site(url: str) -> dict:
    host, _, path, canonical = validate_url(url)
    ips = resolve_public(host)
    # One pinned destination and one GET; never follow redirects. Validate resolution again
    # immediately before opening the TCP connection to reduce DNS rebinding risk.
    current = resolve_public(host)
    if current != ips:
        raise ValueError("تغيرت عناوين DNS أثناء التحقق؛ أُلغي الفحص")
    conn = _PinnedHTTPSConnection(host, ips[0])
    try:
        conn.request("GET", path, headers={"User-Agent": "Rasnira-Site-Scan/1.0", "Accept": "text/html,application/xhtml+xml,*/*;q=0.1", "Connection": "close"})
        response = conn.getresponse()
        status = response.status
        headers = response.getheaders()
        body = response.read(MAX_BODY + 1)
        truncated = len(body) > MAX_BODY
        body = body[:MAX_BODY]
    finally:
        conn.close()
    h = {}
    for key, value in headers:
        h.setdefault(key.lower(), []).append(value)
    findings = []
    checks = []
    def header_check(name, fid, title, fix, predicate=None):
        values = h.get(name, [])
        ok = bool(values) if predicate is None else any(predicate(v) for v in values)
        checks.append({"id": fid, "status": "present" if ok else "not_observed"})
        if values and not ok:
            findings.append({"id": fid, "severity": "medium", "title": title, "description": f"تم رصد ترويسة {name} لكن قيمتها لا تحقق الإعداد المتوقع.", "fix": fix, "file": "URL", "evidence": ", ".join(values)[:500]})
    header_check("strict-transport-security", "hsts", "إعداد HSTS غير كافٍ", "اضبط Strict-Transport-Security على مدة مناسبة مع includeSubDomains عند الملاءمة.", lambda v: bool(re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*(?:\s*;|\s*$)", v, re.I)))
    header_check("content-security-policy", "csp", "سياسة CSP تحتاج مراجعة", "أضف سياسة Content-Security-Policy مناسبة ومقيدة.")
    header_check("x-frame-options", "frame", "إعداد منع التأطير يحتاج مراجعة", "استخدم X-Frame-Options: DENY أو SAMEORIGIN، أو frame-ancestors في CSP.", lambda v: v.lower().strip() in ("deny", "sameorigin"))
    header_check("referrer-policy", "referrer", "سياسة Referrer غير مقيدة", "استخدم سياسة مثل strict-origin-when-cross-origin أو no-referrer.", lambda v: v.lower().strip() in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "no-referrer-when-downgrade"))
    header_check("x-content-type-options", "nosniff", "إعداد nosniff غير صحيح", "اضبط X-Content-Type-Options: nosniff.", lambda v: v.lower().strip() == "nosniff")
    cookies = h.get("set-cookie", [])
    checks.append({"id": "secure_cookies", "status": "present" if cookies else "not_observed"})
    for cookie in cookies:
        if not all(flag in cookie.lower() for flag in ("secure", "httponly", "samesite=")):
            findings.append({"id": "secure_cookies", "severity": "low", "title": "خصائص ملف تعريف الارتباط تحتاج مراجعة", "description": "ملف ارتباط مرصود يفتقد إحدى الخصائص Secure أو HttpOnly أو SameSite؛ الحاجة إليها تعتمد على حساسية الكوكي، ولا يثبت ذلك ثغرة.", "fix": "أضف Secure وHttpOnly وSameSite المناسبة إلى ملفات الارتباط الحساسة.", "file": "URL", "evidence": "[محجوب: لا تُدرج أسماء الكوكيز أو قيمها في التقرير]"})
    content_type = ",".join(h.get("content-type", [])).lower()
    mixed = b"http://" in body.lower() if "html" in content_type else False
    checks.append({"id": "mixed_content", "status": "observed" if mixed else "not_observed"})
    if mixed:
        findings.append({"id": "mixed_content", "severity": "low", "title": "مراجع HTTP في محتوى HTTPS", "description": "عُثر على نص http:// ضمن عينة جسم الاستجابة؛ قد لا يكون مرجعًا نشطًا.", "fix": "راجع موارد الصفحة واستخدم HTTPS للمراجع النشطة.", "file": "URL", "evidence": "http:// (ضمن عينة المحتوى)"})
    return {"findings": findings, "checks": checks, "bytesRead": len(body), "statusCode": status, "coverage": {"scope": "طلب GET واحد فقط، دون تتبع إعادة التوجيه", "bodyLimitBytes": MAX_BODY, "truncated": truncated, "dnsAddressesChecked": len(ips), "limitations": ["فحص سلبي محدود؛ لا يثبت غياب النتائج سلامة الموقع", "الترويسات الغائبة مسجلة not_observed ولا تعد إثباتًا لثغرة", "لم تُفحص الصفحات أو المسارات الأخرى"]}, "generatedAt": datetime.now(timezone.utc).isoformat(), "url": canonical}


def _same_origin(handler) -> bool:
    origin = handler.headers.get("Origin")
    host = handler.headers.get("Host")
    if not origin or not host:
        return False
    try:
        o = urlsplit(origin)
        allowed = {f"127.0.0.1:{handler.server.server_port}", f"localhost:{handler.server.server_port}"}
        return host.lower() in allowed and o.scheme == "http" and o.netloc.lower() == host.lower() and not o.username and not o.password
    except Exception:
        return False


def _rate_allowed(addr: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        hits = [x for x in _rate_hits.get(addr, []) if now - x < RATE_WINDOW]
        if len(hits) >= RATE_MAX:
            _rate_hits[addr] = hits
            return False
        hits.append(now)
        _rate_hits[addr] = hits
        return True


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)
    server_version = "Rasnira/1.0"
    def _json(self, code, data):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)
    def do_GET(self):
        if self.path == "/api/capabilities":
            return self._json(200, {"siteScan": True})
        if self.path.startswith("/api/"):
            return self._json(404, {"error": "not_found", "message": "المسار غير موجود"})
        root = os.path.realpath(getattr(self.server, "public_dir", "public"))
        rel = self.path.split("?", 1)[0].lstrip("/") or "index.html"
        target = os.path.realpath(os.path.join(root, rel))
        if not target.startswith(root + os.sep) or not os.path.isfile(target):
            return self._json(404, {"error": "not_found", "message": "الملف غير موجود"})
        try:
            with open(target, "rb") as f: data = f.read()
            self.send_response(200); self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", mimetypes.guess_type(target)[0] or "application/octet-stream"); self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers(); self.wfile.write(data)
        except OSError:
            self._json(404, {"error": "not_found", "message": "الملف غير متاح"})
    def do_POST(self):
        if self.path != "/api/site-scan":
            return self._json(404, {"error": "not_found", "message": "المسار غير موجود"})
        if not _same_origin(self):
            return self._json(403, {"error": "origin_rejected", "message": "رفض الطلب: Origin وHost غير متطابقين أو Origin مفقود"})
        if not _rate_allowed(self.client_address[0]):
            return self._json(429, {"error": "rate_limited", "message": "تم تجاوز حد الطلبات؛ حاول لاحقًا"})
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > 4096:
            return self._json(413, {"error": "body_too_large", "message": "حجم الطلب غير صالح أو يتجاوز الحد"})
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or payload.get("consent") is not True:
                return self._json(400, {"error": "consent_required", "message": "يلزم consent=true مع تفويض صريح لفحص الموقع"})
            result = scan_site(payload.get("url"))
            return self._json(200, result)
        except ValueError as e:
            return self._json(400, {"error": "invalid_request", "message": str(e)})
        except (socket.timeout, TimeoutError):
            return self._json(504, {"error": "timeout", "message": "انتهت مهلة الفحص (8 ثوانٍ)"})
        except Exception:
            return self._json(502, {"error": "scan_failed", "message": "تعذر إكمال الفحص؛ لا يعني ذلك أن الموقع آمن"})
    def log_message(self, fmt, *args):
        pass


def main():
    public = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "public")
    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "8000"))), Handler)
    server.public_dir = public
    print(f"Serving {public} at http://127.0.0.1:{server.server_port}", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
