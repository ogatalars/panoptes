"""HTTP + TLS + security-header probes, Python stdlib only."""
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

USER_AGENT = "panoptes-monitor (+https://github.com/ogatalars/panoptes)"

# header -> (label, can it be declared with a <meta> tag instead?)
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", False),
    "content-security-policy": ("Content-Security-Policy", True),
    "x-content-type-options": ("X-Content-Type-Options", False),
    "x-frame-options": ("X-Frame-Options", False),
    "referrer-policy": ("Referrer-Policy", True),
    "permissions-policy": ("Permissions-Policy", False),
}
META_PATTERNS = {
    "content-security-policy": re.compile(r"<meta[^>]+http-equiv=[\"']?content-security-policy", re.I),
    "referrer-policy": re.compile(r"<meta[^>]+name=[\"']?referrer", re.I),
}
TLS_WARN_DAYS = 14


def probe_http(url, timeout=10):
    """Return (status, latency_ms, headers, body). status 0 = no HTTP response."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(500_000)
            status, headers = resp.status, resp.headers
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, e.headers, b""
    except (urllib.error.URLError, OSError, ValueError):
        status, headers, body = 0, {}, b""
    ms = round((time.monotonic() - start) * 1000)
    return status, ms, {k.lower(): v for k, v in headers.items()}, body.decode("utf-8", "replace")


def is_good(status, latency_ms, threshold_ms):
    """The SLI predicate: a 2xx that arrived within the latency threshold."""
    return 200 <= status < 300 and latency_ms <= threshold_ms


def days_until(not_after, now):
    """Parse an OpenSSL 'notAfter' string (e.g. 'Mar  7 23:59:59 2027 GMT')."""
    return round((ssl.cert_time_to_seconds(not_after) - now) / 86400, 1)


def tls_days_left(url, now, timeout=10):
    host = urlsplit(url).hostname
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return days_until(tls.getpeercert()["notAfter"], now)
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return None


def security_posture(headers, body, headers_configurable):
    """Each header is 'ok' (header sent), 'meta' (declared in HTML), 'platform'
    (absent, but the host cannot set custom headers, e.g. GitHub Pages) or
    'missing' (absent and the host could set it). Only 'missing' is a real gap."""
    checks = []
    for name, (label, meta_ok) in SECURITY_HEADERS.items():
        if name in headers:
            state = "ok"
        elif meta_ok and META_PATTERNS[name].search(body):
            state = "meta"
        else:
            state = "missing" if headers_configurable else "platform"
        checks.append({"header": label, "state": state})
    return checks
