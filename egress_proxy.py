"""
Egress authorization boundary (Policy Enforcement Point) for the browser-use lab.

A forward proxy on 127.0.0.1:8080. Chrome is pointed at it (BrowserProfile.proxy,
with bypass '<-loopback>' so even loopback traffic is mediated). The proxy enforces a
DEFAULT-DENY allowlist of the hosts the agent's task actually declared. The declared
origin is forwarded; everything else -- including the attacker drop-box -- is refused
before a single byte leaves, and every decision is written to audit.log.

This is the fix the navigation-layer allowlist could not provide: it stops the
OUTBOUND REQUEST, not just the inbound response. Portcullis thesis, enforced at the
right layer.

Sealed lab: loopback only, synthetic data, no cloud egress.
Run:  python3 egress_proxy.py
"""
import datetime
import http.server
import os
import socketserver
import urllib.request
import urllib.error
from urllib.parse import urlparse

AUDIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catcher", "audit.log")

# The declared authority: the only origin the agent's task legitimately needs.
# Everything else is denied by default.
ALLOW_HOSTS = {"localhost:8000"}

# Opener that ignores any ambient http(s)_proxy env so we never loop back on ourselves.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def audit(decision, target):
    line = f"{datetime.datetime.now().isoformat()}\t{decision}\t{target}"
    try:
        with open(AUDIT, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def _hostport(parsed):
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}:{port}"


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one request per connection; keeps relaying simple

    def log_message(self, *a):  # we do our own auditing
        pass

    def do_CONNECT(self):
        # HTTPS tunnels are default-denied (no HTTPS origin is declared in this lab).
        audit("DENY-CONNECT", self.path)
        self.send_error(403, "Egress blocked by authorization boundary")

    def _handle(self):
        parsed = urlparse(self.path)  # proxy requests carry the absolute URL
        hostport = _hostport(parsed)

        if hostport not in ALLOW_HOSTS:
            audit("DENY", f"{self.command} {self.path}")
            body = b"Egress blocked by authorization boundary (undeclared host)\n"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        audit("ALLOW", f"{self.command} {self.path}")
        try:
            data = None
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                data = self.rfile.read(length)
            req = urllib.request.Request(self.path, data=data, method=self.command)
            for h in ("Accept", "User-Agent", "Content-Type"):
                if h in self.headers:
                    req.add_header(h, self.headers[h])
            with _opener.open(req, timeout=10) as resp:
                payload = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "text/html"))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as e:
            payload = e.read()
            self.send_response(e.code)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            self.send_error(502, f"upstream error: {e}")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


class ThreadingProxy(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    addr = ("127.0.0.1", 8080)
    print(f"Egress boundary (PEP) on http://{addr[0]}:{addr[1]}  allow={sorted(ALLOW_HOSTS)}  audit={AUDIT}", flush=True)
    ThreadingProxy(addr, Proxy).serve_forever()
