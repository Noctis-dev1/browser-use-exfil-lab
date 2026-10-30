"""The egress boundary for the deputy campaign, :8090.

The REAL egress_proxy enforcement, but the allowlist now includes the deputy (the agent
is permitted to call the intermediary). Separate port so it does not disturb the Phase-2
proxy already running on :8080. Default-deny on everything else, including the undeclared
drop on :9999.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy

egress_proxy.ALLOW_HOSTS = {"localhost:8000", "localhost:8100"}  # declared origin + allowed deputy

if __name__ == "__main__":
    addr = ("127.0.0.1", 18090)
    print(f"deputy-campaign egress boundary on http://{addr[0]}:{addr[1]}  allow={sorted(egress_proxy.ALLOW_HOSTS)}")
    egress_proxy.ThreadingProxy(addr, egress_proxy.Proxy).serve_forever()
