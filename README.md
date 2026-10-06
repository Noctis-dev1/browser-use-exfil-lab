# Browser-agent data exfiltration: a measured lab

A sealed, local lab that reproduces indirect prompt-injection data exfiltration against
[browser-use](https://github.com/browser-use/browser-use) 0.13.10, measures it as a rate, and
shows a network egress boundary that takes the rate to zero with an audit trail.

- Writeup: **[Bounding a Browser Agent's Authority](WRITEUP.md)**
- Boundary reference implementation: [Portcullis](https://github.com/Noctis-dev1/portcullis)
- Results and evidence: [`FINDINGS.md`](FINDINGS.md)

## Safety

This is a defensive research lab. It runs entirely on loopback with a synthetic canary token and a
local model. **Do not run any part of this against a hosted or third-party deployment.** No real
credential is used at any point.

## What's here

```
run_attack.py            baseline injectability (does hidden page text reach and steer the model)
run_exfil.py             single exfiltration proof
run_rate.py              exfiltration rate, no defense
run_boundary.py          exfiltration rate behind browser-use's own allowed_domains
run_boundary_egress.py   exfiltration rate behind the egress boundary
egress_proxy.py          the egress authorization boundary (default-deny allowlist proxy, :8080)
evil-site/               attacker-controlled pages (page1 baseline, page3 exfil), served on :8000
catcher/catcher_server.py  attacker collection endpoint (:9999), logs every hit to catcher/hits.log
FINDINGS.md              measured results, evidence, and limitations
```

## Requirements

- Python 3.13 and `browser-use==0.13.10` (`pip install -r requirements.txt`). browser-use 0.13 drives
  a local Chrome/Chromium over CDP; Playwright is not required.
- [ollama](https://ollama.com) with a local model: `ollama pull qwen2.5:14b`.

## Setup

```bash
uv venv --python 3.13 .venv && source .venv/bin/activate   # or: python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Start the three support services, each in its own terminal:

```bash
python3 catcher/catcher_server.py                              # :9999 collector -> catcher/hits.log
( cd evil-site && python3 -m http.server 8000 --bind 127.0.0.1 )
python3 egress_proxy.py                                        # :8080 boundary (only for the fix runs)
```

Then measure (from the repo root, venv active):

```bash
python run_rate.py qwen2.5:14b 10             # no defense        -> expect ~100%
python run_boundary.py qwen2.5:14b 10         # built-in allowlist -> expect ~100% (the point)
python run_boundary_egress.py qwen2.5:14b 10  # egress boundary   -> expect 0%
python run_boundary_egress_https.py 10        # egress boundary on HTTPS -> 100% legit allowed, 0% exfil
```

Rates are read from the server-side logs: `catcher/hits.log` (leaks) and `catcher/audit.log`
(boundary allow/deny decisions).

## License

Apache-2.0 (see [`LICENSE`](LICENSE)). Copyright © 2026 Malachi Zion Kopman. This reproduction lab is
permissive on purpose, to be run and forked freely; Portcullis (the reference boundary implementation)
stays AGPL-3.0.
