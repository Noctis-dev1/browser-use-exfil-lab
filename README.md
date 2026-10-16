# Browser-agent data exfiltration: a measured lab

A sealed, local lab that measures indirect prompt-injection data exfiltration against
[browser-use](https://github.com/browser-use/browser-use) 0.13.10 as a rate, and shows a network
egress boundary that takes exfiltration to undeclared destinations to zero with an audit trail.

- Full method, numbers, and limits: **[`phase2/RESULTS.md`](phase2/RESULTS.md)**
- Reference boundary implementation: [Portcullis](https://github.com/Noctis-dev1/portcullis)

## Headline result (N = 50 per cell, 450 runs)

The rigorous re-shoot is in [`phase2/`](phase2/). One visible attack, three defenses, held constant,
with a unique per-run canary as server-side ground truth:

- **No defense:** leaked 98% (49 of 50), 95% CI 89.5 to 99.6.
- **browser-use's built-in `allowed_domains`:** leaked 100% (50 of 50), CI 92.9 to 100. It is a
  navigation control, not a network-egress boundary: it can reject disallowed navigations, but enabling
  it did not stop the canary reaching the collector. Both controls are deterministic; the difference is
  what they mediate.
- **Default-deny egress boundary outside the model:** leaked 0% (0 of 50), CI 0 to 7.1. Holds across all
  three delivery variants (visible, hidden, seeded), with 0 of 50 false-denies on a benign control.

Undefended, attack success is condition-dependent, not a flat 100%: visible 98% (CI 89.5 to 99.6),
seeded 46% (33.0 to 59.6), hidden 12% (5.6 to 23.8). These are three chosen conditions, not a
probability distribution over real attacks, so read them as a 12% to 98% range that depends on delivery,
not as an average. The named limit: with the boundary on, exfiltration routed to the task's own
*allowed* host still succeeded 49 of 50. That is where destination-only enforcement stops; data-aware
egress is the open problem, not solved here.

### Reproduce every number

The raw per-attempt log and a stdlib-only verifier are committed. No model and no network needed: it
recomputes every rate, Wilson interval, and coverage figure from the raw records, and re-hashes the
attacker pages against the manifest.

```bash
python phase2/verify.py
```

It ends on `VERIFIED` when every number matches. To re-run the live experiment yourself, use the
campaign scripts below.

## Safety

This is a defensive research lab. It runs entirely on loopback with a synthetic canary token and a
local model. **Do not run any part of this against a hosted or third-party deployment.** No real
credential is used at any point.

## Reproduce the method live (original N=10 campaign)

The scripts below are the first-pass campaign at N=10 per cell. They run the live experiment end to end;
the N=50 re-shoot in `phase2/` is the version to cite for the numbers above. The first-pass writeup and
findings are in [`WRITEUP.md`](WRITEUP.md) and [`FINDINGS.md`](FINDINGS.md).

### What's here

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

### Requirements

- Python 3.13 and `browser-use==0.13.10` (`pip install -r requirements.txt`). browser-use 0.13 drives
  a local Chrome/Chromium over CDP; Playwright is not required.
- [ollama](https://ollama.com) with a local model: `ollama pull qwen2.5:14b`.

### Setup

```bash
uv venv --python 3.13 .venv && source .venv/bin/activate   # or: python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Run

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
python run_boundary_egress_https.py 10        # egress boundary on HTTPS (enforcement layer) -> 0% exfil
```

Expanded campaign (live agent; needs the HTTPS catcher `catcher/catcher_server_https.py` on :9443 and
the logging site `evil-site/site_server.py` on :8000 in place of the plain file server):

```bash
python run_rate_https.py qwen2.5:14b 10                 # agent exfil over HTTPS, no defense -> ~100%
python run_boundary_egress_https_agent.py qwen2.5:14b 10 # agent exfil over HTTPS, boundary  -> 0%
python run_rate_seeded.py qwen2.5:14b 10                # R1 secret read off account page    -> ~50%
python run_rate_hidden.py qwen2.5:14b 10                # R2 hidden-channel delivery          -> ~30%
python run_boundary_allowed.py qwen2.5:14b 10           # R3 exfil to an ALLOWED host, boundary ON -> ~100%
```

Rates are read from the server-side logs: `catcher/hits.log` (leaks) and `catcher/audit.log`
(boundary allow/deny decisions).

## License

Apache-2.0 (see [`LICENSE`](LICENSE)). Copyright © 2026 Malachi Zion Kopman. This reproduction lab is
permissive on purpose, to be run and forked freely; Portcullis (the reference boundary implementation)
stays AGPL-3.0.
