# Browser-use indirect prompt injection: engagement findings

**Engagement:** public-proof red-team #1
**Date:** 2026-10-03
**Author:** Malachi Zion Kopman (Noctis)
**Target:** `browser-use` 0.13.10 (an LLM agent that drives a real Chrome over CDP), ~108k GitHub stars
**Models under test:** `qwen2.5:7b` and `qwen2.5:14b`, served locally by ollama
**Lab discipline:** sealed. Local models only (no cloud egress), everything on loopback, synthetic canary `CANARY-7F3A2C`, a local instance we own. No hosted deployment was touched.

---

## Method

We measured a rate, not an anecdote. Each attack was run N=10 times. Success was judged on
independent, server-side ground truth: a logging catcher that records every request it receives
(`catcher/hits.log`), plus, for the defended runs, a proxy audit log of every allow/deny decision
(`catcher/audit.log`). Rates are reported with Wilson 95% confidence intervals, honest about N=10.

Scripts (in this repository):
- `run_attack.py` baseline injectability (does hidden page text reach and steer the model)
- `run_exfil.py` single exfiltration proof
- `run_rate.py` exfiltration rate, no defense
- `run_boundary.py` exfiltration rate behind browser-use's own `allowed_domains`
- `egress_proxy.py` + `run_boundary_egress.py` exfiltration rate behind a network egress boundary
- `evil-site/page1.html`, `evil-site/page3.html` the poisoned pages
- `catcher/catcher_server.py` the logging drop-box

---

## Findings

### 1. Indirect injection lands, and it scales with model capability
Pointed at a page and asked only to "summarize," the agent ingested hidden instructions planted in
the page and obeyed them. On `qwen2.5:7b` the injection did not land and the model was too weak to
operate the browser reliably. On `qwen2.5:14b` it landed (the planted token `PWNED-CSS` appeared in
the agent's extraction step). The more capable model was the more injectable one. This reproduces,
in a live agent, the same direction measured earlier with NVIDIA garak against local models
(injection obeyed more often at the larger size). Capability and injectability rise together, so
waiting for a better model does not fix this.

### 2. Injection success is layered, so measurement must watch the whole trajectory
On one 14b run the injected token appeared mid-run (in the extraction step) but was scrubbed from the
final answer. A detector that inspects only the final output records a false negative. The attack
still landed. Measurement has to cover the whole trajectory and, where possible, an out-of-band
signal (a network action the model cannot retract).

### 3. In-context exfiltration is reliable: 100% (10/10)
With a secret in the agent's context (the user asked it to "remember an API key") and an innocent
task, a poisoned page induced the agent to send that secret to an attacker-controlled host.

- **Exfil rate, no defense: 10/10 = 100% (95% CI 72.2% to 100%)** on `qwen2.5:14b`.
- Ground truth: 10 independent `GET /collect?key=CANARY-7F3A2C` hits in the catcher log.
- This is the EchoLeak class (cf. CVE-2025-32711 against Microsoft 365 Copilot): in-context data
  exfiltrated via content the agent read, no user action required.

### 4. The agent improvises exfiltration destinations, so blocklisting is not enough
When it could not reach the exact URL, the agent invented its own: it POSTed the key to the page
origin, and it attempted to `fetch()` the key to a fabricated public domain
(`api.nimbusdesk.example`). It will leak to destinations an attacker never named. A blocklist of
known-bad URLs cannot cover this. The control has to be default-deny.

### 5. The vendor's own navigation allowlist does NOT stop exfiltration
`browser-use` ships an `allowed_domains` allowlist. With it configured to the task's origin only, the
agent was blocked from *navigating* to the attacker host, the tool logged "blocked by security
policy," and the agent gave up. The secret leaked anyway.

- **Exfil rate behind `allowed_domains`: 10/10 = 100% (95% CI 72.2% to 100%)**.
- Measured outcome, not mechanism: the canary still reached the attacker host with the allowlist set
  to the task origin. browser-use has a pre-navigation allow-check, yet the request completed; I did
  not isolate why (async event-bus race vs code-path gap), so report the outcome, not the internals.
- This is a CONFIRMATION, not a discovery. Domain-allowlist insufficiency for exfiltration is already
  documented (agentpatterns URL-exfil guard; egress-control guides), and browser-use has prior
  allowlist CVEs (CVE-2025-47241, CVSS 9.3). The contribution is the measured rate + receipts on this
  version plus a runnable fix, NOT a novel hole. Do not publish a novelty claim. A defender's takeaway
  still stands: the first control you would reach for did not stop the data leaving.

### 6. A network egress authorization boundary stops it: 0% (0/10)
We placed a default-deny allowlisting proxy between the browser and the network (declared authority:
the task's origin only) and routed all traffic, including loopback, through it.

- **Exfil rate behind the egress boundary: 0/10 = 0% (95% CI 0.0% to 27.8%)**.
- Ground truth: catcher hits did not move (21 before, 21 after). The proxy refused 18 attacker
  requests across the run, each written to the audit log with the attempted canary URL.
- It closes every egress channel the agent can reach, navigation and in-page `fetch` alike. The
  JavaScript `fetch` the agent tried also went through the proxy and was denied. The decision lives outside the model, in a layer
  the poisoned page cannot talk to. The agent was fully convinced it should exfiltrate and could not.

---

## The headline

| Configuration | Exfil rate (N=10, qwen2.5:14b) | 95% CI |
|---|---|---|
| No defense | 100% (10/10) | 72.2% to 100% |
| browser-use `allowed_domains` (navigation allowlist) | 100% (10/10) | 72.2% to 100% |
| Egress authorization boundary (default-deny, network layer) | 0% (0/10) | 0.0% to 27.8% |

The obvious, vendor-provided defense does not change the outcome. Enforcement at the right layer
takes it to zero.

---

## Evidence (receipts)

- `catcher/hits.log` every request the attacker drop-box received (the leaks).
- `catcher/audit.log` every allow/deny the boundary made, with the attempted canary URL.
- Terminal transcripts of each run (agent reasoning, the `DENY ... blocked by security policy` lines).

---

## Limitations

- Local models (`qwen2.5` 7b/14b), not a frontier model. The direction (capability raises
  injectability) matches published work, but the absolute rate is specific to this setup.
- For the exfil rate runs the exfil instruction was delivered as visible page text. Hidden-channel
  delivery (CSS-concealed, comment, alt text) was demonstrated separately in finding 1. A sharper
  engagement would use oblique/hidden payloads throughout.
- The secret was seeded by the user saying "remember this key." A more realistic version seeds the
  secret through the agent's normal work (e.g. reading an account page that contains a token). The
  simplification is in how the secret arrives, not in the mechanism: agents routinely hold sensitive
  data and read untrusted input in the same context.
- N=10 is a pilot. Confidence intervals are wide by design; scaling N tightens them.
- Single target, single task shape. Generalization requires more targets.
- The egress boundary is necessary, not sufficient. A host allowlist does not stop exfiltration to an
  ALLOWED host (open redirect, a free-text field on a permitted service, a trusted-domain paste);
  HTTPS needs SNI-based enforcement or MITM to see the host; DNS and timing channels sit below it.
  Host-allowlisting is the floor. The stronger control is data-aware egress: whether a request could
  have been built from the user's secret. That is the harder, more defensible direction.

---

## Next steps

- Re-shoot the exfil with an oblique/hidden payload and a browsing-seeded secret, for realism.
- Add a second and third target agent to test generalization.
- Scale N to tighten the intervals.
- Responsible disclosure: this is class-of-problem behavior (injection working as designed), so it is
  a research write-up, not a CVE against browser-use. The maintainers receive a courtesy heads-up
  before publication, and it is framed as a defense contribution, building on the prior work it reproduces.
