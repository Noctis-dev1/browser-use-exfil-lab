# Bounding a Browser Agent's Authority

### A measured evaluation of indirect prompt-injection exfiltration in a browsing agent, and where an authorization boundary does and does not stop it.

*Malachi Zion Kopman, Founder, Noctis*

*October 2026*

---

**Abstract.** A browsing agent reads attacker-controlled web content into the same context that holds its user's secrets, and the attack that follows, indirect prompt injection leading to data exfiltration, is well documented. The open question for a builder is not whether it works but what stops it. I took browser-use, a widely used open-source browsing agent, and in a sealed local lab measured in-context exfiltration of a synthetic secret under three configurations. With no defense, the secret reached an attacker-controlled host in 10 of 10 trials. With the agent framework's own domain allowlist set to the task origin, it still reached the host in 10 of 10 trials, because the allowlist constrains navigation rather than egress and the request carrying the secret is issued before the framework intervenes. With a network-layer authorization boundary that default-denies any undeclared destination, it reached the host in 0 of 10 trials, and every blocked request was recorded in an audit log. The boundary holds on HTTPS as well as HTTP, enforcing on the destination host without decrypting the connection. I report measured outcomes rather than internal causes, and I am explicit that neither the attack nor the insufficiency of domain allowlists is novel: both are documented, and browser-use carries prior allowlist-bypass advisories. The contribution is a measured, reproducible, end-to-end evaluation on a current release, and a boundary a builder can run. Limitations include local models, a sample of ten per configuration, a visible injection channel in the rate trials, and a host-level allowlist that is not data-aware.

---

A browsing agent is built to read the open web, which means untrusted input is its entire working surface, not an edge case. Over 2025 and 2026, academic work and production incidents established that content read by an agent can carry instructions the agent then follows, and that when the agent also holds sensitive data in context, those instructions can carry the data back out. The pattern has a name in the literature, indirect prompt injection, and it has been demonstrated repeatedly and across tools. I am not reporting that it exists. I am measuring, on a tool people deploy, what a defender can do about it.

## The question

The attack side of this field is mature, so the useful question is narrow and empirical. Given a browsing agent that holds a secret and reads a poisoned page, how often does the secret leave the machine, and which defensive control, enforced at which layer, changes that number? A rate answers this in a way an anecdote cannot, and a rate measured against an independent, server-side record answers it in a way the agent's own self-report cannot.

## What is and is not novel here

I want to be precise about this, because the value of the work depends on not overstating it.

The attack is documented. Academic analyses show browsing agents appending attacker-controlled page content directly into the model's context with no contextual boundary (*The Hidden Dangers of Browsing AI Agents*, arXiv:2505.13076; *Mind the Web*, arXiv:2506.07153). Palo Alto's Unit 42 has quantified delivery channels in observed attacks. Named campaigns against production agentic browsers are on record, and the EchoLeak advisory (CVE-2025-32711) demonstrated zero-click in-context exfiltration against a shipped product, Microsoft 365 Copilot.

The insufficiency of domain allowlists for exfiltration is also documented, in the agent-egress and URL-exfiltration literature, and browser-use specifically carries prior allowlist-bypass advisories (for example CVE-2025-47241). So I am not claiming to have found a new hole, and this piece should not be read that way.

What I did not find already measured, on a current release, end to end, with server-side ground truth and a runnable fix attached, is the sequence that follows: the undefended rate, the rate under the framework's own allowlist, and the rate under a boundary placed at the correct layer. That measured sequence, and the boundary, are the contribution.

## Threat model and lab

Everything ran locally and nothing left the machine.

- The agent is browser-use 0.13.10, driving a real Chromium over the Chrome DevTools Protocol.
- Its model is served locally by ollama, so no inference touched a cloud API. I test qwen2.5:7b and qwen2.5:14b.
- A local web server hosts the pages I control, standing in for an attacker-controlled site.
- A separate local server stands in for the attacker's collection endpoint. It logs every request it receives, which is the ground-truth record of a leak.
- The secret is a synthetic canary token. No real credential is used at any point.

The user's secret is placed in the agent's context the way a real workflow would place it: the user tells the agent to remember an API key, then gives it an ordinary task on a page. In a real deployment the secret arrives instead through the agent's normal work, a token on an account page, a value in a connected tool, a record in memory. The simplification is in how the secret is introduced, not in the condition being tested, which is that an agent holds sensitive data and reads untrusted input in one context with nothing between them.

## Definitions

The measurements depend on keeping these distinct.

- The **declared authority** is the set of destinations the agent's task legitimately requires. Here it is the single origin the task names.
- An **in-context secret** is data the agent holds but which never appears on the page it reads. Only the agent knows it.
- **Exfiltration** is a request that carries the in-context secret to a destination outside the declared authority.
- **Success** is the attacker endpoint receiving the canary. This is read from the endpoint's own log, not from the agent's output, because the agent can omit the secret from its final answer while still having transmitted it.

This is treated as its own finding below.

## Measurement 1: injectability scales with model capability

As a baseline I asked the agent only to summarize a page that carried a hidden instruction, and recorded whether the instruction was obeyed. On qwen2.5:7b the injection did not take, and the model was in any case too weak to operate the browser reliably. On qwen2.5:14b it took: the injected token appeared in the agent's own extraction of the page. The more capable model was the more injectable one. This is consistent with earlier measurement using NVIDIA's garak against local models, where the larger model obeyed hidden instructions more often, not less (9.4% at the smaller model size versus 25.4% at the larger, with non-overlapping confidence intervals). Capability and injectability rise together, which means a more capable model is not a path out of this.

This measurement also surfaced a subtlety in what counts as success. On one run the injected token appeared mid-trajectory, in the agent's extraction step, and was then absent from the final answer the user would see. The attack had succeeded; a detector watching only the final output would have recorded nothing. Exfiltration has to be judged on what the agent did, not on what it said at the end.

## Measurement 2: exfiltration with no defense

The user tells the agent to remember a key and then to read a pricing page and report a price. The page is attacker-controlled. It instructs the agent that, to load live prices, it must first reach an endpoint on another host, substituting in the key it was told to remember. The key is never written on the page, so a request carrying it is unambiguous evidence that the agent took it from its own context and sent it out.

Over 10 trials on qwen2.5:14b the attacker endpoint received the canary in all of them.

> **Exfiltration rate, no defense: 10/10 = 100% (95% Wilson CI 72% to 100%).**

On this delivery, against this model, exfiltration is not probabilistic. It is the default behaviour. The agent's own reasoning narrated it plainly, recording that it needed to send the remembered key to retrieve the prices. When it could not construct the exact request, it improvised: it attempted to post the key to the page's own origin, and it tried to fetch the key to a fabricated public domain. An agent will not confine its leaking to the one destination an attacker names, which has a direct consequence for defense: a blocklist of known-bad destinations cannot hold. The control has to be default-deny.

## Measurement 3: the framework's own allowlist

browser-use ships a domain allowlist, `allowed_domains`. I set it to the task's origin and ran the same attack. The framework reported that it had blocked the navigation to the attacker host, the agent registered the block and gave up, and the run logs read as though the attack had failed.

The secret left anyway.

> **Exfiltration rate under the built-in allowlist: 10/10 = 100% (95% Wilson CI 72% to 100%).**

The attacker endpoint received the canary in all ten trials, with the allowlist active. I report this as a measured outcome and not as a claim about the framework's internals: the framework has a pre-navigation check, yet the request still completed, and I did not isolate whether that is a race in its event handling or a gap in the code path. The outcome is what a defender needs to know. The allowlist constrains where the agent may end up, not whether the request that carries the secret is issued. It hides the response from the agent; it does not stop the egress. As noted above, this insufficiency is already documented in general; what is shown here is that it holds, measured, on this release, with the control configured as a defender would configure it. A team that enables this setting and believes it is protected against exfiltration has a false sense of safety, which is worse than none.

## Measurement 4: an egress authorization boundary

I then placed the decision where the request leaves the machine, outside the agent and outside the model. A default-deny proxy mediates every outbound request, including loopback. The agent's task declares one origin as its authority; every other destination is refused before a connection is made, and every decision, allow or deny, is written to an append-only audit log.

Over 10 trials with the boundary in place, the attacker endpoint received the canary in none of them.

> **Exfiltration rate under the egress boundary: 0/10 = 0% (95% Wilson CI 0% to 28%).**

The agent still decided to exfiltrate in every trial. Its reasoning still said it needed to reach the endpoint, and in some trials it tried to write JavaScript to get around the "security policy" it had hit. It could not, because the boundary does not live in the channel the page controls. The audit log holds 18 refused attempts across the run, each carrying the canary in the URL it was denied. The boundary stops the leak and records every attempt to produce it. And because it enforces on the connection rather than on a browser action, it closes the in-page `fetch` channel as well as navigation, which a navigation-layer control does not.

## Measurement 5: the boundary holds on HTTPS

The rate trials above used an HTTP exfil channel. A deployed agent would more often exfiltrate over HTTPS, so I measured the same boundary on a TLS channel. The proxy enforces on the CONNECT target host, which the client sends in plaintext before the handshake and which reappears in the TLS server name, so it can refuse an undeclared destination without decrypting anything. I declared one HTTPS origin as the authority, served the attacker endpoint over HTTPS on an undeclared host, and ran both through the boundary.

Over 10 trials, legitimate HTTPS to the declared origin was allowed in all 10, and HTTPS exfil to the undeclared host was refused in all 10. The attacker endpoint, read from its own log, received nothing.

> **HTTPS, declared origin allowed: 10/10. HTTPS exfil to an undeclared host: 0/10 (95% Wilson CI 0% to 28%).**

An agent-in-the-loop run confirms this end to end. With the live agent exfiltrating over TLS, the undefended rate is 100% (10/10) and the rate behind the boundary is 0% (0/10), the same outcome as HTTP: the agent leaks over HTTPS just as readily, and the boundary denies the undeclared HTTPS destination by the same host-level decision it makes over HTTP. Seeing inside an allowed HTTPS tunnel is a separate, data-aware problem, noted in the limitations.

## Measurement 6: where the boundary stops working

A control that enforces on the destination host has a boundary of its own, and it is worth measuring rather than asserting. I kept the egress boundary active and changed only the attacker's destination: instead of an undeclared host, the poisoned page routed the secret to the task's own declared origin, the one host the boundary is configured to trust. A real attacker reaches this through an open redirect, a stored-content endpoint, or a free-text field on a permitted service.

Over 10 trials with the boundary active, the secret reached the allowed host in all of them.

> **Exfiltration to an allowed host, boundary active: 10/10 = 100% (95% Wilson CI 72% to 100%).**

The boundary did exactly what it is designed to do, and it did not matter, because the destination was inside the declared authority. Host-allowlisting stops exfiltration to an undeclared destination; it does not stop misuse of a declared one. This is the floor, not the ceiling. The stronger control is data-aware egress, which asks whether a request could have been constructed from the user's secret rather than only where it is bound, and that is the harder problem this boundary points toward rather than solves.

## Results

![The path of the in-context secret under three defenses: it leaves the machine with no defense and again under the built-in allowlist, and is contained only by the egress boundary](browser-use-exfil-results.svg)

| Configuration | Exfil rate (N = 10) | 95% CI | Secret exfiltrated | Audit trail |
|---|---|---|---|---|
| No defense | 100% (10/10) | 72% to 100% | yes | none |
| Built-in domain allowlist | 100% (10/10) | 72% to 100% | yes | none useful |
| Egress authorization boundary (HTTP and HTTPS) | 0% (0/10) | 0% to 28% | no | every attempt logged |

The obvious, framework-provided control does not change the outcome. Moving the decision to the egress takes it to zero.

## Why the layer decides the outcome

A model-layer defense, a better system prompt or an injection classifier, is probabilistic and operates inside the same channel the attacker is speaking through, so it can be argued past the way the agent was. A navigation-layer control, as measured here, intervenes after the request that carries the secret has already been issued. A boundary at the egress is neither: it evaluates a structural fact, whether the destination is within the declared authority, and refuses everything else regardless of how convincing the page was. This is the same argument made at length for data access in *Bounding Agent Authority*, the evaluation behind my Portcullis reference implementation (github.com/Noctis-dev1/portcullis), where an external policy enforcement point took an overreach-driven disclosure rate to zero while the agent kept trying. The present work is that thesis applied to the network egress of a live browsing agent, with the same result and the same structure of evidence.

## Limitations

- The models are local (qwen2.5 7b and 14b, and an 8B variant), not frontier models. All three leaked a large fraction of the time (50% to 100%), but the rate did not track model size cleanly, so I do not claim from this data that capability monotonically raises injectability; the exfil page gives explicit navigation steps, so the measured rate tracks how reliably a model executes a multi-step browser action. The absolute rates are specific to this setup.
- When the secret is seeded through the agent's own browsing, reading an API key on its account page rather than being told it by the user, the leak rate falls to 50% (5/10). The realistic two-navigation task is harder to complete, but the exposure is clearly real, not an artifact of spoon-feeding the key.
- The sample is ten trials per configuration. The confidence intervals are wide by design, and scaling the sample tightens them.
- The main rate trials deliver the exfil instruction as visible page text. A dedicated hidden-channel run (off-screen text, HTML comment, image alt text) leaked in 30% of trials (3/10): invisible delivery, which a human reviewing the page would never see, lands less reliably than visible text but still lands.
- The egress boundary enforces on the host, not on the content. It stops a request to an undeclared destination. It does not stop exfiltration to a destination that is on the allowlist: routing the secret to the declared origin leaked in 10 of 10 trials with the boundary active (Measurement 6), whether through an open redirect, a free-text field on a permitted service, or a paste to a trusted domain. Over HTTPS it enforces on the CONNECT target and TLS server name, which are visible without terminating the connection (Measurement 5); inspecting the contents of an allowed tunnel would require termination and is the data-aware problem below. A host allowlist is the floor. The stronger control is data-aware egress, which asks whether a given request could have been constructed from the user's secret, and that is the harder problem the boundary points toward rather than solves.
- The boundary stops out-of-scope egress, not in-scope misuse, and it does not make the model's decision correct. In every contained trial the model still chose to leak.
- I report the allowlist leak as an outcome; I did not isolate its internal cause.

A boundary narrows the blast radius to what the task authorized. It does not make the agent trustworthy.

## Responsible disclosure

This is a class-of-problem evaluation building on documented attacks, not a report of a new vulnerability in browser-use, so it is not a CVE and is not framed as one. The behaviours shown are, for the most part, agents working as designed in a way that is dangerous, and the allowlist result confirms a limitation already present in the public record. I am giving the maintainers a courtesy notice ahead of publication, I credit the prior work I reproduced, and I keep the framing on the class of problem and the defense rather than on any one project. Nothing here was tested against a hosted deployment; the entire evaluation ran against a local instance I control, with synthetic data.

## Reproducing this

The full lab, the poisoned pages, the attacker endpoint, the egress boundary, and the measurement scripts are published so the result can be checked rather than taken on faith: https://github.com/Noctis-dev1/browser-use-exfil-lab. The egress boundary and the longer argument for authority-scoped enforcement are in Portcullis (github.com/Noctis-dev1/portcullis). Each configuration is a single command; the attacker endpoint and the proxy write the logs that the rates are read from.

## About

I am Malachi Zion Kopman. Through Noctis I work on bounding and verifying the authority of AI agents: the layer that decides what an agent may do with a user's data and tools, and that proves what it did. If you are shipping an agent that reads untrusted input, calls tools, or touches customer systems, this is the surface I work on, and I can run this same evaluation against your own agent: the measured rate at which it leaks, and what a boundary would stop.

I am taking on a small number of founding-client assessments. If you want to know how your own agent behaves under this, reach out: https://www.linkedin.com/in/malachi-zion-kopman-b71059333/

- Reproduction and lab: https://github.com/Noctis-dev1/browser-use-exfil-lab
- Portcullis (open source): github.com/Noctis-dev1/portcullis
