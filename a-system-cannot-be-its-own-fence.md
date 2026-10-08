# A System Cannot Be Its Own Fence

### One enforcement principle across secure boot, AI agent egress, and the disk under my own notes

*Malachi Zion Kopman, Founder, Noctis*

*October 2026*

---

**Abstract.** In an earlier piece I argued that bounding an AI agent's authority (the fence) does more for safety than hardening the model (the fortress). This is the generalization. The same pattern appears wherever a system has to be kept within limits: the enforcement that works is placed outside the thing it governs, in a layer that thing cannot reach or reason past, and the enforcement that fails is the system asked to police itself. I show the pattern in three places I have worked, a browsing agent, a microcontroller, and an encrypted disk, give the one measurement I can stand behind, and name the counter-example that proves the rule. The claim is structural, not a claim that these are the same engineering.

---

## The pattern, stated plainly

A system cannot reliably enforce a limit on itself, because the same machinery that would break the limit is the machinery you are asking to hold it. The fix, every time, is to move the enforcement to a layer the system cannot touch: earlier in the boot chain, lower in the network stack, outside the running session. The governed thing can be fully compromised, fully convinced, fully hostile, and still be unable to act, because the thing saying no is not part of it.

I did not set out to find this everywhere. I noticed it after mapping my own working notes into a graph and watching three unrelated nodes link up: a firmware control, a network control, and a disk control, all the same shape. Here they are.

## Case one: the AI agent, where I have numbers

A browsing agent reads attacker-controlled web content into the same context that holds its user's secrets. That is not an edge case, it is the entire job. The attack that follows, indirect prompt injection carrying data back out, is well documented, so the useful question is not whether it works but what stops it.

I took browser-use, a widely used open-source browsing agent, and in a sealed local lab measured how often a synthetic secret left the machine under three configurations. With no defense, it leaked in ten of ten trials. With the framework's own domain allowlist set to the task's origin, it still leaked in ten of ten, because that allowlist governs where the agent may navigate, not what may leave. The secret left anyway. I report that as a measured outcome and do not claim the internal reason the request completed, which I did not isolate. With a network-layer authorization boundary that default-denies any undeclared destination, placed between the agent and the network, it leaked in zero of ten, and every blocked request was written to an audit log.

In every contained trial, the model still tried. It was fully talked across the line, fully intending to exfiltrate, and it could not, because the decision to allow the connection lived in a proxy outside the model, in a place the poisoned page could not address. The allowlist inside the framework, the first control anyone reaches for, is the system policing itself, and it held the leak rate at one hundred percent. The control that worked was the one the agent could not argue with.

## Case two: the chip, where the hardware world settled this long ago

A microcontroller faces the same problem one layer down. How does a device refuse to run code that is not yours, when the attacker may control the flash the code is read from?

Hardware converged on secure boot. Rather than ask the running firmware to check itself, an immutable boot ROM, burned into the silicon and beyond the reach of anything you can later flash, verifies a signature before it hands control to the next stage. Pair it with flash encryption so the image cannot simply be read off the chip, and you have the two jobs of what I think of as the wax seal, integrity and confidentiality, both enforced from a layer the running code cannot modify. The firmware does not get a vote on whether it is allowed to run. Something beneath it already decided.

This is the same move as the egress boundary. The enforcer sits below and outside the governed system. I have not measured secure boot the way I measured the agent, and I will not pretend otherwise; this is the established design of the field, offered here as the same shape, not as my result.

## Case three: the disk under these very notes

The last case is smaller and closer to home. The notes this argument came from sit on a laptop. What stops a thief who takes the laptop, or pulls the drive out of it, from reading them?

Not the operating system, which by then is not running. Full-disk encryption holds the key outside the booted system, in the secure enclave, released only against a credential supplied at power-on. Without that credential the data at rest is ciphertext, because the key that would unlock it is not stored in the box the thief now holds. The honest scope is narrow: this protects the machine when it is off. A running, unlocked laptop decrypts its own files, and a live compromise reads them like any other process. The guarantee covers the powered-off box, and it comes from putting the key outside. Same pattern, third domain.

## The counter-example that proves it

The principle shows clearest where it is missing. A low-frequency 125 kHz proximity fob, the kind that opens a lot of office doors, has no cryptography and no authentication. It simply announces its number to any reader that energizes it. There is no outside enforcer, nothing that challenges the fob to prove it is genuine, so the number can be read and written to a blank card in seconds. I have done it on my own bench with a Proxmark and a T5577 card.

The fob is insecure for exactly the reason the other three are secure, inverted. Nothing sits outside it to say no. It is trusted to be itself, and anything trusted to police itself can be copied, convinced, or overridden. The higher-frequency cards that resist cloning do so precisely by adding what the prox fob lacks: a challenge from the reader that the card must answer by proving it holds a key it never transmits, enforcement from outside the token.

## What this means for anyone shipping an agent

The current instinct in AI safety is to make the model better behaved: clearer instructions, a stronger system prompt, a refusal it has been trained to give. That is the fortress, and it is the fob. It asks the system to police itself, and a system that can be talked into anything can be talked out of its own rules. My ten-of-ten allowlist result is what self-policing looks like when it is measured.

The question worth asking about an agent is therefore not "is the model safe." It is "what enforces the limit from outside the model, and can the model reach the thing that enforces it." If the only thing standing between a hijacked agent and your customer's data is the agent's own good judgment, you do not have a fence. You have a fob.

## Where the principle stops

This has a hard edge, and it needs marking. The pattern is a lens, not a proof, and an outside boundary is necessary rather than sufficient. A host-level egress boundary stops a request to an undeclared destination. It does not stop exfiltration to a destination that is already allowed, through an open redirect, a free-text field on a permitted service, or a paste to a trusted domain, and over HTTPS it must enforce on the server name or terminate the connection to see the host at all. The outside enforcer narrows the blast radius to what the task authorized. It does not make the agent's decision correct, and the harder problem it points toward, egress that is aware of whether a request could have been built from the user's secret, it does not solve. A fence is the floor. It is not the whole of safety. But it is the part that holds when the thing inside has already been convinced.

---

*The browser-use evaluation, the lab, and the egress boundary are reproducible: github.com/Noctis-dev1/browser-use-exfil-lab. The boundary and the longer argument for authority-scoped enforcement are in Portcullis: github.com/Noctis-dev1/portcullis. I work on bounding and verifying what AI agents may do with a user's data and tools. If you are shipping one, I can measure how it behaves under this: www.linkedin.com/in/malachi-zion-kopman-b71059333*
