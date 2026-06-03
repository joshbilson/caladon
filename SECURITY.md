# Security Policy

Caladon is a **trust-no-one, attested confidential-computing** product. Its entire
value rests on a single claim: that data-touching compute runs inside hardware TEEs
whose attestation the client verifies, fail-closed, before any plaintext leaves the
device. A vulnerability in that chain is not a normal bug — it can silently void the
core guarantee of the product. We treat security reports accordingly, and we hold
**independent security review as the single most valuable contribution anyone can
make to this project.**

This policy covers how to report a vulnerability, what is in scope, and what you can
expect from us.

---

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security report.**
Public disclosure before a fix puts every user at risk.

Report privately, via either channel:

- **Email:** `security@caladon.ai` (PGP-encrypt sensitive details; our key
  fingerprint is published in this file once available — request it in your first
  message if not yet listed).
- **GitHub:** use **Security → Report a vulnerability** (private vulnerability
  reporting / GitHub Security Advisories) on this repository.

Please do **not** use personal email addresses, social media, or chat DMs — those
channels are not monitored for security reports and cannot be triaged safely.

### What to include
A useful report usually has:

1. The **claim it breaks.** What guarantee does this defeat? (e.g. "the client would
   accept a forged attestation", "plaintext reaches the host outside the enclave",
   "the data key is recoverable by the operator".)
2. **Affected component(s)** and version / commit hash.
3. A **reproduction**: minimal steps, proof-of-concept code, captured traffic, or a
   failing assertion. The more deterministic, the faster we can confirm.
4. **Impact and scope:** who is affected, under what trust assumptions, and whether
   it requires a malicious operator, a compromised host, a network attacker, etc.
5. Any suggested remediation, if you have one.

You do not need a complete exploit to report. A credible, well-reasoned weakness in
the trust model is worth more than a flashy PoC against something out of scope.

---

## In scope

The following are explicitly in scope and are the areas we most want reviewed:

### 1. Attestation-verification logic
The client's verification of TEE attestation is the load-bearing wall of the whole
system. In scope:

- Any path where the client would **accept an invalid, forged, replayed, stale, or
  downgraded attestation** (TDX quote, NVIDIA CC evidence, or the report binding the
  channel key to the enclave measurement).
- **Fail-open** behavior: the client sending plaintext when verification should have
  failed (errors swallowed, default-allow, TOCTOU between verify and send, missing
  pinning of expected measurements / RTMRs / event log).
- Incorrect or missing validation of the **PCS collateral / attestation
  certificate chain** (revocation, TCB level, freshness, signature checks).
- Confused-deputy or relay attacks that let one enclave's attestation stand in for
  another.

### 2. Plaintext-exposure paths
Anywhere user plaintext (prompts, agent memory, embeddings, keys, derived secrets)
could be exposed **outside the attested enclave boundary**:

- Plaintext reaching the operator, host OS, hypervisor, inference provider, or logs.
- Data written unencrypted to disk, swap, crash dumps, telemetry, or error
  reporting.
- Key-management flaws: the per-user data key being recoverable by anyone other than
  the user, released to an unverified enclave, or persisting beyond session end.
- Cross-tenant / cross-tier leakage (e.g. the coding tier touching the personal
  key, or one user's data reaching another's enclave).

### 3. Cryptographic envelope
The sealed channel and at-rest encryption:

- Weaknesses in the encryption scheme, key derivation, nonce/IV handling,
  authentication (AEAD misuse), or channel binding to the attested key.
- Downgrade, replay, or MITM against the sealed channel between the client and the
  enclave.
- Insufficient or incorrect use of randomness.

### 4. Claims overreach
This project considers **dishonest or overbroad security claims to be a defect**, and
reports of them are in scope. If the code, UI, marketing, or docs claim a guarantee
the architecture does not actually provide — for example using "end-to-end
encrypted", "zero-knowledge", or "no possibility of leaks" where the design exposes
plaintext to a remote enclave, or asserting an audit/certification that has not
happened — that is a security-relevant bug. Tell us. We would rather be told we
overclaimed than mislead a user about their threat model.

---

## Out of scope

These are generally **not** eligible (report them as ordinary issues unless they
chain into something in scope):

- Findings against third-party infrastructure we do not control (the silicon
  vendors' TEE hardware itself, upstream PCS, hosting provider). Report those to the
  relevant vendor; tell us if it affects our threat model.
- **Traffic metadata** (timing, size, frequency). This is a **disclosed,
  documented non-goal** — content confidentiality does not hide traffic analysis.
  See the privacy model in the README. Novel metadata attacks that meaningfully
  exceed the documented residual risk are still interesting — send them, flagged as
  such.
- Denial of service from raw traffic volume, rate-limiting gaps, or resource
  exhaustion without a confidentiality/integrity impact.
- Social engineering, physical attacks against a user's own device, and issues that
  require an already-fully-compromised client device.
- Missing security headers, weak TLS config, or automated-scanner output with no
  demonstrated impact.
- Outdated dependencies without a demonstrated exploitable path.

When in doubt, report it. We would rather triage an out-of-scope report than miss an
in-scope one.

---

## Our commitment to you

This is an early-stage, **not-yet-independently-audited** project. We will be
straight with you about that.

- **Acknowledgement:** within **3 business days**.
- **Initial assessment** (in scope? severity? reproduced?): within **10 business
  days**.
- **Status updates:** at least every **2 weeks** while a report is open.
- **Fix & disclosure:** we aim to ship a fix and a coordinated public advisory
  within **90 days** of confirmation. For an actively exploited or critical
  attestation/plaintext flaw we will move faster and may issue an interim mitigation.
- **Coordinated disclosure:** we will agree a disclosure date with you and credit you
  in the advisory and release notes **unless you prefer to remain anonymous.**

We do not currently run a paid bug-bounty program. We will say so honestly rather
than imply a reward that does not exist. Recognition is via public credit and our
sincere thanks.

---

## Safe harbor

We will not pursue or support legal action against researchers who:

- Make a good-faith effort to follow this policy;
- Act only against their **own** account, data, and infrastructure (or test
  accounts), and do not access, modify, or destroy other users' data;
- Do not degrade service for other users or exfiltrate more data than is necessary
  to demonstrate the issue; and
- Give us a reasonable opportunity to remediate before public disclosure.

If you are unsure whether an action is authorized, ask first at `security@caladon.ai`.

---

## Why this matters here

For most products a security bug is a problem. For Caladon, a break in the
attestation chain or a hidden plaintext path means the product is silently lying to
its users about the one thing it promises. **Independent, adversarial review of the
verification logic, the crypto envelope, and the honesty of our claims is the most
valued contribution to this project — more than any feature.** Thank you for taking
the time to make it stronger.
