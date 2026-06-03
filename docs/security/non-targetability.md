# Caladon — Non-Targetability Design (Apple-PCC req #4)

**Status:** DESIGN (this round) — concrete plan, no full implementation yet.
**Owner:** the team (design) with **C** (relay/infra) and **D** (iOS client).
**Referenced by:** `docs/security/measurements.md §4`; `infra/transparency/README.md`.
**Relates to:** `docs/security/threat-model.md §6` (metadata is a disclosed partial
mitigation, not solved), `contracts/attestation.md §6` (measurement pinning),
`contracts/identity-envelope.md §9` (payload padding).

> **The property.** Apple's Private Cloud Compute lists five requirements; #5
> (transparency) is delivered by the Sigstore Rekor transparency log
> (`infra/transparency/`). This document specifies **#4 — non-targetability**: an
> attacker who controls the network and the fleet **must not be able to steer a
> *specific* user (or a specific request) to a *specific* compromised node** of
> their choosing. Without this, attestation alone is not enough: an operator who
> can pick which node serves Alice can stand up one node with a leaked/old build,
> route only Alice to it, and serve everyone else honestly. Pinning catches a
> *globally* swapped build; non-targetability is what stops a *targeted* one.

This is **design only**. It states the goal, the threat, the architecture (an
OHTTP relay that hides the client IP, plus load-balanced node selection the
operator cannot bias, plus single-use credentials that carry no stable
identity), what we build in which phase, and how it is verified. No relay is
shipped this round.

---

## 1. What "targetability" buys an attacker (and why pinning is not enough)

The frozen design already gives **content** confidentiality (sealed envelopes,
TEE-only plaintext) and **integrity** of the workload (measurement pinning,
no-TOFU, fail-closed — `attestation.md §6`). The gap a targeting attacker
exploits is **selection**:

1. The operator runs a fleet of attested nodes. All pass attestation *today*.
2. The operator brings up one node running a build whose measurement is **still
   in the pinned set** but is, say, the oldest still-pinned build with a known
   weakness — or simply a node positioned for a side-channel attempt
   (`threat-model.md §6`, TEE side-channel acknowledged break class).
3. If the operator can **decide which node a chosen user reaches** (by IP, by
   account routing, by DNS/anycast steering, by a "sticky" load balancer keyed on
   anything identifying), they get a targeted attack while the fleet still looks
   honest in aggregate and in the transparency log.

Non-targetability removes step 3: the client's request must land on a node the
attacker **could not have chosen for that specific client**, and the request must
not carry anything that lets a node-selection layer recognize *which* user it is.

This composes with — does not replace — the existing controls:

| Layer | Property | This doc adds |
|---|---|---|
| Encryption envelope (`id-env §4`) | content confidentiality | — |
| Measurement pinning (`attestation §6`) | the node runs an *audited* build | — |
| Transparency log (`infra/transparency`) | the pinned set is public + tamper-evident | — |
| **Non-targetability (this doc)** | the attacker can't route *you* to *their* node, and the path carries no stable you-identifier | the missing PCC #4 leg |

---

## 2. Threat model for targeting

**In scope (what this design defends):**

- **IP-based targeting.** The client's source IP is a strong, stable identifier.
  An operator (or an on-path network adversary) who sees `IP → node` can route a
  known IP to a chosen node, and can correlate sessions to a person/household.
- **Account/credential-based targeting.** `account_id` is zero-PII but **stable**
  (`threat-model.md §7`). A node-selection layer keyed on `account_id` (or any
  long-lived token) lets the operator pin a user to a node deterministically.
- **Selection-bias targeting.** Even without an explicit key, a load balancer the
  *operator controls* can be biased (weighting, "maintenance" draining, sticky
  affinity) to push a chosen client onto a chosen node.

**Out of scope (disclosed, not solved — consistent with `threat-model.md §6`):**

- **Global compromise.** If *every* node is malicious, non-targetability does not
  help; that is the measurement-pinning + transparency + reproducible-build leg's
  job (a malicious build should not be pinnable). Non-targetability defends the
  *targeted-subset* case.
- **Traffic-analysis of volume/timing** beyond what padding/batching already
  bound (`id-env §9`). The relay hides the client IP from the backend, but a
  global passive adversary correlating relay-in/relay-out timing is the standard
  mixnet-grade threat we explicitly do **not** claim to solve.
- **A novel TEE hardware break.** Acknowledged break class (`threat-model.md §6`).

---

## 3. Architecture

Three independent mechanisms; each closes one targeting vector. They are designed
to be deployable incrementally (§5).

### 3.1 OHTTP relay — hide the client IP from the backend

Use **Oblivious HTTP** (RFC 9458) with the standard two-party split:

```
  client ──(encapsulated request, TLS)──▶  RELAY  ──(forwarded)──▶  GATEWAY (TEE)
            relay sees: client IP,                  gateway sees: relay IP,
            NOT request contents                    NOT client IP
```

- The client encapsulates its (already-sealed) request under the **gateway's
  HPKE public key**, then sends it to a **relay operated by a party distinct from
  the gateway operator**. The relay forwards to the gateway's OHTTP gateway
  endpoint. Neither party alone sees both *who* (IP) and *what* (contents).
- **Trust split is the point.** The relay sees client IPs but not contents (it
  cannot decrypt the OHTTP encapsulation, and contents are *already*
  envelope-sealed underneath — defense in depth). The gateway sees contents
  (inside the TEE) but only the **relay's** IP, never the client's. For the
  operator to target by IP they would need to collude with the relay → so the
  relay must be **independently operated** (candidate: a CDN/relay provider, or a
  community-run relay), and that independence is the deployment-time security
  assumption we disclose.
- **HPKE key for the gateway is attestation-bound.** The OHTTP gateway key is
  published in / derived alongside the attested channel material so a relay (or
  MITM) cannot substitute its own key to become a decrypting man-in-the-middle —
  it chains to the same measurement-pinned TEE the client already verifies
  (`attestation.md §3` channel binding). This is what stops "the relay is the
  attacker."
- **Why OHTTP and not a full mixnet/Tor:** OHTTP is a *bounded* metadata control
  (it unlinks IP from content for the backend) with low latency — appropriate for
  an interactive assistant. We disclose it as IP-unlinkability, **not** as
  traffic-analysis resistance against a global passive adversary (§2 out-of-scope;
  `threat-model.md §6`).

### 3.2 Operator-blind node selection — the attacker can't pick your node

IP-hiding stops *recognizing* the client; this stops *steering* the request:

- **Selection happens behind the relay, keyed on nothing client-identifying.**
  Node assignment must be a function the operator cannot bias toward a chosen
  client: e.g. random/round-robin over the healthy attested set, or a rendezvous
  hash over a **per-request ephemeral token** (§3.3) — never over `account_id`,
  IP, or any stable field.
- **The client re-verifies attestation on whatever node it lands on**
  (`attestation.md §4`, no-TOFU). Targeting only matters if a *weaker-but-pinned*
  node exists; the mitigation is therefore also **tighten the pinned set**: keep
  the pinned set small and current (retire old builds promptly — the pinned set
  changes only via signed app update, `measurements.md §3`), and publish every
  pinned build to the transparency log so "which builds are acceptable" is itself
  auditable. A targeted node must still be running a currently-pinned build, and
  we minimize how many of those exist.
- **No sticky affinity.** Any session-stickiness (e.g. for warm caches) must key
  on the ephemeral per-session token, expire with the session, and never persist
  an `IP/account → node` mapping the operator could read or set.

### 3.3 Single-use, identity-decoupled credentials — anonymous-but-authorized

To let only paying/authorized clients in **without** handing the selection layer a
stable identifier, use **anonymous, single-use access tokens** (Privacy Pass /
RFC 9578-style **Privacy Pass tokens**, i.e. blind-signed):

- At provisioning/top-up time the client obtains a batch of tokens **blind-signed**
  by the issuer. The issuer signs without learning which token maps to which
  client (blind signature), so redemption is unlinkable to issuance.
- Each request to the relay/gateway spends **one** token. The token proves
  "authorized" but is **single-use and carries no account identity**, so the
  selection layer and the backend cannot use it to recognize or pin a user across
  requests.
- This decouples **billing/authorization** (which legitimately needs `account_id`,
  done at issuance) from **per-request routing** (which must be anonymous). It is
  the credential analogue of the §3.1 IP split: the part that knows *who you are*
  (issuer) is separated from the part that *serves the request* (relay/gateway).
- Relationship to `account_id`: `account_id` stays the at-rest routing key for the
  *encrypted store* (`id-env §4`), but it **must not** appear on the live
  inference path once tokens exist — that path becomes account-anonymous. (This is
  a strengthening of the `threat-model.md §7` "`account_id`/metadata visible" row
  for the live path.)

---

## 4. How each targeting vector is closed

| Targeting vector (§2) | Closed by | Residual (disclosed) |
|---|---|---|
| IP → node routing / IP correlation | §3.1 OHTTP relay (backend never sees client IP) | relay sees IP; requires *independent* relay operator (deployment assumption) |
| `account_id`/token → node pinning | §3.3 single-use blind-signed tokens (no stable id on the live path) | issuer learns *that* you bought tokens, not *which* request is yours |
| operator-biased load balancer | §3.2 selection keyed only on ephemeral per-request token; client re-attests on landing | a *currently-pinned* weak build could still be targeted → mitigate by keeping the pinned set small/current + transparency-logged |
| substitute-key MITM at the relay | §3.1 attestation-bound HPKE gateway key | none beyond the standard sound-hardware/attestation assumption |

---

## 5. Phasing (what we build, when)

This round is **design**. Implementation is staged so each phase delivers a
standalone improvement:

1. **Phase A — relay-ready gateway.** Expose an OHTTP gateway endpoint on the CVM
   and publish the attestation-bound HPKE key. Client can use a *trusted* relay
   (even the operator's, as a first step) — already unlinks IP from content for
   anyone downstream of the relay. (Builds on the in-CVM TLS termination from
   `dstack-compose.gw-v1.yml`.)
2. **Phase B — independent relay.** Move the relay to a party distinct from the
   gateway operator; document the independence assumption and the candidate
   provider. This is when §3.1's trust split becomes real.
3. **Phase C — operator-blind selection.** Replace any identifying routing key
   with ephemeral-token-keyed selection over the healthy attested set; remove
   sticky `IP/account → node` affinity; shrink + transparency-log the pinned set.
4. **Phase D — single-use tokens.** Privacy-Pass-style blind-signed tokens issued
   at billing time, spent one-per-request, removing `account_id` from the live
   path.

Each phase is independently testable and independently disclosable; we never imply
a later phase's property before it ships.

---

## 6. Verification plan

- **IP-unlinkability (Phase A/B):** an integration test asserts the gateway never
  observes the client's IP — only the relay's — across a real OHTTP round-trip,
  and that the gateway rejects a request whose HPKE key does not chain to the
  attested channel material (no substitute-key MITM).
- **Selection cannot be biased (Phase C):** a test that the node-selection input
  is a fresh per-request token with no `account_id`/IP dependence; a property
  check that identical clients are not pinned to the same node across sessions.
- **Token unlinkability (Phase D):** a test that issuance and redemption cannot be
  correlated (blind-signature property), and that a token is rejected on second
  use (single-use), and that the live path carries no `account_id`.
- **Honest disclosure (claims discipline):** the public description states
  IP-unlinkability and operator-blind selection as **bounded** controls and keeps
  traffic-analysis resistance against a global passive adversary an explicit
  non-goal (`threat-model.md §6`, claims-register discipline). Caladon is attested
  confidential computing with non-targetability — we describe each control for
  exactly what it does and no more.

---

## 7. Cross-references

- `docs/security/threat-model.md §6, §7` — metadata as a disclosed partial
  mitigation; the `account_id`/metadata-visible rows this design tightens.
- `contracts/identity-envelope.md §4, §9` — `account_id` as the at-rest routing
  key; payload padding (the other metadata control).
- `contracts/attestation.md §3, §6` — channel binding (anchors the OHTTP gateway
  key); measurement pinning (the global-swap defense this complements).
- `docs/security/measurements.md §4` — the transparency log (Apple-PCC req #5),
  the sibling requirement.
- `infra/transparency/README.md` — the transparency-log tooling.
- RFC 9458 (Oblivious HTTP), RFC 9578 (Privacy Pass token issuance) — the
  standards the relay and token designs follow.
