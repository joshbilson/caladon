# Contract: Gateway API (ciphertext router)  (`/contracts/gateway-api.md`)

**Status:** FROZEN for Phase 1 (2026-06-02). **AMENDED (unattended loop an earlier iteration, 2026-06-03,
for ratification):** added `POST /v1/session` (WMK delivery into the CVM, §6) + a `session_pub`
field in the `GET /v1/attestation` evidence — both ADDITIVE (no existing behaviour changed).
See the security docs under `docs/security/`. Changes require maintainer + project-lead sign-off.
**Owners:** B (gateway, primary), D (iOS/macOS client consumes), C (CVM upstream), H (tests).
**Pairs with:** `identity-envelope.md` (envelope + account_id), `attestation-evidence.md`
(handshake), `inference-providers.md` (upstream). Supersedes the M1b bearer-token API in
`gateway/README.md` for the confidential target.

The gateway is a **ciphertext router**: it routes by `account_id`, forwards opaque
envelopes, and **never holds a key or sees plaintext**. It runs in one of two modes
(`docs/deployment-tiers.md`): `cvm` (T1, inside the attested CVM, TLS terminates in-CVM)
or `plain` (T0 self-host). Multi-tenant from day 1.

## 1. Auth (multi-tenant, replaces `GATEWAY_DEVICE_TOKENS`)
- Client authenticates per-request with a capability derived from the seed, NOT a shared
  token: `Authorization: Caladon acct=<account_id> ts=<unix> sig=<Ed25519(sign over
  acct||ts||method||path)>`. `account_id` per `identity-envelope.md §3` (256-bit, zero PII).
- Gateway verifies the signature against the account's registered Ed25519 pubkey
  (registered at onboarding, §3), checks `ts` freshness (±120s, anti-replay window), maps
  `account_id → that tenant's Agent CVM + Letta agent`. Missing/invalid → 401.
- **No bearer tokens, no PII, no cross-tenant access.** Rate-limited per `account_id`.

## 2. Endpoints (all under the tenant's verified base URL)
| Method · Path | Body / params | Returns |
|---|---|---|
| `GET /health` | — (no auth) | `{"status":"ok","mode":"cvm"|"plain"}` |
| `POST /v1/accounts` | `{account_id, ed25519_pub, kem_pub}` | onboarding: register a tenant (idempotent); provisions the Agent CVM + Letta agent. 201/200 |
| `GET /v1/whoami` | auth | `{authenticated:true, account_id, tier}` |
| `GET /v1/attestation` | auth + `challenge` (`attestation.md §3`) | the attestation evidence bundle (`attestation-evidence.md`) for the tenant's Agent CVM, incl. the CVM `session_pub` (X25519, §6) — client verifies BEFORE sending anything |
| `POST /v1/session` *(AMENDED)* | auth + `{client_eph_pub, sealed_wmk}` (WMK sealed to SK; `identity-envelope.md §6`) | WMK delivery into the CVM (TEE RAM). `cvm` mode only (T0 → 501); fail-closed 400. 200 on establish |
| `GET /v1/messages?limit=N` | auth | array of **envelopes** (`identity-envelope.md §4`) — transcript ciphertext only, newest-last; client decrypts |
| `POST /v1/chat` | auth + body `{envelope}` (encrypted prompt; WMK delivered over the §4 SK channel, never here) | `text/event-stream` (§3) |

## 3. Streaming (SSE — preserved from M1b, now ciphertext)
Events on `POST /v1/chat`: `event: token` (encrypted delta envelope) · `event: reasoning`
(optional, encrypted) · `event: receipt` (per-response inference attestation receipt,
`attestation-evidence.md §3` — client re-verifies) · `event: done` `{}` · `event: error`
`{code, message}` (no plaintext content in errors). Token/reasoning payloads are envelopes
the client decrypts; the gateway never sees plaintext deltas (they originate in the CVM).

## 4. What the gateway sees vs never sees
- **Sees:** `account_id` (routing), envelope blobs, sizes/timing (metadata — minimized per
  `identity-envelope.md §9`), the attestation bundle it passes through.
- **Never:** any key, any plaintext prompt/response/memory. **Fail-closed no-logging** of
  bodies (enforced by `tests/leak/test_no_plaintext_logging.py`, runtime probe in P1).

## 5. Run modes
- `cvm` (T1): bound inside the Agent CVM; TLS cert carries the CVM's TDX quote
  (`attestation.md §2.1 dstack_cert`); `GET /v1/attestation` returns real evidence.
- `plain` (T0): plain VM; `GET /v1/attestation` returns `{regime:"none", tier:"self-host"}`
  and the client's policy must be `trusted-self-host` (operator=user) or it refuses.

## 6. Versioning & test obligations (H)
- `/v1` path version; envelope carries its own `v`. Account-sig verify (good/bad/stale).
- Multi-tenant isolation: tenant A's signed request cannot read tenant B (routing + 401).
- No plaintext in logs/responses/errors (leak tests). SSE event mapping preserved.
- `plain` mode refuses unless client opts into `trusted-self-host`.
