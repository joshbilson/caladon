# `@caladon/protocol` — web client protocol SDK

The TypeScript bridge from a **seed-derived identity → `caladon-core` WASM → the live gateway
protocol**. This is the committable, testable **INJECT** layer that `web-client/SURGERY.md §D`
references — the place the React fork will call to seal prompts, verify attestation, and open
sealed replies. The React file-edits (§A/§B/§C of SURGERY.md) are a separate later step; this
package is self-contained, isomorphic (browser + Node), and proven against the live CVM.

> **Trust model (SURGERY.md §0):** the browser is the only place plaintext or a key exists. The
> shim and the gateway route opaque envelopes. All crypto/attestation runs in the `caladon-core`
> WASM; this SDK is the typed orchestration around it.

---

## What it does — the full fail-closed flow

Mirrors `infra/cvm/gate1_client.py` (the Python reference), end to end (SURGERY.md §D3):

1. **unlock seed** → `argon2id(seed, salt, t, m)` → root → key-bound `account_id` (B2-bis) + raw
   Ed25519 pub. The seed can come from a passkey-PRF-wrapped blob (`unlockViaPasskey`) or recovery
   string — see "Identity custody" below.
2. **onboard** → `POST /v1/accounts` proof-of-possession (idempotent) — a fresh seed self-registers.
3. **attest** → `GET /v1/attestation?challenge=SHA256(eph_pub)` → evidence (TDX v4 quote +
   CVM `session_pub`).
4. **verify (fail-closed)** → JS fetches PCS collateral → `verify_quote_sync(quote, collateral,
   info, now, challenge, pinned)` in WASM → quote→Intel root, TCB **UpToDate**, measurement /
   compose / app_id **pinned** (no TOFU), `report_data[0:32] == challenge`. Any non-`ok` verdict
   under the default `strict` policy **refuses to send**.
5. **session** → `derive_session_key` against the attested `session_pub` → `seal_wmk` → `POST
   /v1/session` (WMK delivered into TEE RAM over the §6 channel).
6. **chat** → `seal_chat(prompt)` → `POST /v1/chat` → stream sealed `token`/`reasoning` deltas →
   `open_chat` each → recovered plaintext. The plaintext prompt/reply never appears on the wire.

```ts
import { CaladonClient } from '@caladon/protocol';

const client = new CaladonClient({
  shimBase: '/api/caladon',          // browser: same-origin shim (web-client/shim)
  pcsCollateralBase: '/pcs-collateral',
  pinned: { measurements: [...], compose_hashes: [...], workload_ids: [...] }, // measurements.md
});
const { handshake, chat } = await client.roundtrip(seed, 'Hello, Caladon.');
console.log(handshake.verdict);  // { ok: true, reason: 'ok', measurement_matched: true }
console.log(chat.reply);         // recovered, decrypted attested-inference reply
```

The client also exposes the steps individually (`unlockSeed`, `onboard`, `getAttestation`,
`verifyAttestation`, `establishSession`, `chat`) for the React integration to drive piecemeal.

---

## WASM build & what we commit

- `./build-wasm.sh` runs `wasm-pack build --target web --features wasm` against `caladon-core`
  (READ-ONLY use of that crate) and writes the wasm-bindgen output to `wasm/`.
- **Commit decision:** we commit the small generated glue (`wasm/caladon_core.js`,
  `wasm/caladon_core.d.ts`, `wasm/caladon_core_bg.wasm.d.ts`, `wasm/package.json`) so the SDK
  type-checks and imports with no build step, but we **git-ignore the ~950 KB binary**
  (`wasm/caladon_core_bg.wasm`) — regenerate it with `./build-wasm.sh` / `npm run build:wasm`.
  See `.gitignore`. The integration test reads the `.wasm` bytes off disk (Node has no
  same-origin fetch for a local path); the browser passes a fetched URL.

The WASM exports used (SURGERY.md §D table): `argon2id`, `account_id`, `authorization_header`,
`challenge_hex`, `x25519_public`, `derive_session_key`, `wmk`, `seal_wmk`, `open_wmk`,
`seal_chat`, `open_chat`, `verify_quote_sync`.

---

## Collateral (the JS side of the WASM attestation design)

`verify_quote_sync` is offline and deterministic: collateral is **fetched by JS and passed in**
(the `wasm` feature omits networking). `src/collateral.ts` mirrors `dcap-qvl`'s
`CollateralClient::fetch`: it extracts the PCK PEM chain embedded in the TDX quote (cert_type 5),
DER-parses the leaf for the Intel FMSPC, then fetches TCB info / QE identity / PCK CRL / root CA
CRL through the shim's CORS-fixing `/pcs-collateral` proxy and assembles a `QuoteCollateralV3`
JSON (byte fields as hex — the form `caladon-core` accepts, proven by its committed fixture).

For pinned hardware you may instead supply `collateralProvider` (e.g. the committed
`caladon-core/tests/fixtures/collateral.json`, which is FMSPC-keyed for the live `caladon-gw`
hardware and so verifies any session quote from that CVM within its validity window). The
integration test uses this provider for determinism.

---

## Tests

- **Offline (`test/offline.test.ts`, no network — default `npm test`):** bytes/base64/hex
  helpers; `argon2id`→`account_id` (the gate1 key-bound value); `authorization_header` shape;
  `derive_session_key` + `seal_chat`/`open_chat` round-trip + tamper-fail-closed; wire-envelope
  round-trip; and the **attestation keystone offline** — `verify_quote_sync` returns
  `ok=true` for the committed live quote + fixture collateral, and fails closed with
  `BINDING_MISMATCH` / `MEASUREMENT_UNPINNED` on tampered inputs. **12 tests, all green.**
- **Live (`test/live.test.ts`, gated on `CALADON_LIVE=1`):** the full round-trip against the real
  `gw.caladon.ai`, mirroring `gate1_client.py`. **2 tests, both green:**

  ```
  CALADON_LIVE=1 npm test
  ```

### What was tested live + the recovered reply

Run 2026-06-03 against `https://gw.caladon.ai` (live Phala dstack Intel TDX CVM `caladon-gw`):

- `GET /v1/attestation` → `regime: tdx-onchain`, real TDX v4 quote + `session_pub`. The challenge
  we sent (`SHA256(eph_pub)`) is bound into `report_data[0:32]` (asserted).
- `verify_quote_sync` (fixture collateral, pin discovered from the live evidence) →
  **`{ ok: true, reason: 'ok', measurement_matched: true }`** — quote verifies to the Intel root,
  TCB UpToDate, measurement + compose_hash + app_id pinned, challenge bound.
- `POST /v1/session` → 200, **32-byte SK** derived; WMK sealed + delivered into TEE RAM (§6).
- `POST /v1/chat` (prompt `"Reply with exactly: CALADON LIVE OK"`) → sealed SSE; the plaintext
  prompt is **absent from the wire** (asserted); opening the sealed `token` deltas under SK
  recovers the real attested-inference reply:

  > **`CALADON LIVE OK`**

- The no-TOFU test confirms a non-matching pin yields `MEASUREMENT_UNPINNED` and the client
  **refuses to send**.

> The live `caladon-gw` is redeployed periodically; per `docs/security/measurements.md` the
> stable identity is `mr_td`/`rtmr0`/`rtmr1` + `os-image-hash`, while `rtmr2`, `app_id`,
> `compose_hash`, and `rtmr3` can change per deploy. The live test therefore **discovers** the
> current measurement/compose/app_id from the live evidence and pins those; the cryptographic
> root of trust (quote → Intel root, TCB, challenge binding) is what the verdict truly asserts.
> A shipping client pins from a signed app update (never at runtime) per `attestation.md §6`.

---

## Identity custody (self-onboard + passkey-PRF)

- **Self-onboard (closed).** `caladon-core` now exports `ed25519_public(root)`, so `unlockSeed`
  fills `ed25519PubB64` (the raw 32-byte Ed25519 pub) and `onboard()` posts the real
  proof-of-possession body `{account_id, ed25519_pub (b64), kem_pub (b64)}` signed by the
  `Authorization` header (Ed25519 over the canonical message). A **fresh random seed self-registers**
  against the live gateway — the gateway checks the PoP signature and that `account_id ==
  key-bound(pub)`. Mirrors `infra/cvm/gate1_client.py` `onboard()`. The live test (below) drives a
  brand-new seed all the way through.
- **Passkey-PRF seed custody (closed; `src/passkey.ts`).** The seed is held under a WebAuthn
  credential's `prf` extension: a 32-byte `prf32` derives a wrapping key
  (`passkey_derive_wrapping_key`, HKDF-SHA256 / `caladon/passkey-wrapping/v1`) that seals the seed
  (`passkey_wrap_seed` → `nonce ‖ ct`) and opens it (`passkey_unwrap_seed`, fail-closed on a wrong
  passkey / tamper). Only the wrapped blob + credential id persist; the seed and `prf32` never do.
  - **Crypto layer** (`deriveWrappingKey` / `wrapSeed` / `unwrapSeed`) is pure WASM and runs
    anywhere — the **offline tests** exercise the round-trip + wrapping key against the wasm exports.
  - **Browser glue** (`BrowserPasskeyCustody`, behind the `PasskeyCustody` interface) calls
    `navigator.credentials.create/get` with `{ extensions: { prf: { eval: { first: salt } } } }` and
    reads `getClientExtensionResults().prf.results.first`. Node has no `navigator.credentials`, so a
    browser wires this while tests inject a `CredentialsContainerLike` stub.
  - `CaladonClient.unlockViaPasskey(prf32, wrappedSeed)` unwraps the seed in WASM, then derives the
    same identity as `unlockSeed` — the rest of the flow is unchanged.

## Known gaps (Track-A dependencies — noted per the brief)

- **Per-response receipt re-verification (SURGERY.md §D3.5 / attestation-evidence.md §3).** The
  SDK opens `token`/`reasoning` deltas; re-verifying each `receipt` SSE event (in-TEE signature
  over the response, signer == handshake-attested key) is a follow-up once the gateway emits
  `receipt` events for this direct-inference path.

---

## Files

```
build-wasm.sh          # regenerate wasm/ from caladon-core (READ-ONLY use of that crate)
wasm/                  # generated glue (committed); caladon_core_bg.wasm git-ignored
src/
  client.ts            # CaladonClient — the full fail-closed orchestration
  passkey.ts           # passkey-PRF seed custody: WASM wrap/unwrap + WebAuthn-PRF browser glue
  wasm.ts              # the single caladon-core WASM loader (browser URL / Node bytes)
  collateral.ts        # PCS collateral fetch + QuoteCollateralV3 assembly (the JS side)
  quote.ts             # TDX measurement-aggregate extraction (the value to pin)
  envelope.ts          # wire envelope (de)serialization + AAD + SHA-256 + random
  bytes.ts             # isomorphic base64/hex/utf8 helpers
  constants.ts         # protocol constants (byte-identical to caladon-core / swifty_crypto)
  types.ts             # wire + protocol types
  index.ts             # public barrel
test/
  offline.test.ts      # no-network unit + attestation-keystone tests (default npm test)
  live.test.ts         # CALADON_LIVE=1 — full round-trip vs gw.caladon.ai
  support.ts           # Node WASM loader + fixture collateral + pinned-set helpers
```
