# Caladon Web Client

The Caladon web client is a **thin-shell fork of [LibreChat](https://github.com/danny-avila/LibreChat)**:
we keep its polished React chat surface and SSE streaming pipeline, and **amputate its entire
trust-bearing backend** — Mongo persistence, server-side LLM/agents orchestration, and Passport
auth. In their place the browser talks to the live Caladon gateway `gw.caladon.ai` (a ciphertext
router in front of a per-tenant attested CVM) through a stateless proxy shim, and does **all crypto
client-side** in the `caladon-core` WASM.

> The browser is the only place plaintext or a key ever exists. The shim and the gateway only ever
> route opaque sealed envelopes.

## Layout

```
web-client/
├─ README.md        ← you are here
├─ SURGERY.md       ← the file-level surgery map: what to RIP OUT / KEEP / LOCK DOWN / INJECT
├─ setup.sh         ← clones the (git-ignored) LibreChat upstream + installs the shim
├─ shim/            ← the stateless Hono proxy (committed). NO DB, NO keys. See shim/README.md
└─ librechat/       ← vendored LibreChat upstream — GIT-IGNORED, NOT committed (run setup.sh)
```

## Quick start

```bash
./web-client/setup.sh                 # clone LibreChat + install the shim
cd web-client/shim && npm run dev      # stateless proxy on :8787
cd web-client/shim && npm run smoke     # plaintext-first round-trip vs the live gateway
```

## How it fits together

```
              ┌──────────────────────────── browser (the only trusted plaintext zone) ───────────────────────────┐
              │  LibreChat React chat UI  +  caladon-core WASM (seal/open · seed-auth sign · attestation verify)  │
              └───────────────┬──────────────────────────────────────────────────────────────────────────────────┘
                              │  /api/caladon/{chat,messages,attestation,session,whoami}  +  /pcs-collateral
                              ▼
                       ┌─────────────┐   forwards opaque envelopes + the signed `Authorization: Caladon …` header
                       │  the shim   │   NO DB · NO keys · NO decryption · keyless HttpOnly session cookie
                       └──────┬──────┘
                              ▼
                    https://gw.caladon.ai   ← ciphertext router → per-tenant attested CVM (RedPill inference)
```

- **Crypto contract:** `/contracts/identity-envelope.md` (envelopes), `/contracts/gateway-api.md`
  (seed-auth + endpoints), `/contracts/attestation-evidence.md` (fail-closed verify). The WASM is
  built from `/caladon-core` (the single source of crypto truth; Python `swifty_crypto` is the
  byte-parity oracle).
- **The surgery plan** — exact files to RIP OUT (Mongo models, server LLM/agents, Passport), KEEP
  (React chat UI, SSE hooks), LOCK DOWN (Artifacts/Sandpack: `sandbox=allow-scripts` +
  CSP `connect-src 'none'`), and INJECT (WASM seal/open/sign + routing) — is in **`SURGERY.md`**.

## Status: SCAFFOLD + SHIM

Delivered this stage:
- Vendored LibreChat pinned (`v0.8.6`, commit `d680763`), git-ignored.
- `SURGERY.md` — the full file-level surgery map.
- `shim/` — the stateless Hono proxy, typechecked + smoke-proven (plaintext-first round-trip).
- `setup.sh` — one-shot bootstrap.

Blocked on **P3 (WASM)**: the `caladon-core` `wasm-bindgen` build and the dcap-qvl attestation
module. Until those land, the client runs the plaintext-first pipe (no seal/open, no fail-closed
attestation). The shim does not change when WASM arrives — see `SURGERY.md §D` for the inject
points and the "Blocked on P3" sections in both `SURGERY.md` and `shim/README.md`.
