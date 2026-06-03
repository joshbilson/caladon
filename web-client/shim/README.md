# Caladon Web Shim

A **stateless** Hono proxy that sits between the Caladon web client (the LibreChat fork) and the
live gateway `gw.caladon.ai`. It is deliberately almost-nothing:

> **NO database. NO keys. NO decryption. NO request signing.**

The shim is a CORS-and-cookie relay. The browser does all crypto (caladon-core WASM); the gateway
is the only real backend (a ciphertext router in front of a per-tenant attested CVM). The shim just
makes the browser ↔ gateway pipe same-origin and adds a keyless session cookie.

```
browser ──/api/caladon/{chat,messages,attestation,session,whoami}──▶ shim ──▶ https://gw.caladon.ai/v1/*
browser ──/pcs-collateral/*──────────────────────────────────────▶ shim ──▶ Intel PCS (CORS-fixed)
browser ──/health────────────────────────────────────────────────▶ shim (+ live gateway probe)
```

## Why it exists (it does the minimum on purpose)

1. **CORS.** The browser can't call `gw.caladon.ai` or Intel PCS cross-origin. The shim re-issues
   the request from the server side and adds CORS headers for **our origin only**.
2. **Cookie hygiene.** The shim sets one opaque **HttpOnly** session cookie (`caladon_sid`, 32
   random bytes, base64url) so a tab can be pinned to a logical session and we have a future CSRF
   anchor. It is **keyless and PII-free** — there is no server-side session store to resolve it
   against (NO DB). The real identity is the client's signed `Authorization: Caladon …` header
   (`/contracts/gateway-api.md §1`), which the shim forwards **verbatim** and the **gateway**
   verifies.
3. **One same-origin base** for the SPA, decoupling it from the gateway hostname.

## What it never does

Hold a key · sign a gateway request · decrypt or even parse an envelope body · persist anything ·
log a body. Request bodies are opaque sealed envelopes streamed through untouched. SSE chat deltas
(`event: token`) are sealed envelopes too — the shim relays them byte-for-byte; only the browser's
WASM can open them.

## Routes

| Public (browser)                         | → Upstream                          | Notes |
|---|---|---|
| `GET  /health`                           | (local) + probes gateway `/health`  | liveness; surfaces live gateway reachability |
| `GET/POST /api/caladon/chat`             | `POST /v1/chat` (SSE)               | sealed prompt envelope in, sealed deltas out; streamed |
| `GET  /api/caladon/messages`             | `GET /v1/messages`                  | transcript as opaque envelopes |
| `GET  /api/caladon/attestation`          | `GET /v1/attestation`               | evidence bundle (challenge in query) |
| `POST /api/caladon/session`              | `POST /v1/session`                  | WMK delivery (sealed) |
| `GET  /api/caladon/whoami`               | `GET /v1/whoami`                    | seed-auth identity check |
| `GET  /pcs-collateral/*`                 | `https://api.trustedservices.intel.com/*` | Intel PCS TDX quote collateral, CORS-fixed |

Header discipline (see `src/proxy.ts`): the browser **Cookie** header is stripped going upstream
(the gateway auths on the signed header, never a cookie); the gateway's **Set-Cookie** is stripped
coming back (only the shim owns the keyless session cookie); hop-by-hop headers are dropped both
ways; CORS headers are re-issued by the shim's own middleware.

## Run

```bash
npm install
npm run dev        # tsx watch, listens on :8787 (PORT env to change)
npm run typecheck  # tsc --noEmit (strict)
npm run smoke      # plaintext-first round-trip proof (see below)
```

### Config (env, all optional)

| Env | Default | Meaning |
|---|---|---|
| `CALADON_GATEWAY_BASE` | `https://gw.caladon.ai` | upstream gateway |
| `CALADON_PCS_BASE` | `https://api.trustedservices.intel.com` | Intel PCS |
| `PORT` | `8787` | shim listen port |
| `CALADON_ALLOWED_ORIGINS` | `http://localhost:3090,http://localhost:8787` | CORS allowlist (SPA origin) |
| `CALADON_UPSTREAM_TIMEOUT_MS` | `30000` | non-stream upstream timeout |
| `CALADON_SESSION_COOKIE` | `caladon_sid` | session cookie name |
| `CALADON_SESSION_MAX_AGE_S` | `86400` | session cookie max-age |
| `CALADON_COOKIE_SECURE` | `false` | set `true` behind TLS in prod |

There are **no secret env vars** — by design. The shim never has a credential to misplace.

## Prove the round-trip (plaintext-first)

`npm run smoke` boots the shim in-process and exercises the **real relay** with **no crypto** (the
seal/open layer is P3). It asserts:

1. `GET /health` → shim ok **and** live gateway reachable (`{status:"ok",mode:"cvm"}`).
2. `/api/caladon/*` issues an HttpOnly keyless session cookie.
3. `GET /api/caladon/whoami` (unauthed) → relayed → **401** (the gateway, not the shim, enforces auth).
4. `GET /pcs-collateral/*` → relayed to Intel PCS with a CORS header (the CORS fix works).

If the **live gateway** is transiently unreachable from your host (the CVM gateway resets
intermittently), checks 1 and 3 report **SKIP**, not FAIL — the relay logic is independently
provable with a local mock gateway:

```bash
# terminal 1 — a 30-line mock standing in for gw.caladon.ai
node -e 'import("node:http").then(({createServer})=>createServer((q,s)=>{
  if(q.url==="/health"){s.writeHead(200,{"content-type":"application/json"});return s.end(`{"status":"ok","mode":"cvm"}`)}
  if(q.url==="/v1/whoami"){const a=q.headers.authorization||"";s.writeHead(a.startsWith("Caladon ")?200:401);return s.end("{}")}
  if(q.url==="/v1/chat"){s.writeHead(200,{"content-type":"text/event-stream"});s.write("event: token\ndata: {}\n\n");s.write("event: done\ndata: {}\n\n");return s.end()}
  s.writeHead(404);s.end()}).listen(9911,()=>console.log("mockgw :9911")))'

# terminal 2 — point the shim at the mock and curl it
CALADON_GATEWAY_BASE=http://localhost:9911 npm run dev
curl -s localhost:8787/health
curl -s -o /dev/null -w "%{http_code}\n" localhost:8787/api/caladon/whoami                                   # 401
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Caladon acct=x ts=1 sig=AA==" localhost:8787/api/caladon/whoami   # 200
curl -sN -X POST localhost:8787/api/caladon/chat -d '{}'   # event: token / event: done  (SSE passthrough)
```

This exact mock run was verified during scaffolding: 401 unauthed, 200 with a `Caladon` header, and
SSE `token`+`done` events streamed through the shim untouched.

## Blocked on P3 (WASM)

The confidential path (sealed prompts, sealed deltas, fail-closed attestation) needs the
`caladon-core` `wasm-bindgen` build + the dcap-qvl attestation module. Until then the shim runs the
**plaintext-first** pipe above. The shim itself does not change when WASM lands — the seal/open and
the attestation verify happen entirely in the browser; the shim keeps forwarding opaque bytes. See
`../SURGERY.md §D` for the inject points.
