# Caladon Gateway (M1b)

Client-facing API in front of Letta. The ONLY surface the iOS app talks to.
Letta's admin credentials never leave the server.

## Endpoints (all under the tailnet HTTPS URL)
- `GET  /health` — `{"status":"ok"}` (no auth)
- `GET  /v1/whoami` — auth probe → `{"authenticated": true}`
- `GET  /v1/messages?limit=N` — conversation history; array of
  `{id, role, content, created_at}` where `role` is `user`|`assistant`
- `POST /v1/chat` — body `{"text": "..."}`; returns `text/event-stream`:
  - `event: token`     data `{"text": "..."}`   — assistant text delta
  - `event: reasoning` data `{"text": "..."}`   — model reasoning delta (optional to render)
  - `event: done`      data `{}`                — stream complete
  - `event: error`     data `{"message": "..."}` — failure

## Auth
Bearer token in `Authorization: Bearer <token>`. Valid tokens are configured via
`GATEWAY_DEVICE_TOKENS` (comma-separated) in `~/caladon-infra/.env`. The iOS app
stores its token in the Keychain. Missing/invalid → 401.

## Connectivity (for M1c)
- **Base URL:** `https://$TAILNET_HOST` (Tailscale Serve;
  valid cert, tailnet-only, ATS-safe — no plaintext, no public exposure).
- The iPhone must have the **Tailscale app** installed and be logged into the
  same tailnet (the device `blake` already is). No ATS exception needed.
- Verified working from a tailnet device: health, auth (401 on bad token), and
  streaming chat (token-by-token) all confirmed over HTTPS on 2026-06-02.

## Configuration (env, `GATEWAY_` prefix)
| Var | Meaning |
|-----|---------|
| `GATEWAY_LETTA_BASE_URL` | upstream Letta (`http://letta:8283` in compose) |
| `GATEWAY_LETTA_PASSWORD` | Letta admin token (server-side only) |
| `GATEWAY_AGENT_ID`       | the `swifty` agent id |
| `GATEWAY_DEVICE_TOKENS`  | comma-separated client tokens |

## Run tests locally
    cd gateway
    uv venv --python 3.12 && uv pip install -e ".[dev]"
    uv run pytest -q          # 13 tests

## Deploy (on the VPS)
Code is synced to `~/caladon-gateway`; the service is built by Compose
(`build: /home/$VPS_USER/caladon-gateway`) and bound to `127.0.0.1:8088`.
`infra/scripts/80-tailscale-serve.sh` publishes it as HTTPS over the tailnet;
`infra/scripts/81-gateway-smoke.sh <url> <token>` runs an end-to-end check.
