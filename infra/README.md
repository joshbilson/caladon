# Caladon infra (M1a)

Provisioning for the backend brain on the VPS.

## Architecture (as built)

- **Chat model:** `Qwen3.6-35B-A3B` (qwen35moe MoE) served by **llama.cpp `llama-server`**
  (prebuilt b9464), OpenAI-compatible, systemd service on `0.0.0.0:8080`.
  Ollama cannot load this architecture (`unknown model architecture: 'qwen35moe'`).
- **Embeddings:** `nomic-embed-text` via **Ollama** on `0.0.0.0:11434`.
- **Agent + memory:** **Letta** (Docker) on `127.0.0.1:8283`, backed by
  **Postgres + pgvector** on `127.0.0.1:5432`.
- Letta reaches the host LLM services via the docker bridge gateway
  (`host.docker.internal`); ufw allows only the docker range to those ports.
- Host reachable over **Tailscale** (`--ssh`); public inbound is default-deny
  except SSH.

## Order of operations (run on the VPS, as the `$VPS_USER` user)
1. `scripts/00-preflight.sh`        — safety checks; DO NOT skip
2. `scripts/10-install-docker.sh`
3. `scripts/20-install-tailscale.sh` — then authorize the node in a browser
4. `scripts/30-harden.sh`           — firewall + SSH hardening (keep a 2nd session open!)
5. `scripts/40-install-ollama.sh`   — Ollama (embeddings) + ufw rule for 11434
6. `scripts/50-pull-model.sh`       — pull Qwen GGUF + nomic-embed-text (smoke test will 500: see note)
7. `scripts/45-llama-server.sh`     — serve Qwen via llama.cpp (reuses the pulled GGUF blob)
8. `cp .env.example .env` → fill secrets → `docker compose up -d` (Postgres + Letta)
   - On a fresh volume, `postgres-init/01-enable-vector.sql` enables pgvector automatically.
9. `scripts/52-register-provider.sh` — register llama-server with Letta (openai BYOK)
10. `scripts/55-create-agent.sh`     — create the 'swifty' agent + chat round-trip test
11. `scripts/70-verify-bindings.sh`  — assert exposure model

> Note: `50-pull-model.sh`'s smoke test returns HTTP 500 — that step pulls via Ollama,
> which can't load qwen35moe. The pull/blob is still valid; `45-llama-server.sh` serves
> it via llama.cpp. The download is the only reason to run step 6.

Copy `.env.example` to `.env` and fill values before `docker compose up`.

## Model handles (Letta)
- chat:      `openai-proxy/qwen3.6-35b-a3b`   (via the `local-openai` BYOK provider)
- embedding: `ollama/nomic-embed-text:latest`

## Benchmarks (pure CPU, EPYC 9645, 20 threads, Q4_K_M, ctx 32768)
- Generation: **25.6 tok/s**
- Prompt processing: **77.3 tok/s**

## Host facts
- Public SSH: `$VPS_USER@$VPS_HOST`
- Tailnet IP: `$TAILNET_IP` (reach the box privately; phone uses the Tailscale app)
- Letta agent id: see `~/caladon-infra/agent_id.txt` on the VPS

## Known gaps / follow-ups
- Ports 80/443 have pre-existing public "Caddy" ufw rules — lock to Tailscale in M1b.
- Full-disk encryption not retrofitted (would require reprovisioning).
- Passwordless sudo enabled for automation (`/etc/sudoers.d/$VPS_USER`).
