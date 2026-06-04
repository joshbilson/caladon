# Caladon — Deploy the whole stack in one attested CVM (`app.caladon.ai`)

This is the **P5 deploy runbook** for option **C**: the gateway **and** the web container run
together inside **one fresh Phala TDX (dstack) CVM**, reachable at **https://app.caladon.ai**. A
phone just opens that URL → unlocks → sealed chat. No separate gateway host, no LibreChat backend,
no database.

```
phone ──TLS──▶ app.caladon.ai ─(dstack-ingress, TLS terminated IN-CVM)─▶ web (shim + SPA)
                                                                          │  http://gateway:8088 (in-CVM only)
                                                                          ▼
                                                                       gateway (ciphertext router)
                                                                          │  RedPill attested inference
                                                                          ▼
                                                                       api.redpill.ai (attested TDX+H100 enclave)
```

Compose: [`infra/cvm/dstack-compose.caladon-app.yml`](infra/cvm/dstack-compose.caladon-app.yml).

## What this is (and is NOT) — claims discipline

This is **attested confidential compute**, **not end-to-end encryption.** The browser
(`caladon-core` WASM) seals the prompt to the CVM's **attested session key**; the gateway opens it
**inside TEE RAM** to call inference, then re-seals to the attested RedPill enclave. The host
operator cannot read plaintext (TDX memory encryption + `logging:none` + no host shell on the
production OS image) — **but the gateway enclave can, by construction.** The trust boundary is the
**attested measurement of this exact compose**, which the client **pins and refuses to send if it
doesn't match (no TOFU)** — *not* a key that only the user's device holds. Say "attested
confidential," never "E2EE."

## ⚠ A fresh CVM means a NEW pin — you MUST rebuild the SPA

`mr_td` + `rtmr0..2` are stable across deploys, but **`app_id` + `rtmr3` change on every deploy**,
and the **`compose_hash` differs** from the gw-v1 CVM because this compose file is different (it
adds the `web` service). The SPA ships its pinned set **baked in at build time**
(`VITE_CALADON_PINNED`). So the order is load-bearing:

> **deploy the CVM first → capture its pin → rebuild the SPA with that pin → bake the SPA into the
> web image → redeploy the CVM with the pinned image.** There is a deliberate two-pass loop in §6.

`docs/security/measurements.md §2.1` is the registry; record the new tuple there.

## Hands-on steps (what NEEDS YOU)

The unattended agent **cannot** do these — each needs a human credential or a public action:

- 🔑 **Phala Cloud API key** — `op read op://$OP_VAULT/phala/api_key` (or set `PHALA_CLOUD_API_KEY`).
- 🔑 **GHCR push credential** — a GitHub PAT with `write:packages` (the `gh` CLI token lacks it).
  Both the gateway image and the new **web** image are pushed here. They carry **NO secrets** so the
  packages can be **public** (dstack then pulls with no creds in the CVM).
- 🔑 **Cloudflare API token** — `Zone:DNS:Edit` on `caladon.ai`, dstack-sealed into the CVM so
  ingress can do DNS-01 + write the CAA record. (B-CF.)
- 📣 **Public push** — making the GHCR packages public, and the DNS change at Cloudflare, are
  externally visible actions. Do them deliberately.

Prereqs on your machine: `docker` (with `buildx`), `node` 20+ / `npm`, `npx`, `jq`,
`dcap-qvl` (`cargo install dcap-qvl-cli`), `op` (1Password CLI) or the raw secrets in env.

---

## 1. Build + push the web image (ghcr) 🔑📣

The web image is built from `web-client/` — it bundles the **committed shim** (`web-client/shim`)
*and* the **built SPA** (the LibreChat fork + Caladon overlay) baked into `CALADON_STATIC_DIR`. The
Dockerfile is being authored in parallel; this runbook assumes it lands at `web-client/Dockerfile`
and produces an image that runs the shim with `CALADON_STATIC_DIR=/srv/spa`.

> **The SPA inside this image is built WITHOUT a real pin on the first pass.** That is expected — §5
> rebuilds it with the captured pin and you re-push + redeploy. To make the FIRST pass connect at
> all (so you can capture the pin), build the SPA with the attestation policy in **observe** mode
> (`VITE_CALADON_ATTESTATION=observe`) and no `VITE_CALADON_PINNED`. The PRODUCTION image (§5) is
> built `strict` (the default) with the real pin.

```bash
cd /Users/joshua/caladon

# Materialise the SPA source (clone pinned LibreChat + apply the Caladon overlay), build the WASM,
# and build the SPA bundle. (apply-overlay.sh prints the exact monorepo build commands.)
./web-client/apply-overlay.sh
( cd web-client/caladon && npm install && npm run build:wasm )
( cd web-client/librechat && npm install \
    && npm run build:data-provider && npm run build:data-schemas \
    && npm run build:api && npm run build:client-package )
# FIRST-PASS SPA build — observe mode, no pin yet (so we can reach the CVM to capture its pin in §4).
( cd web-client/librechat/client && VITE_CALADON_ATTESTATION=observe npm run build )

# Log in to GHCR with a PAT that has write:packages (NOT the gh token).
echo "$GHCR_PAT" | docker login ghcr.io -u joshbilson --password-stdin

# dstack CVMs are linux/amd64 — MUST cross-build or the container crash-loops ("exec format error").
docker buildx inspect caladonx >/dev/null 2>&1 || docker buildx create --name caladonx --driver docker-container
WEB_IMAGE=ghcr.io/joshbilson/caladon-web:caladon-app
docker buildx build --builder caladonx --platform linux/amd64 \
  -t "$WEB_IMAGE" --push web-client/   # build context = web-client/, Dockerfile baked SPA -> /srv/spa
```

The gateway image is already published as `ghcr.io/joshbilson/caladon-gateway:gw-v1` (the gw-v1
pass). If you changed the gateway, re-publish it: `./infra/cvm/publish-gateway.sh` (set `TAG=gw-v1`).

📣 **Make both packages public** in the GitHub UI (Packages → caladon-web / caladon-gateway →
Package settings → Change visibility → Public) so the CVM can pull them with no registry creds.
Verify both are pullable:

```bash
docker logout ghcr.io
docker manifest inspect ghcr.io/joshbilson/caladon-web:caladon-app
docker manifest inspect ghcr.io/joshbilson/caladon-gateway:gw-v1
```

---

## 2. Seal the secrets into an env file (never committed) 🔑

These arrive as **dstack-sealed** env via `--env-file` — they are `${VARS}` in the compose, never
literals, never measured into `compose_hash`, never logged.

```bash
cd /Users/joshua/caladon/infra/cvm

cat > .env.caladon-app <<EOF
WEB_IMAGE=ghcr.io/joshbilson/caladon-web:caladon-app
GATEWAY_IMAGE=ghcr.io/joshbilson/caladon-gateway:gw-v1
CALADON_DOMAIN=app.caladon.ai
CALADON_ALLOWED_ORIGINS=https://app.caladon.ai
GATEWAY_INFERENCE_BASE=https://api.redpill.ai/v1
GATEWAY_INFERENCE_MODEL=phala/qwen3.6-35b-a3b-uncensored
GATEWAY_INFERENCE_KEY=$(op read 'op://$OP_VAULT/redpill/api_key')
CLOUDFLARE_API_TOKEN=$(op read 'op://$OP_VAULT/cloudflare/dns_edit_token')
CERTBOT_EMAIL=you@example.com
EOF
chmod 600 .env.caladon-app   # this file holds live secrets — do NOT commit it (it is .gitignored)
```

> The `GATEWAY_DOMAIN` (dstack wildcard, default `dstack-pha-prod5.phala.network`) only matters if
> you deploy onto a different dstack node — leave the compose default unless Phala tells you otherwise.

---

## 3. Deploy the fresh CVM via the phala CLI / dstack 🔑

```bash
cd /Users/joshua/caladon/infra/cvm
export PHALA_CLOUD_API_KEY="$(op read 'op://$OP_VAULT/phala/api_key')"
PHALA="npx -y phala@1.1.19"

# Clear any stale same-name CVM, then deploy. tdx.small is the gw-v1 tier (~A$0.06/hr).
$PHALA cvms delete caladon-app --yes 2>/dev/null || true
$PHALA deploy \
  --name caladon-app \
  --compose dstack-compose.caladon-app.yml \
  --instance-type tdx.small \
  --env-file .env.caladon-app \
  --wait
```

Resolve the CVM's identity + dstack endpoint (you'll want the CVM UUID and the temporary
`*.dstack-*.phala.network` URL until DNS in §7 points `app.caladon.ai` at it):

```bash
$PHALA cvms get caladon-app --json | tee cvm-get.caladon-app.json | \
  jq -r '[..|strings|select(test("^https://.*(dstack|phala)"))] | unique[]'
```

dstack-ingress provisions the Let's Encrypt cert for `app.caladon.ai` via **DNS-01 inside the CVM**
and writes the **CAA record** automatically (this needs the sealed `CLOUDFLARE_API_TOKEN`). That can
take a couple of minutes after the containers come up. Watch the deploy / ingress until the cert is
issued, then confirm the gateway is alive **through the in-CVM web shim** (the shim's `/health` also
probes the gateway):

```bash
# Until §7 DNS lands, hit the temporary dstack URL the line above printed (TLS may be self-signed
# there → -k; the public app.caladon.ai cert is the CAA-locked LE one).
APP=https://<the-dstack-app-url>
curl -sk "$APP/health" | jq .          # {"shim":"ok","gatewayBase":"http://gateway:8088","gateway":{"reachable":true,"status":200,"body":{"status":"ok","mode":"cvm"}}}
```

---

## 4. Capture THIS deploy's attestation pin 🔑

The pin is `{ measurements: [mr_td‖rtmr0‖rtmr1‖rtmr2 aggregate], compose_hashes: [compose_hash],
workload_ids: [app_id] }` — exactly the JSON `web-client/caladon/test/capture-pin.ts` prints, and
exactly the shape `VITE_CALADON_PINNED` (a `PinnedSet`) wants. **This changes per deploy** (new
`app_id`/`rtmr3`; new `compose_hash` vs gw-v1) — capture it from THIS CVM.

Point the capture script at the CVM's **gateway** evidence. It talks the gateway protocol
(`onboard → GET /v1/attestation`), so use the **`/v1` base** of the running app (the shim relays
`/api/caladon/attestation` → `/v1/attestation`; either base works — the live test uses `${GW}/v1`):

```bash
cd /Users/joshua/caladon/web-client/caladon
# Use the temporary dstack URL (or app.caladon.ai once DNS in §7 has propagated).
CALADON_GATEWAY_BASE="$APP" npx tsx test/capture-pin.ts | tee /tmp/caladon-pin.json
```

Expected output (one line of JSON):

```json
{"measurements":["<128 lowercase-hex: mr_td‖rtmr0‖rtmr1‖rtmr2>"],"compose_hashes":["<64-hex compose_hash>"],"workload_ids":["<40-hex app_id>"]}
```

Sanity-check the crypto root of trust independently with `dcap-qvl` (quote → Intel root, TCB
`UpToDate`) — the pin captures *identity*; this confirms the quote *verifies*:

```bash
curl -sk "$APP/v1/attestation" | jq -r '.intel_quote // .quote' | sed 's/^0x//' | tr -d '\n' | xxd -r -p > /tmp/caladon-app.quote.bin
dcap-qvl verify /tmp/caladon-app.quote.bin | tail -1   # expect status: "UpToDate"
```

📝 Record the new tuple in `docs/security/measurements.md §2.1` (it is a generated file — edit
`infra/transparency/measurements.source.json` and regenerate). Keep the gw-v1 row; add a
`caladon-app` row. `mr_td`/`rtmr0..2` should match gw-v1 (same base image); `compose_hash`/`app_id`
are new.

---

## 5. Rebuild the SPA with the captured pin, re-push the web image 📣

Now bake the **real** pin into a **strict** (default, fail-closed) SPA build and re-push the web
image:

```bash
cd /Users/joshua/caladon
export VITE_CALADON_PINNED="$(cat /tmp/caladon-pin.json)"
# strict is the default — do NOT set VITE_CALADON_ATTESTATION here (no observe/skip in production).
( cd web-client/librechat/client && npm run build )

# Re-push the SAME tag with the pinned SPA baked in.
docker buildx build --builder caladonx --platform linux/amd64 \
  -t ghcr.io/joshbilson/caladon-web:caladon-app --push web-client/
```

> Re-pushing the `web` image **does not** change the CVM's measurement — the image digest is not in
> `compose_hash` unless you pin it by digest in the compose (we pin by tag). The pin you captured in
> §4 stays valid. Now roll the CVM onto the pinned image:

```bash
cd /Users/joshua/caladon/infra/cvm
$PHALA cvms upgrade caladon-app --compose dstack-compose.caladon-app.yml --env-file .env.caladon-app
# (or: redeploy — delete + deploy as in §3. If you DELETE+redeploy, app_id/rtmr3 change again →
#  you must re-capture the pin (§4) and rebuild (§5) once more. `upgrade` in place avoids that.)
```

---

## 6. The two-pass summary (why the loop exists)

1. **Pass A** — build the SPA in **observe** mode (no pin) → web image → deploy CVM (§1–3) →
   capture the pin (§4).
2. **Pass B** — rebuild the SPA **strict** with that pin → re-push the web image → `upgrade` the CVM
   in place (§5). The pin from §4 is still valid because `upgrade` keeps the same instance (app_id /
   rtmr3 unchanged); only the web container's bytes change, and those aren't in the pinned set.

If you ever **delete + redeploy** (not `upgrade`), `app_id`/`rtmr3` change → re-run §4 + §5.

---

## 7. Point `app.caladon.ai` DNS at the CVM (Cloudflare) 🔑📣

dstack-ingress already created the **CAA** record (locking cert issuance to this TEE) and the
**`_acme-challenge` TXT** during DNS-01. You still need the **A/AAAA (or CNAME)** record so
`app.caladon.ai` resolves to the CVM's public endpoint.

- Get the CVM's public address/host from `cvm-get.caladon-app.json` (§3) — the dstack gateway
  endpoint for this app.
- In **Cloudflare → caladon.ai → DNS**, add a record for `app`:
  - If the CVM presents a stable **IP**: `A app → <ip>` (or `AAAA` for IPv6).
  - If it presents a **hostname** (the `*.dstack-*.phala.network` gateway): `CNAME app → <that host>`.
- **DNS-only (grey cloud), NOT proxied (orange cloud).** Proxying through Cloudflare would terminate
  TLS at Cloudflare's edge — that breaks the trust-no-one property (TLS must terminate INSIDE the
  CVM, where the cert is CAA-locked to the TEE). Leave it grey.

You can do this in the dashboard, or with the Cloudflare API using the same token from §2 (scoped
`Zone:DNS:Edit`). Verify propagation + that the public cert is the in-CVM LE one:

```bash
dig +short app.caladon.ai
curl -sS https://app.caladon.ai/health | jq .   # NOTE: no -k now — the public LE cert must be valid
```

---

## 8. Verify end to end (open on phone → unlock → sealed chat)

1. On your phone, open **https://app.caladon.ai**. The SPA loads from the in-CVM shim (same origin).
2. You land on the **unlock screen** (`CaladonUnlock`): **Create new identity** (it shows a recovery
   code = the lowercase hex of your 32-byte seed — save it) or **Restore from recovery code**.
3. On unlock the client runs the **fail-closed handshake**: onboard → `GET /v1/attestation` →
   `verify_quote_sync` against the **pinned set you baked in (§5)** → derive session key → deliver
   the sealed WMK. If the live CVM's measurement does **not** match the pin, the client **refuses to
   connect** ("Could not establish a verified session") — that is the gate working, not a bug
   (re-check you rebuilt the SPA with the §4 pin).
4. Send a message. The first turn may take **3–4 min** if the RedPill enclave cold-started
   (scale-to-zero); keep-warm keeps the pinned models hot after that. You should see streamed
   `token` deltas — each delta is a **sealed envelope opened in the browser**.

Quick CLI smoke of the full confidential round-trip against the live CVM (mirrors §8 in code):

```bash
cd /Users/joshua/caladon/web-client/caladon
CALADON_LIVE=1 CALADON_GATEWAY_BASE=https://app.caladon.ai npm run test:live
```

---

## 9. Teardown / cost

`tdx.small` bills continuously (~A$0.06/hr) — this CVM is meant to run 24/7 for `app.caladon.ai`.
To stop it:

```bash
cd /Users/joshua/caladon/infra/cvm
export PHALA_CLOUD_API_KEY="$(op read 'op://$OP_VAULT/phala/api_key')"
npx -y phala@1.1.19 cvms delete caladon-app --yes
rm -f .env.caladon-app   # shred the sealed-secret env file
```

After teardown, remove/repoint the `app.caladon.ai` DNS record in Cloudflare so it doesn't dangle.

---

## Files

- Compose: `infra/cvm/dstack-compose.caladon-app.yml`
- Gateway image: `gateway/` (Dockerfile) → `ghcr.io/joshbilson/caladon-gateway:gw-v1`
- Web image: `web-client/` (shim + built SPA) → `ghcr.io/joshbilson/caladon-web:caladon-app`
- Pin capture: `web-client/caladon/test/capture-pin.ts`
- Pinned registry: `docs/security/measurements.md` (source: `infra/transparency/measurements.source.json`)
- Pin consumed by the SPA: `web-client/overlay/client/src/lib/caladon/index.ts` (`VITE_CALADON_PINNED`)
```
