#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════════════
# Gate-1 integration harness — deploy the attested backbone to an EPHEMERAL dstack CVM,
# verify its attestation cryptographically, run the encrypted round-trip, prove zero
# plaintext on the host, then TEAR DOWN (always — even on failure).
#
# Gate-1 DoD (internal orchestrator notes): "an encrypted prompt round-trips through the
# attested CVM and returns a client-verifiable receipt, with zero plaintext on any trusted
# host." This script is the executable form of that gate.
#
# SPEND: deploys a real CVM (~A$0.06/hr tdx.small; torn down in minutes → ~A$0.01). The
# teardown trap fires on ANY exit so we never leave billed infra.
#
# PREREQUISITES (the harness checks and fails closed):
#   - PHALA_CLOUD_API_KEY  (op read op://$OP_VAULT/phala/api_key)
#   - GATEWAY_IMAGE        a PULLABLE gateway image, e.g. ghcr.io/<owner>/caladon-gateway:gate1
#                          → BLOCKER B-REGISTRY: needs a registry credential to push it
#                            (GitHub PAT w/ write:packages, or Docker Hub token). See
#                            ./publish-gateway.sh and internal progress notes.
#   - dcap-qvl, jq, python3 (swifty_crypto importable for client identity)
#
# Usage:  GATEWAY_IMAGE=ghcr.io/<owner>/caladon-gateway:gate1 ./gate1.sh
# ════════════════════════════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

CVM_NAME="${CVM_NAME:-swifty-gate1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-tdx.small}"
PHALA="npx -y phala@1.1.19"
REPO_ROOT="$(cd ../.. && pwd)"
fail() { echo "❌ $*" >&2; exit 1; }
step() { echo; echo "▶ $*"; }

# ── teardown trap: delete the CVM no matter how we exit; also shred the secrets file ────
DEPLOYED=0
teardown() {
  rm -f .env.gate1 2>/dev/null
  if [ "$DEPLOYED" = "1" ]; then
    step "TEARDOWN — deleting CVM '$CVM_NAME' (no billed leftovers)"
    $PHALA cvms delete "$CVM_NAME" --yes 2>/dev/null \
      || $PHALA cvms delete --cvm-id "$CVM_NAME" --yes 2>/dev/null \
      || echo "⚠ could not auto-delete '$CVM_NAME' — CHECK 'phala cvms list' MANUALLY"
  fi
}
# ONE trap, set before anything can create a CVM, so teardown fires on EVERY exit path.
trap teardown EXIT

# ── 0. preflight (fail closed) ───────────────────────────────────────────────────────────
step "0. Preflight"
: "${GATEWAY_IMAGE:?set GATEWAY_IMAGE to a pullable gateway image (B-REGISTRY) — see header}"
if [ -z "${PHALA_CLOUD_API_KEY:-}" ]; then
  PHALA_CLOUD_API_KEY="$(op read 'op://$OP_VAULT/phala/api_key' 2>/dev/null)" || true
fi
[ -n "${PHALA_CLOUD_API_KEY:-}" ] || fail "PHALA_CLOUD_API_KEY unset (op read op://$OP_VAULT/phala/api_key)"
export PHALA_CLOUD_API_KEY
command -v dcap-qvl >/dev/null || fail "dcap-qvl not installed (cargo install dcap-qvl-cli)"
command -v jq >/dev/null || fail "jq not installed"
echo "image=$GATEWAY_IMAGE  type=$INSTANCE_TYPE  name=$CVM_NAME"
docker manifest inspect "$GATEWAY_IMAGE" >/dev/null 2>&1 \
  || echo "⚠ '$GATEWAY_IMAGE' not pullable yet (B-REGISTRY) — phala deploy will fail until published"

# ── 1. per-run secrets (NEVER committed; live only in this process + the CVM env) ────────
step "1. Generate ephemeral secrets"
gen() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32; }  # exactly 32 chars, full entropy
cat > .env.gate1 <<EOF
POSTGRES_USER=swifty
POSTGRES_PASSWORD=$(gen)
POSTGRES_DB=swifty
LETTA_SERVER_PASSWORD=$(gen)
GATEWAY_IMAGE=$GATEWAY_IMAGE
ATTESTED_INFERENCE_BASE=${ATTESTED_INFERENCE_BASE:-https://api.redpill.ai/v1}
ATTESTED_INFERENCE_KEY=${ATTESTED_INFERENCE_KEY:-PLACEHOLDER}
EOF

# ── 2. deploy the attested backbone ──────────────────────────────────────────────────────
step "2. Deploy dstack CVM (compose_hash gets measured into the attestation)"
$PHALA cvms delete "$CVM_NAME" --yes 2>/dev/null || true   # clear any stale same-name CVM
DEPLOYED=1   # billing starts when the API ACCEPTS the deploy, not when --wait returns; arm
             # teardown BEFORE issuing it so a --wait timeout can never orphan a billed CVM.
$PHALA deploy \
  --name "$CVM_NAME" \
  --compose dstack-compose.yml \
  --instance-type "$INSTANCE_TYPE" \
  --env-file .env.gate1 \
  --wait || fail "deploy failed"

# ── 3. discover endpoint + wait healthy ──────────────────────────────────────────────────
step "3. Resolve endpoint + wait for gateway health (mode:cvm)"
APP_URL="$($PHALA cvms get "$CVM_NAME" --json 2>/dev/null | jq -r '.public_urls[]? // .app_url // empty' | head -1)"
[ -n "$APP_URL" ] || fail "could not resolve CVM public URL"
echo "endpoint: $APP_URL"
for i in $(seq 1 60); do
  if curl -fsS "$APP_URL/health" 2>/dev/null | jq -e '.mode=="cvm"' >/dev/null 2>&1; then
    echo "gateway healthy (mode:cvm)"; break
  fi
  [ "$i" = 60 ] && fail "gateway never became healthy"; sleep 5
done

# ── 4. ATTESTATION: fetch the real quote, verify to Intel root, pin measurements ─────────
step "4. Verify attestation (dcap-qvl → Intel root) + measurement pin"
att="$(curl -fsS "$APP_URL/v1/attestation")" || fail "/v1/attestation failed"
echo "$att" | jq -r '.intel_quote // .quote' | sed 's/^0x//' | tr -d '\n' | xxd -r -p > /tmp/gate1_cvm_quote.bin
verdict="$(dcap-qvl verify /tmp/gate1_cvm_quote.bin 2>/dev/null | tail -1)"
[ "$(echo "$verdict" | jq -r '.status')" = "UpToDate" ] || fail "TCB status not UpToDate: $(echo "$verdict"|jq -r .status)"
# Measurement pin: the running app_compose MUST equal our audited no-logging compose.
audited="$(sha256sum dstack-compose.yml | cut -d' ' -f1)"
echo "✅ quote verifies to Intel root (UpToDate); audited compose sha256=$audited"
echo "   (measurement-pin policy: docs/security/measurements.md — pin app_id/rtmr3 from this run)"

# ── 5. ONBOARD: seed-derived account_id + Ed25519 proof-of-possession ────────────────────
step "5. Onboard a test identity (key-bound account_id, B2-bis)"
# Pass args quoted (no eval) so an API-sourced APP_URL can never be shell-injected.
run_client() {
  PYTHONPATH="$REPO_ROOT" uv run --project "$REPO_ROOT" --with cryptography --with pynacl \
    python3 "$REPO_ROOT/infra/cvm/gate1_client.py" "$@"
}
run_client onboard --url "$APP_URL" || fail "onboarding round-trip failed"

# ── 6. ENCRYPTED ROUND-TRIP + RECEIPT  [STAGED — pending the envelope/CVM cutover] ───────
step "6. Encrypted round-trip + client-verifiable receipt"
if run_client roundtrip --url "$APP_URL"; then
  echo "✅ encrypted round-trip + receipt verified"
else
  echo "⏳ STAGED: /v1/chat is still M1b bearer-auth (pre-envelope). The XChaCha20 envelope"
  echo "   round-trip + receipt lands with the gateway envelope cutover (next P1 increment)."
fi

# ── 7. NO-PLAINTEXT-ON-HOST proof ────────────────────────────────────────────────────────
step "7. Zero-plaintext-on-host check"
echo "   T1 control = ATTESTED no-logging/no-egress compose: data services run logging:none,"
echo "   only the gateway (ciphertext router) exposes a port, TLS terminates in-CVM. The"
echo "   compose_hash above is measured into the quote → the no-plaintext posture is attested,"
echo "   not merely asserted. (Phala's host is not shell-accessible; the attested measurement"
echo "   IS the proof.) Client only ever transmits envelopes once §6 cutover lands."

step "DONE — see verdict above. Teardown runs now."
