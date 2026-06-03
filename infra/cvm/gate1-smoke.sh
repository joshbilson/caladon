#!/usr/bin/env bash
# Gate-1 LIVE smoke — deploy the real Swifty gateway into a dstack TDX CVM, prove it's
# reachable + attested + serves live multi-tenant onboarding & the ciphertext-router
# /v1/messages, capture the CVM's attestation measurements, then TEAR DOWN (always).
# Ephemeral (~A$0.01). Full backbone (Letta) layers on later via dstack-compose.yml.
set -uo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
REPO_ROOT="$(cd ../.. && pwd)"
CVM_NAME="${CVM_NAME:-swifty-g1diag}"
GATEWAY_IMAGE="${GATEWAY_IMAGE:-ghcr.io/joshbilson/caladon-gateway:gate1}"
PHALA="npx -y phala@1.1.19"
OUT="$REPO_ROOT/infra/spikes/gate1-live"; mkdir -p "$OUT"
step() { echo; echo "▶ $*"; }

DEPLOYED=0
CVM_UUID=""
teardown() {
  if [ "$DEPLOYED" = "1" ]; then
    step "TEARDOWN — deleting CVM (uuid='${CVM_UUID:-?}' name='$CVM_NAME')"
    # Delete by the captured UUID (collision-proof) first, then by name as a fallback.
    { [ -n "$CVM_UUID" ] && $PHALA cvms delete --cvm-id "$CVM_UUID" --yes 2>/dev/null; } \
      || $PHALA cvms delete "$CVM_NAME" --yes 2>/dev/null \
      || echo "⚠ could not auto-delete — CHECK 'phala cvms list' MANUALLY"
  fi
}
trap teardown EXIT

step "0. Preflight"
[ -n "${PHALA_CLOUD_API_KEY:-}" ] || PHALA_CLOUD_API_KEY="$(op read 'op://$OP_VAULT/phala/api_key' 2>/dev/null)"
export PHALA_CLOUD_API_KEY
[ -n "${PHALA_CLOUD_API_KEY:-}" ] || { echo "❌ no PHALA key"; exit 1; }
docker logout ghcr.io >/dev/null 2>&1
docker manifest inspect "$GATEWAY_IMAGE" >/dev/null 2>&1 && echo "image pullable ✅" || { echo "❌ image not pullable"; exit 1; }
$PHALA cvms delete "$CVM_NAME" --yes 2>/dev/null || true   # clear any stale same-name CVM

step "1. Deploy gateway-only dstack CVM (cvm mode)"
DEPLOYED=1   # arm teardown BEFORE the deploy (billing starts on accept, not on --wait)
$PHALA deploy --name "$CVM_NAME" --compose dstack-compose.gateway-only.yml \
  --instance-type tdx.small --wait 2>&1 | tee "$OUT/deploy.txt" | tail -8
CVM_UUID="$(grep -iE 'CVM ID:' "$OUT/deploy.txt" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)"
echo "captured CVM_UUID=$CVM_UUID"

step "2. Resolve endpoint + wait for /health (mode:cvm)"
sleep 20  # give provisioning a moment before first query
$PHALA cvms get "${CVM_UUID:-$CVM_NAME}" --json 2>/dev/null > "$OUT/cvm-get.json" || true
echo "--- cvm-get.json keys ---"; jq -r 'paths(scalars) as $p | "\($p|join("."))" ' "$OUT/cvm-get.json" 2>/dev/null | grep -iE 'url|host|domain|endpoint|gateway' | head
APP_URL=""
for i in $(seq 1 18); do
  $PHALA cvms get "${CVM_UUID:-$CVM_NAME}" --json 2>/dev/null > "$OUT/cvm-get.json" || true
  # Try known fields, then ANY https URL mentioning port 8088 / the dstack gateway domain.
  APP_URL="$(jq -r '[..|strings|select(test("^https?://"))]|map(select(test("8088")))[0]//empty' "$OUT/cvm-get.json" 2>/dev/null)"
  [ -z "$APP_URL" ] && APP_URL="$(jq -r '[..|strings|select(test("^https://.*(dstack|phala).*"))][0]//empty' "$OUT/cvm-get.json" 2>/dev/null)"
  [ -n "$APP_URL" ] && break; sleep 10
done
echo "endpoint: ${APP_URL:-<none>}"
CURL="curl -sS -m 12 -k"   # -k: dstack RA-TLS cert may not chain to a public CA; attestation verified separately
HEALTHY=0
for i in $(seq 1 24); do   # ~6 min (boot+pull); time wasn't the issue last run, so don't over-wait
  body="$($CURL "$APP_URL/health" 2>"$OUT/curl.err")"
  if echo "$body" | jq -e '.mode=="cvm"' >/dev/null 2>&1; then
    echo "$body" > "$OUT/health.json"; echo "gateway healthy (mode:cvm) ✅"; HEALTHY=1; break
  fi
  [ $((i % 4)) -eq 0 ] && echo "  [${i}] curl_err=$(tr -d '\n' < "$OUT/curl.err" | cut -c1-70)"
  sleep 15
done
if [ "$HEALTHY" != 1 ]; then
  echo "⚠ not healthy — grabbing container logs:"
  $PHALA cvms logs "${CVM_UUID:-$CVM_NAME}" 2>&1 | tail -40 | tee "$OUT/logs.txt"
fi

step "3. Live multi-tenant onboarding (seed-auth, key-bound account_id)"
if [ "$HEALTHY" = 1 ]; then
  PYTHONPATH="$REPO_ROOT" uv run --project "$REPO_ROOT" --with cryptography --with pynacl \
    python3 "$REPO_ROOT/infra/cvm/gate1_client.py" onboard --url "$APP_URL" 2>&1 | tee "$OUT/onboard.txt"
fi

step "4. CVM attestation measurements (phala cvms attestation)"
$PHALA cvms attestation "${CVM_UUID:-$CVM_NAME}" --json 2>/dev/null | tee "$OUT/cvm-attestation.json" \
  | jq -r '{app_id, mrtd: (.tcb_info.mrtd // .mrtd), rtmr0: (.tcb_info.rtmr0 // .rtmr0)} | "app_id=\(.app_id) mrtd=\(.mrtd[0:24])… rtmr0=\(.rtmr0[0:24])…"' 2>/dev/null \
  || echo "(attestation capture — see cvm-attestation.json)"

step "DONE — teardown runs now"
