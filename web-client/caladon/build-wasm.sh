#!/usr/bin/env bash
# Build the caladon-core WASM glue for the web client's protocol SDK.
#
# Output: web-client/caladon/wasm/  (caladon_core.js + .d.ts are COMMITTED; the heavy
# caladon_core_bg.wasm binary is git-ignored — regenerate it here). See README.md
# §"WASM build & what we commit".
#
# READ-ONLY use of caladon-core: this only invokes wasm-pack against that crate; it never
# edits it. Re-run after any caladon-core crypto/binding change so the SDK glue stays in sync.
#
# Requires: rustup wasm32 target + wasm-pack (~/.cargo/bin/wasm-pack).
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-pack
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$(cd "$HERE/../../caladon-core" && pwd)"
OUT="$HERE/wasm"
WASM_PACK="${WASM_PACK:-$HOME/.cargo/bin/wasm-pack}"

command -v "$WASM_PACK" >/dev/null 2>&1 || { echo "FAIL: wasm-pack not found at $WASM_PACK (cargo install wasm-pack)"; exit 2; }
[ -d "$CORE" ] || { echo "FAIL: caladon-core not found at $CORE"; exit 2; }

echo "[build-wasm] caladon-core: $CORE"
echo "[build-wasm] out:         $OUT"

# `--out-dir` and the other options MUST precede the crate path (this wasm-pack forwards a
# trailing path to `cargo build`, which rejects --out-dir).
( cd "$CORE" && "$WASM_PACK" build --target web --out-dir "$OUT" --features wasm )

# wasm-pack drops a `.gitignore` (containing `*`) into the out dir; remove it so our own
# top-level .gitignore (commit .js/.d.ts, ignore the .wasm) governs instead.
rm -f "$OUT/.gitignore"

echo "[build-wasm] done. Committed glue: caladon_core.js / *.d.ts. Ignored binary: caladon_core_bg.wasm"
ls -la "$OUT"
