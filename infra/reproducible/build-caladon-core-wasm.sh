#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────────────────
# build-caladon-core-wasm.sh — REPRODUCIBLE build of the caladon-core WASM trust-core.
#
# Load-bearing claim (docs/security/reproducible-builds.md, threat-model.md §5):
#   "pinned measurement == audited public source". For the WEB fork that reduces to:
#   a stranger checks out `source-ref`, runs THIS script, and gets the SAME
#   caladon_core_bg.wasm sha256 the web client ships — so the dcap-qvl attestation
#   verifier + sealed-channel crypto running in their browser is provably the public source.
#
# What it builds:  the `wasm` feature of caladon-core (caladon-core/Cargo.toml) →
#   wasm32-unknown-unknown via wasm-pack. Pure-Rust verify (rustcrypto), NO networking
#   (JS fetches PCS collateral and passes JSON into verify_quote_sync).
#
# Determinism levers (why two machines agree byte-for-byte):
#   1. PINNED TOOLCHAIN — rustc/cargo version is pinned (rust-toolchain.toml is the canonical
#      pin; this script enforces it and fails closed if the active toolchain disagrees).
#   2. PINNED DEPS      — Cargo.lock is committed (caladon-core/.gitignore keeps it tracked).
#   3. NO TIMESTAMPS    — SOURCE_DATE_EPOCH=0; wasm carries no build clock.
#   4. NO ABSOLUTE PATHS— --remap-path-prefix strips $HOME/$CARGO_HOME/$PWD from any embedded
#      panic/debug paths so the build host can't leak into the artifact.
#   5. PINNED wasm-opt  — wasm-pack's wasm-opt pass is DISABLED here (binaryen version is not
#      pinned and varies wasm output); we ship the wasm-bindgen output directly. Optimize in a
#      separate, separately-pinned step if needed (see README §"wasm-opt").
#
# Usage:
#   infra/reproducible/build-caladon-core-wasm.sh
#   RUST_TOOLCHAIN=1.96.0 infra/reproducible/build-caladon-core-wasm.sh   # override the pin
#   KEEP_PKG=1 ...                                                        # don't wipe pkg/ first
#
# Output: caladon-core/pkg/caladon_core_bg.wasm  +  <repo>/infra/reproducible/out/caladon-core-wasm.sha256
# Exit:   0 build+hash ok · 2 toolchain/target missing · 3 toolchain pin mismatch · 4 build failed
# ──────────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# --- locate repo + crate (resolve symlinks; do not rely on cwd) ---------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CRATE_DIR="$REPO_ROOT/caladon-core"
OUT_DIR="$SCRIPT_DIR/out"
PKG_DIR="$CRATE_DIR/pkg"
WASM="$PKG_DIR/caladon_core_bg.wasm"

[ -f "$CRATE_DIR/Cargo.toml" ] || { echo "❌ caladon-core/Cargo.toml not found at $CRATE_DIR"; exit 4; }

# --- 1. pinned toolchain ------------------------------------------------------------------
# Canonical pin is caladon-core/rust-toolchain.toml. If present we read it; the env var
# RUST_TOOLCHAIN overrides (for testing a candidate bump). Default falls back to a known pin.
TOOLCHAIN_FILE="$CRATE_DIR/rust-toolchain.toml"
PINNED_TOOLCHAIN="${RUST_TOOLCHAIN:-}"
if [ -z "$PINNED_TOOLCHAIN" ] && [ -f "$TOOLCHAIN_FILE" ]; then
  # extract:  channel = "1.96.0"
  PINNED_TOOLCHAIN="$(grep -E '^\s*channel\s*=' "$TOOLCHAIN_FILE" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
fi
PINNED_TOOLCHAIN="${PINNED_TOOLCHAIN:-1.96.0}"

command -v rustup    >/dev/null 2>&1 || { echo "❌ rustup not found — install rustup (it enforces the toolchain pin)"; exit 2; }
command -v wasm-pack >/dev/null 2>&1 || { echo "❌ wasm-pack not found — 'cargo install wasm-pack --version 0.15.0'"; exit 2; }

echo "▶ pinned toolchain: $PINNED_TOOLCHAIN"
if ! rustup toolchain list 2>/dev/null | grep -q "^$PINNED_TOOLCHAIN"; then
  echo "  installing toolchain $PINNED_TOOLCHAIN …"
  rustup toolchain install "$PINNED_TOOLCHAIN" --profile minimal >/dev/null
fi
# wasm32 target for the pinned toolchain
if ! rustup target list --toolchain "$PINNED_TOOLCHAIN" --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
  echo "  adding wasm32-unknown-unknown target to $PINNED_TOOLCHAIN …"
  rustup target add wasm32-unknown-unknown --toolchain "$PINNED_TOOLCHAIN" >/dev/null
fi

ACTIVE_RUSTC="$(rustup run "$PINNED_TOOLCHAIN" rustc --version | awk '{print $2}')"
echo "  rustc(active for pin): $ACTIVE_RUSTC"
case "$ACTIVE_RUSTC" in
  "$PINNED_TOOLCHAIN"*) : ;;  # ok: 1.96.0 matches "1.96.0", also "stable-1.96.0" style
  *) echo "❌ toolchain pin mismatch: pinned=$PINNED_TOOLCHAIN active=$ACTIVE_RUSTC"; exit 3 ;;
esac

# --- 2. determinism env -------------------------------------------------------------------
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
# Strip host paths from any path embedded in the binary (debug strings, panic locations).
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$CARGO_HOME_DIR/registry=/cargo-registry --remap-path-prefix=$CRATE_DIR=/caladon-core --remap-path-prefix=$HOME=/home"
# Locked deps — fail if Cargo.lock would change (a stranger MUST build the exact pinned graph).
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-false}"

echo "▶ SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH  TZ=$TZ  LC_ALL=$LC_ALL"
echo "  RUSTFLAGS=$RUSTFLAGS"

# Cargo.lock must exist and be respected (--locked). It is tracked on purpose.
[ -f "$CRATE_DIR/Cargo.lock" ] || { echo "❌ caladon-core/Cargo.lock missing — reproducible builds REQUIRE a committed lockfile"; exit 4; }

# --- 3. clean output (reproducible builds start from a known state) -----------------------
if [ -z "${KEEP_PKG:-}" ]; then
  rm -rf "$PKG_DIR"
fi
mkdir -p "$OUT_DIR"

# --- 4. build -----------------------------------------------------------------------------
# wasm-pack:
#   --target web      : ESM glue for the browser (matches pkg/package.json "type":"module")
#   --release         : optimized, no dev assertions
#   --no-opt          : SKIP wasm-opt (binaryen) — its version is not pinned and changes bytes
#   -- --locked --features wasm   : cargo args; pin the dep graph + select the wasm feature
echo "▶ wasm-pack build (pinned toolchain $PINNED_TOOLCHAIN, --no-opt, --locked, --features wasm) …"
# NOTE: the crate dir is a POSITIONAL arg to `wasm-pack build`; --out-dir is resolved
# RELATIVE to it, so we pass "pkg" (= $PKG_DIR) not an absolute path.
WASM_PACK_ARGS=( build "$CRATE_DIR" --target web --release --out-dir pkg )
# --no-opt was added in wasm-pack 0.13; tolerate older by feature-detecting.
if wasm-pack build --help 2>&1 | grep -q -- '--no-opt'; then
  WASM_PACK_ARGS+=( --no-opt )
else
  echo "  (note: this wasm-pack lacks --no-opt; wasm-opt MUST be pinned for determinism — see README)"
fi

# Run wasm-pack under the pinned toolchain so its internal cargo invocation uses the pin.
RUSTUP_TOOLCHAIN="$PINNED_TOOLCHAIN" \
  wasm-pack "${WASM_PACK_ARGS[@]}" -- --locked --no-default-features --features wasm \
  || { echo "❌ wasm-pack build failed"; exit 4; }

[ -f "$WASM" ] || { echo "❌ expected artifact not produced: $WASM"; exit 4; }

# --- 5. hash + record ---------------------------------------------------------------------
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
WASM_SHA="$(sha "$WASM")"
WASM_BYTES="$(wc -c < "$WASM" | tr -d ' ')"
SRC_REF="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

SHA_FILE="$OUT_DIR/caladon-core-wasm.sha256"
{
  echo "# caladon-core WASM reproducible-build record"
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
  echo "artifact:        caladon-core/pkg/caladon_core_bg.wasm"
  echo "sha256:          $WASM_SHA"
  echo "bytes:           $WASM_BYTES"
  echo "rust-toolchain:  $PINNED_TOOLCHAIN"
  echo "wasm-pack:       $(wasm-pack --version 2>/dev/null | awk '{print $2}')"
  echo "target:          wasm32-unknown-unknown"
  echo "features:        wasm (no-default-features)"
  echo "source-ref:      $SRC_REF"
  echo "SOURCE_DATE_EPOCH: 0"
} > "$SHA_FILE"
# Also a plain checksum line (sha256sum -c friendly) for the transparency log feed.
echo "$WASM_SHA  caladon_core_bg.wasm" > "$OUT_DIR/caladon-core-wasm.SHA256SUMS"

echo ""
echo "✅ caladon-core WASM built reproducibly"
echo "   sha256: $WASM_SHA"
echo "   bytes:  $WASM_BYTES"
echo "   record: $SHA_FILE"
echo ""
echo "Feed to the transparency log (README §4):"
echo "   $WASM_SHA  caladon_core_bg.wasm  (source-ref $SRC_REF, toolchain $PINNED_TOOLCHAIN)"
