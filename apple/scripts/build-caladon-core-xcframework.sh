#!/usr/bin/env bash
# Build the caladon-core UniFFI Swift xcframework + emit the generated Swift bindings.
#
# Produces:
#   apple/Frameworks/CaladonCoreFFI.xcframework            (BUILD ARTIFACT — gitignored; .a only)
#   apple/Sources/CaladonCoreShim/include/caladon_coreFFI.h + module.modulemap (C module — COMMITTED)
#   apple/Sources/CaladonCoreFFI/caladon_core.swift        (generated bindings — COMMITTED)
#
# The xcframework carries ONLY the static archives. The `caladon_coreFFI` C module (header +
# modulemap) is vended by the committed `CaladonCoreShim` SwiftPM C target instead of from inside
# the xcframework, because a static-library binaryTarget's `Headers/module.modulemap` is flattened
# by xcodebuild into the shared `<config>/include/` and would collide with dcap-qvl-swift's
# DcapQvlFFI ("Multiple commands produce …/include/module.modulemap"). A normal C target's
# `include/` is namespaced per target, so both `swift test` and the `xcodebuild` app build resolve
# the module cleanly from the SAME artifact. See Package.swift (CaladonCoreShim) for the wiring.
#
# caladon-core uses UniFFI PROC-MACRO mode (`setup_scaffolding!` — see caladon-core/src/lib.rs),
# so Swift bindings are generated in LIBRARY MODE from a compiled staticlib, using a uniffi-bindgen
# pinned to the exact `uniffi` version (0.28.3) the library was built with (apple/scripts/uniffi-bindgen).
#
# crate-type override: caladon-core's [lib] crate-type is ["cdylib","rlib"] (for wasm/host), which
# we MUST NOT edit. xcframeworks link a static archive, so we build with `cargo rustc
# --crate-type staticlib` per target to emit a `.a` without touching the manifest.
#
# Targets:
#   device   : aarch64-apple-ios
#   simulator: aarch64-apple-ios-sim + x86_64-apple-ios  (lipo'd into a universal sim slice)
#   macOS    : aarch64-apple-darwin + x86_64-apple-darwin  (lipo'd into a universal slice)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$APPLE_DIR/.." && pwd)"
CORE_DIR="$REPO_DIR/caladon-core"
BINDGEN_DIR="$SCRIPT_DIR/uniffi-bindgen"

LIB_BASENAME="libcaladon_core.a"          # cargo replaces '-' with '_' in artifact names
MODULE_NAME="CaladonCoreFFI"
NAMESPACE="caladon_core"                   # the UniFFI namespace (see setup_scaffolding!)

FRAMEWORKS_DIR="$APPLE_DIR/Frameworks"
XCFRAMEWORK="$FRAMEWORKS_DIR/${MODULE_NAME}.xcframework"
BINDINGS_OUT="$APPLE_DIR/Sources/$MODULE_NAME"   # committed generated Swift lives here
# The C shim target vends the `${NAMESPACE}FFI` clang module (header + module.modulemap). Keeping
# the modulemap HERE (a normal SwiftPM C target, per-target namespaced `include/`) instead of inside
# the xcframework avoids the two-static-xcframework `include/module.modulemap` collision under
# xcodebuild (caladon-core + dcap-qvl-swift's DcapQvlFFI), while staying discoverable by `swift test`.
SHIM_INCLUDE="$APPLE_DIR/Sources/CaladonCoreShim/include"   # committed C module (header + modulemap)
WORK="$APPLE_DIR/.build/caladon-ffi"             # scratch (under the already-gitignored .build)

FEATURES="uniffi-bindings"
RELEASE_DIR_FOR() { echo "$CORE_DIR/target/$1/release"; }

echo "==> caladon-core: $CORE_DIR"
echo "==> output xcframework: $XCFRAMEWORK"

# 1. Ensure the Apple Rust targets exist (idempotent). `x86_64-apple-ios` is the x86_64 iOS
#    SIMULATOR target — required because `xcodebuild -destination 'generic/platform=iOS Simulator'`
#    (the app-build CI step) compiles for BOTH sim archs, so the sim slice must be a universal
#    arm64+x86_64 archive (matching dcap-qvl-swift's ios-arm64_x86_64-simulator) or the x86_64 sim
#    link fails ("fat file missing arch 'x86_64'").
echo "==> rustup target add"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

# 2. Build a staticlib for each target. `cargo rustc --crate-type staticlib` overrides the
#    manifest crate-type for THIS build only (no manifest edit).
build_target() {
  local triple="$1"
  echo "==> cargo build ($triple)"
  ( cd "$CORE_DIR" && cargo rustc --release --features "$FEATURES" \
      --target "$triple" --crate-type staticlib )
  local out; out="$(RELEASE_DIR_FOR "$triple")/$LIB_BASENAME"
  [ -f "$out" ] || { echo "ERROR: expected $out not produced" >&2; exit 1; }
  echo "    -> $out"
}

build_target aarch64-apple-ios
build_target aarch64-apple-ios-sim
build_target x86_64-apple-ios          # x86_64 iOS simulator slice
build_target aarch64-apple-darwin
build_target x86_64-apple-darwin

# 3. Generate Swift bindings in LIBRARY MODE from the device staticlib (the FFI surface is
#    identical across targets). Emits <namespace>.swift, <namespace>FFI.h, <namespace>FFI.modulemap.
echo "==> generate Swift bindings (uniffi-bindgen, library mode)"
GEN="$WORK/gen"
rm -rf "$GEN"; mkdir -p "$GEN"
DEVICE_LIB="$(RELEASE_DIR_FOR aarch64-apple-ios)/$LIB_BASENAME"
( cd "$BINDGEN_DIR" && cargo run --release -- \
    generate --library "$DEVICE_LIB" --language swift --no-format --out-dir "$GEN" )

ls -1 "$GEN"
SWIFT_SRC="$GEN/${NAMESPACE}.swift"
HEADER="$GEN/${NAMESPACE}FFI.h"
MODMAP_GENERATED="$GEN/${NAMESPACE}FFI.modulemap"
for f in "$SWIFT_SRC" "$HEADER" "$MODMAP_GENERATED"; do
  [ -f "$f" ] || { echo "ERROR: bindgen did not emit $f" >&2; exit 1; }
done

# 4. Install the C module (header + modulemap) into the COMMITTED `CaladonCoreShim` C target's
#    `include/` — NOT into the xcframework. SwiftPM/clang then import the `${NAMESPACE}FFI` module
#    from this per-target (namespaced) include dir. See the SHIM_INCLUDE note above for WHY the
#    modulemap lives here rather than in the xcframework (the two-static-xcframework collision).
echo "==> install C module (header + modulemap) -> $SHIM_INCLUDE"
rm -rf "$SHIM_INCLUDE"; mkdir -p "$SHIM_INCLUDE"
cp "$HEADER" "$SHIM_INCLUDE/"
# uniffi emits the modulemap named '<namespace>FFI.modulemap'; SwiftPM/clang want 'module.modulemap'.
cp "$MODMAP_GENERATED" "$SHIM_INCLUDE/module.modulemap"

# 5. lipo the multi-arch slices: macOS (arm64 + x86_64) and simulator (arm64 + x86_64, so the
#    `generic/platform=iOS Simulator` app build links on both Apple-silicon and Intel sims).
echo "==> lipo universal slices"
MACOS_LIB="$WORK/macos/$LIB_BASENAME"
SIM_LIB="$WORK/sim/$LIB_BASENAME"
mkdir -p "$WORK/macos" "$WORK/sim"
lipo -create \
  "$(RELEASE_DIR_FOR aarch64-apple-darwin)/$LIB_BASENAME" \
  "$(RELEASE_DIR_FOR x86_64-apple-darwin)/$LIB_BASENAME" \
  -output "$MACOS_LIB"
lipo -create \
  "$(RELEASE_DIR_FOR aarch64-apple-ios-sim)/$LIB_BASENAME" \
  "$(RELEASE_DIR_FOR x86_64-apple-ios)/$LIB_BASENAME" \
  -output "$SIM_LIB"
DEVICE_OUT="$WORK/ios/$LIB_BASENAME"
mkdir -p "$WORK/ios"
cp "$DEVICE_LIB" "$DEVICE_OUT"

lipo -info "$MACOS_LIB" "$SIM_LIB" "$DEVICE_OUT"

# 6. Create the xcframework with NO headers — just the static `.a` per slice. The `${NAMESPACE}FFI`
#    C module (header + modulemap) is vended by the `CaladonCoreShim` target (step 4), so the
#    xcframework ships only the archive. This is the load-bearing collision fix: without a
#    `Headers/module.modulemap` inside the xcframework, `ProcessXCFramework` writes nothing to the
#    shared `<config>/include/`, so it can't collide with dcap-qvl-swift's DcapQvlFFI there.
echo "==> xcodebuild -create-xcframework (libraries only, no headers)"
rm -rf "$XCFRAMEWORK"; mkdir -p "$FRAMEWORKS_DIR"
xcodebuild -create-xcframework \
  -library "$DEVICE_OUT" \
  -library "$SIM_LIB" \
  -library "$MACOS_LIB" \
  -output "$XCFRAMEWORK"

# 7. Drop the generated Swift binding into the COMMITTED source target. It `import ${NAMESPACE}FFI`s
#    the module the `CaladonCoreShim` C target exposes.
echo "==> install generated Swift bindings -> $BINDINGS_OUT"
mkdir -p "$BINDINGS_OUT"
cp "$SWIFT_SRC" "$BINDINGS_OUT/${NAMESPACE}.swift"

echo "==> DONE"
echo "    xcframework: $XCFRAMEWORK (gitignored build artifact — .a only, no headers)"
echo "    C module:    $SHIM_INCLUDE/{${NAMESPACE}FFI.h,module.modulemap} (commit these)"
echo "    swift binding: $BINDINGS_OUT/${NAMESPACE}.swift (commit this)"
