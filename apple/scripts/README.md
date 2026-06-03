# caladon-core native binding (UniFFI xcframework) — reproducible recipe

`caladon-core` (the shared Rust trust-core) is consumed by the native app via a UniFFI Swift
xcframework. This directory builds it. As of the native migration it **IS wired into the default
`Package.swift` + CI**: `SwiftyKit` thin-wraps the UniFFI surface, and the `swift-tests` +
`app-build` macOS CI jobs build the xcframework before `swift test` / `xcodebuild`.

## Build
```sh
apple/scripts/build-caladon-core-xcframework.sh
```
- Adds the 5 Apple Rust targets, builds `caladon-core` static libs (`--features uniffi-bindings`),
  generates the Swift bindings via the version-pinned `apple/scripts/uniffi-bindgen/` helper
  (matches caladon-core's locked uniffi 0.28.3 — no global install), lipo's universal sim/macOS
  slices, and emits `apple/Frameworks/CaladonCoreFFI.xcframework` (3 slices: ios-arm64,
  ios-arm64_x86_64-simulator, macos-arm64_x86_64). The xcframework (~250 MB) is a build artifact —
  **gitignored**.
- It also installs the COMMITTED outputs: the generated Swift binding
  (`apple/Sources/CaladonCoreFFI/caladon_core.swift`) and the C module
  (`apple/Sources/CaladonCoreShim/include/{caladon_coreFFI.h,module.modulemap}`).

## Wiring (in the default `Package.swift`)
- `binaryTarget CaladonCoreFFIBinary` → the xcframework. It ships **only the `.a` slices** (no
  `Headers/`).
- `CaladonCoreShim` (a normal SwiftPM C target) → vends the `caladon_coreFFI` clang module (the
  header + `module.modulemap` under its own `include/`).
- `CaladonCoreFFI` (Swift target, the generated `caladon_core.swift`) → depends on the shim, with
  `linkerSettings: [.linkedFramework("SystemConfiguration"), .linkedFramework("CoreFoundation")]`
  (the static archive carries no autolink directives; `dcap-qvl/report` pulls `system-configuration`).
- `SwiftyKit` depends on `CaladonCoreFFI`.

### Why the C module lives in a shim, not the xcframework
A static-library binaryTarget's `Headers/module.modulemap` is flattened by `xcodebuild` into the
shared `<config>/include/`, so two such xcframeworks (CaladonCoreFFI **+** dcap-qvl-swift's
DcapQvlFFI, both still used) collide on `include/module.modulemap` ("Multiple commands produce …").
Relocating to `Modules/` fixes xcodebuild but breaks plain `swift test` (SwiftPM only discovers a
binaryTarget's clang module from `Headers/module.modulemap`). Moving the header + modulemap into a
normal SwiftPM **C target** (whose `include/` is namespaced per target) resolves cleanly for BOTH
`swift test` and `xcodebuild`, from the same headerless `.a` artifact.

## Proof (now in CI via `swift test`)
`Tests/SwiftyKitTests/CaladonCoreFFITests.swift` calls caladon-core through UniFFI and asserts
byte-for-byte against the Python `swifty_crypto` parity vectors (x25519_public, derive_session_key,
challenge_hex, seal/open WMK round-trip). `cd apple && swift test` = **65** (60 existing + 5).
`native-binding/` retains reference copies of the generated bindings + the proof test.

## Migration status (what SwiftyKit thin-wraps vs. keeps)
- **Migrated onto CaladonCoreFFI:** `Session` (x25519 / session-key / seal+open WMK & chat),
  `SeedCodec` (Crockford base32 + checksum), `Padding` (bucketed metadata padding).
- **Still on libsodium (`swift-sodium`):** `SwiftyCrypto.argon2id` + the raw `seal`/`open`/`aad`
  (Argon2id and an arbitrary-AAD raw envelope are NOT exposed by the FFI surface) and `SeedIdentity`
  (uses `argon2id` + CryptoKit HKDF).
- **Still on `dcap-qvl-swift`:** `DcapVerifier` (its typed `Quote`/`parse`/`reportData` API — pinned
  by the offline parse test — is not in the FFI; the FFI only exposes the collateral-in
  `verifyQuote` verdict path). Both deps therefore REMAIN in `Package.swift`.
