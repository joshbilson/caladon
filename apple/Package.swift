// swift-tools-version: 5.9
import PackageDescription

// SwiftyKit — the shared, testable client LOGIC library (iOS + macOS), independent of any
// app UI. The SwiftUI app (forked from Enchanted, docs/oss-reuse-map.md) will depend on
// this. Keeping logic here means it is unit-testable via `swift test` without an app
// bundle. The attestation verifier keystone (dcap-qvl-swift + tinfoil-swift, multi-regime)
// lands here in later iterations.
//
// MIGRATION (caladon-core): the cryptographic trust-core now thin-wraps the shared Rust
// `caladon-core` via the UniFFI Swift xcframework (`CaladonCoreFFI`). Session/SeedCodec/
// Padding call the Rust core; Crypto/SeedIdentity keep libsodium (Argon2id has no FFI
// surface) and DcapVerifier keeps dcap-qvl-swift (its `parse`/typed-`Quote` API is not in
// the FFI). Build the xcframework BEFORE `swift test`/`xcodebuild`:
//   apple/scripts/build-caladon-core-xcframework.sh
// (it emits apple/Frameworks/CaladonCoreFFI.xcframework — a gitignored build artifact — and
// regenerates apple/Sources/CaladonCoreFFI/caladon_core.swift, which IS committed).
let package = Package(
    name: "SwiftyKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SwiftyKit", targets: ["SwiftyKit"]),
    ],
    dependencies: [
        // libsodium (established primitive — charter: no custom crypto): Argon2id (seed->root),
        // which neither CryptoKit nor the caladon-core FFI surface provides. Used to byte-match
        // the Python `swifty_crypto` reference (SwiftyCrypto/SeedIdentity).
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
        // dcap-qvl (Phala's Rust DCAP verifier via UniFFI; prebuilt xcframework) — REAL TDX
        // quote verification to the Intel root. DcapVerifier keeps this because it exposes the
        // typed `Quote`/`parse`/`reportData` surface the offline parse test pins; the
        // caladon-core FFI only exposes the collateral-in `verifyQuote` verdict path.
        .package(url: "https://github.com/Phala-Network/dcap-qvl-swift.git", from: "0.5.2"),
    ],
    targets: [
        // The caladon-core UniFFI static-archive xcframework (BUILD ARTIFACT — gitignored;
        // regenerate with apple/scripts/build-caladon-core-xcframework.sh). It carries ONLY the
        // `.a` slices (no Headers/modulemap): the `caladon_coreFFI` C module is vended by the
        // `CaladonCoreShim` target below instead.
        //
        // WHY: a static-library binaryTarget's `Headers/module.modulemap` is flattened by Xcode
        // into the shared `<config>/include/`, so two such xcframeworks (here + dcap-qvl-swift's
        // DcapQvlFFI) collide on `include/module.modulemap` ("Multiple commands produce …") under
        // `xcodebuild` (the app-build job). Moving the modulemap+header into a normal SwiftPM C
        // target (whose `include/` is namespaced per target) keeps the module discoverable by BOTH
        // plain `swift test` and `xcodebuild`, from the same artifact.
        .binaryTarget(
            name: "CaladonCoreFFIBinary",
            path: "Frameworks/CaladonCoreFFI.xcframework"
        ),
        // Vends the `caladon_coreFFI` C module (header + module.modulemap under its own
        // `include/`). The actual symbols come from the linked static archive (binaryTarget).
        .target(
            name: "CaladonCoreShim",
            dependencies: ["CaladonCoreFFIBinary"]
        ),
        // The generated Swift binding (committed). The static archive carries no autolink
        // directives, and `dcap-qvl/report` (compiled into caladon-core) pulls
        // `system-configuration`, so we link SystemConfiguration + CoreFoundation explicitly.
        .target(
            name: "CaladonCoreFFI",
            dependencies: ["CaladonCoreShim"],
            linkerSettings: [
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .target(
            name: "SwiftyKit",
            dependencies: [
                "CaladonCoreFFI",
                .product(name: "Sodium", package: "swift-sodium"),
                .product(name: "DcapQvl", package: "dcap-qvl-swift"),
            ]
        ),
        // The proof test (`CaladonCoreFFITests`) calls the generated bindings directly, so the
        // test target also links `CaladonCoreFFI` (it is otherwise an internal dep of SwiftyKit).
        .testTarget(name: "SwiftyKitTests", dependencies: ["SwiftyKit", "CaladonCoreFFI"]),
    ]
)
