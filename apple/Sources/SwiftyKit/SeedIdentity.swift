import CryptoKit
import Foundation

/// A stretched seed root (the Argon2id output, identity-envelope.md §3) — NOT a raw seed.
/// The newtype forces the stretch step to be explicit at every derivation call site, so a
/// caller can't accidentally pass raw seed bytes and silently downgrade to HKDF-only
/// security. A `deriveRoot(seed:salt:)` Argon2id factory lands with libsodium-in-Swift.
public struct RootKey: Sendable {
    let bytes: Data
    /// The caller asserts `bytes` is the Argon2id-stretched root, not a raw seed.
    public init(stretched bytes: Data) { self.bytes = bytes }
}

/// Client-side key derivation (contracts/identity-envelope.md §3) — the Swift counterpart
/// of the Python reference `swifty_crypto`. Derives byte-identical keys + account_id so the
/// client and server/CVM agree (cross-language interop vectors in the tests).
public enum SeedIdentity {
    static let wmkLabel = "swifty/working-mem/v1"
    static let transcriptLabel = "swifty/transcript/v1"
    static let gatewayAuthLabel = "swifty/gateway-auth/v1"
    static let accountDomain = "swifty/account/v1"

    /// Argon2id seed→root factory (identity-envelope §3) — the stretch the `RootKey` newtype
    /// guards. `salt` is the app-domain constant ("swifty/v1"). Byte-identical to
    /// `swifty_crypto.argon2id`. The default params are REFERENCE (m=64MiB), matching the
    /// Python default; a PRODUCTION client MUST pass `SwiftyCrypto.{ops,mem}LimitProduction`
    /// AND the gateway/CVM must use the same params for that envelope `v` (see §10) — else
    /// the derived keys silently diverge.
    public static func deriveRoot(
        seed: Data,
        salt: String = "swifty/v1",
        opsLimit: Int = SwiftyCrypto.opsLimitReference,
        memLimit: Int = SwiftyCrypto.memLimitReference
    ) throws -> RootKey {
        let root = try SwiftyCrypto.argon2id(
            seed: [UInt8](seed), salt: salt, opsLimit: opsLimit, memLimit: memLimit
        )
        return RootKey(stretched: Data(root))
    }

    public static func hkdf(_ root: RootKey, label: String, length: Int = 32) -> Data {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: root.bytes),
            info: Data(label.utf8),
            outputByteCount: length
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    public static func wmk(_ root: RootKey) -> Data { hkdf(root, label: wmkLabel) }
    public static func transcriptRoot(_ root: RootKey) -> Data { hkdf(root, label: transcriptLabel) }

    public static func ed25519PrivateKey(_ root: RootKey) throws -> Curve25519.Signing.PrivateKey {
        try Curve25519.Signing.PrivateKey(rawRepresentation: hkdf(root, label: gatewayAuthLabel))
    }

    public static func ed25519PublicKey(_ root: RootKey) throws -> Data {
        try ed25519PrivateKey(root).publicKey.rawRepresentation
    }

    /// Key-bound, zero-PII account_id (B2-bis): urlsafe_b64_nopad(SHA-256(domain || pub)).
    public static func accountID(_ root: RootKey) throws -> String {
        var hasher = SHA256()
        hasher.update(data: Data(accountDomain.utf8))
        hasher.update(data: try ed25519PublicKey(root))
        return Data(hasher.finalize()).base64URLEncodedStringNoPad()
    }
}

private extension Data {
    func base64URLEncodedStringNoPad() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
