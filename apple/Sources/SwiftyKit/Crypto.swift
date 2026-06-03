import CryptoKit
import Foundation
import Sodium

/// Client-side primitives that CryptoKit does not provide — Argon2id (seed→root) and
/// XChaCha20-Poly1305 (192-bit nonce) — via libsodium (`swift-sodium`). Byte-identical to
/// the Python reference `swifty_crypto` (kdf.py / envelope.py) so the iOS/macOS client,
/// the gateway, and the CVM all agree. Charter: established primitives only, no custom crypto.
public enum SwiftyCrypto {
    public enum CryptoError: Error {
        case argon2Failed, sealFailed, openFailed, badKeyLength, badNonceLength, badSeedLength
    }

    public static let keyLength = 32
    public static let nonceLength = 24       // XChaCha20-Poly1305-IETF NPUBBYTES
    static let minSeedLength = 16            // high-entropy secret (identity-envelope §3 / B3)

    // Argon2id params are part of the identity-envelope §10 versioned contract: the params
    // used to derive a root MUST match on every side (client, gateway, CVM) for a given
    // envelope `v`, or the derived keys diverge and AEAD open fails as if it were a network
    // error. These mirror the Python `swifty_crypto` constants EXACTLY. Both sides default
    // to REFERENCE (so a naive call on either side agrees); production deployments pass
    // `*Production` on BOTH sides. (Wiring params-by-`v` automatically is a tracked follow-up.)
    public static let opsLimitReference = 3
    public static let memLimitReference = 64 * 1024 * 1024            // reference/test only
    public static let opsLimitProduction = 3                          // == ARGON2ID_OPSLIMIT_PRODUCTION
    public static let memLimitProduction = 256 * 1024 * 1024          // == ARGON2ID_MEMLIMIT_PRODUCTION

    private static let sodium = Sodium()

    /// Argon2id(seed, salt) → 32-byte root. `salt` is the app-domain constant (e.g.
    /// "swifty/v1"), hashed to libsodium's 16-byte salt — exactly as `swifty_crypto.argon2id`
    /// (`salt16 = sha256(salt)[:16]`). Security rests on `seed` being a 256-bit secret.
    public static func argon2id(
        seed: [UInt8],
        salt: String,
        opsLimit: Int = opsLimitReference,
        memLimit: Int = memLimitReference
    ) throws -> [UInt8] {
        guard seed.count >= minSeedLength else { throw CryptoError.badSeedLength }
        let salt16 = Array(SHA256.hash(data: Data(salt.utf8)).prefix(16))
        guard let root = sodium.pwHash.hash(
            outputLength: keyLength,
            passwd: seed,
            salt: salt16,
            opsLimit: opsLimit,
            memLimit: memLimit,
            alg: .Argon2ID13
        ) else { throw CryptoError.argon2Failed }
        return root
    }

    /// XChaCha20-Poly1305 AEAD seal → (nonce, ct). A FRESH CSPRNG nonce per call (24 bytes,
    /// identity-envelope §4/B4). `aad` is authenticated (covered by the tag) but not encrypted.
    public static func seal(key: [UInt8], plaintext: [UInt8], aad: [UInt8]) throws -> (nonce: [UInt8], ct: [UInt8]) {
        guard key.count == keyLength else { throw CryptoError.badKeyLength }
        guard let (ct, nonce): (Bytes, Bytes) = sodium.aead.xchacha20poly1305ietf.encrypt(
            message: plaintext, secretKey: key, additionalData: aad
        ) else { throw CryptoError.sealFailed }
        return (nonce, ct)
    }

    /// Decrypt + verify; throws on ANY tamper (ct or aad) — never returns data for a modified
    /// envelope. Mirrors `swifty_crypto.open`.
    public static func open(key: [UInt8], nonce: [UInt8], ct: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        guard key.count == keyLength else { throw CryptoError.badKeyLength }
        guard nonce.count == nonceLength else { throw CryptoError.badNonceLength }
        guard let pt = sodium.aead.xchacha20poly1305ietf.decrypt(
            authenticatedCipherText: ct, secretKey: key, nonce: nonce, additionalData: aad
        ) else { throw CryptoError.openFailed }
        return pt
    }

    /// Envelope AAD = SHA-256("{account_id}\n{purpose}\n{v}") — byte-identical to
    /// `swifty_crypto._aad` (newline-delimited so the fields can't be re-segmented).
    public static func aad(accountID: String, purpose: String, v: Int) -> [UInt8] {
        Array(SHA256.hash(data: Data("\(accountID)\n\(purpose)\n\(v)".utf8)))
    }
}
