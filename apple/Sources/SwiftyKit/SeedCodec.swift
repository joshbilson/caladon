import CaladonCoreFFI
import CryptoKit
import Foundation

#if canImport(Security)
import Security
#endif

/// The account seed (identity-envelope.md §2): a locally-generated 256-bit secret — the
/// ONLY thing the user keeps. Encoded human-transcribably (Mullvad-style) as Crockford
/// base32 groups with a checksum so a mistyped backup is caught, not silently wrong.

public enum SeedError: Error, Equatable {
    case badLength
    case badChecksum
    case badCharacter
    case rngFailure
}

public enum Seed {
    public static let byteCount = 32  // 256-bit entropy

    /// Generate a fresh 256-bit seed from the system CSPRNG (SecRandomCopyBytes). This stays
    /// platform-native (Security) — the seed never leaves the device, and the Rust core takes
    /// the seed as input rather than minting it.
    public static func generate() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        guard status == errSecSuccess else { throw SeedError.rngFailure }
        return Data(bytes)
    }
}

/// Seed transcription codec — now a thin wrapper over the shared `caladon-core` Rust trust
/// core (`CaladonCoreFFI.seedEncode`/`seedDecode`). The Rust impl is byte-identical to the
/// prior in-Swift `Base32Crockford` codec (the Swift impl was its oracle): seed (32B) +
/// 2-byte SHA-256 checksum → Crockford base32 grouped in 4s, with the strict trailing-pad-bits
/// decode that rejects a corrupt final character.
public enum SeedCodec {
    /// seed (32B) + checksum (2B) -> Crockford base32, grouped in 4s with '-'.
    public static func encode(_ seed: Data) throws -> String {
        do {
            return try CaladonCoreFFI.seedEncode(seed: seed)
        } catch let e as CaladonCoreFFI.SeedError {
            throw map(e)
        }
    }

    /// Inverse of `encode`. Case-insensitive; '-' and whitespace ignored; Crockford
    /// normalization (I/L→1, O→0). Throws on a bad checksum / length / character.
    public static func decode(_ text: String) throws -> Data {
        do {
            return try CaladonCoreFFI.seedDecode(text: text)
        } catch let e as CaladonCoreFFI.SeedError {
            throw map(e)
        }
    }

    private static func map(_ e: CaladonCoreFFI.SeedError) -> SeedError {
        switch e {
        case .BadLength: return .badLength
        case .BadChecksum: return .badChecksum
        case .BadCharacter: return .badCharacter
        }
    }
}
