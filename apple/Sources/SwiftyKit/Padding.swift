import CaladonCoreFFI
import Foundation

/// Metadata padding — the sealed-sender SIZE analog (identity-envelope.md §9). Pad the
/// plaintext to a fixed bucket before sealing so the ciphertext length reveals only the
/// bucket, not the true size. Now a thin wrapper over the shared `caladon-core` Rust trust
/// core (`CaladonCoreFFI.pad`/`unpad`), which is byte-identical to the Python reference
/// `swifty_crypto.padding` (deterministic: uint32_be(len) ‖ plaintext ‖ zero filler → next
/// bucket) and to the prior in-Swift implementation.
public enum Padding {
    public static let buckets: [Int] = [256, 1024, 4096, 16384, 65536, 262144]
    static let lenPrefix = 4

    public enum PaddingError: Error, Equatable { case tooShort, badLength }

    /// Pad to a fixed bucket. `pad(x).count` reveals only the bucket, not `x.count`.
    /// The Rust core's only failure is a plaintext longer than 2^32 bytes (impossible for any
    /// real payload), so this keeps the historically non-throwing surface.
    public static func pad(_ plaintext: Data) -> Data {
        // `pad` over the FFI throws only `PadError.TooLong` (len > u32::MAX), unreachable here.
        try! CaladonCoreFFI.pad(plaintext: plaintext)
    }

    /// Recover the exact plaintext. Fail-closed on a malformed/short buffer.
    public static func unpad(_ padded: Data) throws -> Data {
        do {
            return try CaladonCoreFFI.unpad(padded: padded)
        } catch CaladonCoreFFI.PadError.TooShort {
            throw PaddingError.tooShort
        } catch {
            // DeclaredLenExceedsBuffer (or any other malformed-buffer failure) → fail closed.
            throw PaddingError.badLength
        }
    }
}
