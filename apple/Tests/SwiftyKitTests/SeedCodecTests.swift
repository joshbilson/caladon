import Foundation
import XCTest

@testable import SwiftyKit

final class SeedCodecTests: XCTestCase {
    private let seed = Data(repeating: 0xAB, count: 32)

    func testGenerateProduces256Bits() throws {
        let a = try Seed.generate()
        let b = try Seed.generate()
        XCTAssertEqual(a.count, 32)
        XCTAssertNotEqual(a, b)  // overwhelmingly likely; sanity that it's not constant
    }

    func testEncodeDecodeRoundtrips() throws {
        let encoded = try SeedCodec.encode(seed)
        XCTAssertEqual(try SeedCodec.decode(encoded), seed)
    }

    func testEncodedIsGroupedCrockfordAlphabet() throws {
        let encoded = try SeedCodec.encode(seed)
        XCTAssertTrue(encoded.contains("-"))
        let allowed = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ-")
        XCTAssertTrue(encoded.allSatisfy { allowed.contains($0) })
    }

    func testDecodeIsCaseAndSeparatorInsensitive() throws {
        let encoded = try SeedCodec.encode(seed)
        let messy = encoded.lowercased().replacingOccurrences(of: "-", with: " ")
        XCTAssertEqual(try SeedCodec.decode(messy), seed)
    }

    func testCorruptedCharFailsChecksum() throws {
        var chars = Array(try SeedCodec.encode(seed))
        // flip a non-separator char to a different valid Crockford char
        let i = chars.firstIndex { $0 != "-" }!
        chars[i] = chars[i] == "0" ? "1" : "0"
        XCTAssertThrowsError(try SeedCodec.decode(String(chars))) { error in
            XCTAssertEqual(error as? SeedError, .badChecksum)
        }
    }

    func testLastCharCorruptionIsRejected() throws {
        // The final base32 char carries zero-padded trailing bits; flipping its low bit
        // (same top-2 bits) must be rejected by the strict residual-bits check, not
        // silently decoded.
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var encoded = try SeedCodec.encode(seed)
        let last = encoded.removeLast()  // last group has <4 chars, so this is a base32 char
        let idx = alphabet.firstIndex(of: last)!
        encoded.append(alphabet[idx ^ 1])  // flip low bit -> non-zero residue
        XCTAssertThrowsError(try SeedCodec.decode(encoded)) { error in
            XCTAssertEqual(error as? SeedError, .badCharacter)
        }
    }

    func testDecodeRejectsBadCharacter() {
        XCTAssertThrowsError(try SeedCodec.decode("U!!!")) { error in
            // 'U' is excluded from Crockford; '!' is invalid
            XCTAssertEqual(error as? SeedError, .badCharacter)
        }
    }

    func testEncodeRejectsWrongSeedLength() {
        XCTAssertThrowsError(try SeedCodec.encode(Data(repeating: 0, count: 16))) { error in
            XCTAssertEqual(error as? SeedError, .badLength)
        }
    }

    func testDecodedSeedFlowsToSeedIdentity() throws {
        // the decoded seed, once stretched (deferred), would derive identity; here just
        // confirm the decoded bytes are the right length to be a root/seed input.
        let decoded = try SeedCodec.decode(try SeedCodec.encode(seed))
        XCTAssertEqual(decoded.count, Seed.byteCount)
    }
}
