import CryptoKit
import Foundation
import XCTest

@testable import SwiftyKit

/// Cross-language parity: Swift libsodium primitives MUST be byte-identical to the Python
/// reference `swifty_crypto`. Vectors below were generated from `swifty_crypto` with
/// seed = 0x02·32, salt = "swifty/v1", reference Argon2id params (ops=3, mem=64MiB).
final class CryptoTests: XCTestCase {
    // swifty_crypto vectors (see PROGRESS.md iter-19 decision log).
    let seed = [UInt8](repeating: 0x02, count: 32)
    let rootHex = "81786b525c5b61818aed27aad88ae7272f6168550df0f6738d4f0486e04b7514"
    let wmkHex = "a76469241255213b0fadd13caedab241d60a4768f116c2aa4cd665f1bb6103df"
    let acct = "oY9ac7mkGzFajJPLzW4xi_FIURU9qpRpNbiOBwo23nU"
    let nonceHex = "fb6a069ff250795acaddc3abdbc820a2475e3429c1935444"
    let aadHex = "e12ed41692e95bf8058a0c2851f5db5cf1593a558e03735431b9a52640db0324"
    let ctHex = "b74c46253646fdc60e636ba73720741e31507d1db3ccab0f87c5225d"

    func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    func bytes(_ h: String) -> [UInt8] {
        var out = [UInt8](); var i = h.startIndex
        while i < h.endIndex { let j = h.index(i, offsetBy: 2); out.append(UInt8(h[i..<j], radix: 16)!); i = j }
        return out
    }

    // Production Argon2id params (m=256MiB, t=3) — same seed/salt, different vector.
    let rootProdHex = "ea6effddce0a7970350ba4927d107d3a34a75cb86562ad9af70d433acc4f4a3d"

    func testArgon2idMatchesPythonReference() throws {
        let root = try SwiftyCrypto.argon2id(seed: seed, salt: "swifty/v1")
        XCTAssertEqual(hex(root), rootHex, "Argon2id seed→root diverges from swifty_crypto")
    }

    func testArgon2idProductionParamsMatchPython() throws {
        // Production params MUST also match the Python reference (the reference vector alone
        // wouldn't catch a production-only divergence).
        let root = try SwiftyCrypto.argon2id(
            seed: seed, salt: "swifty/v1",
            opsLimit: SwiftyCrypto.opsLimitProduction, memLimit: SwiftyCrypto.memLimitProduction
        )
        XCTAssertEqual(hex(root), rootProdHex)
        XCTAssertNotEqual(hex(root), rootHex)  // and is distinct from the reference-params root
    }

    func testFullDerivationChainMatches() throws {
        // seed →(argon2id)→ root →(HKDF)→ {WMK, account_id} all match the Python reference.
        let root = try SeedIdentity.deriveRoot(seed: Data(seed))
        XCTAssertEqual(SeedIdentity.wmk(root).map { String(format: "%02x", $0) }.joined(), wmkHex)
        XCTAssertEqual(try SeedIdentity.accountID(root), acct)
    }

    func testOpensPythonSealedCiphertext() throws {
        // Decrypt a ciphertext produced by swifty_crypto.seal — proves AEAD interop.
        let pt = try SwiftyCrypto.open(key: bytes(wmkHex), nonce: bytes(nonceHex), ct: bytes(ctHex), aad: bytes(aadHex))
        XCTAssertEqual(String(decoding: pt, as: UTF8.self), "hello swifty")
    }

    func testAADMatchesPythonReference() throws {
        // aad = SHA256("{account_id}\n{purpose}\n{v}") — must equal the Python _aad bytes.
        let aad = SwiftyCrypto.aad(accountID: acct, purpose: "working-mem", v: 1)
        XCTAssertEqual(hex(aad), aadHex)
    }

    func testSealOpenRoundTrip() throws {
        let key = bytes(wmkHex)
        let aad = SwiftyCrypto.aad(accountID: acct, purpose: "working-mem", v: 1)
        let msg = Array("round trip 🛰".utf8)
        let (nonce, ct) = try SwiftyCrypto.seal(key: key, plaintext: msg, aad: aad)
        XCTAssertEqual(nonce.count, SwiftyCrypto.nonceLength)
        XCTAssertEqual(try SwiftyCrypto.open(key: key, nonce: nonce, ct: ct, aad: aad), msg)
    }

    func testOpenFailsOnTamperedCiphertext() throws {
        var ct = bytes(ctHex)
        ct[0] ^= 0x01  // flip a bit
        XCTAssertThrowsError(try SwiftyCrypto.open(key: bytes(wmkHex), nonce: bytes(nonceHex), ct: ct, aad: bytes(aadHex)))
    }

    func testOpenFailsOnTamperedAAD() throws {
        var aad = bytes(aadHex)
        aad[0] ^= 0x01
        XCTAssertThrowsError(try SwiftyCrypto.open(key: bytes(wmkHex), nonce: bytes(nonceHex), ct: bytes(ctHex), aad: aad))
    }

    func testArgon2idRejectsShortSeed() {
        XCTAssertThrowsError(try SwiftyCrypto.argon2id(seed: [1, 2, 3], salt: "swifty/v1"))
    }

    func testOpenRejectsSubTagCiphertext() {
        // ct shorter than the 16-byte Poly1305 tag must throw, never return data.
        XCTAssertThrowsError(
            try SwiftyCrypto.open(key: bytes(wmkHex), nonce: bytes(nonceHex), ct: [0x00, 0x01], aad: bytes(aadHex))
        )
    }
}
