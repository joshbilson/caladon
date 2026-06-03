import CryptoKit
import Foundation
import XCTest

@testable import SwiftyKit

/// Parity: Swift session-key derivation MUST match `swifty_crypto.session`. Vectors from
/// privs 0x11·32 (client) / 0x22·32 (cvm).
final class SessionTests: XCTestCase {
    let clientPriv = Data(repeating: 0x11, count: 32)
    let cvmPriv = Data(repeating: 0x22, count: 32)
    let clientPubHex = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
    let cvmPubHex = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
    let skHex = "6de96e935bc6ff553866ba3477ace6942c0a1c391efa9a0b7c22794bd9bd6253"

    func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testPublicKeysMatchPython() throws {
        XCTAssertEqual(hex(try Session.x25519Public(privateBytes: clientPriv)), clientPubHex)
        XCTAssertEqual(hex(try Session.x25519Public(privateBytes: cvmPriv)), cvmPubHex)
    }

    func testSessionKeyMatchesPythonVector() throws {
        let clientPub = try Session.x25519Public(privateBytes: clientPriv)
        let cvmPub = try Session.x25519Public(privateBytes: cvmPriv)
        let sk = try Session.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPub, clientPub: clientPub, cvmPub: cvmPub
        )
        XCTAssertEqual(hex(sk), skHex)
    }

    func testClientAndCvmAgree() throws {
        let clientPub = try Session.x25519Public(privateBytes: clientPriv)
        let cvmPub = try Session.x25519Public(privateBytes: cvmPriv)
        let skClient = try Session.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPub, clientPub: clientPub, cvmPub: cvmPub
        )
        let skCvm = try Session.deriveSessionKey(
            myPrivate: cvmPriv, theirPublic: clientPub, clientPub: clientPub, cvmPub: cvmPub
        )
        XCTAssertEqual(skClient, skCvm)
    }

    func testWMKDeliveryRoundTrip() throws {
        let clientPub = try Session.x25519Public(privateBytes: clientPriv)
        let cvmPub = try Session.x25519Public(privateBytes: cvmPriv)
        let skClient = try Session.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPub, clientPub: clientPub, cvmPub: cvmPub
        )
        let skCvm = try Session.deriveSessionKey(
            myPrivate: cvmPriv, theirPublic: clientPub, clientPub: clientPub, cvmPub: cvmPub
        )
        let wmk = Data(repeating: 0xAB, count: 32)
        let acct = "acct_0123456789abcdef"
        let (nonce, ct) = try Session.sealWMK(sessionKey: skClient, wmk: wmk, accountID: acct)
        XCTAssertEqual(try Session.openWMK(sessionKey: skCvm, nonce: nonce, ct: ct, accountID: acct, v: 1), wmk)
    }

    func testLowOrderPointFailsClosed() throws {
        // All-zero (identity) peer point -> all-zero ECDH -> must throw (parity with Python).
        let clientPub = try Session.x25519Public(privateBytes: clientPriv)
        let cvmPub = try Session.x25519Public(privateBytes: cvmPriv)
        XCTAssertThrowsError(try Session.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: Data(repeating: 0, count: 32),
            clientPub: clientPub, cvmPub: cvmPub
        ))
    }

    func testSubstitutedKeyFailsOpen() throws {
        let clientPub = try Session.x25519Public(privateBytes: clientPriv)
        let cvmPub = try Session.x25519Public(privateBytes: cvmPriv)
        let attackerPub = try Session.x25519Public(privateBytes: Data(repeating: 0x33, count: 32))
        let skHonest = try Session.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPub, clientPub: clientPub, cvmPub: cvmPub
        )
        let skWrong = try Session.deriveSessionKey(
            myPrivate: cvmPriv, theirPublic: clientPub, clientPub: clientPub, cvmPub: attackerPub
        )
        XCTAssertNotEqual(skHonest, skWrong)
        let (nonce, ct) = try Session.sealWMK(sessionKey: skHonest, wmk: Data(repeating: 1, count: 32), accountID: "acct_0123456789abcdef")
        XCTAssertThrowsError(try Session.openWMK(sessionKey: skWrong, nonce: nonce, ct: ct, accountID: "acct_0123456789abcdef", v: 1))
    }

    func testRejectsBadPubLength() {
        XCTAssertThrowsError(try Session.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPriv, clientPub: Data([1, 2, 3]), cvmPub: cvmPriv
        ))
    }
}
