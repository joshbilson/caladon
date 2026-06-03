import Foundation
import XCTest

// PROOF that the caladon-core Rust trust-core links + runs in Swift via UniFFI. These call the
// REAL Rust code (X25519 / HKDF-SHA256, Argon2-adjacent sealed channel) through the generated
// CaladonCoreFFI bindings backed by the CaladonCoreFFI.xcframework static archive, and assert
// byte-for-byte against the SAME Python `swifty_crypto` parity vectors used by SessionTests /
// CryptoTests. If the xcframework didn't link or the FFI marshalling were wrong, these fail.
//
// NOTE: this module intentionally lives ALONGSIDE the existing swift-sodium / dcap-qvl-swift
// implementations (Session.swift etc.) — it does not replace them. The migration is a follow-up.
import CaladonCoreFFI

final class CaladonCoreFFITests: XCTestCase {
    // Same fixed private scalars + expected public/session values as SessionTests (Python oracle).
    let clientPriv = Data(repeating: 0x11, count: 32)
    let cvmPriv = Data(repeating: 0x22, count: 32)
    let clientPubHex = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
    let cvmPubHex = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
    let skHex = "6de96e935bc6ff553866ba3477ace6942c0a1c391efa9a0b7c22794bd9bd6253"

    func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    /// X25519 base-point multiply through the Rust FFI matches the Python vectors. This is the
    /// load-bearing "does the xcframework actually link and execute Rust" assertion.
    func testX25519PublicMatchesPythonVector() throws {
        XCTAssertEqual(hex(try CaladonCoreFFI.x25519Public(privateBytes: clientPriv)), clientPubHex)
        XCTAssertEqual(hex(try CaladonCoreFFI.x25519Public(privateBytes: cvmPriv)), cvmPubHex)
    }

    /// Full session-key derivation (X25519 ECDH + HKDF-SHA256 with the bound info) through the
    /// FFI matches the Python `swifty_crypto.session` vector — proving the marshalling of multiple
    /// `Data` args + the return value across the UniFFI boundary.
    func testDeriveSessionKeyMatchesPythonVector() throws {
        let clientPub = try CaladonCoreFFI.x25519Public(privateBytes: clientPriv)
        let cvmPub = try CaladonCoreFFI.x25519Public(privateBytes: cvmPriv)
        let sk = try CaladonCoreFFI.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPub, clientPub: clientPub, cvmPub: cvmPub
        )
        XCTAssertEqual(hex(sk), skHex)
    }

    /// Client and CVM independently derive the SAME session key — the symmetric-ECDH agreement
    /// property, computed entirely inside Rust over the FFI.
    func testClientAndCvmAgreeOverFFI() throws {
        let clientPub = try CaladonCoreFFI.x25519Public(privateBytes: clientPriv)
        let cvmPub = try CaladonCoreFFI.x25519Public(privateBytes: cvmPriv)
        let skClient = try CaladonCoreFFI.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPub, clientPub: clientPub, cvmPub: cvmPub
        )
        let skCvm = try CaladonCoreFFI.deriveSessionKey(
            myPrivate: cvmPriv, theirPublic: clientPub, clientPub: clientPub, cvmPub: cvmPub
        )
        XCTAssertEqual(skClient, skCvm)
        XCTAssertEqual(hex(skClient), skHex)
    }

    /// `challengeHex` (SHA-256 hex of the ephemeral pubkey — the report_data[0:32] binding) over
    /// the FFI matches a directly-computed CryptoKit SHA-256, proving the hashing path + the
    /// String return marshalling.
    func testChallengeHexOverFFI() {
        let ephPub = Data(repeating: 0x11, count: 32)
        let expected = "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc" // sha256(0x11*32)
        XCTAssertEqual(CaladonCoreFFI.challengeHex(ephPub: ephPub), expected)
    }

    /// Sealed-channel round-trip through Rust: seal the WMK to SK on one side, open it on the
    /// other. Exercises the throwing AEAD path + the `nonce ‖ ct` framing across the FFI.
    func testSealOpenWMKRoundTripOverFFI() throws {
        let clientPub = try CaladonCoreFFI.x25519Public(privateBytes: clientPriv)
        let cvmPub = try CaladonCoreFFI.x25519Public(privateBytes: cvmPriv)
        let sk = try CaladonCoreFFI.deriveSessionKey(
            myPrivate: clientPriv, theirPublic: cvmPub, clientPub: clientPub, cvmPub: cvmPub
        )
        let wmk = Data(repeating: 0xAB, count: 32)
        let acct = "acct_0123456789abcdef"
        let sealed = try CaladonCoreFFI.sealWmk(sessionKey: sk, wmk: wmk, accountId: acct, v: 1)
        let opened = try CaladonCoreFFI.openWmk(sessionKey: sk, nonceCt: sealed, accountId: acct, v: 1)
        XCTAssertEqual(opened, wmk)
    }
}
