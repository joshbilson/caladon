import Foundation
import XCTest

@testable import SwiftyKit

/// Cross-language interop: these vectors were generated from the Python reference
/// `swifty_crypto` (root = 0x01 * 32). If the Swift CryptoKit derivations ever drift from
/// the Python/CVM side, onboarding + decryption break — so this test is load-bearing.
final class SeedIdentityTests: XCTestCase {
    private let root = RootKey(stretched: Data(repeating: 0x01, count: 32))

    func testMatchesPythonReferenceVectors() throws {
        XCTAssertEqual(
            SeedIdentity.wmk(root).hexString,
            "fa52a2cb1dff5fe4c9354ea9b18b2d704146a01c19b9d8b77f0a24b5dcb86dd0")
        XCTAssertEqual(
            SeedIdentity.transcriptRoot(root).hexString,
            "37ad86a0d90fb1afbacd7a2983e072f1d00473da46b89770a5e5e1737323dcf4")
        XCTAssertEqual(
            try SeedIdentity.ed25519PublicKey(root).hexString,
            "7adf48f55343f74247444a675bad258d6a3c781d0539958c08935b6a5475c28a")
        XCTAssertEqual(
            try SeedIdentity.accountID(root),
            "6ShZmo4MSidVudq3H6sJA4Tp6cJfvm9_sx-N2mQ4Ah0")
    }

    func testDomainSeparation() {
        XCTAssertNotEqual(SeedIdentity.wmk(root), SeedIdentity.transcriptRoot(root))
        XCTAssertNotEqual(
            SeedIdentity.wmk(root),
            SeedIdentity.hkdf(root, label: SeedIdentity.gatewayAuthLabel))
    }

    func testDeterministic() {
        XCTAssertEqual(SeedIdentity.wmk(root), SeedIdentity.wmk(root))
    }

    func testAccountIDIsValidFormat() throws {
        XCTAssertTrue(SeedAuth.isValidAccountID(try SeedIdentity.accountID(root)))
    }
}

// Test-only helper (kept out of the shipping module).
extension Data {
    fileprivate var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
