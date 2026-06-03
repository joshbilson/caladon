import CryptoKit
import XCTest

@testable import SwiftyKit

final class SeedAuthTests: XCTestCase {

    func testCanonicalIsDeterministicAndMethodUppercased() {
        XCTAssertEqual(
            SeedAuth.canonical(accountId: "a", ts: 1, method: "post", path: "/x"),
            SeedAuth.canonical(accountId: "a", ts: 1, method: "POST", path: "/x")
        )
        XCTAssertNotEqual(
            SeedAuth.canonical(accountId: "a", ts: 1, method: "POST", path: "/x"),
            SeedAuth.canonical(accountId: "a", ts: 1, method: "POST", path: "/y")
        )
    }

    func testHeaderSignatureVerifiesAndBindsMethodPath() throws {
        let key = Curve25519.Signing.PrivateKey()
        let acct = "acct_0123456789abcdef"
        let ts = 100
        let header = try SeedAuth.authorizationHeader(
            privateKey: key, accountId: acct, ts: ts, method: "GET", path: "/v1/whoami"
        )
        XCTAssertTrue(header.hasPrefix("Swifty acct=\(acct) ts=\(ts) sig="))

        guard let r = header.range(of: "sig=") else { return XCTFail("no sig field") }
        let sig = Data(base64Encoded: String(header[r.upperBound...]))!

        // verifies over the exact canonical
        XCTAssertTrue(key.publicKey.isValidSignature(
            sig, for: SeedAuth.canonical(accountId: acct, ts: ts, method: "GET", path: "/v1/whoami")))
        // bound to path: a different path must NOT verify
        XCTAssertFalse(key.publicKey.isValidSignature(
            sig, for: SeedAuth.canonical(accountId: acct, ts: ts, method: "GET", path: "/v1/other")))
        // bound to method
        XCTAssertFalse(key.publicKey.isValidSignature(
            sig, for: SeedAuth.canonical(accountId: acct, ts: ts, method: "POST", path: "/v1/whoami")))
    }

    func testInvalidAccountIDThrows() {
        let key = Curve25519.Signing.PrivateKey()
        XCTAssertThrowsError(try SeedAuth.authorizationHeader(
            privateKey: key, accountId: "bad id with spaces", ts: 1, method: "GET", path: "/x"))
        XCTAssertThrowsError(try SeedAuth.authorizationHeader(
            privateKey: key, accountId: "short", ts: 1, method: "GET", path: "/x"))
    }
}
