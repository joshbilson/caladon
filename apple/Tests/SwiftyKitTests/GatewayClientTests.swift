import CryptoKit
import Foundation
import XCTest

@testable import SwiftyKit

/// Records the last request and returns a canned response.
private final class FakeTransport: Transport, @unchecked Sendable {
    var response: (Data, Int)
    var lastHeaders: [String: String] = [:]
    var lastURL: URL?
    init(response: (Data, Int)) { self.response = response }
    func send(method: String, url: URL, headers: [String: String], body: Data?) async throws
        -> (body: Data, status: Int)
    {
        lastHeaders = headers
        lastURL = url
        return response
    }
}

private struct ThrowingTransport: Transport {
    struct Boom: Error {}
    func send(method: String, url: URL, headers: [String: String], body: Data?) async throws
        -> (body: Data, status: Int)
    { throw Boom() }
}

private struct FakeVerifier: QuoteVerifier {
    var result: Result<VerifiedQuote, VerdictReason>
    func verify(regime: Regime, raw: [String: String]) -> Result<VerifiedQuote, VerdictReason> {
        result
    }
}

private let PINNED = PinnedSet(measurements: ["M1"], composeHashes: ["C1"], workloadIDs: ["W1"])

private func client(transport: Transport, quote: Result<VerifiedQuote, VerdictReason>) -> GatewayClient {
    GatewayClient(
        baseURL: URL(string: "https://gw.test")!,
        accountID: "acct_0123456789abcdef",
        signingKey: Curve25519.Signing.PrivateKey(),
        attestation: Attestation(pinned: PINNED, verifier: FakeVerifier(result: quote)),
        transport: transport,
        now: { 1000 }
    )
}

private func tdxBundleJSON() -> Data {
    // The bundle's trusted reportData/measurement come from the (fake) QuoteVerifier, not
    // these raw JSON fields, so the JSON just needs a valid regime to parse.
    try! JSONSerialization.data(withJSONObject: ["regime": "tdx-onchain", "intel_quote": "0400..."])
}

final class GatewayClientTests: XCTestCase {

    func testVerifyServerSucceedsAndSendsSignedAuth() async throws {
        let transport = FakeTransport(response: (tdxBundleJSON(), 200))
        let good = VerifiedQuote(measurement: "M1", composeHash: "C1", workloadID: "W1",
                                 reportData: "chal", noLog: true)
        let c = client(transport: transport, quote: .success(good))
        try await c.verifyServer(expectedChallenge: "chal")
        // the request carried a seed-auth header for the account
        XCTAssertTrue(transport.lastHeaders["Authorization"]?.hasPrefix("Swifty acct=acct_0123456789abcdef") ?? false)
        // query carried the challenge; signed path excludes the query
        XCTAssertTrue(transport.lastURL?.absoluteString.contains("challenge=chal") ?? false)
    }

    func testVerifyServerFailsClosedOnBadVerdict() async {
        let transport = FakeTransport(response: (tdxBundleJSON(), 200))
        let c = client(transport: transport, quote: .failure(.tcbOutOfDate))
        do {
            try await c.verifyServer(expectedChallenge: "chal")
            XCTFail("expected attestation to fail closed")
        } catch GatewayError.attestationFailed(let reason) {
            XCTAssertEqual(reason, .tcbOutOfDate)
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testVerifyServerThrowsOnHTTPError() async {
        let transport = FakeTransport(response: (Data(), 503))
        let good = VerifiedQuote(measurement: "M1", composeHash: "C1", workloadID: "W1",
                                 reportData: "chal", noLog: true)
        let c = client(transport: transport, quote: .success(good))
        do {
            try await c.verifyServer(expectedChallenge: "chal")
            XCTFail("expected http error")
        } catch GatewayError.http(let code) {
            XCTAssertEqual(code, 503)
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testParseEvidenceRejectsUnknownRegime() {
        let bad = try! JSONSerialization.data(withJSONObject: ["regime": "bogus"])
        XCTAssertThrowsError(try GatewayClient.parseEvidence(bad))
    }

    func testVerifyServerPropagatesTransportError() async {
        let good = VerifiedQuote(measurement: "M1", composeHash: "C1", workloadID: "W1",
                                 reportData: "chal", noLog: true)
        let c = client(transport: ThrowingTransport(), quote: .success(good))
        do {
            try await c.verifyServer(expectedChallenge: "chal")
            XCTFail("transport error must propagate (caller must not proceed)")
        } catch is ThrowingTransport.Boom {
            // ok — fail-closed: no normal return when the network fails
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testParseEvidenceFlattensNestedInfo() throws {
        let json = try JSONSerialization.data(withJSONObject: [
            "regime": "tdx-onchain",
            "intel_quote": "0400",
            "info": ["compose_hash": "C1", "app_id": "W1"],
        ])
        let ev = try GatewayClient.parseEvidence(json)
        XCTAssertEqual(ev.raw["info.compose_hash"], "C1")
        XCTAssertEqual(ev.raw["info.app_id"], "W1")
        XCTAssertEqual(ev.raw["intel_quote"], "0400")
    }
}
