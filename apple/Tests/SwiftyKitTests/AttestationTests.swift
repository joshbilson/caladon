import CryptoKit
import Foundation
import XCTest

@testable import SwiftyKit

/// Fake quote verifier: returns a preset Result so adapter success/failure reasons are
/// exercised independently of the decision-core checks.
private struct FakeVerifier: QuoteVerifier {
    var result: Result<VerifiedQuote, VerdictReason>
    func verify(regime: Regime, raw: [String: String]) -> Result<VerifiedQuote, VerdictReason> {
        result
    }
}

private let PINNED = PinnedSet(measurements: ["M1"], composeHashes: ["C1"], workloadIDs: ["W1"])
private let EV = Evidence(regime: .tdxOnchain, raw: ["intel_quote": "0400..."])

// The CVM session pubkey the verify call is given, and its attested binding
// (report_data[32:64] = SHA-256(session_pub), lowercase hex) — the §4.6b keystone binding.
private let SESSION_PUB = Data(repeating: 0x11, count: 32)
private let SESSION_BINDING = SHA256.hash(data: SESSION_PUB).map { String(format: "%02x", $0) }.joined()

private func goodQuote(
    measurement: String = "M1", composeHash: String = "C1", workloadID: String = "W1",
    reportData: String = "chal", sessionBinding: String = SESSION_BINDING, noLog: Bool = true
) -> VerifiedQuote {
    VerifiedQuote(measurement: measurement, composeHash: composeHash, workloadID: workloadID,
                  reportData: reportData, sessionBinding: sessionBinding, noLog: noLog)
}

private func att(_ result: Result<VerifiedQuote, VerdictReason>) -> Attestation {
    Attestation(pinned: PINNED, verifier: FakeVerifier(result: result))
}

final class AttestationTests: XCTestCase {

    func testHappyPathVerifies() {
        XCTAssertEqual(att(.success(goodQuote())).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: true, reason: .ok))
    }

    func testAdapterFailureReasonSurfacesDistinctly() {
        // a TCB-out-of-date failure must NOT collapse into quoteSigInvalid
        XCTAssertEqual(att(.failure(.tcbOutOfDate)).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .tcbOutOfDate))
        XCTAssertEqual(att(.failure(.quoteSigInvalid)).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .quoteSigInvalid))
    }

    func testUnpinnedMeasurementFailsClosed() {
        XCTAssertEqual(att(.success(goodQuote(measurement: "ROGUE"))).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .measurementUnpinned))
    }

    func testUnpinnedComposeHashFailsClosed() {
        XCTAssertEqual(att(.success(goodQuote(composeHash: "ROGUE"))).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .composeMismatch))
    }

    func testWrongWorkloadFailsClosed() {
        XCTAssertEqual(att(.success(goodQuote(workloadID: "ROGUE"))).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .appIDMismatch))
    }

    func testChannelBindingMismatchFailsClosed() {
        XCTAssertEqual(att(.success(goodQuote(reportData: "OTHER"))).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .bindingMismatch))
    }

    func testSessionBindingMismatchFailsClosed() {
        // report_data[0:32] matches the challenge, but report_data[32:64] does NOT match
        // SHA-256(session_pub) -> a substituted CVM session key is rejected (the CC-1 keystone).
        XCTAssertEqual(att(.success(goodQuote(sessionBinding: "deadbeef"))).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .bindingMismatch))
    }

    func testNoLogAbsentFailsClosed() {
        XCTAssertEqual(att(.success(goodQuote(noLog: false))).verify(EV, expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .noLogAbsent))
    }

    func testNoneRegimeUnsupported() {
        XCTAssertEqual(att(.success(goodQuote())).verify(Evidence(regime: .none, raw: [:]),
                                                         expectedChallenge: "chal", sessionPub: SESSION_PUB),
                       Verdict(ok: false, reason: .regimeUnsupported))
    }
}
