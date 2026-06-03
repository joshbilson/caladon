import Foundation
import XCTest

@testable import SwiftyKit

/// OFFLINE parse test for the real dcap-qvl verifier (no network). Proves the prebuilt
/// xcframework parses a REAL TDX v4 quote in CI and that report_data carries the expected
/// channel binding. Full chain VERIFICATION (PCS collateral) is exercised locally /
/// integration (network), not in CI.
final class DcapVerifierTests: XCTestCase {
    private func hexToData(_ h: String) -> Data {
        var d = Data(capacity: h.count / 2)
        var i = h.startIndex
        while i < h.endIndex {
            let j = h.index(i, offsetBy: 2)
            d.append(UInt8(h[i..<j], radix: 16)!)
            i = j
        }
        return d
    }

    func testParsesRealTDXQuote() throws {
        let raw = hexToData(QuoteFixture.redpillTDXQuoteHex)
        let quote = try DcapVerifier.parse(rawQuote: raw)
        XCTAssertEqual(quote.header.version, 4)        // TDX v4
        XCTAssertEqual(quote.header.teeType, 0x81)     // TDX

        // report_data = signing_address(20) ‖ pad(12) ‖ client_nonce(32)
        let rd = DcapVerifier.reportData(of: quote).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(rd.count, 128)  // 64 bytes
        XCTAssertTrue(rd.hasPrefix("4c4e5e69fadffb8e55c306d867dc88792bd3221d"))  // signing address
        XCTAssertTrue(rd.hasSuffix("d722376784b491577d7b92566d84abba0ddad02bcb41b5f4dd520779376bace9"))  // nonce
    }

    func testRejectsGarbageQuote() {
        XCTAssertThrowsError(try DcapVerifier.parse(rawQuote: Data([0x01, 0x02, 0x03, 0x04])))
    }
}
