import Foundation
import XCTest

@testable import SwiftyKit

/// Parity with swifty_crypto.padding (§9).
final class PaddingTests: XCTestCase {
    func testParityVector() {
        let v = Padding.pad(Data("hello".utf8))
        XCTAssertEqual(v.count, 256)
        XCTAssertEqual(Array(v.prefix(9)), [0, 0, 0, 5] + Array("hello".utf8))  // uint32_be(5) ‖ hello
        XCTAssertEqual(Array(v.suffix(from: 9)), [UInt8](repeating: 0, count: 256 - 9))
    }

    func testRoundTrip() throws {
        for n in [0, 1, 5, 251, 252, 253, 1000, 5000, 70000] {
            let msg = Data(repeating: 0x78, count: n)
            XCTAssertEqual(try Padding.unpad(Padding.pad(msg)), msg)
        }
    }

    func testBucketBoundaries() {
        XCTAssertEqual(Padding.pad(Data(count: 0)).count, 256)
        XCTAssertEqual(Padding.pad(Data(count: 252)).count, 256)   // body 256
        XCTAssertEqual(Padding.pad(Data(count: 253)).count, 1024)  // body 257
        XCTAssertEqual(Padding.pad(Data(count: 70000)).count, 262144)
    }

    func testSizeHiddenWithinBucket() {
        XCTAssertEqual(Padding.pad(Data(count: 1)).count, Padding.pad(Data(count: 100)).count)
    }

    func testUnpadRejectsBadLength() {
        XCTAssertThrowsError(try Padding.unpad(Data([0xff, 0xff, 0xff, 0xff]) + Data("short".utf8)))
        XCTAssertThrowsError(try Padding.unpad(Data([0, 0])))
    }
}
