import Foundation
import XCTest

@testable import SwiftyKit

/// SeedStore round-trip via the in-memory store. (KeychainSeedStore is exercised by the app
/// build + on-device runs; the login keychain isn't reliably available to unsigned `swift
/// test` in CI, so it isn't unit-tested here.)
final class SeedStoreTests: XCTestCase {
    func testRoundTrip() throws {
        let store = InMemorySeedStore()
        XCTAssertNil(try store.load())
        let seed = try Seed.generate()
        try store.save(seed)
        XCTAssertEqual(try store.load(), seed)
        try store.deleteSeed()
        XCTAssertNil(try store.load())
    }

    func testRejectsWrongLength() {
        let store = InMemorySeedStore()
        XCTAssertThrowsError(try store.save(Data([1, 2, 3]))) { err in
            XCTAssertEqual(err as? SeedStoreError, .badSeedLength)
        }
    }

    func testOverwriteReplacesSeed() throws {
        let store = InMemorySeedStore()
        let a = try Seed.generate(), b = try Seed.generate()
        try store.save(a)
        try store.save(b)
        XCTAssertEqual(try store.load(), b)
    }
}
