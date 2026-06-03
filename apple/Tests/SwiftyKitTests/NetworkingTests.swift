import CryptoKit
import Foundation
import XCTest

@testable import SwiftyKit

private struct StubVerifier: QuoteVerifier {
    func verify(regime: Regime, raw: [String: String]) -> Result<VerifiedQuote, VerdictReason> {
        .failure(.regimeUnsupported)
    }
}

final class NetworkingTests: XCTestCase {
    /// The seed→client factory derives the account_id + signing key from the root (not from
    /// any caller-supplied value), so the client's identity is exactly the seed's.
    func testFactoryDerivesAccountFromRoot() throws {
        let root = try SeedIdentity.deriveRoot(seed: Data(repeating: 0x02, count: 32))
        let pinned = PinnedSet(measurements: ["M1"], composeHashes: ["C1"], workloadIDs: ["W1"])
        let client = try GatewayClient.make(
            baseURL: URL(string: "https://gw.test")!, root: root, verifier: StubVerifier(), pinned: pinned
        )
        XCTAssertEqual(client.accountID, try SeedIdentity.accountID(root))
        // and the signing key matches the seed-derived gateway-auth key
        XCTAssertEqual(
            client.signingKey.publicKey.rawRepresentation,
            try SeedIdentity.ed25519PublicKey(root)
        )
    }
}
