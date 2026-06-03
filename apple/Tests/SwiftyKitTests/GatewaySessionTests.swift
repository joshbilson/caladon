import CryptoKit
import Foundation
import XCTest

@testable import SwiftyKit

/// End-to-end client↔server protocol test for the confidential round-trip (§6 + /v1/chat).
/// `CVMSim` is a Transport that SIMULATES the in-CVM gateway using the real Session crypto:
/// it attests, derives the same SK, opens the delivered WMK, opens the sealed prompt, and
/// returns a sealed response delta. So this proves the SwiftyKit client's establishSession +
/// chat produce/consume exactly what the gateway expects.

private let ACCT = "acct_0123456789abcdef"
private let PINNED = PinnedSet(measurements: ["M1"], composeHashes: ["C1"], workloadIDs: ["W1"])
private let WMK = Data(repeating: 0xAB, count: 32)

/// Verifier that echoes the evidence's `challenge` as the quote reportData, so the channel
/// binding check passes for whatever ephemeral challenge the client generated.
private struct EchoVerifier: QuoteVerifier {
    func verify(regime: Regime, raw: [String: String]) -> Result<VerifiedQuote, VerdictReason> {
        .success(VerifiedQuote(measurement: "M1", composeHash: "C1", workloadID: "W1",
                               reportData: raw["challenge"] ?? "", noLog: true))
    }
}

private final class CVMSim: Transport, @unchecked Sendable {
    let cvmPriv: Data
    let cvmPub: Data
    var sk: Data?
    var openedWMK: Data?
    var openedPrompt: String?

    init() { let kp = Session.x25519Keypair(); cvmPriv = kp.privateBytes; cvmPub = kp.publicBytes }

    private func b(_ env: [String: Any], _ k: String) -> [UInt8] { [UInt8](Data(base64Encoded: env[k] as! String)!) }

    func send(method: String, url: URL, headers: [String: String], body: Data?) async throws
        -> (body: Data, status: Int)
    {
        let path = url.path
        if path.hasSuffix("/v1/attestation") {
            let challenge = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first { $0.name == "challenge" }?.value ?? ""
            let ev: [String: Any] = ["regime": "tdx-onchain", "challenge": challenge,
                                     "session_pub": cvmPub.base64EncodedString()]
            return (try JSONSerialization.data(withJSONObject: ev), 200)
        }
        let obj = (try? JSONSerialization.jsonObject(with: body ?? Data()) as? [String: Any]) ?? [:]
        if path.hasSuffix("/v1/session") {
            let ephPub = Data(base64Encoded: obj["client_eph_pub"] as! String)!
            sk = try Session.deriveSessionKey(myPrivate: cvmPriv, theirPublic: ephPub, clientPub: ephPub, cvmPub: cvmPub)
            let env = obj["sealed_wmk"] as! [String: Any]
            openedWMK = try Session.openWMK(sessionKey: sk!, nonce: b(env, "nonce"), ct: b(env, "ct"),
                                            accountID: ACCT, v: env["v"] as! Int)
            return (try JSONSerialization.data(withJSONObject: ["session": "established"]), 200)
        }
        if path.hasSuffix("/v1/chat") {
            let env = obj["envelope"] as! [String: Any]
            openedPrompt = String(decoding: try Session.openChat(sessionKey: sk!, nonce: b(env, "nonce"),
                                                                 ct: b(env, "ct"), accountID: ACCT, v: env["v"] as! Int),
                                  as: UTF8.self)
            let (n, c) = try Session.sealChat(sessionKey: sk!, plaintext: Data("Hi there".utf8), accountID: ACCT)
            let aad = SwiftyCrypto.aad(accountID: ACCT, purpose: Session.chatPurpose, v: 1)
            let tokenEnv: [String: Any] = ["v": 1, "alg": "xchacha20poly1305", "kid": "chat",
                                           "nonce": Data(n).base64EncodedString(),
                                           "aad": Data(aad).base64EncodedString(),
                                           "ct": Data(c).base64EncodedString()]
            let tokenData = String(decoding: try JSONSerialization.data(withJSONObject: ["envelope": tokenEnv]), as: UTF8.self)
            let sse = "event: token\ndata: \(tokenData)\n\nevent: receipt\ndata: {}\n\nevent: done\ndata: {}\n\n"
            return (Data(sse.utf8), 200)
        }
        return (Data(), 404)
    }
}

private func makeClient(_ t: Transport) -> GatewayClient {
    GatewayClient(
        baseURL: URL(string: "https://gw.test")!, accountID: ACCT,
        signingKey: Curve25519.Signing.PrivateKey(),
        attestation: Attestation(pinned: PINNED, verifier: EchoVerifier()),
        transport: t, now: { 1000 }
    )
}

final class GatewaySessionTests: XCTestCase {
    func testEstablishSessionDeliversWMK() async throws {
        let cvm = CVMSim()
        let sk = try await makeClient(cvm).establishSession(wmk: WMK)
        XCTAssertEqual(cvm.openedWMK, WMK)  // the CVM opened the delivered WMK
        XCTAssertEqual(cvm.sk, sk)          // client and CVM agree on SK
    }

    func testChatRoundTrip() async throws {
        let cvm = CVMSim()
        let c = makeClient(cvm)
        let sk = try await c.establishSession(wmk: WMK)
        let deltas = try await c.chat(prompt: "hello agent", sessionKey: sk)
        XCTAssertEqual(cvm.openedPrompt, "hello agent")  // CVM decrypted the prompt
        XCTAssertEqual(deltas, ["Hi there"])             // client decrypted the sealed delta
    }
}
