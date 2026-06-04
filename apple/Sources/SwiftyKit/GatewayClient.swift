import CryptoKit
import Foundation

/// Client send-gate (contracts/gateway-api.md, attestation.md §3-§4). Composes seed-auth
/// signing + the fail-closed pre-send attestation handshake: the client verifies the
/// server's enclave BEFORE transmitting anything. Networking is injected (`Transport`) so
/// the gate is unit-testable without a live server.

public enum GatewayError: Error, Equatable {
    case http(Int)
    case attestationFailed(VerdictReason)
    case decode
}

public protocol Transport: Sendable {
    func send(method: String, url: URL, headers: [String: String], body: Data?) async throws
        -> (body: Data, status: Int)
}

public struct GatewayClient: Sendable {
    let baseURL: URL
    let accountID: String
    let signingKey: Curve25519.Signing.PrivateKey
    let attestation: Attestation
    let transport: Transport
    let now: @Sendable () -> Int

    public init(
        baseURL: URL,
        accountID: String,
        signingKey: Curve25519.Signing.PrivateKey,
        attestation: Attestation,
        transport: Transport,
        now: @escaping @Sendable () -> Int = { Int(Date().timeIntervalSince1970) }
    ) {
        self.baseURL = baseURL
        self.accountID = accountID
        self.signingKey = signingKey
        self.attestation = attestation
        self.transport = transport
        self.now = now
    }

    /// Seed-auth header for `method`+`path`. `path` is the raw path (no query), matching the
    /// gateway's canonical (gateway/app/seed_auth.py).
    func authHeaders(method: String, path: String) throws -> [String: String] {
        [
            "Authorization": try SeedAuth.authorizationHeader(
                privateKey: signingKey, accountId: accountID, ts: now(), method: method, path: path
            )
        ]
    }

    /// Pre-send handshake: fetch the attestation evidence and verify it fail-closed.
    /// `expectedChallenge` = `SHA-256(eph_pub)`. Throws unless the verdict is `.ok`; the
    /// caller MUST NOT send any prompt/key until this returns without throwing.
    public func verifyServer(expectedChallenge: String) async throws {
        _ = try await fetchVerifiedEvidence(expectedChallenge: expectedChallenge)
    }

    /// Fetch + fail-closed-verify the evidence, returning it (so callers can read the CVM
    /// `session_pub` for §6). Throws unless the verdict is `.ok`.
    func fetchVerifiedEvidence(expectedChallenge: String) async throws -> Evidence {
        let path = "/v1/attestation"
        guard
            var comps = URLComponents(
                url: baseURL.appendingPathComponent("v1/attestation"), resolvingAgainstBaseURL: false
            )
        else { throw GatewayError.decode }
        comps.queryItems = [URLQueryItem(name: "challenge", value: expectedChallenge)]
        guard let url = comps.url else { throw GatewayError.decode }

        let (data, status) = try await transport.send(
            method: "GET", url: url, headers: try authHeaders(method: "GET", path: path), body: nil
        )
        guard status == 200 else { throw GatewayError.http(status) }

        let evidence = try Self.parseEvidence(data)
        // The CVM X25519 session_pub arrives in UNTRUSTED evidence; we decode it here and feed
        // it INTO the fail-closed verifier, which requires the verified quote to attest
        // report_data[32:64] == SHA-256(session_pub). A relay that swaps session_pub fails that
        // bind (BINDING_MISMATCH) — so we never derive SK against an attacker. session_pub MUST
        // be present (absence => fail-closed: there is nothing the quote can bind against).
        guard let spB64 = evidence.raw["session_pub"], let sessionPub = Data(base64Encoded: spB64) else {
            throw GatewayError.attestationFailed(.bindingMismatch)
        }
        let verdict = attestation.verify(
            evidence, expectedChallenge: expectedChallenge, sessionPub: sessionPub
        )
        guard verdict.ok else { throw GatewayError.attestationFailed(verdict.reason) }
        return evidence
    }

    /// Register this account with the gateway (idempotent `POST /v1/accounts`, proof-of-
    /// possession over the seed-auth signature). REQUIRED before the first attestation/session
    /// call — the gateway rejects requests from an unknown account with 401. Safe to call every
    /// connect: 201 on first registration, 200 if already registered (no key rebind).
    public func onboard() async throws {
        let edPub = signingKey.publicKey.rawRepresentation        // the registered Ed25519 key
        let (_, kemPub) = Session.x25519Keypair()                 // KEM pub (stored; v1 uses a fresh session key)
        let body: [String: Any] = [
            "account_id": accountID,
            "ed25519_pub": edPub.base64EncodedString(),
            "kem_pub": kemPub.base64EncodedString(),
        ]
        let (_, status) = try await postJSON(path: "/v1/accounts", body: body)
        guard status == 200 || status == 201 else { throw GatewayError.http(status) }
    }

    /// §6 WMK delivery. Generates an ephemeral X25519 key (its pub IS the attestation
    /// challenge, `SHA-256(pub)`), verifies the CVM, derives SK against the CVM `session_pub`
    /// from the VERIFIED evidence, seals WMK to SK, and POSTs it. Returns SK for chat turns.
    /// Fail-closed: if the CVM doesn't verify, nothing is sent.
    public func establishSession(wmk: Data) async throws -> Data {
        let (ephPriv, ephPub) = Session.x25519Keypair()
        let challenge = Self.challenge(forEphemeralPub: ephPub)
        let evidence = try await fetchVerifiedEvidence(expectedChallenge: challenge)
        // fetchVerifiedEvidence already proved the quote attests SHA-256(session_pub) at
        // report_data[32:64], so this `cvmPub` is the SAME bytes the enclave bound — we derive
        // SK against the attested session key, not a relay's substitute. (Same decode as the
        // verifier; absence/garbage is already fail-closed above, so this guard is belt-and-braces.)
        guard let spB64 = evidence.raw["session_pub"], let cvmPub = Data(base64Encoded: spB64) else {
            throw GatewayError.decode
        }
        let sk = try Session.deriveSessionKey(
            myPrivate: ephPriv, theirPublic: cvmPub, clientPub: ephPub, cvmPub: cvmPub
        )
        let (nonce, ct) = try Session.sealWMK(sessionKey: sk, wmk: wmk, accountID: accountID)
        let aad = SwiftyCrypto.aad(accountID: accountID, purpose: Session.wmkDeliveryPurpose, v: 1)
        let body: [String: Any] = [
            "client_eph_pub": ephPub.base64EncodedString(),
            "sealed_wmk": Self.wireEnvelope(nonce: nonce, aad: aad, ct: ct, kid: "v1"),
        ]
        let (_, status) = try await postJSON(path: "/v1/session", body: body)
        guard status == 200 else { throw GatewayError.http(status) }
        return sk
    }

    /// Confidential live turn: seal the prompt to SK, POST it, and return the decrypted
    /// response deltas (opened under SK). The plaintext prompt/deltas never traverse the wire.
    public func chat(prompt: String, sessionKey: Data) async throws -> [String] {
        let (nonce, ct) = try Session.sealChat(sessionKey: sessionKey, plaintext: Data(prompt.utf8), accountID: accountID)
        let aad = SwiftyCrypto.aad(accountID: accountID, purpose: Session.chatPurpose, v: 1)
        let body: [String: Any] = ["envelope": Self.wireEnvelope(nonce: nonce, aad: aad, ct: ct, kid: "chat")]
        let (data, status) = try await postJSON(path: "/v1/chat", body: body)
        guard status == 200 else { throw GatewayError.http(status) }
        return try Self.parseSSEDeltas(data, sessionKey: sessionKey, accountID: accountID)
    }

    // MARK: - helpers

    func postJSON(path: String, body: [String: Any]) async throws -> (Data, Int) {
        let url = baseURL.appendingPathComponent(String(path.dropFirst()))
        let payload = try JSONSerialization.data(withJSONObject: body)
        var headers = try authHeaders(method: "POST", path: path)
        headers["Content-Type"] = "application/json"
        return try await transport.send(method: "POST", url: url, headers: headers, body: payload)
    }

    static func challenge(forEphemeralPub pub: Data) -> String {
        SHA256.hash(data: pub).map { String(format: "%02x", $0) }.joined()
    }

    static func wireEnvelope(nonce: [UInt8], aad: [UInt8], ct: [UInt8], kid: String) -> [String: Any] {
        [
            "v": 1, "alg": "xchacha20poly1305", "kid": kid,
            "nonce": Data(nonce).base64EncodedString(),
            "aad": Data(aad).base64EncodedString(),
            "ct": Data(ct).base64EncodedString(),
        ]
    }

    /// Parse an SSE stream, opening each token/reasoning envelope under SK into a plaintext
    /// delta. Non-token events (receipt/done) are ignored. Fail-closed: a delta that won't
    /// open throws (the response is not trusted).
    static func parseSSEDeltas(_ data: Data, sessionKey: Data, accountID: String) throws -> [String] {
        let text = String(decoding: data, as: UTF8.self)
        var deltas: [String] = []
        var lastEvent = ""
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.hasPrefix("event:") {
                lastEvent = String(line.dropFirst("event:".count)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("data:") {
                // Non-token/reasoning events (receipt/done/error) carry no sealed delta -> skip.
                guard lastEvent == "token" || lastEvent == "reasoning" else { continue }
                // But a token/reasoning event MUST carry a well-formed, openable envelope.
                // A structurally-broken one (e.g. a tamper that strips `v`) is FAIL-CLOSED:
                // we throw `decode` rather than silently dropping an unauthenticated delta.
                let json = String(line.dropFirst("data:".count)).trimmingCharacters(in: .whitespaces)
                guard
                    let obj = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
                    let env = obj["envelope"] as? [String: Any],
                    let nB = env["nonce"] as? String, let nonce = Data(base64Encoded: nB),
                    let cB = env["ct"] as? String, let ct = Data(base64Encoded: cB),
                    let v = env["v"] as? Int
                else { throw GatewayError.decode }
                let pt = try Session.openChat(
                    sessionKey: sessionKey, nonce: [UInt8](nonce), ct: [UInt8](ct), accountID: accountID, v: v
                )
                deltas.append(String(decoding: pt, as: UTF8.self))
            }
        }
        return deltas
    }

    static func parseEvidence(_ data: Data) throws -> Evidence {
        guard
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let regimeStr = obj["regime"] as? String,
            let regime = Regime(rawValue: regimeStr)
        else { throw GatewayError.decode }
        var raw: [String: String] = [:]
        Self.flatten(obj, prefix: "", into: &raw)  // nested objects (e.g. `info`) -> "info.compose_hash"
        return Evidence(regime: regime, raw: raw)
    }

    /// Flatten the bundle to `[String: String]` with dotted keys so nested fields (the TDX
    /// bundle's `info.compose_hash`, `info.app_id`, …) reach the regime adapter. The adapter
    /// reads the dotted-key convention. Arrays (e.g. `all_attestations`) are skipped here.
    static func flatten(_ dict: [String: Any], prefix: String, into raw: inout [String: String]) {
        for (key, value) in dict {
            let fullKey = prefix.isEmpty ? key : "\(prefix).\(key)"
            if let s = value as? String {
                raw[fullKey] = s
            } else if let nested = value as? [String: Any] {
                flatten(nested, prefix: fullKey, into: &raw)
            } else if let n = value as? NSNumber {
                raw[fullKey] = n.stringValue
            }
        }
    }
}
