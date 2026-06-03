import CryptoKit
import Foundation

/// Real `Transport` over URLSession. NOTE: `data(for:)` buffers the whole response, so SSE
/// arrives as one chunk that `parseSSEDeltas` then splits — fine for correctness; token-by-token
/// streaming (URLSession.bytes + incremental parse) is a UX enhancement for later.
public struct URLSessionTransport: Transport {
    let session: URLSession
    public init(session: URLSession = .shared) { self.session = session }

    public func send(method: String, url: URL, headers: [String: String], body: Data?) async throws
        -> (body: Data, status: Int)
    {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.httpBody = body
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let (data, resp) = try await session.data(for: req)
        return (data, (resp as? HTTPURLResponse)?.statusCode ?? 0)
    }
}

extension GatewayClient {
    /// Build a client from the seed root: the Ed25519 signing key + zero-PII account_id are
    /// derived from `root` (identity-envelope §3). `verifier` is the regime quote verifier
    /// (dcap-qvl-swift / tinfoil-swift); `pinned` is the measurement allow-list.
    public static func make(
        baseURL: URL,
        root: RootKey,
        verifier: QuoteVerifier,
        pinned: PinnedSet,
        transport: Transport = URLSessionTransport()
    ) throws -> GatewayClient {
        GatewayClient(
            baseURL: baseURL,
            accountID: try SeedIdentity.accountID(root),
            signingKey: try SeedIdentity.ed25519PrivateKey(root),
            attestation: Attestation(pinned: pinned, verifier: verifier),
            transport: transport
        )
    }
}
