import CryptoKit
import Foundation

/// Client side of the gateway's seed-signature auth (contracts/gateway-api.md §1).
///
/// The Ed25519 signing key is derived from the user's seed; the canonical string and the
/// `Authorization: Swifty acct=.. ts=.. sig=..` format MUST byte-match the server
/// (`gateway/app/seed_auth.py`) or the gateway will 401. Tests assert that interop.
public enum SeedAuthError: Error {
    case invalidAccountID
}

public enum SeedAuth {

    /// account_id format the gateway accepts (gateway/app/ids.py): url-safe, 16-128 chars.
    static func isValidAccountID(_ id: String) -> Bool {
        id.range(of: "^[A-Za-z0-9_-]{16,128}$", options: .regularExpression) != nil
    }

    /// The exact bytes the client signs and the gateway verifies. Newline-delimited;
    /// method upper-cased; `path` is the raw URI path (no query string).
    public static func canonical(accountId: String, ts: Int, method: String, path: String) -> Data {
        Data("\(accountId)\n\(ts)\n\(method.uppercased())\n\(path)".utf8)
    }

    /// Build the `Authorization` header value for a request.
    public static func authorizationHeader(
        privateKey: Curve25519.Signing.PrivateKey,
        accountId: String,
        ts: Int,
        method: String,
        path: String
    ) throws -> String {
        guard isValidAccountID(accountId) else { throw SeedAuthError.invalidAccountID }
        let signature = try privateKey.signature(
            for: canonical(accountId: accountId, ts: ts, method: method, path: path)
        )
        return "Swifty acct=\(accountId) ts=\(ts) sig=\(signature.base64EncodedString())"
    }
}
