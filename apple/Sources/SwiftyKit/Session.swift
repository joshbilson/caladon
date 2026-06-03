import CaladonCoreFFI
import CryptoKit
import Foundation

/// Confidential session channel — WMK delivery into the CVM (identity-envelope.md §6).
/// Now a thin wrapper over the shared `caladon-core` Rust trust core (`CaladonCoreFFI`):
/// X25519 ECDH + HKDF-SHA256 session-key derivation and the XChaCha20-Poly1305 sealed
/// envelopes (WMK delivery + live "chat" turns) all run in Rust, byte-identical to
/// `swifty_crypto.session` and the prior CryptoKit/libsodium implementation, so the client
/// and CVM derive the SAME session key and the WMK opens in TEE RAM. The KDF info binds BOTH
/// endpoints' public keys (anti-UKS/MITM) inside the core.
public enum Session {
    public static let label = Data("swifty/session/v1".utf8)
    public static let wmkDeliveryPurpose = "wmk-delivery"
    static let keyLength = 32
    static let nonceLength = 24  // XChaCha20-Poly1305 nonce; the FFI seal returns `nonce ‖ ct`

    public static let chatPurpose = "chat"  // live-turn prompt/response envelopes sealed to SK

    public enum SessionError: Error { case badPublicKeyLength, lowOrderPoint }

    /// Fresh ephemeral X25519 keypair: (privateBytes[32], publicBytes[32]). The client's
    /// ephemeral pub doubles as the attestation challenge (SHA-256(pub)) and the ECDH input.
    /// Stays platform-native (CryptoKit CSPRNG) — only the resulting bytes flow into the core.
    public static func x25519Keypair() -> (privateBytes: Data, publicBytes: Data) {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        return (priv.rawRepresentation, priv.publicKey.rawRepresentation)
    }

    /// X25519 public key (32 bytes) for an ephemeral private scalar.
    public static func x25519Public(privateBytes: Data) throws -> Data {
        do {
            return try CaladonCoreFFI.x25519Public(privateBytes: privateBytes)
        } catch let e as CaladonCoreFFI.SealError {
            throw map(e)
        }
    }

    /// SK = HKDF(X25519(myPrivate, theirPublic), info = label ‖ clientPub ‖ cvmPub).
    /// Both sides pass the SAME clientPub/cvmPub and their own private + the peer's public.
    /// Fails closed on a bad public-key length or a low-order/identity peer point (the core
    /// rejects the all-zero shared secret, matching Python's `cryptography`).
    public static func deriveSessionKey(
        myPrivate: Data, theirPublic: Data, clientPub: Data, cvmPub: Data
    ) throws -> Data {
        do {
            return try CaladonCoreFFI.deriveSessionKey(
                myPrivate: myPrivate, theirPublic: theirPublic, clientPub: clientPub, cvmPub: cvmPub
            )
        } catch let e as CaladonCoreFFI.SealError {
            throw map(e)
        }
    }

    /// Client seals WMK to the session key for delivery (§6). Returns (nonce, ct); the aad
    /// binds account_id ‖ purpose ‖ v inside the core, exactly as `swifty_crypto.seal_wmk`.
    public static func sealWMK(sessionKey: Data, wmk: Data, accountID: String, v: Int = 1) throws
        -> (nonce: [UInt8], ct: [UInt8])
    {
        do {
            let nonceCt = try CaladonCoreFFI.sealWmk(
                sessionKey: sessionKey, wmk: wmk, accountId: accountID, v: Int64(v)
            )
            return splitNonceCt(nonceCt)
        } catch let e as CaladonCoreFFI.SealError {
            throw map(e)
        }
    }

    /// CVM-side open of the sealed WMK; fails closed on any tamper / wrong session. `v` MUST
    /// be the version carried by the RECEIVED envelope (no default — the aad binds `v`, so a
    /// wrong `v` silently fails the open; the caller must source it from the wire envelope,
    /// exactly as Python's `open_wmk` reads `envelope["v"]`).
    public static func openWMK(
        sessionKey: Data, nonce: [UInt8], ct: [UInt8], accountID: String, v: Int
    ) throws -> Data {
        do {
            return try CaladonCoreFFI.openWmk(
                sessionKey: sessionKey, nonceCt: joinNonceCt(nonce, ct), accountId: accountID, v: Int64(v)
            )
        } catch let e as CaladonCoreFFI.SealError {
            throw map(e)
        }
    }

    /// Seal a live-turn payload (prompt or delta) to SK (purpose "chat"). Returns (nonce, ct).
    public static func sealChat(sessionKey: Data, plaintext: Data, accountID: String, v: Int = 1) throws
        -> (nonce: [UInt8], ct: [UInt8])
    {
        do {
            let nonceCt = try CaladonCoreFFI.sealChat(
                sessionKey: sessionKey, plaintext: plaintext, accountId: accountID, v: Int64(v)
            )
            return splitNonceCt(nonceCt)
        } catch let e as CaladonCoreFFI.SealError {
            throw map(e)
        }
    }

    /// Open a sealed live-turn payload (a response delta) under SK. Fails closed on tamper.
    public static func openChat(sessionKey: Data, nonce: [UInt8], ct: [UInt8], accountID: String, v: Int) throws -> Data {
        do {
            return try CaladonCoreFFI.openChat(
                sessionKey: sessionKey, nonceCt: joinNonceCt(nonce, ct), accountId: accountID, v: Int64(v)
            )
        } catch let e as CaladonCoreFFI.SealError {
            throw map(e)
        }
    }

    // MARK: - FFI framing + error mapping

    /// The core returns/consumes `nonce ‖ ct`; SwiftyKit's public surface keeps the (nonce, ct)
    /// tuple (the gateway wire envelope carries the nonce separately).
    private static func splitNonceCt(_ nonceCt: Data) -> (nonce: [UInt8], ct: [UInt8]) {
        (nonce: [UInt8](nonceCt.prefix(nonceLength)), ct: [UInt8](nonceCt.dropFirst(nonceLength)))
    }

    private static func joinNonceCt(_ nonce: [UInt8], _ ct: [UInt8]) -> Data {
        Data(nonce) + Data(ct)
    }

    private static func map(_ e: CaladonCoreFFI.SealError) -> SessionError {
        switch e {
        case .LowOrderPoint: return .lowOrderPoint
        // BadKey / BadNonce / OpenFailed / SealFailed all surface here as a fail-closed
        // key/length rejection (the only non-low-order path the public API can hit pre-open
        // is a bad public-key length).
        default: return .badPublicKeyLength
        }
    }
}
