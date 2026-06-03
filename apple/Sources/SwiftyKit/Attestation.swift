import Foundation

/// The attestation verifier KEYSTONE decision core (contracts/attestation.md §4,
/// contracts/attestation-evidence.md). Fail-closed: the client transmits nothing unless
/// `verify` returns `.ok`.
///
/// The regime-specific cryptographic quote check (TDX -> Intel DCAP via dcap-qvl-swift;
/// SEV-SNP+Sigstore via tinfoil-swift) is INJECTED via `QuoteVerifier`, so this decision
/// logic — channel binding, no-TOFU measurement/compose/workload pinning, no-log posture,
/// regime dispatch — is unit-testable now; the real adapters wire in later. All trusted
/// values come from the cryptographically-verified quote, never from untrusted evidence.
///
/// Scope: §4.1-§4.8 (the pre-send handshake). §4.9 per-response receipt (mid-session swap)
/// is a SEPARATE session-layer flow (RECEIPT_INVALID) — intentionally not here.

public enum Regime: String, Sendable {
    case tdxOnchain = "tdx-onchain"
    case sevSigstore = "sev-sigstore"
    case none  // T0 self-host (operator == user); no remote TEE to attest
}

/// A7 failure→code table (attestation-evidence.md §1). RECEIPT_INVALID is session-layer.
public enum VerdictReason: String, Sendable, Error {
    case ok
    case quoteSigInvalid = "QUOTE_SIG_INVALID"
    case tcbOutOfDate = "TCB_OUT_OF_DATE"
    case collateralStale = "COLLATERAL_STALE"
    case measurementUnpinned = "MEASUREMENT_UNPINNED"
    case composeMismatch = "COMPOSE_MISMATCH"
    case appIDMismatch = "APPID_MISMATCH"
    case bindingMismatch = "BINDING_MISMATCH"
    case noLogAbsent = "NO_LOG_ABSENT"
    case regimeUnsupported = "REGIME_UNSUPPORTED"
}

public struct Verdict: Equatable, Sendable {
    public let ok: Bool
    public let reason: VerdictReason
}

public struct Evidence: Sendable {
    public let regime: Regime
    public let raw: [String: String]  // opaque per-regime artifacts (quote, payloads, …)
    public init(regime: Regime, raw: [String: String]) {
        self.regime = regime
        self.raw = raw
    }
}

/// The trusted claims a verified quote yields (extracted ONLY after the signature/TCB chain
/// is validated to the vendor root). Every field here is trusted; nothing from `Evidence`.
public struct VerifiedQuote: Sendable {
    public let measurement: String   // mrtd/rtmr aggregate (TDX) or image digest (SEV)
    public let composeHash: String   // dstack compose hash (TDX) / config hash (SEV)
    public let workloadID: String    // app_id (TDX) / repo+digest (SEV)
    public let reportData: String    // the challenge bound into the quote
    public let noLog: Bool           // measured-config asserts no-logging (§4.7)
    public init(measurement: String, composeHash: String, workloadID: String,
                reportData: String, noLog: Bool) {
        self.measurement = measurement
        self.composeHash = composeHash
        self.workloadID = workloadID
        self.reportData = reportData
        self.noLog = noLog
    }
}

/// Regime-specific cryptographic verification. Returns the trusted claims on success, or a
/// SPECIFIC failure reason (so TCB-out-of-date / collateral-stale / sig-invalid surface as
/// distinct diagnostics per §8). Real impls: dcap-qvl-swift (TDX), tinfoil-swift (SEV).
public protocol QuoteVerifier: Sendable {
    func verify(regime: Regime, raw: [String: String]) -> Result<VerifiedQuote, VerdictReason>
}

/// The client-shipped pinned set (docs/security/measurements.md). NO TOFU / accept-new.
public struct PinnedSet: Sendable {
    public let measurements: Set<String>
    public let composeHashes: Set<String>
    public let workloadIDs: Set<String>
    public init(measurements: Set<String>, composeHashes: Set<String>, workloadIDs: Set<String>) {
        self.measurements = measurements
        self.composeHashes = composeHashes
        self.workloadIDs = workloadIDs
    }
}

public struct Attestation: Sendable {
    let pinned: PinnedSet
    let verifier: QuoteVerifier

    public init(pinned: PinnedSet, verifier: QuoteVerifier) {
        self.pinned = pinned
        self.verifier = verifier
    }

    /// Fail-closed verification (attestation.md §4 order). `expectedChallenge` is the
    /// client's `SHA-256(eph_pub)`. Every non-ok path returns ok=false with a distinct reason.
    public func verify(_ evidence: Evidence, expectedChallenge: String) -> Verdict {
        guard evidence.regime != .none else {
            return Verdict(ok: false, reason: .regimeUnsupported)
        }
        // §4.1-§4.2 quote sig -> vendor root + TCB (delegated; specific reason preserved).
        let quote: VerifiedQuote
        switch verifier.verify(regime: evidence.regime, raw: evidence.raw) {
        case .failure(let reason):
            return Verdict(ok: false, reason: reason)
        case .success(let q):
            quote = q
        }
        // §4.3 measurement pinned (no TOFU)
        guard pinned.measurements.contains(quote.measurement) else {
            return Verdict(ok: false, reason: .measurementUnpinned)
        }
        // §4.4 compose-hash pinned (registry cross-check is in the adapter)
        guard pinned.composeHashes.contains(quote.composeHash) else {
            return Verdict(ok: false, reason: .composeMismatch)
        }
        // §4.5 app id / workload pinned
        guard pinned.workloadIDs.contains(quote.workloadID) else {
            return Verdict(ok: false, reason: .appIDMismatch)
        }
        // §4.6 channel binding
        guard quote.reportData == expectedChallenge else {
            return Verdict(ok: false, reason: .bindingMismatch)
        }
        // §4.7 no-log posture
        guard quote.noLog else {
            return Verdict(ok: false, reason: .noLogAbsent)
        }
        return Verdict(ok: true, reason: .ok)
    }
}
