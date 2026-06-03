import DcapQvl
import Foundation

/// Real DCAP (TDX/SGX) quote verification via dcap-qvl (Phala's Rust lib, UniFFI binding,
/// prebuilt xcframework). This is the attestation keystone's quote crypto (attestation.md §4):
/// it parses a raw quote and verifies it against Intel PCS collateral to the vendor root —
/// the same library proven against a real TDX quote (Python CLI).
///
/// `verify` needs PCS collateral (network), so it is async-by-caller (the collateral JSON is
/// fetched and passed in). `parse` is offline. Wiring this into the GatewayClient's
/// (currently synchronous) attestation handshake — making that path async + fetching
/// collateral keyed on the quote's FMSPC — is the next increment.
public enum DcapVerifier {
    /// Parse a raw quote into its typed structure (offline; no network). Throws on a malformed
    /// quote.
    public static func parse(rawQuote: Data) throws -> Quote {
        try parseQuote(rawQuote: rawQuote)
    }

    /// Verify a raw quote against PCS `collateralJson` as of `nowSecs`. Returns the verified
    /// report (TCB status + measurements + report_data). Throws on any verification failure
    /// (fail-closed). Prefer `verifyPinningRoot` in production to pin the Intel root CA.
    public static func verify(rawQuote: Data, collateralJson: Data, nowSecs: UInt64) throws -> VerifiedReport {
        try DcapQvl.verify(rawQuote: rawQuote, collateralJson: collateralJson, nowSecs: nowSecs)
    }

    /// Verify pinning an explicit Intel root CA (DER) — stronger than trusting the collateral's
    /// chain alone; use a vendor-rooted pin in production.
    public static func verifyPinningRoot(rawQuote: Data, collateralJson: Data, rootCaDer: Data, nowSecs: UInt64) throws -> VerifiedReport {
        try DcapQvl.verifyWithRootCa(rawQuote: rawQuote, collateralJson: collateralJson, rootCaDer: rootCaDer, nowSecs: nowSecs)
    }

    /// The 64-byte `report_data` (the channel binding the client checks) from a parsed quote,
    /// across TDX (TD10/TD15) and SGX reports.
    public static func reportData(of quote: Quote) -> Data {
        let rd: Data
        switch quote.report {
        case .td10(let r): rd = r.reportData
        case .td15(let r): rd = r.base.reportData  // TD15 embeds the TD10 report
        case .sgx(let r): rd = r.reportData
        }
        // report_data is always 64 bytes; a mismatch means an upstream dcap-qvl binding drift
        // (the parse test also pins this in CI).
        assert(rd.count == 64, "report_data must be 64 bytes; check the dcap-qvl binding")
        return rd
    }
}
