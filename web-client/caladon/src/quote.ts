/**
 * Minimal TDX quote field extraction — the §4.3 measurement aggregate the client PINS.
 *
 * The WASM exports `verify_quote_sync` (the full verdict) but NOT `measurement_of`, so to build /
 * compare a pinned-measurement set the host extracts the aggregate from the fixed TDX v4 quote
 * layout. This mirrors caladon-core `attestation::measurement_of` (mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2,
 * lowercase hex; rtmr3 EXCLUDED — it carries the per-instance app-id/compose event log).
 *
 * TDX v4 quote layout (offsets in bytes):
 *   header                              48
 *   TDReport10 (the "TD report body") starts at 48:
 *     tee_tcb_svn        16
 *     mr_seam            48
 *     mr_signer_seam     48
 *     seam_attributes     8
 *     td_attributes       8
 *     xfam                8     -> mr_td begins here (offset 48 + 136 = 184)
 *     mr_td              48
 *     mr_config_id       48
 *     mr_owner           48
 *     mr_owner_config    48     -> rt_mr0 begins here
 *     rt_mr0..rt_mr3   4×48
 *     report_data        64
 *
 * report_data (64 bytes) is written VERBATIM by dstack GetQuote and binds BOTH session keys:
 *   report_data[0:32]  = SHA-256(client_eph_pub)   — the channel "challenge" (reportDataChallenge)
 *   report_data[32:64] = SHA-256(cvm_session_pub)  — the gateway X25519 session pub (KEYSTONE binding)
 * (each hash is over the RAW 32-byte public key bytes). The client's verify_quote_sync checks both;
 * this module only extracts the measurement aggregate + the challenge half for pinning/diagnostics.
 */

import { toHex } from './bytes.js';

const HEADER = 48;
const MR_TD_OFF = HEADER + 16 + 48 + 48 + 8 + 8 + 8; // 184
const RTMR0_OFF = MR_TD_OFF + 48 + 48 + 48 + 48; // after mr_td + 3 mr_* = 376
const REG = 48;

export interface TdxMeasurements {
  mrTd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  /** lowercase-hex aggregate mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2 — the value to pin. */
  aggregate: string;
  /** the 32-byte challenge bound into report_data[0:32] = SHA-256(client_eph_pub), lowercase hex.
   *  (report_data[32:64] = SHA-256(cvm_session_pub) is verified in verify_quote_sync, not here.) */
  reportDataChallenge: string;
}

/** Extract the TDX measurements from a raw quote (must be a TD10/TD15 v4 quote, ≥ 568 bytes here). */
export function tdxMeasurements(quote: Uint8Array): TdxMeasurements {
  if (quote.length < RTMR0_OFF + 4 * REG + 64) {
    throw new Error('quote too short to be a TDX v4 quote');
  }
  const at = (off: number) => quote.subarray(off, off + REG);
  const mrTd = toHex(at(MR_TD_OFF));
  const rtmr0 = toHex(at(RTMR0_OFF));
  const rtmr1 = toHex(at(RTMR0_OFF + REG));
  const rtmr2 = toHex(at(RTMR0_OFF + 2 * REG));
  const rtmr3 = toHex(at(RTMR0_OFF + 3 * REG));
  const reportData = quote.subarray(RTMR0_OFF + 4 * REG, RTMR0_OFF + 4 * REG + 64);
  return {
    mrTd,
    rtmr0,
    rtmr1,
    rtmr2,
    rtmr3,
    aggregate: mrTd + rtmr0 + rtmr1 + rtmr2,
    reportDataChallenge: toHex(reportData.subarray(0, 32)),
  };
}
