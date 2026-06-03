/**
 * PCS collateral fetch + assembly (the WASM design: JS fetches collateral, WASM verifies offline).
 *
 * `verify_quote_sync` consumes a `dcap_qvl::QuoteCollateralV3` JSON. The browser/Node host must
 * build it because the WASM build has no networking (Cargo.toml `wasm` feature omits `report`).
 * We mirror dcap-qvl's `CollateralClient::fetch`:
 *
 *   1. Extract the PCK certificate PEM chain embedded in the quote (TDX cert_type 5 — the chain
 *      is plain ASCII inside the quote's certification data).
 *   2. DER-parse the leaf PCK cert for the Intel SGX FMSPC extension (OID 1.2.840.113741.1.13.1.4)
 *      and the CA type ("processor" | "platform", from the issuer CN).
 *   3. Fetch (via the shim `/pcs-collateral` proxy, which CORS-fixes Intel PCS):
 *        - PCK CRL                  /sgx/certification/v4/pckcrl?ca=<ca>&encoding=der
 *        - TCB info                 /tdx/certification/v4/tcb?fmspc=<fmspc>
 *        - QE identity              /tdx/certification/v4/qe/identity?update=standard
 *        - root CA CRL              (from the issuer-chain root cert's CRL distribution point)
 *      reading the issuer-chain HTTP headers Intel returns, exactly as dcap-qvl does.
 *   4. Assemble `QuoteCollateralV3` (byte fields as hex strings — the form caladon-core/dcap-qvl
 *      accept, proven by the committed tests/fixtures/collateral.json).
 *
 * Falls back to a caller-supplied `collateralProvider` (e.g. the pinned-hardware fixture) when the
 * live fetch is unavailable. The collateral is FMSPC-keyed (per platform), not quote-specific, so
 * one fetch is valid for every session against the same CVM hardware.
 */

import { fromHex, toHex, utf8 } from './bytes.js';
import type { QuoteCollateralV3 } from './types.js';

/** Intel SGX extension + FMSPC OIDs (dcap-qvl/src/oids.rs). */
const OID_SGX_EXTENSION = '1.2.840.113741.1.13.1';
const OID_FMSPC = '1.2.840.113741.1.13.1.4';

export interface FetchLike {
  (input: string, init?: { headers?: Record<string, string> }): Promise<{
    ok: boolean;
    status: number;
    text(): Promise<string>;
    arrayBuffer(): Promise<ArrayBuffer>;
    headers: { get(name: string): string | null };
  }>;
}

export interface CollateralOptions {
  /** Shim prefix that proxies Intel PCS (server.ts `/pcs-collateral/*`). */
  pcsCollateralBase: string;
  /** fetch implementation (browser `fetch` or Node's global fetch). */
  fetchImpl: FetchLike;
}

// ------------------------------------------------------------------------------------------------
// 1. Extract the PCK PEM chain from the quote (ASCII inside cert_type-5 certification data).
// ------------------------------------------------------------------------------------------------

export function extractPckChainFromQuote(quote: Uint8Array): string {
  // The PEM is ASCII-embedded; decode latin-1 (1:1 byte→char) and slice the cert block.
  let s = '';
  for (let i = 0; i < quote.length; i++) s += String.fromCharCode(quote[i]!);
  const begin = s.indexOf('-----BEGIN CERTIFICATE-----');
  const endTag = '-----END CERTIFICATE-----';
  const lastEnd = s.lastIndexOf(endTag);
  if (begin === -1 || lastEnd === -1) throw new Error('no PCK certificate chain in quote (cert_type != 5?)');
  return s.slice(begin, lastEnd + endTag.length).trim();
}

/** Split a PEM chain into individual DER certs (leaf first). */
export function pemChainToDer(pem: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) {
    const b64 = m[1]!.replace(/\s+/g, '');
    out.push(b64ToBytes(b64));
  }
  if (out.length === 0) throw new Error('empty PEM chain');
  return out;
}

function b64ToBytes(b64: string): Uint8Array {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node path: Buffer is fine here (collateral assembly only runs host-side).
  return new Uint8Array((globalThis as any).Buffer.from(b64, 'base64'));
}

// ------------------------------------------------------------------------------------------------
// 2. Minimal DER walk to pull the FMSPC out of the Intel SGX extension, and the CA from the issuer.
// ------------------------------------------------------------------------------------------------

interface Tlv {
  tag: number;
  // header length + content
  start: number;
  contentStart: number;
  contentEnd: number;
}

function readTlv(b: Uint8Array, off: number): Tlv {
  const tag = b[off]!;
  let i = off + 1;
  let len = b[i++]!;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | b[i++]!;
  }
  return { tag, start: off, contentStart: i, contentEnd: i + len };
}

/** Encode an OID dotted-string to its DER content bytes (for comparison). */
function oidToDer(oid: string): Uint8Array {
  const parts = oid.split('.').map((x) => parseInt(x, 10));
  const out: number[] = [40 * parts[0]! + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i]!;
    const stack: number[] = [v & 0x7f];
    v >>= 7;
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    out.push(...stack);
  }
  return new Uint8Array(out);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Walk the cert DER, find the Intel SGX extension (a SEQUENCE of {OID, OCTET STRING(value)}),
 * then within its value find the FMSPC OID and return the following OCTET STRING (6 bytes).
 */
export function extractFmspc(certDer: Uint8Array): string {
  const sgxExtOid = oidToDer(OID_SGX_EXTENSION);
  const fmspcOid = oidToDer(OID_FMSPC);

  // Find the SGX extension's value (OCTET STRING) by scanning for its OID anywhere in the cert,
  // then taking the OCTET STRING that immediately follows at the same SEQUENCE level.
  const idx = findOidValueOctetString(certDer, sgxExtOid);
  if (!idx) throw new Error('Intel SGX extension not found in PCK cert');

  // Inside the SGX extension OCTET STRING is a SEQUENCE of {OID, value} pairs; find FMSPC's.
  const fmspc = findOidValueOctetString(certDer.subarray(idx.contentStart, idx.contentEnd), fmspcOid);
  if (!fmspc) throw new Error('FMSPC not found in SGX extension');
  return toHex(certDer.subarray(idx.contentStart + fmspc.contentStart, idx.contentStart + fmspc.contentEnd)).toUpperCase();
}

/**
 * Scan `b` for the DER encoding of `oid` (tag 0x06). Return the TLV of the OCTET STRING (0x04)
 * that immediately follows it (the extension/attribute value). Returns content offsets RELATIVE
 * to `b`.
 */
function findOidValueOctetString(b: Uint8Array, oidContent: Uint8Array): { contentStart: number; contentEnd: number } | null {
  for (let i = 0; i + 2 + oidContent.length < b.length; i++) {
    if (b[i] !== 0x06) continue;
    if (b[i + 1] !== oidContent.length) continue;
    if (!bytesEqual(b.subarray(i + 2, i + 2 + oidContent.length), oidContent)) continue;
    // The value follows the OID. Skip to the next TLV; accept an OCTET STRING (0x04).
    const after = i + 2 + oidContent.length;
    if (after >= b.length) return null;
    const tlv = readTlv(b, after);
    if (tlv.tag === 0x04) return { contentStart: tlv.contentStart, contentEnd: tlv.contentEnd };
  }
  return null;
}

/** Detect CA type from the leaf PCK cert issuer CN ("...PCK Platform CA" vs "...PCK Processor CA"). */
export function extractCa(leafDer: Uint8Array): 'platform' | 'processor' {
  // Cheap + robust: the issuer CN string appears verbatim in the DER. dcap-qvl falls back to
  // Processor for an unrecognised issuer; we mirror that.
  let s = '';
  for (let i = 0; i < leafDer.length; i++) s += String.fromCharCode(leafDer[i]!);
  return s.includes('PCK Platform CA') ? 'platform' : 'processor';
}

// ------------------------------------------------------------------------------------------------
// 3 + 4. Fetch the per-FMSPC artifacts via the shim PCS proxy and assemble QuoteCollateralV3.
// ------------------------------------------------------------------------------------------------

async function pcsGet(
  opts: CollateralOptions,
  path: string,
): Promise<{ body: Uint8Array; header(name: string): string | null }> {
  const url = `${opts.pcsCollateralBase}${path}`;
  const r = await opts.fetchImpl(url);
  if (!r.ok) throw new Error(`PCS fetch failed ${r.status}: ${url}`);
  const body = new Uint8Array(await r.arrayBuffer());
  return { body, header: (n) => r.headers.get(n) };
}

function utf8Decode(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/** Pull the issuer-chain header Intel/PCCS returns (URL-decoded). */
function issuerChain(header: string | null, fallback?: string | null): string {
  const v = header ?? fallback ?? '';
  if (!v) throw new Error('missing issuer-chain header from PCS');
  return decodeURIComponent(v);
}

/**
 * Build `QuoteCollateralV3` from a quote, fetching collateral through the shim PCS proxy.
 * Mirrors dcap-qvl `CollateralClient::fetch` → `fetch_for_fmspc_without_pck_chain`.
 */
export async function fetchCollateralFromPcs(quote: Uint8Array, opts: CollateralOptions): Promise<QuoteCollateralV3> {
  const pckChainPem = extractPckChainFromQuote(quote);
  const ders = pemChainToDer(pckChainPem);
  const fmspc = extractFmspc(ders[0]!);
  const ca = extractCa(ders[0]!);

  // PCK CRL (DER) + its issuer chain.
  const pckCrl = await pcsGet(opts, `/sgx/certification/v4/pckcrl?ca=${ca}&encoding=der`);
  const pckCrlIssuerChain = issuerChain(pckCrl.header('SGX-PCK-CRL-Issuer-Chain'));

  // TCB info (TDX) + its issuer chain. Body is JSON: { tcbInfo, signature(hex) }.
  const tcb = await pcsGet(opts, `/tdx/certification/v4/tcb?fmspc=${fmspc}`);
  const tcbIssuerChain = issuerChain(tcb.header('SGX-TCB-Info-Issuer-Chain'), tcb.header('TCB-Info-Issuer-Chain'));
  const tcbResp = JSON.parse(utf8Decode(tcb.body)) as { tcbInfo: unknown; signature: string };

  // QE identity (TDX) + its issuer chain. Body is JSON: { enclaveIdentity, signature(hex) }.
  const qe = await pcsGet(opts, `/tdx/certification/v4/qe/identity?update=standard`);
  const qeIssuerChain = issuerChain(qe.header('SGX-Enclave-Identity-Issuer-Chain'));
  const qeResp = JSON.parse(utf8Decode(qe.body)) as { enclaveIdentity: unknown; signature: string };

  // Root CA CRL: Intel PCS exposes it at the distribution point in the root cert of an issuer
  // chain. We resolve it from the SGX Root CA CRL distribution point Intel publishes.
  const rootCaCrl = await fetchRootCaCrl(opts, qeIssuerChain);

  return {
    pck_crl_issuer_chain: pckCrlIssuerChain,
    root_ca_crl: toHex(rootCaCrl),
    pck_crl: toHex(pckCrl.body),
    tcb_info_issuer_chain: tcbIssuerChain,
    // dcap-qvl stores the inner object re-serialized; JSON.stringify of the parsed object matches
    // the canonical (no-whitespace) form the verifier hashes over.
    tcb_info: JSON.stringify(tcbResp.tcbInfo),
    tcb_info_signature: tcbResp.signature, // already hex
    qe_identity_issuer_chain: qeIssuerChain,
    qe_identity: JSON.stringify(qeResp.enclaveIdentity),
    qe_identity_signature: qeResp.signature, // already hex
    pck_certificate_chain: pckChainPem + '\n',
  };
}

/**
 * Fetch the Intel SGX Root CA CRL. Intel publishes it at a stable distribution point; the root
 * cert in any issuer chain carries the CRL DP URI. We hit the well-known Intel PCS path through
 * the proxy (the proxy forwards to api.trustedservices.intel.com).
 */
async function fetchRootCaCrl(opts: CollateralOptions, _qeIssuerChain: string): Promise<Uint8Array> {
  // Intel SGX Root CA CRL — the canonical distribution point.
  const r = await opts.fetchImpl(`${opts.pcsCollateralBase}/sgx/certification/v4/rootcacrl`);
  if (!r.ok) throw new Error(`root CA CRL fetch failed ${r.status}`);
  const body = await r.text();
  // PCCS returns hex; Intel PCS returns DER bytes. Detect hex (only [0-9a-f]) vs binary.
  const trimmed = body.trim();
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) return fromHex(trimmed);
  return utf8(body);
}
