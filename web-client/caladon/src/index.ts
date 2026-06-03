/**
 * @caladon/protocol — the web client's protocol SDK.
 *
 * Public surface: the CaladonClient (full fail-closed flow), the WASM loader, the wire types,
 * the byte/envelope helpers, and the collateral fetcher. See README.md.
 */

export { CaladonClient, CaladonError, AttestationFailedError } from './client.js';
export type { CaladonClientConfig, HandshakeResult, ChatResult } from './client.js';

export { loadCaladonWasm, __resetWasmForTests } from './wasm.js';
export type { CaladonWasm, WasmInput } from './wasm.js';

export {
  fetchCollateralFromPcs,
  extractPckChainFromQuote,
  extractFmspc,
  extractCa,
  pemChainToDer,
} from './collateral.js';
export type { CollateralOptions, FetchLike } from './collateral.js';

export { tdxMeasurements } from './quote.js';
export type { TdxMeasurements } from './quote.js';

export {
  deriveWrappingKey,
  wrapSeed,
  unwrapSeed,
  BrowserPasskeyCustody,
  DEFAULT_PRF_SALT,
} from './passkey.js';
export type {
  PasskeyCustody,
  PasskeyResult,
  PasskeyRegisterOptions,
  PasskeyGetOptions,
  CredentialsContainerLike,
} from './passkey.js';

export { toWireEnvelope, fromWireEnvelope, aad, sha256, randomBytes } from './envelope.js';
export * from './bytes.js';
export * from './constants.js';
export type {
  Envelope,
  OnboardBody,
  AttestationEvidence,
  SessionBody,
  ChatBody,
  QuoteCollateralV3,
  PinnedSet,
  Verdict,
  ChatDelta,
  Identity,
} from './types.js';
