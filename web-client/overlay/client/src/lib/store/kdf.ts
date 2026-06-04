/**
 * Caladon device store — key derivation (Batch 1 client foundation).
 *
 * The store's SQLCipher key is `device_store_key(root)` from caladon-core (Rust), exposed through
 * the WASM module. It is `HKDF(root, "caladon/device-store/v1", 32)` — the SINGLE source of truth
 * (the native client calls the same UniFFI export) so the key is byte-identical and never
 * re-implemented in JS/Swift. We DO NOT reimplement HKDF here; we only hex-encode the 32 raw bytes
 * the wasm returns for `PRAGMA key`.
 *
 * The wasm handle is obtained the same way the SDK does — via `loadCaladonWasm` from
 * `@caladon/protocol` (idempotent; reuses the already-initialised module). `device_store_key` is a
 * real export of the built `caladon_core` wasm (see web-client/caladon/wasm/caladon_core.d.ts) but
 * is not yet listed on the SDK's narrowed `CaladonWasm` interface, so we widen it locally rather
 * than touch the SDK.
 */

import { loadCaladonWasm } from '@caladon/protocol';
import type { CaladonWasm } from '@caladon/protocol';

/** The caladon-core export this module needs, widened over the SDK's narrowed `CaladonWasm`. */
export interface DeviceStoreWasm {
  /** `HKDF(root, "caladon/device-store/v1", 32)` -> 32 raw bytes. NEVER leaves the device. */
  device_store_key(root: Uint8Array): Uint8Array;
}

/** A wasm handle usable for store-key derivation: the SDK surface plus `device_store_key`. */
export type StoreKeyWasm = CaladonWasm & DeviceStoreWasm;

/** Lowercase-hex of raw bytes (no Buffer dependency; isomorphic). */
function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

/**
 * Derive the store key from an explicit, already-initialised wasm handle and return it as the
 * lowercase-hex string used for `PRAGMA key`. Use this inside the worker (where the wasm has been
 * initialised with the same `?url` input as the SDK) to avoid re-loading the module.
 *
 * The returned hex (and the raw bytes) are sensitive: the caller must hand them straight to
 * `PRAGMA key` and drop the reference. Never log it; never postMessage it out of the worker.
 */
export function deriveStoreKeyHexFrom(wasm: StoreKeyWasm, root: Uint8Array): string {
  const raw = wasm.device_store_key(root);
  const hex = toHex(raw);
  // Best-effort zero of the raw key bytes; the hex copy lives until the caller drops it.
  raw.fill(0);
  return hex;
}

/**
 * Derive the store key as lowercase-hex, loading (idempotently) the caladon-core wasm the same way
 * the SDK does. `wasmInput` mirrors the SDK's `?url` import (pass it so the module resolves to the
 * built binary same-origin); when omitted, the already-initialised singleton is reused.
 */
export async function deriveStoreKeyHex(
  root: Uint8Array,
  wasmInput?: string | URL,
): Promise<string> {
  const wasm = (await loadCaladonWasm(wasmInput)) as StoreKeyWasm;
  return deriveStoreKeyHexFrom(wasm, root);
}
