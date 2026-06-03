/**
 * Test support — Node helpers for the live integration test.
 *
 * Loads the WASM by reading the built `.wasm` bytes off disk (Node has no same-origin fetch for a
 * local path), and assembles config (shim base, pinned set, collateral) for the live round-trip.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import type { PinnedSet, QuoteCollateralV3 } from '../src/types.js';
import type { WasmInput } from '../src/wasm.js';

const here = dirname(fileURLToPath(import.meta.url));

/** The built WASM binary path (regenerate with build-wasm.sh). */
export const WASM_PATH = resolve(here, '../wasm/caladon_core_bg.wasm');

/** Read the .wasm bytes for the Node `init` path. */
export async function wasmBytes(): Promise<WasmInput> {
  const buf = await readFile(WASM_PATH);
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength) as unknown as WasmInput;
}

/** The committed offline collateral fixture (caladon-core/tests/fixtures/collateral.json). It is
 * FMSPC-keyed for the live caladon-gw hardware, so it verifies any session quote from that CVM
 * within its validity window (issue 2026-06-03 .. next_update 2026-07-03). */
export async function fixtureCollateral(): Promise<QuoteCollateralV3> {
  const p = resolve(here, '../../../caladon-core/tests/fixtures/collateral.json');
  return JSON.parse(await readFile(p, 'utf8')) as QuoteCollateralV3;
}

/**
 * The pinned measurement set for the live caladon-gw CVM (docs/security/measurements.md §2.1,
 * gateway-v1 row). The §4.3 aggregate is mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2 (lowercase hex). app_id is
 * per-deploy (advisory) — the test resolves the CURRENT app_id/compose_hash from the live evidence
 * and pins those so the round-trip is robust to redeploys (mr_td/rtmr0..2 are the stable identity).
 */
export const STABLE_MEASUREMENT_AGGREGATE =
  'f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077' +
  '68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96' +
  '07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c' +
  'a2a58c9a959a4fa44bd6da0c97a2270c051faf12084cfe91ae900e4fdff6cdd4f69a82005e04ee920f231497894d677f';

/** Build a pinned set; compose_hash + app_id default to the live values discovered at test time. */
export function pinnedSet(composeHash: string, appId: string): PinnedSet {
  return {
    measurements: [STABLE_MEASUREMENT_AGGREGATE],
    compose_hashes: [composeHash],
    workload_ids: [appId],
  };
}
