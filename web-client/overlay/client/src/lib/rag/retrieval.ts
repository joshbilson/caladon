/**
 * Caladon RAG — on-device retrieval + the embed-worker client (Batch 1 client foundation).
 *
 * This module owns two things, both ENTIRELY on-device:
 *
 *  1. The embed-worker client (`embedTexts`): a singleton wrapper over `worker/embed.worker.ts` that
 *     turns text into MiniLM vectors without ever touching the network (the model is served
 *     same-origin from /models/). Both the ingest path (useRag) and the query path (here) use it.
 *
 *  2. The in-memory cosine index (`RagIndex`): rebuilt from `StoreProxy.hydrateVectors()` (the
 *     persisted, SQLCipher-encrypted Float32 BLOBs). Vectors are L2-normalized at embed time, so
 *     cosine similarity is a plain dot product. No sqlite-vec; the ranking is a tight JS loop over
 *     a packed Float32 matrix.
 *
 * The trust-critical export is `augmentPromptWithRAG(promptText)`: it embeds the user's query
 * on-device, ranks the index, and — only if there are real hits — PREPENDS a `<context>…</context>`
 * block to the prompt. The Integrate step calls this BEFORE `CaladonClient.sealChat`, so the gateway
 * only ever sees the sealed envelope: the retrieved document text is injected inside the trust
 * boundary and sealed with everything else. If embedding/ranking fails, we fail OPEN to the original
 * prompt (RAG is an enhancement, never a gate) — but we NEVER fall back to a remote service.
 */

import { getStoreProxy } from '~/lib/store';
import type { StoredVector } from '~/lib/store';
import type {
  EmbedWorkerRequest,
  EmbedWorkerResponse,
  EmbedBackend,
} from '~/lib/store/worker/embed.worker';

/* ------------------------------------------------------------------ *
 * Embed-worker client (singleton)
 * ------------------------------------------------------------------ */

interface PendingEmbed {
  resolve: (vectors: Float32Array[]) => void;
  reject: (err: Error) => void;
}

let embedWorker: Worker | null = null;
const embedPending = new Map<string, PendingEmbed>();
let lastBackend: EmbedBackend | null = null;
let embedCounter = 0;

function nextEmbedId(): string {
  embedCounter = (embedCounter + 1) % Number.MAX_SAFE_INTEGER;
  return `e${embedCounter}_${Date.now().toString(36)}`;
}

function ensureEmbedWorker(): Worker {
  if (embedWorker) return embedWorker;
  // Relative (not the ~/ alias) inside new URL() so worker resolution never depends on the bundler's
  // alias handling — matches client.ts and is Rollup/Vite-resolver-independent.
  const worker = new Worker(new URL('../store/worker/embed.worker.ts', import.meta.url), {
    type: 'module',
  });
  worker.onmessage = (ev: MessageEvent<EmbedWorkerResponse>) => {
    const res = ev.data;
    if (res.type === 'WARMED') {
      lastBackend = res.backend;
      const p = embedPending.get(res.requestId);
      if (p) {
        embedPending.delete(res.requestId);
        p.resolve([]);
      }
      return;
    }
    const p = embedPending.get(res.requestId);
    if (!p) return;
    embedPending.delete(res.requestId);
    if (res.type === 'ERROR') {
      p.reject(new Error(res.message));
    } else {
      lastBackend = res.backend;
      p.resolve(res.vectors);
    }
  };
  worker.onerror = (ev: ErrorEvent) => {
    const err = new Error(`embed worker error: ${ev.message}`);
    for (const [, p] of embedPending) p.reject(err);
    embedPending.clear();
  };
  embedWorker = worker;
  return worker;
}

function postEmbed(req: EmbedWorkerRequest): Promise<Float32Array[]> {
  const worker = ensureEmbedWorker();
  return new Promise<Float32Array[]>((resolve, reject) => {
    embedPending.set(req.requestId, { resolve, reject });
    worker.postMessage(req);
  });
}

/**
 * Embed a batch of texts on-device. Returns one 384-dim, L2-normalized Float32Array per input, in
 * order. Used by both ingest (chunks) and retrieval (the query). NEVER hits the network.
 */
export async function embedTexts(texts: string[]): Promise<Float32Array[]> {
  if (texts.length === 0) return [];
  return postEmbed({ type: 'EMBED', requestId: nextEmbedId(), texts });
}

/** Pre-load the model so the first real embed isn't paying the cold-start cost. Best-effort. */
export async function warmupEmbedder(): Promise<void> {
  try {
    await postEmbed({ type: 'WARMUP', requestId: nextEmbedId() });
  } catch (e) {
    console.warn('[rag] embedder warmup failed (will retry lazily):', e);
  }
}

/** The backend the embed worker actually ran on, once known ('webgpu' | 'wasm' | null). */
export function embedBackend(): EmbedBackend | null {
  return lastBackend;
}

/* ------------------------------------------------------------------ *
 * In-memory cosine index
 * ------------------------------------------------------------------ */

/** One indexed chunk: its provenance + a view into the packed matrix. */
interface IndexEntry {
  messageId: string;
  ord: number;
  text: string;
}

/** A single retrieval result: the chunk text, its provenance, and the cosine score. */
export interface RagHit {
  messageId: string;
  ord: number;
  text: string;
  /** Cosine similarity in [-1, 1]; higher is more relevant. */
  score: number;
}

/**
 * A flat, packed cosine index. Vectors are stored contiguously in one Float32Array (`matrix`) of
 * `count * dim` so ranking is a single cache-friendly pass. All vectors are assumed L2-normalized
 * (the embed worker normalizes), so cosine === dot product.
 */
export class RagIndex {
  private entries: IndexEntry[] = [];
  private matrix = new Float32Array(0);
  private dim = 0;

  get size(): number {
    return this.entries.length;
  }

  get dimension(): number {
    return this.dim;
  }

  /** Replace the entire index from persisted vectors (HYDRATE_VECTORS output). */
  load(vectors: StoredVector[]): void {
    const usable = vectors.filter((v) => v.vec && v.vec.length > 0);
    this.dim = usable.length ? usable[0]!.vec.length : 0;
    this.entries = [];
    this.matrix = new Float32Array(usable.length * this.dim);
    let row = 0;
    for (const v of usable) {
      // Skip dimension mismatches defensively (e.g. a stale model change) rather than corrupt the matrix.
      if (v.vec.length !== this.dim) continue;
      this.matrix.set(v.vec, row * this.dim);
      this.entries.push({ messageId: v.messageId, ord: v.ord, text: v.text });
      row++;
    }
    // If any rows were skipped, trim the matrix to the rows we actually kept.
    if (row !== usable.length) {
      this.matrix = this.matrix.slice(0, row * this.dim);
    }
  }

  /** True once at least one vector is indexed (so callers can skip the embed/rank work when empty). */
  get isReady(): boolean {
    return this.entries.length > 0 && this.dim > 0;
  }

  /**
   * Rank the index against a normalized query vector. Returns the top `k` hits above `minScore`,
   * best first. `query` must be the same dimension as the index and L2-normalized.
   */
  search(query: Float32Array, k: number, minScore: number): RagHit[] {
    if (!this.isReady || query.length !== this.dim) return [];

    const n = this.entries.length;
    const dim = this.dim;
    const scored: RagHit[] = [];
    for (let i = 0; i < n; i++) {
      const base = i * dim;
      let dot = 0;
      for (let d = 0; d < dim; d++) dot += this.matrix[base + d]! * query[d]!;
      if (dot >= minScore) {
        const e = this.entries[i]!;
        scored.push({ messageId: e.messageId, ord: e.ord, text: e.text, score: dot });
      }
    }
    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, k);
  }
}

/* ------------------------------------------------------------------ *
 * Index lifecycle (hydrate from the encrypted store)
 * ------------------------------------------------------------------ */

let sharedIndex: RagIndex | null = null;
let hydratePromise: Promise<RagIndex> | null = null;

/** The shared in-memory RAG index singleton. */
export function getRagIndex(): RagIndex {
  if (!sharedIndex) sharedIndex = new RagIndex();
  return sharedIndex;
}

/**
 * (Re)build the in-memory index from the encrypted store's persisted vectors. Coalesces concurrent
 * callers onto one hydrate; pass `force` to bust the cache after an ingest added new vectors.
 */
export async function hydrateRagIndex(force = false): Promise<RagIndex> {
  const index = getRagIndex();

  // FAIL-OPEN GUARD (critical): StoreProxy.hydrateVectors() awaits the proxy's internal `ready`,
  // which only settles after openStore(). If the store has NOT been opened yet — or its open is
  // still in flight (slow/hung OPFS init) — that await never resolves, so an `await hydrateRagIndex()`
  // on the send hot path (augmentPromptWithRAG → here) would BLOCK the send forever. Returning the
  // (empty) index immediately when the store isn't open keeps RAG a pure enhancement: the prompt is
  // sent un-augmented rather than blocked. A later call (post-open, with `force`) rebuilds the index.
  if (!getStoreProxy().isOpen) {
    if (!hydratePromise) index.load([]);
    return index;
  }

  if (hydratePromise && !force) return hydratePromise;

  hydratePromise = (async () => {
    try {
      const vectors = await getStoreProxy().hydrateVectors();
      index.load(vectors);
    } catch (e) {
      console.warn('[rag] index hydrate failed (retrieval will be skipped):', e);
      index.load([]);
    }
    return index;
  })();

  // Allow the next `force` (or a retry after failure) to re-hydrate.
  hydratePromise.finally(() => {
    if (force) hydratePromise = null;
  });

  return hydratePromise;
}

/** Drop the in-memory index (logout / clear). The persisted vectors are handled by StoreProxy. */
export function resetRagIndex(): void {
  sharedIndex = new RagIndex();
  hydratePromise = null;
}

/* ------------------------------------------------------------------ *
 * Prompt augmentation (the trust-critical entry point)
 * ------------------------------------------------------------------ */

/** Default retrieval knobs. Tuned for a small on-device index: a few high-confidence chunks. */
const DEFAULT_TOP_K = 4;
/** Minimum cosine similarity for a chunk to be considered relevant (filters weak/irrelevant hits). */
const DEFAULT_MIN_SCORE = 0.35;
/** Cap the injected context so a huge retrieval can't blow the model's prompt budget. */
const MAX_CONTEXT_CHARS = 6000;

export interface RagAugmentOptions {
  topK?: number;
  minScore?: number;
  maxContextChars?: number;
}

/**
 * The Integrate-step hook: embed `promptText` on-device, rank the in-memory index, and — only when
 * there are relevant hits — PREPEND a `<context>…</context>` block so the model can ground its
 * answer in the retrieved chunks. Returns the augmented prompt; returns the ORIGINAL prompt
 * unchanged when there are no hits or anything fails (fail-open enhancement).
 *
 * MUST be called BEFORE `sealChat`: the returned text is sealed with the rest of the prompt, so the
 * retrieved document content never leaves the device in the clear.
 */
export async function augmentPromptWithRAG(
  promptText: string,
  options: RagAugmentOptions = {},
): Promise<string> {
  const query = promptText?.trim();
  if (!query) return promptText;

  try {
    const index = await hydrateRagIndex();
    if (!index.isReady) return promptText;

    const [queryVec] = await embedTexts([query]);
    if (!queryVec || queryVec.length !== index.dimension) return promptText;

    const hits = index.search(
      queryVec,
      options.topK ?? DEFAULT_TOP_K,
      options.minScore ?? DEFAULT_MIN_SCORE,
    );
    if (hits.length === 0) return promptText;

    const contextBlock = buildContextBlock(hits, options.maxContextChars ?? MAX_CONTEXT_CHARS);
    if (!contextBlock) return promptText;

    return `${contextBlock}\n\n${promptText}`;
  } catch (e) {
    // RAG is an enhancement, never a gate. On any failure, send the prompt as-is — but only ever
    // on-device: there is no remote fallback path here.
    console.warn('[rag] augmentation skipped:', e);
    return promptText;
  }
}

/** Build the `<context>…</context>` block from ranked hits, de-duped and length-capped. */
function buildContextBlock(hits: RagHit[], maxChars: number): string {
  const seen = new Set<string>();
  const parts: string[] = [];
  let total = 0;

  for (const hit of hits) {
    const text = hit.text.trim();
    if (!text) continue;
    const key = text.slice(0, 200);
    if (seen.has(key)) continue;
    seen.add(key);

    const piece = `<chunk source="msg:${escapeAttr(hit.messageId)}#${hit.ord}">\n${text}\n</chunk>`;
    if (total + piece.length > maxChars) {
      // Include a final truncated chunk if there's meaningful room left; otherwise stop.
      const room = maxChars - total;
      if (room > 400) {
        parts.push(
          `<chunk source="msg:${escapeAttr(hit.messageId)}#${hit.ord}">\n${text.slice(
            0,
            room - 120,
          )}…\n</chunk>`,
        );
      }
      break;
    }
    parts.push(piece);
    total += piece.length + 1;
  }

  if (parts.length === 0) return '';
  return [
    '<context>',
    'The following excerpts were retrieved from the user\'s own documents/history on their device. ' +
      'Use them to ground your answer when relevant; cite nothing that is not present here.',
    ...parts,
    '</context>',
  ].join('\n');
}

/** Minimal attribute escaping so a message id can't break out of the `source="…"` attribute. */
function escapeAttr(s: string): string {
  return s.replace(/[&<>"]/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&quot;',
  );
}
