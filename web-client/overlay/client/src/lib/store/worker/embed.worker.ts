/**
 * Caladon RAG — the embedding Web Worker (Batch 1 client foundation).
 *
 * A single module Web Worker that runs the on-device sentence-embedding model
 * (Xenova/all-MiniLM-L6-v2, 384-dim) via @huggingface/transformers' feature-extraction pipeline.
 * It is the ONLY place text is turned into vectors, and it does so ENTIRELY in-browser: the model
 * weights + tokenizer are served SAME-ORIGIN from /models/ (env.allowRemoteModels=false), so no
 * embedding text and no model bytes ever touch the network. This keeps RAG inside the trust
 * boundary — plaintext (document chunks, the user's query) is embedded here on the device and only
 * the resulting Float32 vectors leave the worker.
 *
 * Why a worker: model load + inference are CPU/GPU heavy; running them off the main thread keeps the
 * chat UI responsive. The pipeline tries WebGPU first (fast) and falls back to the WASM backend when
 * WebGPU is unavailable or the device init throws — the WHOLE pipeline() call is wrapped so a single
 * try/catch covers both "no navigator.gpu" and "adapter request rejected" failure modes.
 *
 * Protocol: requestId-keyed, mirroring the store worker's style. EMBED takes an array of texts and
 * returns an array of Float32Array vectors (one per input, same order). The model is loaded lazily on
 * the first EMBED and reused for the worker's lifetime.
 */

/// <reference lib="webworker" />

/* ------------------------------------------------------------------ *
 * @huggingface/transformers typing (narrowed surface we use).
 * The package isn't installed in the overlay-only tree (the librechat build adds it), so we type
 * only what we touch. The single expected tsc diagnostic is the TS2307 for this dynamic import.
 * ------------------------------------------------------------------ */

/** A pooled, normalized embedding tensor: `.data` is the flat Float32 buffer, `.dims` its shape. */
interface FeatureTensor {
  data: Float32Array | number[];
  dims: number[];
}

type FeatureExtractionPipeline = (
  texts: string[],
  opts?: { pooling?: 'mean' | 'cls' | 'none'; normalize?: boolean },
) => Promise<FeatureTensor>;

interface TransformersEnv {
  allowRemoteModels: boolean;
  allowLocalModels: boolean;
  localModelPath: string;
  /** WASM backend tuning (best-effort; guarded so missing fields don't throw). */
  backends?: {
    onnx?: {
      wasm?: { numThreads?: number; proxy?: boolean };
    };
  };
}

interface TransformersModule {
  env: TransformersEnv;
  pipeline: (
    task: 'feature-extraction',
    model: string,
    opts?: { device?: 'webgpu' | 'wasm'; dtype?: string },
  ) => Promise<FeatureExtractionPipeline>;
}

/* ------------------------------------------------------------------ *
 * RPC contract (main thread <-> embed worker)
 * ------------------------------------------------------------------ */

/** Embed a batch of texts; returns one 384-dim vector per input, in order. */
export interface EmbedRequest {
  type: 'EMBED';
  requestId: string;
  texts: string[];
}

/** Warm the model (load weights) without embedding anything — used to hide first-token latency. */
export interface WarmupRequest {
  type: 'WARMUP';
  requestId: string;
}

export type EmbedWorkerRequest = EmbedRequest | WarmupRequest;

/** Successful embed: the dense vectors + the backend that actually ran ('webgpu' | 'wasm'). */
export interface EmbeddedResponse {
  type: 'EMBEDDED';
  requestId: string;
  vectors: Float32Array[];
  backend: EmbedBackend;
}

/** Warmup ack (model loaded). */
export interface WarmedResponse {
  type: 'WARMED';
  requestId: string;
  backend: EmbedBackend;
}

/** Structured failure; the main-thread proxy rejects the matching Promise. */
export interface EmbedErrorResponse {
  type: 'ERROR';
  requestId: string;
  message: string;
}

export type EmbedWorkerResponse = EmbeddedResponse | WarmedResponse | EmbedErrorResponse;

export type EmbedBackend = 'webgpu' | 'wasm';

/* ------------------------------------------------------------------ *
 * Model identity / constants (must match fetch-rag-model.sh + chunker dims)
 * ------------------------------------------------------------------ */

const MODEL_ID = 'Xenova/all-MiniLM-L6-v2';
/** MiniLM-L6 embedding dimensionality. Sanity-checked against the model output. */
export const EMBED_DIM = 384;
/** Same-origin model root (served by the shim/static host; NEVER a remote HF fetch). */
const LOCAL_MODEL_PATH = '/models/';

/* ------------------------------------------------------------------ *
 * Lazy model load (WebGPU first, WASM fallback)
 * ------------------------------------------------------------------ */

let pipelinePromise: Promise<{ extract: FeatureExtractionPipeline; backend: EmbedBackend }> | null =
  null;

async function getPipeline(): Promise<{ extract: FeatureExtractionPipeline; backend: EmbedBackend }> {
  if (pipelinePromise) return pipelinePromise;

  pipelinePromise = (async () => {
    const transformers = (await import('@huggingface/transformers')) as unknown as TransformersModule;
    const { env, pipeline } = transformers;

    // LOCK the model resolution to same-origin /models/. This is the trust-critical config: with
    // allowRemoteModels=false the library will NEVER reach out to huggingface.co — a missing local
    // file becomes a load error here rather than a silent network fetch of model bytes.
    env.allowRemoteModels = false;
    env.allowLocalModels = true;
    env.localModelPath = LOCAL_MODEL_PATH;
    // Single-threaded WASM avoids needing SharedArrayBuffer cross-origin headers for the ORT pool;
    // OPFS isolation already gives us crossOriginIsolated, but we keep this conservative + robust.
    if (env.backends?.onnx?.wasm) {
      env.backends.onnx.wasm.proxy = false;
    }

    // Try WebGPU (fast path). Wrap the WHOLE pipeline() call so both "no navigator.gpu" and a
    // rejected adapter/device request fall through to the WASM backend. We probe navigator.gpu
    // first to skip the (sometimes noisy) WebGPU init attempt when it's plainly unavailable.
    const hasWebGpu =
      typeof (self as unknown as { navigator?: { gpu?: unknown } }).navigator !== 'undefined' &&
      !!(self as unknown as { navigator?: { gpu?: unknown } }).navigator?.gpu;

    // dtype 'q8' pins BOTH backends to onnx/model_quantized.onnx — the ONLY weight file we fetch +
    // serve same-origin. Without it, transformers.js v4 defaults the WebGPU path to fp32
    // (onnx/model.onnx, not present) → the load throws and WebGPU is silently never used. Pinning q8
    // keeps the fast WebGPU path real (and the WASM fallback already used the quantized file).
    if (hasWebGpu) {
      try {
        const extract = await pipeline('feature-extraction', MODEL_ID, { device: 'webgpu', dtype: 'q8' });
        return { extract, backend: 'webgpu' as const };
      } catch (e) {
        console.warn('[embed.worker] WebGPU pipeline unavailable, falling back to WASM:', e);
      }
    }

    const extract = await pipeline('feature-extraction', MODEL_ID, { device: 'wasm', dtype: 'q8' });
    return { extract, backend: 'wasm' as const };
  })();

  // If load fails, clear the cached promise so a later request can retry rather than getting the
  // same rejected promise forever.
  pipelinePromise.catch(() => {
    pipelinePromise = null;
  });

  return pipelinePromise;
}

/* ------------------------------------------------------------------ *
 * Embedding
 * ------------------------------------------------------------------ */

/**
 * Embed a batch with mean pooling + L2 normalization (the standard MiniLM sentence-embedding
 * recipe — normalized vectors make cosine similarity a plain dot product downstream). Returns one
 * Float32Array per input text, each a fresh copy (so the underlying tensor buffer can be freed and
 * so the arrays are transferable back to the main thread).
 */
async function embed(texts: string[]): Promise<{ vectors: Float32Array[]; backend: EmbedBackend }> {
  const clean = texts.map((t) => (typeof t === 'string' ? t : String(t ?? '')));
  if (clean.length === 0) {
    const { backend } = await getPipeline();
    return { vectors: [], backend };
  }

  const { extract, backend } = await getPipeline();
  const out = await extract(clean, { pooling: 'mean', normalize: true });

  // `out.data` is a flat Float32 buffer of shape [batch, dim]; slice it into per-input vectors.
  const flat = out.data instanceof Float32Array ? out.data : Float32Array.from(out.data);
  const dim = out.dims[out.dims.length - 1] ?? EMBED_DIM;
  const batch = clean.length;

  const vectors: Float32Array[] = [];
  for (let i = 0; i < batch; i++) {
    // .slice() detaches a standalone, transferable copy from the shared tensor buffer.
    vectors.push(flat.slice(i * dim, i * dim + dim));
  }
  return { vectors, backend };
}

/* ------------------------------------------------------------------ *
 * RPC dispatch — sequential (model inference is not reentrant-friendly)
 * ------------------------------------------------------------------ */

async function handle(req: EmbedWorkerRequest): Promise<EmbedWorkerResponse> {
  switch (req.type) {
    case 'WARMUP': {
      const { backend } = await getPipeline();
      return { type: 'WARMED', requestId: req.requestId, backend };
    }
    case 'EMBED': {
      const { vectors, backend } = await embed(req.texts);
      return { type: 'EMBEDDED', requestId: req.requestId, vectors, backend };
    }
    default: {
      const _exhaustive: never = req;
      throw new Error(`unknown embed request: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

/** Collect the transferable ArrayBuffers from a response so vectors move (not copy) to the main thread. */
function transfersFor(res: EmbedWorkerResponse): Transferable[] {
  if (res.type === 'EMBEDDED') {
    // Each Float32Array is backed by an ArrayBuffer here (the .slice() copy in `embed`), so these
    // are real Transferables; narrow off the generic ArrayBufferLike for the postMessage signature.
    return res.vectors
      .map((v) => v.buffer)
      .filter((b): b is ArrayBuffer => b instanceof ArrayBuffer);
  }
  return [];
}

// Serialize all work behind a single promise chain so inference calls never interleave.
let queue: Promise<unknown> = Promise.resolve();

self.onmessage = (ev: MessageEvent<EmbedWorkerRequest>) => {
  const req = ev.data;
  queue = queue
    .then(() => handle(req))
    .then((res) => {
      (self as unknown as Worker).postMessage(res, transfersFor(res));
    })
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      const res: EmbedWorkerResponse = {
        type: 'ERROR',
        requestId: req?.requestId ?? 'unknown',
        message,
      };
      (self as unknown as Worker).postMessage(res);
    });
};

export {}; // module worker
