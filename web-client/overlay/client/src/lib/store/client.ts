/**
 * Caladon device store — main-thread proxy (Batch 1 client foundation).
 *
 * `StoreProxy` is a framework-free singleton that owns the single store Web Worker and exposes a
 * promise-based API mirroring the RPC contract in `./types`. It spawns the worker as an ESM module
 * worker (`new Worker(new URL("./worker/store.worker.ts", import.meta.url), { type: "module" })`),
 * keeps a `requestId`-keyed map of pending Promises, and resolves/rejects them as the worker
 * replies. Feature code (history, search, RAG) builds against these method signatures.
 *
 * Lifecycle: construct the proxy lazily; call `openStore(hexKey)` once after the seed is unlocked
 * (the hex comes from `deriveStoreKeyHex` in `./kdf`). `ready` resolves when the store is open; all
 * other methods `await this.ready` first so callers never race the open. The store key is passed
 * straight through to the worker (which drops it after INIT) — it is never retained on the main
 * thread beyond the INIT postMessage.
 */

import type {
  StoreRequest,
  StoreResponse,
  StoredConversation,
  StoredMessage,
  StoredVector,
  SearchHit,
  VectorChunk,
} from './types';

interface Pending {
  resolve: (res: StoreResponse) => void;
  reject: (err: Error) => void;
}

let counter = 0;
function nextRequestId(): string {
  counter = (counter + 1) % Number.MAX_SAFE_INTEGER;
  return `r${counter}_${Date.now().toString(36)}`;
}

export class StoreProxy {
  private worker: Worker | null = null;
  private pending = new Map<string, Pending>();
  private opened = false;

  /** Resolves once the store has been opened (INIT acked). Awaited by every op. */
  public ready: Promise<void>;
  private resolveReady!: () => void;
  private rejectReady!: (err: Error) => void;

  constructor() {
    this.ready = new Promise<void>((res, rej) => {
      this.resolveReady = res;
      this.rejectReady = rej;
    });
    // Attach a no-op rejection handler so an openStore() failure (which rejects `ready`) never
    // surfaces as an "Uncaught (in promise)" before a call site awaits it — every op already
    // re-rejects from its own `await this.ready`, where the caller handles it.
    this.ready.catch(() => undefined);
  }

  /** Spawn the worker (idempotent) and wire the message pump. */
  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    const worker = new Worker(new URL('./worker/store.worker.ts', import.meta.url), {
      type: 'module',
    });
    worker.onmessage = (ev: MessageEvent<StoreResponse>) => {
      const res = ev.data;
      const p = this.pending.get(res.requestId);
      if (!p) return;
      this.pending.delete(res.requestId);
      if (res.type === 'ERROR') {
        const err = new Error(res.message);
        if (res.code) (err as Error & { code?: string }).code = res.code;
        p.reject(err);
      } else {
        p.resolve(res);
      }
    };
    worker.onerror = (ev: ErrorEvent) => {
      const err = new Error(`store worker error: ${ev.message}`);
      for (const [, p] of this.pending) p.reject(err);
      this.pending.clear();
    };
    this.worker = worker;
    return worker;
  }

  /** Send a request and await the matching typed response. */
  private send<R extends StoreResponse>(req: StoreRequest): Promise<R> {
    const worker = this.ensureWorker();
    return new Promise<R>((resolve, reject) => {
      this.pending.set(req.requestId, {
        resolve: (res) => resolve(res as R),
        reject,
      });
      worker.postMessage(req);
    });
  }

  /**
   * Open (or create) the encrypted store with the lowercase-hex of `device_store_key(root)`.
   * Idempotent: a second call with the store already open is a no-op. Resolves `ready`.
   */
  async openStore(hexKey: string): Promise<void> {
    if (this.opened) return this.ready;
    try {
      await this.send({ type: 'INIT', requestId: nextRequestId(), hexKey });
      this.opened = true;
      this.resolveReady();
    } catch (err) {
      this.rejectReady(err instanceof Error ? err : new Error(String(err)));
      throw err;
    }
    return this.ready;
  }

  /** Persist one chat turn (user + assistant message) and upsert the conversation row. */
  async persistTurn(
    conversationId: string,
    userMsg: StoredMessage,
    assistantMsg: StoredMessage,
    convo: StoredConversation,
  ): Promise<void> {
    await this.ready;
    await this.send({
      type: 'PERSIST_TURN',
      requestId: nextRequestId(),
      conversationId,
      userMsg,
      assistantMsg,
      convo,
    });
  }

  /** Load a conversation row and its messages (createdAt-ordered). */
  async hydrate(
    conversationId: string,
  ): Promise<{ conversation: StoredConversation | null; messages: StoredMessage[] }> {
    await this.ready;
    const res = await this.send<Extract<StoreResponse, { type: 'HYDRATE' }>>({
      type: 'HYDRATE_CONVO',
      requestId: nextRequestId(),
      conversationId,
    });
    return { conversation: res.conversation, messages: res.messages };
  }

  /** List conversations (most-recently-updated first), keyset-paginated. */
  async listConversations(
    limit = 50,
    cursor?: number,
  ): Promise<{ conversations: StoredConversation[]; nextCursor: number | null }> {
    await this.ready;
    const res = await this.send<Extract<StoreResponse, { type: 'LIST_CONVOS' }>>({
      type: 'LIST_CONVOS',
      requestId: nextRequestId(),
      limit,
      cursor,
    });
    return { conversations: res.conversations, nextCursor: res.nextCursor };
  }

  /** Fork a conversation at a message; resolves to the new conversation's id. */
  async forkConversation(conversationId: string, fromMessageId: string): Promise<string> {
    await this.ready;
    const res = await this.send<Extract<StoreResponse, { type: 'OK' }>>({
      type: 'FORK',
      requestId: nextRequestId(),
      conversationId,
      fromMessageId,
    });
    return String(res.result);
  }

  /** Import a parsed LibreChat-style chat export into the store. */
  async importChatExport(json: unknown): Promise<void> {
    await this.ready;
    await this.send({ type: 'IMPORT', requestId: nextRequestId(), json });
  }

  /** Delete a conversation and everything that cascades from it. */
  async deleteConversation(conversationId: string): Promise<void> {
    await this.ready;
    await this.send({ type: 'DELETE_CONVO', requestId: nextRequestId(), conversationId });
  }

  /** Full-text search over message text (highlighted + bm25-ranked), keyset-paginated. */
  async search(
    query: string,
    limit = 20,
    cursor?: number,
  ): Promise<{ hits: SearchHit[]; nextCursor: number | null }> {
    await this.ready;
    const res = await this.send<Extract<StoreResponse, { type: 'SEARCH' }>>({
      type: 'SEARCH',
      requestId: nextRequestId(),
      query,
      limit,
      cursor,
    });
    return { hits: res.hits, nextCursor: res.nextCursor };
  }

  /** Persist the embedding chunks for a message (replaces any existing chunks for it). */
  async storeVectors(messageId: string, chunks: VectorChunk[]): Promise<void> {
    await this.ready;
    await this.send({ type: 'STORE_VECTORS', requestId: nextRequestId(), messageId, chunks });
  }

  /** Load all persisted vectors so the in-memory cosine index can be rebuilt. */
  async hydrateVectors(): Promise<StoredVector[]> {
    await this.ready;
    const res = await this.send<Extract<StoreResponse, { type: 'VECTORS' }>>({
      type: 'HYDRATE_VECTORS',
      requestId: nextRequestId(),
    });
    return res.vectors;
  }

  /** Wipe every table (logout / panic). The store stays open; data is gone. */
  async clearStore(): Promise<void> {
    await this.ready;
    await this.send({ type: 'CLEAR_ALL', requestId: nextRequestId() });
  }

  /** True once `openStore` has completed. */
  get isOpen(): boolean {
    return this.opened;
  }

  /**
   * Tear the proxy down: kill the worker (which holds the DB handle + the store key for the CURRENT
   * identity), reject every in-flight op, and reset `opened`/`ready`. Used on lock/logout so the
   * NEXT unlock — which may be a DIFFERENT seed → different `device_store_key` → different SQLCipher
   * key — gets a fresh worker that re-runs INIT with the new key. Without this, `openStore`'s
   * `if (this.opened) return` short-circuit (and the worker's own `if (db) return` in init) keep the
   * connection keyed to the FIRST identity, so identity B would read/write identity A's encrypted DB.
   */
  terminate(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    const err = new Error('store proxy terminated');
    for (const [, p] of this.pending) p.reject(err);
    this.pending.clear();
    this.opened = false;
    // Reject the OLD ready so anything still awaiting it fails fast (fail-open at the call sites)
    // rather than hanging forever, then install a fresh pending ready for the next openStore.
    try {
      this.rejectReady(err);
    } catch {
      /* ready may already be settled */
    }
    this.ready = new Promise<void>((res, rej) => {
      this.resolveReady = res;
      this.rejectReady = rej;
    });
    // The freshly-created rejected/pending promises must not surface as unhandled rejections.
    this.ready.catch(() => undefined);
  }
}

let singleton: StoreProxy | null = null;

/** The shared store proxy singleton (constructed lazily on first access). */
export function getStoreProxy(): StoreProxy {
  if (!singleton) singleton = new StoreProxy();
  return singleton;
}

/**
 * Tear down the shared proxy (lock / logout / identity switch). Kills the worker so the next
 * `getStoreProxy().openStore(...)` re-INITs with the new identity's key. MUST be called on lock so a
 * re-unlock with a different seed cannot read or write the previous identity's encrypted store.
 */
export function resetStoreProxy(): void {
  if (singleton) {
    singleton.terminate();
    singleton = null;
  }
}
