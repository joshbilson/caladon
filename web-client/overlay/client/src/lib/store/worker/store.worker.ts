/**
 * Caladon device store — the store Web Worker (Batch 1 client foundation).
 *
 * A single module Web Worker owning the encrypted SQLite store. It is the ONLY place the database
 * handle and the store key exist. The main-thread `StoreProxy` talks to it over the requestId-keyed
 * RPC contract in `../types.ts`; the raw DB handle is never returned across postMessage and the key
 * reference is dropped immediately after INIT.
 *
 * Persistence: OPFS via @evolu/sqlite-wasm (= @sqlite.org/sqlite-wasm + SQLite3MultipleCiphers).
 * Requires cross-origin isolation (COOP same-origin + COEP require-corp) for the OPFS SAH pool;
 * if unavailable we fall back to an in-memory database (history is then session-only). Either way
 * `PRAGMA key = "<hex>"` is applied first so the on-disk file is SQLCipher-encrypted.
 *
 * Requests are processed sequentially (a single message handler, awaited) so multi-statement ops
 * are not interleaved; write ops that touch several rows run inside a transaction.
 */

/// <reference lib="webworker" />

import { SCHEMA_SQL } from '../schema.sql';
import type {
  StoreRequest,
  StoreResponse,
  StoredConversation,
  StoredMessage,
  StoredVector,
  SearchHit,
} from '../types';

/* ------------------------------------------------------------------ *
 * @evolu/sqlite-wasm typing (narrowed OO1 surface we use).
 * The package re-exports the official @sqlite.org/sqlite-wasm OO1 Database; we type only what we
 * touch so this compiles without the upstream @types being present in the overlay-only tree.
 * ------------------------------------------------------------------ */

interface Sqlite3Statement {
  bind(args: unknown[]): Sqlite3Statement;
  step(): boolean;
  get(index: number): unknown;
  getColumnName(index: number): string;
  columnCount: number;
  reset(clearBindings?: boolean): Sqlite3Statement;
  finalize(): void;
}

interface Sqlite3ExecOptions {
  sql: string;
  bind?: unknown[];
  rowMode?: 'array' | 'object' | number | string;
  resultRows?: unknown[];
  returnValue?: 'this' | 'resultRows' | 'saveSql';
}

interface Sqlite3Db {
  exec(sql: string): Sqlite3Db;
  exec(opts: Sqlite3ExecOptions): unknown;
  prepare(sql: string): Sqlite3Statement;
  selectValue(sql: string, bind?: unknown[]): unknown;
  close(): void;
}

interface Sqlite3OO1 {
  /** Plain in-memory / VFS-backed database (used for the in-memory fallback). */
  DB: new (filename: string, flags?: string) => Sqlite3Db;
  /** OPFS SyncAccessHandle pool VFS — durable, no SharedArrayBuffer required. */
  OpfsSAHPoolDb?: new (filename: string) => Sqlite3Db;
}

interface Sqlite3ApiObject {
  oo1: Sqlite3OO1;
  /** Lazily-installed OPFS SAH pool VFS utility (present only when OPFS is available). */
  installOpfsSAHPoolVfs?: (opts?: {
    name?: string;
  }) => Promise<{ OpfsSAHPoolDb: new (filename: string) => Sqlite3Db }>;
  capi: Record<string, unknown>;
}

type Sqlite3InitModule = (config?: {
  print?: (msg: string) => void;
  printErr?: (msg: string) => void;
}) => Promise<Sqlite3ApiObject>;

/* ------------------------------------------------------------------ *
 * Worker state
 * ------------------------------------------------------------------ */

const DB_FILE = 'caladon-store-v1.db';
const FLOAT_BYTES = 4;

let db: Sqlite3Db | null = null;
let persistent = false;

/* ------------------------------------------------------------------ *
 * Small SQL helpers (over the narrowed OO1 surface)
 * ------------------------------------------------------------------ */

/** Run a parametrised statement that returns no rows. */
function run(sql: string, bind: unknown[] = []): void {
  const stmt = mustDb().prepare(sql);
  try {
    if (bind.length) stmt.bind(bind);
    stmt.step();
  } finally {
    stmt.finalize();
  }
}

/** Run a parametrised query and map each row to an object keyed by column name. */
function query(sql: string, bind: unknown[] = []): Record<string, unknown>[] {
  const stmt = mustDb().prepare(sql);
  const rows: Record<string, unknown>[] = [];
  try {
    if (bind.length) stmt.bind(bind);
    const n = stmt.columnCount;
    while (stmt.step()) {
      const row: Record<string, unknown> = {};
      for (let i = 0; i < n; i++) row[stmt.getColumnName(i)] = stmt.get(i);
      rows.push(row);
    }
  } finally {
    stmt.finalize();
  }
  return rows;
}

/** Run `fn` inside a single IMMEDIATE transaction; roll back on throw. */
function tx<T>(fn: () => T): T {
  mustDb().exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    mustDb().exec('COMMIT');
    return out;
  } catch (e) {
    try {
      mustDb().exec('ROLLBACK');
    } catch {
      /* ignore rollback failure */
    }
    throw e;
  }
}

function mustDb(): Sqlite3Db {
  if (!db) throw new Error('store not initialised (send INIT first)');
  return db;
}

/* ------------------------------------------------------------------ *
 * BLOB <-> Float32 conversion for embeddings
 * ------------------------------------------------------------------ */

function vecToBlob(vec: Float32Array): Uint8Array {
  return new Uint8Array(vec.buffer, vec.byteOffset, vec.byteLength).slice();
}

function blobToVec(blob: unknown): Float32Array {
  const bytes =
    blob instanceof Uint8Array
      ? blob
      : blob instanceof ArrayBuffer
        ? new Uint8Array(blob)
        : new Uint8Array(0);
  // Copy into an aligned buffer (the blob view may not be 4-byte aligned).
  const aligned = new Uint8Array(bytes.byteLength);
  aligned.set(bytes);
  return new Float32Array(aligned.buffer, 0, Math.floor(bytes.byteLength / FLOAT_BYTES));
}

/* ------------------------------------------------------------------ *
 * Row mappers
 * ------------------------------------------------------------------ */

function rowToConvo(r: Record<string, unknown>): StoredConversation {
  return {
    conversationId: String(r.conversationId),
    title: (r.title as string | null) ?? null,
    endpoint: (r.endpoint as string | null) ?? null,
    model: (r.model as string | null) ?? null,
    createdAt: Number(r.createdAt),
    updatedAt: Number(r.updatedAt),
    convoJson: String(r.convo_json),
  };
}

function rowToMessage(r: Record<string, unknown>): StoredMessage {
  return {
    messageId: String(r.messageId),
    conversationId: String(r.conversationId),
    parentMessageId: (r.parentMessageId as string | null) ?? null,
    isCreatedByUser: Number(r.isCreatedByUser) === 1,
    text: String(r.text ?? ''),
    contentJson: (r.content_json as string | null) ?? null,
    model: (r.model as string | null) ?? null,
    createdAt: Number(r.createdAt),
    updatedAt: Number(r.updatedAt),
  };
}

/* ------------------------------------------------------------------ *
 * INIT: load wasm, open (OPFS or in-memory), key, schema, verify FTS5
 * ------------------------------------------------------------------ */

async function init(hexKey: string): Promise<void> {
  if (db) return; // idempotent

  // @evolu/sqlite-wasm re-exports the official build (ESM, with the embedded .wasm). Its default
  // export is the Emscripten module factory.
  const mod = (await import('@evolu/sqlite-wasm')) as unknown as {
    default: Sqlite3InitModule;
    sqlite3InitModule?: Sqlite3InitModule;
  };
  const initModule = mod.default ?? mod.sqlite3InitModule;
  if (typeof initModule !== 'function') {
    throw new Error('@evolu/sqlite-wasm: no init module export found');
  }
  const sqlite3 = await initModule({
    printErr: (m: string) => console.error('[store.worker][sqlite]', m),
  });

  // Prefer durable OPFS (SAH pool VFS — no SharedArrayBuffer requirement, only crossOriginIsolated
  // for OPFS itself). Fall back to in-memory when OPFS is unavailable (e.g. not isolated).
  db = await openDb(sqlite3);

  // SQLCipher key MUST be the first statement executed against the connection.
  // The hex form lets SQLite3MultipleCiphers use the raw 32 bytes verbatim (no KDF re-stretch).
  run(`PRAGMA key = "x'${hexKey}'"`);

  // Recommended pragmas for a single-connection encrypted store.
  mustDb().exec('PRAGMA foreign_keys = ON');
  mustDb().exec('PRAGMA journal_mode = WAL');
  mustDb().exec('PRAGMA synchronous = NORMAL');

  // Apply the schema (idempotent).
  mustDb().exec(SCHEMA_SQL);

  // Verify FTS5 is available — a missing FTS5 means the search path is silently broken, so fail loud.
  const ftsVer = mustDb().selectValue('SELECT fts5_version()');
  if (ftsVer == null) {
    throw new Error('FTS5 not available in this SQLite build');
  }
}

async function openDb(sqlite3: Sqlite3ApiObject): Promise<Sqlite3Db> {
  const isolated =
    typeof self !== 'undefined' && (self as unknown as { crossOriginIsolated?: boolean }).crossOriginIsolated;
  if (isolated && typeof sqlite3.installOpfsSAHPoolVfs === 'function') {
    try {
      const pool = await sqlite3.installOpfsSAHPoolVfs({ name: 'caladon-store' });
      persistent = true;
      return new pool.OpfsSAHPoolDb(`/${DB_FILE}`);
    } catch (e) {
      console.warn('[store.worker] OPFS SAH pool unavailable, falling back to in-memory:', e);
    }
  } else if (isolated && sqlite3.oo1.OpfsSAHPoolDb) {
    try {
      persistent = true;
      return new sqlite3.oo1.OpfsSAHPoolDb(`/${DB_FILE}`);
    } catch (e) {
      console.warn('[store.worker] OpfsSAHPoolDb ctor failed, falling back to in-memory:', e);
    }
  }
  persistent = false;
  // ':memory:' connection — session-only, still keyed (no-op on memory but keeps the code path uniform).
  return new sqlite3.oo1.DB(':memory:', 'ct');
}

/* ------------------------------------------------------------------ *
 * Conversation / message persistence
 * ------------------------------------------------------------------ */

function upsertConvo(c: StoredConversation): void {
  run(
    `INSERT INTO conversations
       (conversationId, title, endpoint, model, createdAt, updatedAt, convo_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(conversationId) DO UPDATE SET
       title=excluded.title,
       endpoint=excluded.endpoint,
       model=excluded.model,
       updatedAt=excluded.updatedAt,
       convo_json=excluded.convo_json`,
    [c.conversationId, c.title, c.endpoint, c.model, c.createdAt, c.updatedAt, c.convoJson],
  );
}

function upsertMessage(m: StoredMessage): void {
  run(
    `INSERT INTO messages
       (messageId, conversationId, parentMessageId, isCreatedByUser, text, content_json, model, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(messageId) DO UPDATE SET
       conversationId=excluded.conversationId,
       parentMessageId=excluded.parentMessageId,
       isCreatedByUser=excluded.isCreatedByUser,
       text=excluded.text,
       content_json=excluded.content_json,
       model=excluded.model,
       updatedAt=excluded.updatedAt`,
    [
      m.messageId,
      m.conversationId,
      m.parentMessageId,
      m.isCreatedByUser ? 1 : 0,
      m.text,
      m.contentJson,
      m.model,
      m.createdAt,
      m.updatedAt,
    ],
  );
}

function persistTurn(c: StoredConversation, userMsg: StoredMessage, assistantMsg: StoredMessage): void {
  tx(() => {
    upsertConvo(c);
    upsertMessage(userMsg);
    upsertMessage(assistantMsg);
  });
}

function hydrateConvo(conversationId: string): {
  conversation: StoredConversation | null;
  messages: StoredMessage[];
} {
  const convoRows = query('SELECT * FROM conversations WHERE conversationId = ?', [conversationId]);
  const conversation = convoRows.length ? rowToConvo(convoRows[0]!) : null;
  const msgRows = query(
    'SELECT * FROM messages WHERE conversationId = ? ORDER BY createdAt ASC, rowid ASC',
    [conversationId],
  );
  return { conversation, messages: msgRows.map(rowToMessage) };
}

function listConvos(limit: number, cursor?: number): { conversations: StoredConversation[]; nextCursor: number | null } {
  const lim = Math.max(1, Math.min(limit, 200));
  // Keyset on updatedAt DESC; `cursor` is the updatedAt of the last row already shown.
  const rows = cursor
    ? query(
        'SELECT * FROM conversations WHERE updatedAt < ? ORDER BY updatedAt DESC LIMIT ?',
        [cursor, lim + 1],
      )
    : query('SELECT * FROM conversations ORDER BY updatedAt DESC LIMIT ?', [lim + 1]);
  const hasMore = rows.length > lim;
  const page = hasMore ? rows.slice(0, lim) : rows;
  const conversations = page.map(rowToConvo);
  const nextCursor = hasMore ? conversations[conversations.length - 1]!.updatedAt : null;
  return { conversations, nextCursor };
}

function deleteConvo(conversationId: string): void {
  // ON DELETE CASCADE drops messages (and their message_embeddings); FTS triggers maintain the index.
  run('DELETE FROM conversations WHERE conversationId = ?', [conversationId]);
}

/* ------------------------------------------------------------------ *
 * Fork: copy the lineage root..fromMessageId into a new conversation
 * ------------------------------------------------------------------ */

function forkConversation(conversationId: string, fromMessageId: string): string {
  return tx(() => {
    const all = query('SELECT * FROM messages WHERE conversationId = ?', [conversationId]).map(
      rowToMessage,
    );
    const byId = new Map(all.map((m) => [m.messageId, m]));
    // Walk parent pointers from the fork point up to the root to collect the kept lineage.
    const lineage: StoredMessage[] = [];
    let cur: StoredMessage | undefined = byId.get(fromMessageId);
    const guard = new Set<string>();
    while (cur && !guard.has(cur.messageId)) {
      guard.add(cur.messageId);
      lineage.push(cur);
      cur = cur.parentMessageId ? byId.get(cur.parentMessageId) : undefined;
    }
    lineage.reverse(); // root -> fork point

    const srcConvoRows = query('SELECT * FROM conversations WHERE conversationId = ?', [
      conversationId,
    ]);
    const now = Date.now();
    const newConvoId = randomId();

    // Clone the conversation row (lossless convo_json carried over; new id + timestamps).
    const srcConvo = srcConvoRows.length ? rowToConvo(srcConvoRows[0]!) : null;
    let convoJson = srcConvo?.convoJson ?? '{}';
    try {
      const parsed = JSON.parse(convoJson) as Record<string, unknown>;
      parsed.conversationId = newConvoId;
      convoJson = JSON.stringify(parsed);
    } catch {
      /* leave convoJson as-is if not valid JSON */
    }
    upsertConvo({
      conversationId: newConvoId,
      title: srcConvo ? `${srcConvo.title ?? 'Conversation'} (fork)` : 'Conversation (fork)',
      endpoint: srcConvo?.endpoint ?? null,
      model: srcConvo?.model ?? null,
      createdAt: now,
      updatedAt: now,
      convoJson,
    });

    // Re-key the message ids so the fork is independent; remap parent pointers within the lineage.
    const idMap = new Map<string, string>();
    for (const m of lineage) idMap.set(m.messageId, randomId());
    for (const m of lineage) {
      upsertMessage({
        ...m,
        messageId: idMap.get(m.messageId)!,
        conversationId: newConvoId,
        parentMessageId: m.parentMessageId ? idMap.get(m.parentMessageId) ?? null : null,
        updatedAt: now,
      });
    }
    return newConvoId;
  });
}

/* ------------------------------------------------------------------ *
 * Import a LibreChat-style chat export
 * ------------------------------------------------------------------ */

function importChatExport(json: unknown): void {
  // LibreChat exports are loosely shaped; accept a single conversation object or an array of them.
  const convos = Array.isArray(json) ? json : [json];
  tx(() => {
    for (const raw of convos) {
      if (!raw || typeof raw !== 'object') continue;
      const c = raw as Record<string, unknown>;
      const conversationId = String(c.conversationId ?? c.id ?? randomId());
      const now = Date.now();
      const messages = Array.isArray(c.messages) ? (c.messages as Record<string, unknown>[]) : [];
      upsertConvo({
        conversationId,
        title: (c.title as string | null) ?? null,
        endpoint: (c.endpoint as string | null) ?? null,
        model: (c.model as string | null) ?? null,
        createdAt: toMs(c.createdAt) ?? now,
        updatedAt: toMs(c.updatedAt) ?? now,
        convoJson: JSON.stringify(raw),
      });
      for (const m of messages) {
        const text =
          typeof m.text === 'string'
            ? m.text
            : Array.isArray(m.content)
              ? extractText(m.content)
              : '';
        upsertMessage({
          messageId: String(m.messageId ?? randomId()),
          conversationId,
          parentMessageId: (m.parentMessageId as string | null) ?? null,
          isCreatedByUser: Boolean(m.isCreatedByUser ?? m.sender === 'User'),
          text,
          contentJson: m.content != null ? JSON.stringify(m.content) : null,
          model: (m.model as string | null) ?? null,
          createdAt: toMs(m.createdAt) ?? now,
          updatedAt: toMs(m.updatedAt) ?? now,
        });
      }
    }
  });
}

function extractText(content: unknown[]): string {
  const parts: string[] = [];
  for (const part of content) {
    if (part && typeof part === 'object') {
      const p = part as Record<string, unknown>;
      if (typeof p.text === 'string') parts.push(p.text);
      else if (p.text && typeof p.text === 'object' && typeof (p.text as Record<string, unknown>).value === 'string') {
        parts.push((p.text as Record<string, unknown>).value as string);
      }
    }
  }
  return parts.join('\n');
}

function toMs(v: unknown): number | null {
  if (v == null) return null;
  if (typeof v === 'number') return v;
  const t = Date.parse(String(v));
  return Number.isNaN(t) ? null : t;
}

/* ------------------------------------------------------------------ *
 * FTS search (MATCH + highlight + bm25, keyset on rank)
 * ------------------------------------------------------------------ */

function search(queryStr: string, limit: number, cursor?: number): { hits: SearchHit[]; nextCursor: number | null } {
  const lim = Math.max(1, Math.min(limit, 100));
  const match = sanitizeFtsQuery(queryStr);
  if (!match) return { hits: [], nextCursor: null };

  // bm25(messages_fts) is negative; lower = better. Keyset paginates on rank > cursor.
  const rows = cursor
    ? query(
        `SELECT m.messageId      AS messageId,
                m.conversationId AS conversationId,
                m.createdAt      AS createdAt,
                highlight(messages_fts, 0, '<mark>', '</mark>') AS snippet,
                bm25(messages_fts) AS rank
         FROM messages_fts
         JOIN messages m ON m.rowid = messages_fts.rowid
         WHERE messages_fts MATCH ? AND bm25(messages_fts) > ?
         ORDER BY rank ASC
         LIMIT ?`,
        [match, cursor, lim + 1],
      )
    : query(
        `SELECT m.messageId      AS messageId,
                m.conversationId AS conversationId,
                m.createdAt      AS createdAt,
                highlight(messages_fts, 0, '<mark>', '</mark>') AS snippet,
                bm25(messages_fts) AS rank
         FROM messages_fts
         JOIN messages m ON m.rowid = messages_fts.rowid
         WHERE messages_fts MATCH ?
         ORDER BY rank ASC
         LIMIT ?`,
        [match, lim + 1],
      );

  const hasMore = rows.length > lim;
  const page = hasMore ? rows.slice(0, lim) : rows;
  const hits: SearchHit[] = page.map((r) => ({
    messageId: String(r.messageId),
    conversationId: String(r.conversationId),
    snippet: String(r.snippet ?? ''),
    rank: Number(r.rank),
    createdAt: Number(r.createdAt),
  }));
  const nextCursor = hasMore ? hits[hits.length - 1]!.rank : null;
  return { hits, nextCursor };
}

/**
 * Make an arbitrary user query safe for FTS5 MATCH: split on whitespace, strip FTS operator chars,
 * and quote each token as a phrase so punctuation/operators can't be injected. Empty -> ''.
 */
function sanitizeFtsQuery(q: string): string {
  const tokens = q
    .split(/\s+/)
    .map((t) => t.replace(/["()*:^-]/g, '').trim())
    .filter(Boolean)
    .map((t) => `"${t}"`);
  return tokens.join(' ');
}

/* ------------------------------------------------------------------ *
 * Per-message vectors
 * ------------------------------------------------------------------ */

function storeVectors(messageId: string, chunks: { text: string; vec: Float32Array }[]): void {
  tx(() => {
    run('DELETE FROM message_embeddings WHERE messageId = ?', [messageId]);
    chunks.forEach((chunk, ord) => {
      run('INSERT INTO message_embeddings (messageId, ord, text, vec) VALUES (?, ?, ?, ?)', [
        messageId,
        ord,
        chunk.text,
        vecToBlob(chunk.vec),
      ]);
    });
  });
}

function hydrateVectors(): StoredVector[] {
  const rows = query('SELECT messageId, ord, text, vec FROM message_embeddings ORDER BY messageId, ord');
  return rows.map((r) => ({
    messageId: String(r.messageId),
    ord: Number(r.ord),
    text: String(r.text),
    vec: blobToVec(r.vec),
  }));
}

/* ------------------------------------------------------------------ *
 * Clear all
 * ------------------------------------------------------------------ */

function clearAll(): void {
  tx(() => {
    // Children first (or rely on cascade); explicit for the doc-RAG tables that have no parent here.
    mustDb().exec('DELETE FROM message_embeddings');
    mustDb().exec('DELETE FROM embeddings');
    mustDb().exec('DELETE FROM chunks');
    mustDb().exec('DELETE FROM files');
    mustDb().exec('DELETE FROM messages');
    mustDb().exec('DELETE FROM conversations');
  });
  mustDb().exec("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')");
}

/* ------------------------------------------------------------------ *
 * Utilities
 * ------------------------------------------------------------------ */

function randomId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `c_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

/* ------------------------------------------------------------------ *
 * RPC dispatch — sequential, one request at a time
 * ------------------------------------------------------------------ */

async function handle(req: StoreRequest): Promise<StoreResponse> {
  switch (req.type) {
    case 'INIT':
      await init(req.hexKey);
      return { type: 'OK', requestId: req.requestId };

    case 'PERSIST_TURN':
      persistTurn(req.convo, req.userMsg, req.assistantMsg);
      return { type: 'OK', requestId: req.requestId };

    case 'HYDRATE_CONVO': {
      const { conversation, messages } = hydrateConvo(req.conversationId);
      return { type: 'HYDRATE', requestId: req.requestId, conversation, messages };
    }

    case 'LIST_CONVOS': {
      const { conversations, nextCursor } = listConvos(req.limit ?? 50, req.cursor);
      return { type: 'LIST_CONVOS', requestId: req.requestId, conversations, nextCursor };
    }

    case 'FORK': {
      const newId = forkConversation(req.conversationId, req.fromMessageId);
      return { type: 'OK', requestId: req.requestId, result: newId };
    }

    case 'IMPORT':
      importChatExport(req.json);
      return { type: 'OK', requestId: req.requestId };

    case 'DELETE_CONVO':
      deleteConvo(req.conversationId);
      return { type: 'OK', requestId: req.requestId };

    case 'SEARCH': {
      const { hits, nextCursor } = search(req.query, req.limit ?? 20, req.cursor);
      return { type: 'SEARCH', requestId: req.requestId, hits, nextCursor };
    }

    case 'STORE_VECTORS':
      storeVectors(req.messageId, req.chunks);
      return { type: 'OK', requestId: req.requestId };

    case 'HYDRATE_VECTORS':
      return { type: 'VECTORS', requestId: req.requestId, vectors: hydrateVectors() };

    case 'CLEAR_ALL':
      clearAll();
      return { type: 'OK', requestId: req.requestId };

    default: {
      const _exhaustive: never = req;
      throw new Error(`unknown request: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

// Serialize all work behind a single promise chain so multi-statement ops never interleave.
let queue: Promise<unknown> = Promise.resolve();

self.onmessage = (ev: MessageEvent<StoreRequest>) => {
  const req = ev.data;
  queue = queue
    .then(() => handle(req))
    .then((res) => {
      (self as unknown as Worker).postMessage(res);
    })
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      const res: StoreResponse = { type: 'ERROR', requestId: req?.requestId ?? 'unknown', message };
      (self as unknown as Worker).postMessage(res);
    });
};

export {}; // module worker
