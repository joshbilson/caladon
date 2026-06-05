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
 * if unavailable we fall back to an in-memory database (history is then session-only).
 *
 * Encryption: the OPFS connection is opened through the cipher-wrapped VFS name
 * "multipleciphers-opfs-sahpool" (NOT the OpfsSAHPoolDb subclass, which hardcodes the bare
 * 'opfs-sahpool' name and cannot be encrypted). `PRAGMA key = "x'<hex>'"` is then applied first so
 * every page is encrypted at rest with the raw 32-byte device key (aes256cbc, SQLCipher-style).
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
  StoredMemory,
  StoredAgent,
  StoredSkill,
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

/** Options form of the OO1 DB ctor — lets us pass an explicit (cipher-wrapped) VFS name. */
interface Sqlite3DbCtorOpts {
  filename: string;
  flags?: string;
  vfs?: string;
}

interface Sqlite3OO1 {
  /**
   * Plain DB ctor. dbCtorHelper passes `opt.vfs` straight to sqlite3_open_v2, so an explicit VFS
   * name (e.g. the cipher-wrapped 'multipleciphers-opfs-sahpool') opens through SQLite3 Multiple
   * Ciphers — unlike the OpfsSAHPoolDb subclass, which hardcodes the BARE 'opfs-sahpool' name and
   * therefore cannot be encrypted ("Encryption is not supported by the VFS").
   */
  DB: new (filenameOrOpts: string | Sqlite3DbCtorOpts, flags?: string) => Sqlite3Db;
}

/** The pool utility installOpfsSAHPoolVfs returns; we use it to unlink a specific DB file on the
 *  NOTADB self-heal path (a corrupt / incompatible-older-version file) without nuking other files. */
interface OpfsSAHPool {
  unlink?: (name: string) => boolean | void;
  wipeFiles?: () => void | Promise<void>;
  getFileNames?: () => string[];
}

interface Sqlite3ApiObject {
  oo1: Sqlite3OO1;
  /**
   * Installs the OPFS SAH-pool VFS and registers it under `name` (default 'opfs-sahpool').
   * We open through the cipher wrapper rather than via the returned OpfsSAHPoolDb subclass.
   */
  installOpfsSAHPoolVfs?: (opts?: { name?: string }) => Promise<OpfsSAHPool>;
  capi: Record<string, unknown>;
}

type Sqlite3InitModule = (config?: {
  print?: (msg: string) => void;
  printErr?: (msg: string) => void;
}) => Promise<Sqlite3ApiObject>;

/* ------------------------------------------------------------------ *
 * Worker state
 * ------------------------------------------------------------------ */

// Per-identity DB file: each identity's device_store_key gets its OWN encrypted file, so different
// identities on one device never collide (opening identity A's encrypted DB with identity B's key
// throws SQLITE_NOTADB). The tag is a NON-secret SHA-256 prefix of the key, never the key itself.
const DB_FILE_BASE = 'caladon-store-v1';
async function dbFileFor(hexKey: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(hexKey));
  const tag = [...new Uint8Array(digest)]
    .slice(0, 8)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${DB_FILE_BASE}-${tag}.db`;
}
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

  // Prefer durable OPFS (SAH-pool VFS, opened THROUGH the SQLite3 Multiple Ciphers wrapper so the
  // page cipher is applied — see openDb). Fall back to in-memory when OPFS is unavailable.
  // Per-identity encrypted file (so different identities/keys never collide on one device, and the
  // pre-encryption v3/v4 leftover 'caladon-store-v1.db' is simply never reopened).
  const dbFile = await dbFileFor(hexKey);
  db = await openDb(sqlite3, dbFile);

  // SQLCipher key MUST be the first statement executed against the connection.
  // The hex form lets SQLite3MultipleCiphers use the raw 32 bytes verbatim (no KDF re-stretch).
  run(`PRAGMA key = "x'${hexKey}'"`);

  // PRAGMA key returns OK even with a WRONG key (the key is not applied until the first page read),
  // so force a read to fail loud. Brand-new file → 0 rows; an EXISTING per-identity file this key
  // can't decrypt (corrupt, or an incompatible older build) → SQLITE_NOTADB. Since the file is
  // per-identity it holds no data this identity could read, so wipe + recreate rather than disabling
  // history forever. (Only on the encrypted/persistent path; harmless on :memory:.)
  if (persistent) {
    try {
      mustDb().selectValue('SELECT count(*) FROM sqlite_schema');
    } catch (readErr) {
      console.warn('[store.worker] device DB unreadable for this identity; recreating:', readErr);
      try {
        mustDb().close();
      } catch {
        /* ignore */
      }
      db = null;
      try {
        if (poolUtil?.unlink) poolUtil.unlink(`/${dbFile}`);
        else if (poolUtil?.wipeFiles) await poolUtil.wipeFiles();
      } catch {
        /* ignore — the reopen below surfaces any persistent failure */
      }
      db = await openDb(sqlite3, dbFile);
      run(`PRAGMA key = "x'${hexKey}'"`);
      mustDb().selectValue('SELECT count(*) FROM sqlite_schema');
    }
  }

  // Recommended pragmas for a single-connection encrypted store. NOTE: the OPFS post-open callback
  // that auto-sets busy_timeout is keyed by the BARE vfs pointer and is SKIPPED when opening through
  // the cipher wrapper, so set it ourselves.
  mustDb().exec('PRAGMA busy_timeout = 10000');
  mustDb().exec('PRAGMA foreign_keys = ON');
  // SAH-pool is single-connection; MEMORY journal avoids a second OPFS file and is plenty for a
  // chat-history store (WAL gives little here and adds a -wal/-shm sidecar).
  mustDb().exec(persistent ? 'PRAGMA journal_mode = MEMORY' : 'PRAGMA journal_mode = WAL');
  mustDb().exec('PRAGMA synchronous = NORMAL');

  // MIGRATION (schema v1→v2): the original message_embeddings carried a foreign key
  // `messageId REFERENCES messages(messageId) ON DELETE CASCADE`. RAG stores UPLOADED-DOCUMENT
  // vectors under a synthetic "doc:<fileId>" owner id (not a message row), so every document ingest
  // failed with SQLITE_CONSTRAINT_FOREIGNKEY — meaning the table is guaranteed EMPTY. Drop the
  // old-shaped table so the FK-free CREATE in SCHEMA_SQL below recreates it. Keyed off the table's
  // own DDL so it runs exactly once, only where the old shape exists (no-op on fresh dbs).
  const meSql = mustDb().selectValue(
    "SELECT sql FROM sqlite_schema WHERE type='table' AND name='message_embeddings'",
  );
  if (typeof meSql === 'string' && /REFERENCES\s+messages/i.test(meSql)) {
    mustDb().exec('DROP TABLE message_embeddings');
  }

  // Apply the schema (idempotent).
  mustDb().exec(SCHEMA_SQL);

  // FTS5 availability is PROVEN by SCHEMA_SQL above succeeding (it does CREATE VIRTUAL TABLE
  // messages_fts USING fts5(...), which throws if the FTS5 module is absent). Confirm the table
  // materialized — do NOT call the fts5_version() SQL HELPER: this @evolu/@sqlite.org wasm build
  // ships the FTS5 MODULE but not the fts5_version() function, so selecting it throws
  // "no such function: fts5_version" and would fail the store open even though FTS5 works.
  const ftsOk = mustDb().selectValue(
    "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='messages_fts'",
  );
  if (!ftsOk) {
    throw new Error('FTS5 messages_fts table not created (FTS5 unavailable in this SQLite build)');
  }
}

// The SAH-pool VFS name we register; the cipher wrapper auto-creates "multipleciphers-<this>".
const SAHPOOL_VFS = 'opfs-sahpool';
const CIPHER_VFS = `multipleciphers-${SAHPOOL_VFS}`;

// Cached SAH-pool handle (the VFS may only be installed ONCE per worker; reused by the NOTADB
// self-heal path to unlink a specific corrupt file).
let poolUtil: OpfsSAHPool | null = null;

async function openDb(sqlite3: Sqlite3ApiObject, dbFile: string): Promise<Sqlite3Db> {
  const isolated =
    typeof self !== 'undefined' && (self as unknown as { crossOriginIsolated?: boolean }).crossOriginIsolated;
  if (isolated && typeof sqlite3.installOpfsSAHPoolVfs === 'function') {
    try {
      // 1. Register the real OPFS SAH-pool VFS under 'opfs-sahpool' — ONCE per worker (installing it
      //    twice under the same name throws). No SAB needed; only OPFS + cross-origin isolation,
      //    both satisfied by the shim's COOP/COEP.
      if (!poolUtil) poolUtil = await sqlite3.installOpfsSAHPoolVfs({ name: SAHPOOL_VFS });
      // 2. Open through the cipher-wrapped VFS name. SQLite3 Multiple Ciphers' sqlite3mcCheckVfs
      //    sees the "multipleciphers-" prefix, strips it, finds the real 'opfs-sahpool' VFS, and
      //    auto-creates+registers "multipleciphers-opfs-sahpool" layered over it (mcIoRead/mcIoWrite
      //    encrypt/decrypt each page around the real xRead/xWrite). We MUST use the plain oo1.DB
      //    ctor here — the OpfsSAHPoolDb subclass hardcodes the BARE 'opfs-sahpool' name and would
      //    bypass the wrapper, reproducing "Encryption is not supported by the VFS".
      const handle = new sqlite3.oo1.DB({
        filename: `file:/${dbFile}?vfs=${CIPHER_VFS}`,
        flags: 'c',
        vfs: CIPHER_VFS,
      });
      persistent = true;
      return handle;
    } catch (e) {
      console.warn('[store.worker] OPFS SAH pool / cipher VFS unavailable, falling back to in-memory:', e);
    }
  }
  persistent = false;
  // ':memory:' connection — session-only. NOTE: :memory: DBs are NOT file-backed, so the page cipher
  // cannot apply; PRAGMA key is effectively a no-op here. This fallback is unencrypted by nature and
  // is only reached when OPFS/isolation is missing (history is then session-only anyway).
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
 * Memory (persistent cross-conversation facts; device-only)
 * ------------------------------------------------------------------ */

/** Cheap token estimate (~4 chars/token) — enough for the memory-usage meter; no tokenizer needed. */
function estimateTokens(s: string): number {
  return Math.max(1, Math.ceil(s.length / 4));
}

function upsertMemory(key: string, value: string, previousKey?: string): void {
  tx(() => {
    // A rename (previousKey != key) drops the old row first so the meter/list don't double-count.
    if (previousKey && previousKey !== key) {
      run('DELETE FROM memories WHERE key = ?', [previousKey]);
    }
    run(
      `INSERT INTO memories (key, value, tokenCount, updatedAt)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, tokenCount=excluded.tokenCount, updatedAt=excluded.updatedAt`,
      [key, value, estimateTokens(value), Date.now()],
    );
  });
}

function deleteMemory(key: string): void {
  run('DELETE FROM memories WHERE key = ?', [key]);
}

function listMemories(): StoredMemory[] {
  const rows = query('SELECT key, value, tokenCount, updatedAt FROM memories ORDER BY updatedAt DESC');
  return rows.map((r) => ({
    key: String(r.key),
    value: String(r.value),
    tokenCount: Number(r.tokenCount),
    updatedAt: Number(r.updatedAt),
  }));
}

/* ------------------------------------------------------------------ *
 * Agents (user-authored assistant configs; device-only)
 * ------------------------------------------------------------------ */

function rowToAgent(r: Record<string, unknown>): StoredAgent {
  return {
    agentId: String(r.agentId),
    name: String(r.name),
    description: (r.description as string | null) ?? null,
    instructions: (r.instructions as string | null) ?? null,
    model: (r.model as string | null) ?? null,
    provider: (r.provider as string | null) ?? null,
    tools: (r.tools as string | null) ?? null,
    configJson: String(r.configJson),
    createdAt: Number(r.createdAt),
    updatedAt: Number(r.updatedAt),
  };
}

function upsertAgent(a: StoredAgent): void {
  run(
    `INSERT INTO agents
       (agentId, name, description, instructions, model, provider, tools, configJson, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(agentId) DO UPDATE SET
       name=excluded.name, description=excluded.description, instructions=excluded.instructions,
       model=excluded.model, provider=excluded.provider, tools=excluded.tools,
       configJson=excluded.configJson, updatedAt=excluded.updatedAt`,
    [a.agentId, a.name, a.description, a.instructions, a.model, a.provider, a.tools, a.configJson, a.createdAt, a.updatedAt],
  );
}

function getAgent(agentId: string): StoredAgent | null {
  const rows = query('SELECT * FROM agents WHERE agentId = ?', [agentId]);
  return rows.length ? rowToAgent(rows[0]!) : null;
}

function listAgents(): StoredAgent[] {
  return query('SELECT * FROM agents ORDER BY updatedAt DESC').map(rowToAgent);
}

function deleteAgent(agentId: string): void {
  run('DELETE FROM agents WHERE agentId = ?', [agentId]);
}

/* ---- Skills (reusable instruction snippets; device-only) ---- */

function rowToSkill(r: Record<string, unknown>): StoredSkill {
  return {
    skillId: String(r.skillId),
    name: String(r.name),
    description: (r.description as string | null) ?? null,
    body: String(r.body),
    createdAt: Number(r.createdAt),
    updatedAt: Number(r.updatedAt),
  };
}

function upsertSkill(s: StoredSkill): void {
  run(
    `INSERT INTO skills (skillId, name, description, body, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(skillId) DO UPDATE SET
       name=excluded.name, description=excluded.description, body=excluded.body, updatedAt=excluded.updatedAt`,
    [s.skillId, s.name, s.description, s.body, s.createdAt, s.updatedAt],
  );
}

function getSkill(skillId: string): StoredSkill | null {
  const rows = query('SELECT * FROM skills WHERE skillId = ?', [skillId]);
  return rows.length ? rowToSkill(rows[0]!) : null;
}

function listSkills(): StoredSkill[] {
  return query('SELECT * FROM skills ORDER BY updatedAt DESC').map(rowToSkill);
}

function deleteSkill(skillId: string): void {
  run('DELETE FROM skills WHERE skillId = ?', [skillId]);
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
    mustDb().exec('DELETE FROM memories');
    mustDb().exec('DELETE FROM agents');
    mustDb().exec('DELETE FROM skills');
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

    case 'UPSERT_MEMORY':
      upsertMemory(req.key, req.value, req.previousKey);
      return { type: 'OK', requestId: req.requestId };

    case 'DELETE_MEMORY':
      deleteMemory(req.key);
      return { type: 'OK', requestId: req.requestId };

    case 'LIST_MEMORIES':
      return { type: 'MEMORIES', requestId: req.requestId, memories: listMemories() };

    case 'UPSERT_AGENT':
      upsertAgent(req.agent);
      return { type: 'OK', requestId: req.requestId };

    case 'GET_AGENT':
      return { type: 'AGENT', requestId: req.requestId, agent: getAgent(req.agentId) };

    case 'LIST_AGENTS':
      return { type: 'AGENTS', requestId: req.requestId, agents: listAgents() };

    case 'UPSERT_SKILL':
      upsertSkill(req.skill);
      return { type: 'OK', requestId: req.requestId };
    case 'GET_SKILL':
      return { type: 'SKILL', requestId: req.requestId, skill: getSkill(req.skillId) };
    case 'LIST_SKILLS':
      return { type: 'SKILLS', requestId: req.requestId, skills: listSkills() };
    case 'DELETE_SKILL':
      deleteSkill(req.skillId);
      return { type: 'OK', requestId: req.requestId };
    case 'DELETE_AGENT':
      deleteAgent(req.agentId);
      return { type: 'OK', requestId: req.requestId };

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
