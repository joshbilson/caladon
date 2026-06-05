/**
 * Caladon device store — schema DDL (Batch 1 client foundation).
 *
 * One encrypted SQLite store (@evolu/sqlite-wasm = @sqlite.org/sqlite-wasm + SQLite3MultipleCiphers)
 * holding LibreChat-mirrored history + RAG chunks/embeddings + an FTS5 index over message text.
 *
 * Design notes:
 *  - `messages_fts` is an EXTERNAL CONTENT FTS5 table (content='messages', content_rowid='rowid')
 *    so the index does not duplicate the (already-encrypted) text; after-insert/update/delete
 *    triggers keep it in sync. FTS5 is built in to @sqlite.org/sqlite-wasm.
 *  - `convo_json` / `content_json` are lossless serializations of the LibreChat TConversation /
 *    TMessage so hydration is byte-faithful even as the upstream shape evolves.
 *  - `embeddings.vec` is a raw Float32 BLOB (little-endian, length 384*4 bytes for MiniLM). No
 *    sqlite-vec; the cosine index is rebuilt in memory on the main thread from these BLOBs.
 *  - `PRAGMA user_version = 1` marks the schema version for future migrations.
 *
 * This DDL is idempotent (`IF NOT EXISTS`) so re-opening an existing store is a no-op.
 */

export const SCHEMA_VERSION = 2;

export const SCHEMA_SQL = /* sql */ `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS conversations (
  conversationId TEXT PRIMARY KEY,
  title          TEXT,
  endpoint       TEXT,
  model          TEXT,
  createdAt      INTEGER NOT NULL,
  updatedAt      INTEGER NOT NULL,
  convo_json     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  messageId        TEXT PRIMARY KEY,
  conversationId   TEXT NOT NULL REFERENCES conversations(conversationId) ON DELETE CASCADE,
  parentMessageId  TEXT,
  isCreatedByUser  INTEGER NOT NULL DEFAULT 0,
  text             TEXT NOT NULL DEFAULT '',
  content_json     TEXT,
  model            TEXT,
  createdAt        INTEGER NOT NULL,
  updatedAt        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_conversationId
  ON messages(conversationId);
CREATE INDEX IF NOT EXISTS idx_messages_parentMessageId
  ON messages(parentMessageId);

-- External-content FTS5 over messages.text. Kept in sync by the triggers below.
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
  text,
  content='messages',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);

-- Keep the FTS index in lockstep with the content table.
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts(rowid, text) VALUES (new.rowid, new.text);
END;

CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
END;

CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text) VALUES ('delete', old.rowid, old.text);
  INSERT INTO messages_fts(rowid, text) VALUES (new.rowid, new.text);
END;

CREATE TABLE IF NOT EXISTS files (
  fileId         TEXT PRIMARY KEY,
  conversationId TEXT,
  name           TEXT NOT NULL,
  mime           TEXT,
  createdAt      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chunks (
  chunkId   TEXT PRIMARY KEY,
  fileId    TEXT NOT NULL REFERENCES files(fileId) ON DELETE CASCADE,
  ord       INTEGER NOT NULL,
  text      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chunks_fileId
  ON chunks(fileId);

CREATE TABLE IF NOT EXISTS embeddings (
  chunkId TEXT PRIMARY KEY REFERENCES chunks(chunkId) ON DELETE CASCADE,
  vec     BLOB NOT NULL
);

-- Embedding vectors for the STORE_VECTORS / HYDRATE_VECTORS path (the in-memory cosine index is
-- rebuilt from here). messageId is a generic owner key, NOT a foreign key into messages: the RAG
-- ingest stores UPLOADED-DOCUMENT vectors under a synthetic "doc:<fileId>" owner id (see useRag),
-- which is not a row in messages. A FK to messages here would (and did) make every document ingest
-- fail with SQLITE_CONSTRAINT_FOREIGNKEY. Deletion is explicit: storeVectors replaces an owner's
-- rows (DELETE-then-insert) and removeFile clears them, so no ON DELETE CASCADE is needed.
CREATE TABLE IF NOT EXISTS message_embeddings (
  messageId TEXT NOT NULL,
  ord       INTEGER NOT NULL,
  text      TEXT NOT NULL,
  vec       BLOB NOT NULL,
  PRIMARY KEY (messageId, ord)
);

CREATE INDEX IF NOT EXISTS idx_message_embeddings_messageId
  ON message_embeddings(messageId);

PRAGMA user_version = ${SCHEMA_VERSION};
`;
