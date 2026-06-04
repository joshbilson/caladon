/**
 * Caladon device store — RPC contract (Batch 1 client foundation).
 *
 * A `requestId`-keyed, discriminated-union message protocol between the main thread
 * (StoreProxy in `client.ts`) and the single store Web Worker (`worker/store.worker.ts`).
 *
 * Trust model (LOCKED design): ALL of this runs on-device. The store key (hex of
 * `device_store_key(root)`) is delivered ONCE via `INIT` and never leaves the worker again.
 * Conversations + messages mirror LibreChat's `TConversation`/`TMessage` shape but carry a
 * lossless `convo_json` / `content_json` payload so nothing about the chat is dropped on the
 * round-trip through SQLite. RAG vectors (per-message chunk embeddings) live alongside so the
 * worker can serve history + FTS search + the on-device retrieval index from one place.
 *
 * Every request carries `requestId`; every response echoes it so the proxy can resolve the
 * matching Promise. Responses are one of the typed result shapes (Ok / Hydrate / ListConvos /
 * Search / Vectors) or a structured `Error`.
 */

/* ------------------------------------------------------------------ *
 * Persisted row shapes (mirror LibreChat TConversation / TMessage)
 * ------------------------------------------------------------------ */

/**
 * A persisted conversation row. Mirrors the salient `TConversation` fields the UI lists/sorts on;
 * `convoJson` is the lossless serialized `TConversation` so hydration is byte-for-byte faithful.
 */
export interface StoredConversation {
  conversationId: string;
  title: string | null;
  endpoint: string | null;
  model: string | null;
  createdAt: number;
  updatedAt: number;
  /** Lossless JSON of the full LibreChat `TConversation` (string, as stored). */
  convoJson: string;
}

/**
 * A persisted message row. Mirrors the salient `TMessage` fields; `contentJson` is the lossless
 * serialized `TMessage.content` (or the whole message) so rich content survives the round-trip.
 */
export interface StoredMessage {
  messageId: string;
  conversationId: string;
  parentMessageId: string | null;
  isCreatedByUser: boolean;
  text: string;
  /** Lossless JSON of the LibreChat `TMessage` content (string, as stored). May be null. */
  contentJson: string | null;
  model: string | null;
  createdAt: number;
  updatedAt: number;
}

/** One embedding chunk for a message: the chunk text + its dense vector (384-dim MiniLM). */
export interface VectorChunk {
  text: string;
  /** Float32 embedding (length 384 for Xenova/all-MiniLM-L6-v2). */
  vec: Float32Array;
}

/** A single FTS search hit: the message + a highlighted snippet + bm25 rank. */
export interface SearchHit {
  messageId: string;
  conversationId: string;
  /** Highlighted snippet (FTS5 `highlight()` / `snippet()` markup). */
  snippet: string;
  /** Lower (more negative) bm25 = better. */
  rank: number;
  createdAt: number;
}

/** One persisted vector row, keyed by the owning message + chunk ordinal. */
export interface StoredVector {
  messageId: string;
  ord: number;
  text: string;
  vec: Float32Array;
}

/* ------------------------------------------------------------------ *
 * Requests (main thread -> worker)
 * ------------------------------------------------------------------ */

/** Open/create the encrypted store. `hexKey` is the lowercase-hex of `device_store_key(root)`. */
export interface InitRequest {
  type: 'INIT';
  requestId: string;
  hexKey: string;
}

/** Persist one chat turn (the user message + the assistant reply) and upsert the conversation. */
export interface PersistTurnRequest {
  type: 'PERSIST_TURN';
  requestId: string;
  conversationId: string;
  userMsg: StoredMessage;
  assistantMsg: StoredMessage;
  convo: StoredConversation;
}

/** Load all messages (and the conversation row) for a conversation. */
export interface HydrateConvoRequest {
  type: 'HYDRATE_CONVO';
  requestId: string;
  conversationId: string;
}

/** List conversations (most-recently-updated first) for the sidebar. */
export interface ListConvosRequest {
  type: 'LIST_CONVOS';
  requestId: string;
  /** Optional page size; the proxy may page with `cursor`. */
  limit?: number;
  /** Keyset cursor: the `updatedAt` of the last row from the previous page. */
  cursor?: number;
}

/**
 * Fork a conversation at a message: create a new conversation containing the lineage from the
 * root down to `fromMessageId` (inclusive). Returns the new conversation's id in the Ok response.
 */
export interface ForkRequest {
  type: 'FORK';
  requestId: string;
  conversationId: string;
  fromMessageId: string;
}

/** Import a LibreChat-style chat export (the parsed JSON) into the store. */
export interface ImportRequest {
  type: 'IMPORT';
  requestId: string;
  /** Parsed chat-export JSON (LibreChat conversation export shape). */
  json: unknown;
}

/** Delete a conversation and all its messages/vectors (ON DELETE CASCADE). */
export interface DeleteConvoRequest {
  type: 'DELETE_CONVO';
  requestId: string;
  conversationId: string;
}

/** Full-text search over message text (FTS5 MATCH + highlight + bm25), keyset-paginated. */
export interface SearchRequest {
  type: 'SEARCH';
  requestId: string;
  query: string;
  limit?: number;
  /** Keyset cursor: the `rank` of the last hit from the previous page. */
  cursor?: number;
}

/** Persist the embedding chunks for a message (replaces any existing chunks for that message). */
export interface StoreVectorsRequest {
  type: 'STORE_VECTORS';
  requestId: string;
  messageId: string;
  chunks: VectorChunk[];
}

/** Load all persisted vectors so the main-thread retrieval index can be rebuilt. */
export interface HydrateVectorsRequest {
  type: 'HYDRATE_VECTORS';
  requestId: string;
}

/** Wipe every table (logout / panic). The store key reference is dropped on the next INIT. */
export interface ClearAllRequest {
  type: 'CLEAR_ALL';
  requestId: string;
}

/** The full request union. */
export type StoreRequest =
  | InitRequest
  | PersistTurnRequest
  | HydrateConvoRequest
  | ListConvosRequest
  | ForkRequest
  | ImportRequest
  | DeleteConvoRequest
  | SearchRequest
  | StoreVectorsRequest
  | HydrateVectorsRequest
  | ClearAllRequest;

/** Discriminant union of request `type`s. */
export type StoreRequestType = StoreRequest['type'];

/* ------------------------------------------------------------------ *
 * Responses (worker -> main thread)
 * ------------------------------------------------------------------ */

/** Generic success. `result` carries an op-specific payload (e.g. FORK's new conversationId). */
export interface OkResponse {
  type: 'OK';
  requestId: string;
  /** Optional op-specific scalar payload (e.g. the new conversationId from FORK). */
  result?: unknown;
}

/** Structured failure. The proxy rejects the matching Promise with this `message`. */
export interface ErrorResponse {
  type: 'ERROR';
  requestId: string;
  message: string;
  /** Optional machine-readable code (e.g. 'NOT_INITIALIZED', 'OPFS_UNAVAILABLE'). */
  code?: string;
}

/** A hydrated conversation: the conversation row + its messages (parent-ordered by createdAt). */
export interface HydrateResponse {
  type: 'HYDRATE';
  requestId: string;
  conversation: StoredConversation | null;
  messages: StoredMessage[];
}

/** A page of conversations for the sidebar. `nextCursor` is null when exhausted. */
export interface ListConvosResponse {
  type: 'LIST_CONVOS';
  requestId: string;
  conversations: StoredConversation[];
  nextCursor: number | null;
}

/** A page of FTS search hits. `nextCursor` is null when exhausted. */
export interface SearchResponse {
  type: 'SEARCH';
  requestId: string;
  hits: SearchHit[];
  nextCursor: number | null;
}

/** All persisted vectors, for rebuilding the in-memory retrieval index. */
export interface VectorsResponse {
  type: 'VECTORS';
  requestId: string;
  vectors: StoredVector[];
}

/** The full response union. */
export type StoreResponse =
  | OkResponse
  | ErrorResponse
  | HydrateResponse
  | ListConvosResponse
  | SearchResponse
  | VectorsResponse;

/** Discriminant union of response `type`s. */
export type StoreResponseType = StoreResponse['type'];
