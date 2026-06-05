/**
 * Caladon device store — public barrel (Batch 1 client foundation).
 *
 * The on-device encrypted SQLite store: one @evolu/sqlite-wasm DB (SQLCipher-keyed with
 * `device_store_key(root)`) behind a single Web Worker, serving LibreChat history, FTS5 search,
 * and the RAG vector index. Feature code imports the proxy + key derivation from here.
 *
 *   import { getStoreProxy, deriveStoreKeyHex } from '~/lib/store';
 *
 * Trust model (LOCKED): plaintext + the store key exist only on-device. The key never leaves the
 * worker after INIT; RAG context is injected before sealing; nothing here ever talks to the network.
 */

export { StoreProxy, getStoreProxy, resetStoreProxy } from './client';
export { deriveStoreKeyHex, deriveStoreKeyHexFrom } from './kdf';
export type { StoreKeyWasm, DeviceStoreWasm } from './kdf';
export { SCHEMA_SQL, SCHEMA_VERSION } from './schema.sql';

export type {
  // RPC contract
  StoreRequest,
  StoreResponse,
  StoreRequestType,
  StoreResponseType,
  // Persisted shapes
  StoredConversation,
  StoredMessage,
  StoredVector,
  StoredMemory,
  VectorChunk,
  SearchHit,
  // Request shapes
  InitRequest,
  PersistTurnRequest,
  HydrateConvoRequest,
  ListConvosRequest,
  ForkRequest,
  ImportRequest,
  DeleteConvoRequest,
  SearchRequest,
  StoreVectorsRequest,
  HydrateVectorsRequest,
  ClearAllRequest,
  // Response shapes
  OkResponse,
  ErrorResponse,
  HydrateResponse,
  ListConvosResponse,
  SearchResponse,
  VectorsResponse,
} from './types';
