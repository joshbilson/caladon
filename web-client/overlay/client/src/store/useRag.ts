/**
 * Caladon RAG — the ingest hook (Batch 1 client foundation).
 *
 * `useRag()` drives the on-device ingest pipeline for a file the user attaches for retrieval:
 *
 *   parse (in-browser)  →  chunk  →  embed (embed.worker)  →  StoreProxy.storeVectors  →  re-hydrate
 *
 * Every step runs on the device and NOTHING is uploaded: the file bytes are parsed locally
 * (parsers.ts), embedded locally (the same-origin MiniLM model in embed.worker), and the resulting
 * vectors are written to the SQLCipher-encrypted store. The vectors then become retrievable at chat
 * time via `augmentPromptWithRAG`, which seals the retrieved context before it ever leaves the
 * browser. This hook never calls the gateway.
 *
 * It is deliberately OFF the chat hot path: ingest is awaited by the attach UI (which shows
 * per-file progress), not by the send flow. Persisting vectors is the only durable side effect; the
 * in-memory index is force-re-hydrated afterwards so the new chunks are immediately retrievable.
 *
 * Style: matches the overlay's React conventions (function hook returning state + actions, toast for
 * user-facing errors). It does NOT use Recoil global state — ingest status is local to the attach
 * surface — but it lives under `~/store` per the agreed file layout.
 */

import { useCallback, useRef, useState } from 'react';
import { useToastContext } from '@librechat/client';
import { NotificationSeverity } from '@librechat/client';
import { getStoreProxy } from '~/lib/store';
import type { VectorChunk } from '~/lib/store';
import { parseBlob, detectKind, ParseError } from '~/lib/rag/parsers';
import { chunkText } from '~/lib/rag/chunker';
import { embedTexts, hydrateRagIndex } from '~/lib/rag/retrieval';

/* ------------------------------------------------------------------ *
 * Public state shapes
 * ------------------------------------------------------------------ */

export type RagFileStatus = 'parsing' | 'chunking' | 'embedding' | 'storing' | 'done' | 'error';

/** Per-file ingest record surfaced to the attach UI. */
export interface RagFile {
  /** Stable client id (also the messageId vectors are keyed under in the store). */
  id: string;
  name: string;
  status: RagFileStatus;
  /** Number of chunks produced (known after chunking). */
  chunks: number;
  /** Error message when `status === 'error'`. */
  error?: string;
}

export interface UseRagResult {
  /** The files ingested (or in-flight) this session, in attach order. */
  files: RagFile[];
  /** True while any file is still being ingested. */
  isIngesting: boolean;
  /** Ingest one or more attached files (parse → chunk → embed → store). Resolves when all settle. */
  ingestFiles: (files: File[] | FileList) => Promise<void>;
  /** Remove a file's vectors from the store and the in-memory list. */
  removeFile: (id: string) => Promise<void>;
  /** Clear the session list (does not delete persisted vectors). */
  clear: () => void;
}

/* ------------------------------------------------------------------ *
 * Constants
 * ------------------------------------------------------------------ */

/** Embed in batches so a large document doesn't hand the worker one giant array. */
const EMBED_BATCH = 16;

/** Vectors for an ingested document are keyed under a synthetic "doc:" messageId in the store. */
function docMessageId(fileId: string): string {
  return `doc:${fileId}`;
}

function newFileId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `f_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

/* ------------------------------------------------------------------ *
 * Hook
 * ------------------------------------------------------------------ */

export function useRag(): UseRagResult {
  const { showToast } = useToastContext();
  const [files, setFiles] = useState<RagFile[]>([]);
  const [inFlight, setInFlight] = useState(0);

  // Guard against a re-render losing the latest setter when many files update concurrently.
  const setFileState = useCallback((id: string, patch: Partial<RagFile>) => {
    setFiles((prev) => prev.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  }, []);

  // Keep a ref of ids currently mounted so an unmount-during-ingest doesn't throw on setState.
  const mounted = useRef(true);

  const ingestOne = useCallback(
    async (file: File): Promise<void> => {
      const id = newFileId();
      const kind = detectKind(file.name, file.type);
      const record: RagFile = { id, name: file.name, status: 'parsing', chunks: 0 };

      if (kind === 'unsupported') {
        record.status = 'error';
        record.error = 'Unsupported file type for retrieval.';
        setFiles((prev) => [...prev, record]);
        showToast({
          message: `Can't index "${file.name}": unsupported file type.`,
          severity: NotificationSeverity.WARNING,
        });
        return;
      }

      setFiles((prev) => [...prev, record]);
      setInFlight((n) => n + 1);

      try {
        // 1. Parse on-device (never uploaded).
        const parsed = await parseBlob(file);
        if (!parsed.text.trim()) {
          throw new ParseError('No extractable text found in the document.');
        }

        // 2. Chunk.
        setFileState(id, { status: 'chunking' });
        const chunks = chunkText(parsed.text);
        if (chunks.length === 0) {
          throw new ParseError('Document produced no indexable chunks.');
        }
        setFileState(id, { chunks: chunks.length });

        // 3. Embed on-device, in batches, in the embed worker.
        setFileState(id, { status: 'embedding' });
        const vectors: Float32Array[] = [];
        for (let i = 0; i < chunks.length; i += EMBED_BATCH) {
          const batch = chunks.slice(i, i + EMBED_BATCH);
          const embedded = await embedTexts(batch);
          vectors.push(...embedded);
        }
        if (vectors.length !== chunks.length) {
          throw new Error('Embedding produced an unexpected vector count.');
        }

        // 4. Persist to the encrypted store (replaces any prior vectors for this doc id).
        setFileState(id, { status: 'storing' });
        const vectorChunks: VectorChunk[] = chunks.map((text, ord) => ({
          text,
          vec: vectors[ord]!,
        }));
        await getStoreProxy().storeVectors(docMessageId(id), vectorChunks);

        // 5. Re-hydrate the in-memory cosine index so the new chunks are immediately retrievable.
        await hydrateRagIndex(true);

        setFileState(id, { status: 'done' });
      } catch (err) {
        const message =
          err instanceof ParseError
            ? err.message
            : err instanceof Error
              ? err.message
              : 'Failed to index the document.';
        setFileState(id, { status: 'error', error: message });
        showToast({
          message: `Couldn't index "${file.name}": ${message}`,
          severity: NotificationSeverity.ERROR,
        });
      } finally {
        if (mounted.current) setInFlight((n) => Math.max(0, n - 1));
      }
    },
    [setFileState, showToast],
  );

  const ingestFiles = useCallback(
    async (input: File[] | FileList): Promise<void> => {
      const list = Array.from(input);
      // Ingest sequentially: the embed worker serializes anyway, and this keeps progress legible
      // and memory bounded for multi-file attaches.
      for (const file of list) {
        // eslint-disable-next-line no-await-in-loop
        await ingestOne(file);
      }
    },
    [ingestOne],
  );

  const removeFile = useCallback(async (id: string): Promise<void> => {
    setFiles((prev) => prev.filter((f) => f.id !== id));
    try {
      // Replace with an empty set to drop this doc's vectors from the store, then re-hydrate.
      await getStoreProxy().storeVectors(docMessageId(id), []);
      await hydrateRagIndex(true);
    } catch (e) {
      console.warn('[rag] removeFile failed to clear vectors:', e);
    }
  }, []);

  const clear = useCallback(() => setFiles([]), []);

  return {
    files,
    isIngesting: inFlight > 0,
    ingestFiles,
    removeFile,
    clear,
  };
}

export default useRag;
