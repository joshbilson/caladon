/**
 * Caladon — useImportConversation (Batch 1 client foundation, in-browser import).
 *
 * Upstream LibreChat imports a ChatGPT / LibreChat export by UPLOADING the `.json` to the gateway
 * (`useUploadConversationsMutation` → multipart POST). Caladon does the OPPOSITE: the file is read
 * ENTIRELY in the browser with `FileReader`, parsed to JSON, and handed to the on-device store
 * (`StoreProxy.importChatExport(json)`), which maps it to `TConversation` / `TMessage` rows and
 * writes them into the encrypted SQLite store inside its worker transaction. The file's bytes NEVER
 * leave the device — no upload, no FormData, no network. After the import we invalidate the
 * conversation-list queries so the sidebar shows the imported chats.
 *
 * We do a light, defensive parse here (valid JSON + a recognizable export shape) purely to fail fast
 * with a useful error; the authoritative mapping (ChatGPT mapping-tree vs LibreChat array vs single
 * conversation) lives in the worker so plaintext + the schema mapping stay on the trusted side.
 *
 * Trust model (LOCKED): plaintext exists only on-device; the store key never leaves the worker; this
 * hook reads the user-chosen file locally and passes opaque parsed JSON straight into the store.
 */

import { useCallback, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { InfiniteData } from '@tanstack/react-query';
import { QueryKeys, Constants } from 'librechat-data-provider';
import type { TConversation } from 'librechat-data-provider';
import { addConversationToAllConversationsQueries } from '~/utils';
import type { ConversationCursorData } from '~/utils';
import { getStoreProxy } from '~/lib/store';
import type { StoredConversation } from '~/lib/store';

export interface UseImportConversationOptions {
  onSuccess?: () => void;
  onError?: (error: unknown) => void;
  /** Called synchronously when import starts (e.g. to show an "importing…" toast / spinner). */
  onMutate?: () => void;
  /**
   * Optional cap on the file size accepted (bytes). The whole point is local processing, but a
   * pathologically large file would still block the main thread on `FileReader`/`JSON.parse`, so
   * the caller may pass a limit (e.g. from startup config) to reject early.
   */
  maxFileSizeBytes?: number;
}

/** Thrown for a file that isn't valid JSON or isn't a recognizable chat-export shape. */
export class UnsupportedImportError extends Error {
  constructor(message = 'Unsupported import type') {
    super(message);
    this.name = 'UnsupportedImportError';
  }
}

/** The canonical default `allConversations` key the sidebar's query registers (no tags/search). */
const DEFAULT_ALL_CONVERSATIONS_KEY = [
  QueryKeys.allConversations,
  {
    isArchived: undefined,
    sortBy: undefined,
    sortDirection: undefined,
    tags: undefined,
    search: undefined,
  },
] as const;

/** Best-effort JSON parse; returns `undefined` on any malformed payload (never throws). */
function safeParse<T = unknown>(json: string | null | undefined): T | undefined {
  if (json == null || json === '') {
    return undefined;
  }
  try {
    return JSON.parse(json) as T;
  } catch {
    return undefined;
  }
}

/** Reconstruct a `TConversation` from a stored row (prefers the lossless `convoJson`). */
function toTConversation(row: StoredConversation): TConversation {
  const parsed = safeParse<TConversation>(row.convoJson);
  if (parsed && typeof parsed === 'object') {
    return { ...parsed, conversationId: parsed.conversationId ?? row.conversationId } as TConversation;
  }
  return {
    conversationId: row.conversationId,
    title: row.title ?? 'New Chat',
    endpoint: row.endpoint,
    model: row.model,
    createdAt: new Date(row.createdAt).toISOString(),
    updatedAt: new Date(row.updatedAt).toISOString(),
  } as unknown as TConversation;
}

/** Read a File fully in-browser as text. Rejects on read error. NEVER uploads. */
function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
    reader.onerror = () => reject(reader.error ?? new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

/**
 * A shallow shape check: is this parsed JSON plausibly a chat export we can hand to the store?
 * Recognizes the three common shapes:
 *   - LibreChat single-conversation export: `{ conversationId, messages: [...] }` or has `messages`
 *   - LibreChat / generic array of conversations: `[ {...}, {...} ]`
 *   - ChatGPT export: `{ mapping: {...} }` or an array of `{ mapping }` objects
 * The worker owns the precise mapping; this only rejects obvious garbage so we can show a clean
 * "unsupported file" error instead of a cryptic worker rejection.
 */
function looksLikeChatExport(json: unknown): boolean {
  if (Array.isArray(json)) {
    return json.length === 0 || json.some((item) => looksLikeChatExport(item));
  }
  if (json != null && typeof json === 'object') {
    const obj = json as Record<string, unknown>;
    return (
      'messages' in obj ||
      'mapping' in obj ||
      'conversationId' in obj ||
      'conversation_id' in obj ||
      'recordType' in obj || // LibreChat export envelope
      'conversations' in obj
    );
  }
  return false;
}

/**
 * In-browser conversation import. Returns `importFile(file)` (reads + parses + stores + refreshes)
 * and `isImporting` for button/spinner state.
 */
export function useImportConversation(options: UseImportConversationOptions = {}) {
  const { onSuccess, onError, onMutate, maxFileSizeBytes } = options;
  const queryClient = useQueryClient();
  const [isImporting, setIsImporting] = useState(false);

  const importFile = useCallback(
    async (file: File): Promise<boolean> => {
      if (!file) {
        return false;
      }
      if (maxFileSizeBytes != null && file.size > maxFileSizeBytes) {
        const err = new Error('File too large');
        onError?.(err);
        return false;
      }

      setIsImporting(true);
      onMutate?.();
      try {
        // 1) Read the user-selected file locally. Nothing is uploaded.
        const text = await readFileAsText(file);

        // 2) Parse to JSON (fail fast on a non-JSON file).
        let json: unknown;
        try {
          json = JSON.parse(text);
        } catch {
          throw new UnsupportedImportError('Selected file is not valid JSON');
        }

        // 3) Reject obviously-unsupported shapes before bothering the store.
        if (!looksLikeChatExport(json)) {
          throw new UnsupportedImportError();
        }

        // 4) Hand the parsed JSON to the on-device store; the worker maps + persists it.
        const store = getStoreProxy();
        await store.importChatExport(json);

        // 5) Refresh the sidebar DIRECTLY from the store. We must NOT invalidate the
        //    `allConversations` query here: in Caladon that query is backed by the shim's
        //    /api/convos stub, which returns an EMPTY list — invalidating would refetch that empty
        //    response and CLOBBER the cache, and useConversationList (deps: [isAuthenticated,
        //    queryClient]) does not re-run on import, so the imported chats would never appear. The
        //    authoritative source is the on-device store, so we re-read it and seed the sidebar
        //    cache the same way useConversationList does (fan-out + de-dupe by conversationId).
        const { conversations } = await store.listConversations(200);
        if (conversations.length > 0) {
          queryClient.setQueryData<InfiniteData<ConversationCursorData>>(
            DEFAULT_ALL_CONVERSATIONS_KEY,
            (old) =>
              old ?? {
                pageParams: [undefined],
                pages: [{ conversations: [], nextCursor: null }],
              },
          );
          const tConvos = conversations.map(toTConversation);
          // listConversations returns newest-first; insert in reverse so the fan-out (which prepends)
          // preserves newest-first ordering.
          for (let i = tConvos.length - 1; i >= 0; i--) {
            const convo = tConvos[i];
            if (convo.conversationId == null || convo.conversationId === Constants.NEW_CONVO) {
              continue;
            }
            addConversationToAllConversationsQueries(queryClient, convo);
          }
        }

        onSuccess?.();
        return true;
      } catch (error) {
        onError?.(error);
        return false;
      } finally {
        setIsImporting(false);
      }
    },
    [queryClient, onMutate, onSuccess, onError, maxFileSizeBytes],
  );

  return { importFile, isImporting };
}

export default useImportConversation;
