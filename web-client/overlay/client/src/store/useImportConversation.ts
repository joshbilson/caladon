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
import { QueryKeys } from 'librechat-data-provider';
import { getStoreProxy } from '~/lib/store';

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
        await getStoreProxy().importChatExport(json);

        // 5) Refresh the sidebar: the imported conversations come from the store, so invalidate the
        //    list queries to re-pull them (active + archived buckets).
        await Promise.all([
          queryClient.invalidateQueries([QueryKeys.allConversations]),
          queryClient.invalidateQueries([QueryKeys.archivedConversations]),
        ]);

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
