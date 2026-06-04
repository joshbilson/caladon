/**
 * Caladon device-store rehydration — single-conversation history restore (Batch 1 client foundation).
 *
 * On a hard reload / deep-link to `/c/<id>`, LibreChat's chat view reads messages from the
 * React Query cache under `[QueryKeys.messages, id]` and the active conversation under
 * `[QueryKeys.conversation, id]`. In Caladon the gateway has NO server-side message store
 * (the shim stubs /api/convos + /api/messages empty), and the messages query is mounted with
 * `refetchOnMount: false` — so whatever we seed into that cache key is what renders, and it is
 * NOT clobbered by a refetch.
 *
 * This hook restores that history from the on-device encrypted store: gated on an unlocked
 * (authenticated) session, a real (non-"new"/non-PENDING) conversation id, and an OPEN store,
 * it awaits `StoreProxy.hydrate(id)` and — ONLY when the cache for that id is still empty —
 * seeds `[QueryKeys.messages, id]` and `[QueryKeys.conversation, id]` exactly the way
 * `useSSE`'s `finalHandler` writes them (`TMessage[]` and `TConversation`, respectively).
 *
 * Trust model (LOCKED): the store key + plaintext live only on-device; nothing here touches the
 * network. We never overwrite a cache that already holds messages (e.g. a turn the user just sent),
 * so live state always wins over the persisted snapshot.
 */

import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { QueryKeys, Constants } from 'librechat-data-provider';
import type { TMessage, TConversation } from 'librechat-data-provider';
import { useAuthContext } from '~/hooks/AuthContext';
import { getStoreProxy } from '~/lib/store';
import type { StoredConversation, StoredMessage } from '~/lib/store';

/** Ids that are not yet a persisted conversation — never hydrate these. */
function isRealConversationId(id: string | undefined | null): id is string {
  return (
    id != null &&
    id !== '' &&
    id !== Constants.NEW_CONVO &&
    id !== Constants.PENDING_CONVO &&
    id !== Constants.SEARCH
  );
}

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

/**
 * Reconstruct a LibreChat `TMessage` from a persisted row. Prefers the lossless `contentJson`
 * (so rich content survives the round-trip); falls back to the salient columns. `contentJson`
 * may hold either the full serialized message or just `TMessage.content` — handle both.
 */
function toTMessage(row: StoredMessage): TMessage {
  const parsed = safeParse<Record<string, unknown>>(row.contentJson);

  // Case A: the lossless payload is the whole message (it carries a messageId).
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && 'messageId' in parsed) {
    return parsed as unknown as TMessage;
  }

  // Case B: the lossless payload is just the content (array of parts) — or absent.
  const content = parsed as TMessage['content'] | undefined;
  return {
    messageId: row.messageId,
    conversationId: row.conversationId,
    parentMessageId: row.parentMessageId ?? Constants.NO_PARENT,
    isCreatedByUser: row.isCreatedByUser,
    text: row.text,
    ...(content != null ? { content } : {}),
    ...(row.model != null ? { model: row.model } : {}),
    createdAt: new Date(row.createdAt).toISOString(),
    updatedAt: new Date(row.updatedAt).toISOString(),
    error: false,
    unfinished: false,
  } as unknown as TMessage;
}

/**
 * Reconstruct a LibreChat `TConversation` from a persisted row. Prefers the lossless `convoJson`;
 * falls back to the salient columns so the title/endpoint/model still render.
 */
function toTConversation(row: StoredConversation): TConversation {
  const parsed = safeParse<TConversation>(row.convoJson);
  if (parsed && typeof parsed === 'object') {
    // Guarantee the id even if the serialized blob somehow lost it.
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

/**
 * Restore a conversation's messages + metadata from the on-device store into the React Query
 * cache, but only when that cache is still empty (so we never clobber live/streamed state).
 *
 * @param conversationId the active conversation id from the route (`useParams`), may be "new".
 */
export default function useHydrateConversation(conversationId: string | undefined | null): void {
  const { isAuthenticated } = useAuthContext();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!isAuthenticated || !isRealConversationId(conversationId)) {
      return;
    }

    const store = getStoreProxy();
    // The proxy's methods await an internal `ready` that only resolves after `openStore`. If the
    // store isn't open yet (pre-unlock, or OPFS init still pending), bail and let a later run —
    // re-triggered when `isAuthenticated`/`conversationId` change — pick it up.
    if (!store.isOpen) {
      return;
    }

    // Live state always wins: if the messages cache already has entries for this id (e.g. the
    // user just sent a turn, or another mount already hydrated), do nothing.
    const cached = queryClient.getQueryData<TMessage[]>([QueryKeys.messages, conversationId]);
    if (cached && cached.length > 0) {
      return;
    }

    let cancelled = false;

    void (async () => {
      try {
        const { conversation, messages } = await store.hydrate(conversationId);
        if (cancelled) {
          return;
        }

        // Re-check after the await: a turn may have landed while we were reading the store.
        const nowCached = queryClient.getQueryData<TMessage[]>([
          QueryKeys.messages,
          conversationId,
        ]);
        if (nowCached && nowCached.length > 0) {
          return;
        }

        // Nothing persisted for this id — leave the cache untouched (the view shows empty/loads).
        if (messages.length === 0 && conversation == null) {
          return;
        }

        // Seed messages exactly like finalHandler: `[QueryKeys.messages, id] -> TMessage[]`.
        const tMessages = messages.map(toTMessage);
        queryClient.setQueryData<TMessage[]>([QueryKeys.messages, conversationId], tMessages);

        // Seed the active conversation: `[QueryKeys.conversation, id] -> TConversation`.
        if (conversation != null) {
          queryClient.setQueryData<TConversation>(
            [QueryKeys.conversation, conversationId],
            toTConversation(conversation),
          );
        }
      } catch (err) {
        // Hydration is best-effort; a failure must never break the chat view.
        console.error('[caladon] failed to hydrate conversation from device store:', err);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, conversationId, queryClient]);
}
