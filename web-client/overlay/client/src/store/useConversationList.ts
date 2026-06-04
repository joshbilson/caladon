/**
 * Caladon device-store rehydration — sidebar conversation list (Batch 1 client foundation).
 *
 * The sidebar (`ConversationsSection`) reads history from an INFINITE React Query under
 * `[QueryKeys.allConversations, { isArchived, sortBy, sortDirection, tags, search }]` via
 * `useConversationsInfiniteQuery`. In Caladon the gateway has NO server-side conversation store
 * (the shim stubs /api/convos empty), so that query resolves to nothing and the sidebar is blank
 * after a reload.
 *
 * This hook restores the list from the on-device encrypted store: gated on an unlocked
 * (authenticated) session and an OPEN store, it pulls `StoreProxy.listConversations()` and seeds
 * the `allConversations` cache so the sidebar shows persisted history immediately. We seed the
 * `InfiniteData<ConversationCursorData>` shape LibreChat expects (`{ pages: [{ conversations,
 * nextCursor }], pageParams }`), reusing the same `addConversationToAllConversationsQueries`
 * prefix-fan-out the event handlers use — so it lands under every mounted `allConversations`
 * variant (tags/search permutations) without us guessing the exact key — plus the canonical
 * default key so the list is populated even before its own query first runs.
 *
 * Trust model (LOCKED): plaintext + the store key live only on-device; nothing here hits the
 * network. We never overwrite a conversation already present in the cache (live state wins).
 */

import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { InfiniteData } from '@tanstack/react-query';
import { QueryKeys, Constants } from 'librechat-data-provider';
import type { TConversation } from 'librechat-data-provider';
import { addConversationToAllConversationsQueries } from '~/utils';
import type { ConversationCursorData } from '~/utils';
import { useAuthContext } from '~/hooks/AuthContext';
import { getStoreProxy } from '~/lib/store';
import type { StoredConversation } from '~/lib/store';

/** Page size to pull from the store for the initial sidebar seed. */
const SEED_PAGE_SIZE = 50;

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

/**
 * Reconstruct a LibreChat `TConversation` from a persisted row. Prefers the lossless `convoJson`
 * (so the sidebar renders the exact stored conversation); falls back to the salient columns.
 */
function toTConversation(row: StoredConversation): TConversation {
  const parsed = safeParse<TConversation>(row.convoJson);
  if (parsed && typeof parsed === 'object') {
    return {
      ...parsed,
      conversationId: parsed.conversationId ?? row.conversationId,
    } as TConversation;
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
 * On unlock, seed the sidebar's `allConversations` cache from the on-device store so persisted
 * history is visible after a reload. Idempotent: re-running only adds conversations the cache
 * doesn't already hold (live state wins), and the seed is skipped once the cache is non-empty.
 */
export default function useConversationList(): void {
  const { isAuthenticated } = useAuthContext();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

    const store = getStoreProxy();
    // The proxy awaits an internal `ready` that only resolves after `openStore`. If the store
    // isn't open yet (pre-unlock / OPFS init pending), bail; a later run (re-triggered when
    // `isAuthenticated` flips) will seed it.
    if (!store.isOpen) {
      return;
    }

    // If the sidebar cache already holds conversations (a fresh turn, or a prior seed), skip:
    // live state always wins over the persisted snapshot.
    const existing = queryClient.getQueryData<InfiniteData<ConversationCursorData>>(
      DEFAULT_ALL_CONVERSATIONS_KEY,
    );
    if (existing?.pages?.some((p) => p.conversations.length > 0)) {
      return;
    }

    let cancelled = false;

    void (async () => {
      try {
        const { conversations } = await store.listConversations(SEED_PAGE_SIZE);
        if (cancelled || conversations.length === 0) {
          return;
        }

        // Ensure the canonical default key exists as a well-formed empty InfiniteData so the
        // fan-out below has a page-0 to prepend into (covers "sidebar hasn't mounted yet").
        queryClient.setQueryData<InfiniteData<ConversationCursorData>>(
          DEFAULT_ALL_CONVERSATIONS_KEY,
          (old) =>
            old ?? {
              pageParams: [undefined],
              pages: [{ conversations: [], nextCursor: null }],
            },
        );

        // `listConversations` returns most-recently-updated FIRST; the fan-out prepends each
        // conversation to page-0, so insert in REVERSE to preserve newest-first ordering.
        const tConvos = conversations.map(toTConversation);
        for (let i = tConvos.length - 1; i >= 0; i--) {
          const convo = tConvos[i];
          if (convo.conversationId == null || convo.conversationId === Constants.NEW_CONVO) {
            continue;
          }
          // Prefix-matches every mounted `allConversations` variant AND the default key seeded
          // above; de-dupes by conversationId so re-running never double-inserts.
          addConversationToAllConversationsQueries(queryClient, convo);
        }
      } catch (err) {
        // Best-effort: a failure must never break the sidebar.
        console.error('[caladon] failed to seed conversation list from device store:', err);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, queryClient]);
}
