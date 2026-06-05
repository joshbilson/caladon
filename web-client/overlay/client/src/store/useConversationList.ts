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
/** How long (ms) the just-unlocked window during which we re-assert the seed lasts, and the tick. */
const RESEED_WINDOW_MS = 4000;
const RESEED_TICK_MS = 200;
/** Max ticks to wait for the store worker to finish opening (OPFS init) after auth flips. */
const OPEN_WAIT_TICKS = 50;

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** True when the sidebar's allConversations cache holds at least one conversation. */
function listHasConversations(queryClient: ReturnType<typeof useQueryClient>): boolean {
  const data = queryClient.getQueryData<InfiniteData<ConversationCursorData>>(
    DEFAULT_ALL_CONVERSATIONS_KEY,
  );
  return !!data?.pages?.some((p) => p.conversations.length > 0);
}

export default function useConversationList(): void {
  const { isAuthenticated } = useAuthContext();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

    const store = getStoreProxy();
    let cancelled = false;

    // The sidebar reads history from `useConversationsInfiniteQuery` → GET /api/convos, which in
    // Caladon the shim stubs EMPTY (the gateway keeps no server-side conversation store). That
    // network query races our store seed and, whenever it resolves empty AFTER we seed, CLOBBERS
    // the seeded list back to nothing (the bug that left the sidebar blank on prod even though the
    // conversation persisted and hydrated fine). Pin the query so it treats seeded data as fresh
    // and never auto-refetches it away. (Defaults are read when the query is (re)observed; the
    // re-assert loop below is the hard guarantee against an already-in-flight empty fetch.)
    queryClient.setQueryDefaults([QueryKeys.allConversations], {
      staleTime: Infinity,
      gcTime: Infinity,
      refetchOnMount: false,
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
    });

    void (async () => {
      // Wait out the store open (openStore is awaited before auth flips, but the worker's OPFS
      // init can still trail the first effect run — poll briefly rather than bail with no retry).
      for (let i = 0; i < OPEN_WAIT_TICKS && !store.isOpen && !cancelled; i++) {
        await delay(RESEED_TICK_MS);
      }
      if (cancelled || !store.isOpen) {
        return;
      }

      let stored: TConversation[] = [];
      try {
        const { conversations } = await store.listConversations(SEED_PAGE_SIZE);
        if (cancelled) {
          return;
        }
        stored = conversations
          .map(toTConversation)
          .filter((c) => c.conversationId != null && c.conversationId !== Constants.NEW_CONVO);
      } catch (err) {
        // Best-effort: a failure must never break the sidebar.
        console.error('[caladon] failed to seed conversation list from device store:', err);
        return;
      }
      if (stored.length === 0) {
        return; // genuinely-empty identity — nothing to seed (and nothing to fight over).
      }

      // Seed, then re-assert for a short window so the empty /api/convos fetch can't leave the
      // sidebar blank: every tick where the list is empty, re-inject the stored conversations.
      // Bounded to the just-unlocked window so a later user-initiated "delete all" is NOT undone
      // (we only resurrect during the initial seed race, never afterwards).
      const seed = (): void => {
        // Ensure the canonical default key exists as well-formed empty InfiniteData so the fan-out
        // has a page-0 to prepend into (covers "sidebar query hasn't mounted yet").
        queryClient.setQueryData<InfiniteData<ConversationCursorData>>(
          DEFAULT_ALL_CONVERSATIONS_KEY,
          (old) =>
            old ?? { pageParams: [undefined], pages: [{ conversations: [], nextCursor: null }] },
        );
        // listConversations returns most-recently-updated FIRST; the fan-out prepends to page-0,
        // so insert in REVERSE to preserve newest-first order. De-dupes by id (idempotent).
        for (let i = stored.length - 1; i >= 0; i--) {
          addConversationToAllConversationsQueries(queryClient, stored[i]);
        }
      };

      const ticks = Math.ceil(RESEED_WINDOW_MS / RESEED_TICK_MS);
      for (let t = 0; t < ticks && !cancelled; t++) {
        if (!listHasConversations(queryClient)) {
          seed();
        }
        await delay(RESEED_TICK_MS);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, queryClient]);
}
