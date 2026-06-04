/**
 * Caladon local search query (Batch 1 client foundation).
 *
 * A DROP-IN replacement for LibreChat's `useMessagesInfiniteQuery`, but backed entirely by the
 * on-device encrypted store (`StoreProxy.search` over the FTS5 index) instead of `/api/search`.
 * Same call signature, same React Query shape, same `MessagesListResponse` page shape
 * (`{ messages: TMessage[]; nextCursor }`) so `routes/Search.tsx` can swap one import and nothing
 * downstream (`SearchMessage` / `SearchContent` / `useNavScrolling`) needs to change.
 *
 * Trust model (LOCKED): the query never touches the network. Plaintext message text + the FTS5
 * index live only in the device store; this hook just renders hits the worker already has.
 *
 * Mapping the store's `SearchHit` onto a `TMessage`:
 *   - The store returns a `snippet` with `<mark>…</mark>` highlight markup. `SearchContent`'s
 *     fallback path renders `message.text` through `MarkdownLite`, which (deliberately) carries no
 *     `rehype-raw`, so raw `<mark>` HTML would render as literal text. We therefore translate the
 *     highlight into Markdown strong emphasis (`**…**`) — exactly how the rest of the overlay
 *     highlights matched text (cf. `VariableForm`) — and place it in `message.text`.
 *   - `content` is left empty so `SearchContent` takes the text/markdown branch (not the
 *     content-parts branch), and `searchResult` is set so the message is treated as a search row.
 *
 * Pagination: the store keysets on bm25 `rank` (lower = better). We encode a composite
 * `rank:createdAt` string as the React Query `pageParam` for a stable keyset (rank is the primary
 * key; `createdAt` disambiguates rank ties across pages) and hand the numeric `rank` to
 * `StoreProxy.search`.
 */
import { useInfiniteQuery } from '@tanstack/react-query';
import { QueryKeys, Constants } from 'librechat-data-provider';
import type { UseInfiniteQueryOptions } from '@tanstack/react-query';
import type {
  TMessage,
  MessagesListParams,
  MessagesListResponse,
} from 'librechat-data-provider';
import { getStoreProxy } from '~/lib/store';
import type { SearchHit } from '~/lib/store';

/** Default page size, mirroring the server search default. */
const DEFAULT_LIMIT = 20;

/**
 * Encode a keyset cursor from the last hit of a page: `"<rank>:<createdAt>"`.
 * `null` once the page is short (no further pages).
 */
function encodeCursor(hits: SearchHit[], limit: number): string | null {
  if (hits.length < limit) {
    return null;
  }
  const last = hits[hits.length - 1];
  return `${last.rank}:${last.createdAt}`;
}

/** Decode the numeric bm25 `rank` from a `"<rank>:<createdAt>"` cursor (undefined for page 1). */
function decodeRankCursor(pageParam: unknown): number | undefined {
  if (typeof pageParam !== 'string' || pageParam.length === 0) {
    return undefined;
  }
  const rank = Number.parseFloat(pageParam.split(':')[0]);
  return Number.isFinite(rank) ? rank : undefined;
}

/**
 * Translate the store's `<mark>…</mark>` highlight snippet into Markdown strong emphasis so it
 * renders as a highlight through `MarkdownLite` (which has no `rehype-raw`). Any other stray HTML
 * tags in the snippet are stripped to plain text — the snippet is local, but we still never inject
 * raw HTML into the markdown renderer.
 */
function snippetToText(snippet: string): string {
  return snippet
    .replace(/<mark>/gi, '**')
    .replace(/<\/mark>/gi, '**')
    .replace(/<[^>]+>/g, '');
}

/** Map one FTS hit onto a minimal-but-faithful `TMessage` the search UI can render. */
function hitToMessage(hit: SearchHit): TMessage {
  return {
    messageId: hit.messageId,
    conversationId: hit.conversationId,
    parentMessageId: Constants.NO_PARENT,
    text: snippetToText(hit.snippet),
    isCreatedByUser: false,
    searchResult: true,
    createdAt: new Date(hit.createdAt).toISOString(),
    updatedAt: new Date(hit.createdAt).toISOString(),
    error: false,
    unfinished: false,
  } as TMessage;
}

/**
 * Local, on-device equivalent of `useMessagesInfiniteQuery`. Same signature and page shape; the
 * `search` param drives a FTS5 query against the device store. When `search` is empty the query
 * stays disabled (the store is never hit), matching the server hook's behavior on `routes/Search`.
 */
export const useLocalSearchQuery = (
  params: MessagesListParams,
  config?: UseInfiniteQueryOptions<MessagesListResponse, unknown>,
) => {
  const { search, pageSize } = params;
  const query = (search ?? '').trim();
  const limit = pageSize ?? DEFAULT_LIMIT;

  return useInfiniteQuery<MessagesListResponse>({
    queryKey: [QueryKeys.messages, { search: query }],
    queryFn: async ({ pageParam }) => {
      if (query === '') {
        return { messages: [], nextCursor: null };
      }
      const store = getStoreProxy();
      const { hits } = await store.search(query, limit, decodeRankCursor(pageParam));
      return {
        messages: hits.map(hitToMessage),
        nextCursor: encodeCursor(hits, limit),
      };
    },
    getNextPageParam: (lastPage) => lastPage?.nextCursor ?? undefined,
    keepPreviousData: true,
    staleTime: 5 * 60 * 1000, // 5 minutes
    cacheTime: 30 * 60 * 1000, // 30 minutes
    enabled: query !== '',
    ...config,
  });
};

export default useLocalSearchQuery;
