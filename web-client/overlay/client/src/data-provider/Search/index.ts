/**
 * Caladon local search data-provider — public barrel (Batch 1 client foundation).
 *
 * Exposes `useLocalSearchQuery`, the on-device drop-in for LibreChat's `useMessagesInfiniteQuery`
 * (same signature + `MessagesListResponse` page shape) backed by the encrypted FTS5 store. The
 * Integrate phase swaps the import in `routes/Search.tsx` and flips `/api/search/enable` to the
 * local provider.
 */

export { useLocalSearchQuery } from './useLocalSearchQuery';
export { default } from './useLocalSearchQuery';
