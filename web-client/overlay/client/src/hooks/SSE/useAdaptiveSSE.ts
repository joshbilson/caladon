import type { TSubmission } from 'librechat-data-provider';
import type { EventHandlerParams } from './useEventHandlers';
import useResumableSSE from './useResumableSSE';
import useSSE from './useSSE';

type ChatHelpers = Pick<
  EventHandlerParams,
  'setMessages' | 'getMessages' | 'setConversation' | 'setIsSubmitting' | 'newConversation'
>;

/**
 * Caladon surgery (SURGERY.md §B2/§D4) — FORCE the standard, sealed+signed `useSSE` path for EVERY
 * chat turn; the resumable path is hard-disabled.
 *
 * Upstream `useAdaptiveSSE` defaults to `useResumableSSE` for all non-assistants endpoints. That
 * path does a `startGeneration` pre-flight which POSTs the **plaintext** submission to the chat
 * route with NO Caladon signed `Authorization` header — it is NOT wired through the Caladon
 * seal/sign in the overlay's `useSSE`. Against the attested gateway that yields a 401 (the gateway
 * rejects the unsigned request) and, worse, would put plaintext on the wire if it didn't. The whole
 * trust model requires the prompt to be sealed and the request signed in the browser before it
 * leaves, which is exactly what the overlay's `useSSE` does (seal prompt → sign → open sealed
 * deltas). So we always drive `useSSE` with the real submission and feed `useResumableSSE` a `null`
 * submission so it never fires (both are still called, per React's Rules of Hooks).
 */
export default function useAdaptiveSSE(
  submission: TSubmission | null,
  chatHelpers: ChatHelpers,
  isAddedRequest = false,
  runIndex = 0,
) {
  // Caladon: standard sealed SSE only — NEVER the resumable/startGeneration (unsealed) path.
  useSSE(submission, chatHelpers, isAddedRequest, runIndex);
  useResumableSSE(null, chatHelpers, isAddedRequest, runIndex);
  return { streamId: undefined as string | undefined, resumableEnabled: false };
}
