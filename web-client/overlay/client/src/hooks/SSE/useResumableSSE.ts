import { useState } from 'react';
import type { TSubmission } from 'librechat-data-provider';
import type { EventHandlerParams } from './useEventHandlers';

type ChatHelpers = Pick<
  EventHandlerParams,
  'setMessages' | 'getMessages' | 'setConversation' | 'setIsSubmitting' | 'newConversation'
>;

/**
 * Caladon surgery (SURGERY.md §B2/§D4) — the resumable SSE path is HARD-DISABLED.
 *
 * Upstream `useResumableSSE` splits a chat turn into a `startGeneration` pre-flight POST (which
 * returns a `streamId`) and a separate GET `EventSource` subscription. Both halves are fatal to the
 * Caladon trust model:
 *
 *   - `startGeneration` calls `createPayload(submission)` and `request.post(url, payload)` — i.e. it
 *     posts the **plaintext** LibreChat submission (including `userMessage.text`, the raw prompt) to
 *     the chat route with NO Caladon signed `Authorization: Swifty …` header. The prompt is NOT
 *     sealed (`@caladon/protocol`) and the request is NOT signed. Against the attested gateway this
 *     yields a 401 (the gateway rejects the unsigned request) and — worse — would put the prompt
 *     plaintext on the wire if the gateway ever accepted it.
 *   - The GET subscription rides a Bearer JWT, not the signed Caladon channel, and opens unsealed
 *     deltas.
 *
 * The ONLY acceptable chat path is the overlay's `useSSE`, which seals the prompt → signs the
 * request → POSTs to /api/caladon/chat as SSE → opens sealed deltas. `useAdaptiveSSE` drives that
 * path for every turn.
 *
 * This hook is therefore a pure no-op: it never reads the submission, never calls `createPayload`,
 * never POSTs, never opens an `EventSource`. It exists only so the call site keeps a stable hook
 * call (React's Rules of Hooks) and a `{ streamId }` shape. `streamId` is permanently `null`, so any
 * caller that branches on it treats resumable as "off".
 *
 * NOTE: the params are intentionally unused. Do NOT reintroduce `startGeneration`/`subscribeToStream`
 * here — that would re-open the plaintext, unsigned POST path the whole architecture forbids.
 */
export default function useResumableSSE(
  _submission: TSubmission | null,
  _chatHelpers: ChatHelpers,
  _isAddedRequest = false,
  _runIndex = 0,
) {
  // Permanently null — the resumable/startGeneration plaintext path is dead. Sealed `useSSE` only.
  const [streamId] = useState<string | null>(null);
  return { streamId };
}
