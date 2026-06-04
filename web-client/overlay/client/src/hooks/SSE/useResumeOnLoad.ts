import type { TMessage } from 'librechat-data-provider';

/**
 * Caladon surgery (SURGERY.md §B2/§D4) — resume-on-load is HARD-DISABLED.
 *
 * Upstream `useResumeOnLoad` polls a `streamStatus` endpoint on navigation and, when it finds an
 * "active job", builds a synthetic submission carrying a `resumeStreamId` and writes it into the
 * shared `submissionByIndex(runIndex)` atom — the SAME atom a composer submit writes. Its sole
 * purpose is to feed `useResumableSSE` so it GET-subscribes to an in-flight server stream instead of
 * starting a new one.
 *
 * The resumable path is dead in Caladon (see overlay `useResumableSSE.ts`): the gateway runs one
 * sealed, signed turn per request and the client holds no server-side resumable stream to rejoin.
 * If this hook still ran, it would write a `resumeStreamId` submission into the submission atom,
 * which `useAdaptiveSSE` now routes into the sealed `useSSE` — re-driving a seal/sign/POST for a
 * synthetic, non-composer submission. That is both wrong (no prompt to send) and a way to put an
 * unintended request on the wire. So we neuter it entirely: it never polls, never sets the
 * submission atom, never resumes.
 *
 * The signature is preserved so ChatView's call site is unchanged; the body is a no-op.
 */
export default function useResumeOnLoad(
  _conversationId: string | undefined,
  _getMessages: () => TMessage[] | undefined,
  _runIndex = 0,
  _messagesLoaded = true,
) {
  // No-op: resume-on-load is disabled. The only chat path is a fresh, sealed `useSSE` turn.
}
