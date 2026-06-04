import { useEffect, useState } from 'react';
import { v4 } from 'uuid';
import { SSE } from 'sse.js';
import { useSetRecoilState } from 'recoil';
import {
  Constants,
  ContentTypes,
  createPayload,
  removeNullishValues,
} from 'librechat-data-provider';
import type {
  TMessage,
  TPayload,
  TSubmission,
  EventSubmission,
  TMessageContentParts,
} from 'librechat-data-provider';
import type { EventHandlerParams } from './useEventHandlers';
import type { TResData } from '~/common';
import { useGetStartupConfig, useGetUserBalance } from '~/data-provider';
import { useAuthContext } from '~/hooks/AuthContext';
import useEventHandlers from './useEventHandlers';
import { clearAllDrafts } from '~/utils';
import {
  isUnlocked,
  sealChat,
  signRequest,
  openDelta,
  CaladonError,
} from '~/lib/caladon';
import store from '~/store';

type ChatHelpers = Pick<
  EventHandlerParams,
  'setMessages' | 'getMessages' | 'setConversation' | 'setIsSubmitting' | 'newConversation'
>;

/** The shim opener path → gateway POST /v1/chat. Signed against the upstream /v1 path. */
const CALADON_CHAT_PATH = '/api/caladon/chat';
const CALADON_GATEWAY_CHAT_PATH = '/v1/chat';

export default function useSSE(
  submission: TSubmission | null,
  chatHelpers: ChatHelpers,
  isAddedRequest = false,
  runIndex = 0,
) {
  const setActiveRunId = useSetRecoilState(store.activeRunFamily(runIndex));

  const { isAuthenticated } = useAuthContext();
  const [completed, setCompleted] = useState(new Set());
  const setAbortScroll = useSetRecoilState(store.abortScrollFamily(runIndex));
  const setShowStopButton = useSetRecoilState(store.showStopButtonByIndex(runIndex));

  const { setMessages, getMessages, setConversation, setIsSubmitting, newConversation } =
    chatHelpers;

  const {
    clearStepMaps,
    stepHandler,
    syncHandler,
    finalHandler,
    errorHandler,
    contentHandler,
    createdHandler,
    titleHandler,
    attachmentHandler,
    abortConversation,
  } = useEventHandlers({
    setMessages,
    getMessages,
    setCompleted,
    isAddedRequest,
    setConversation,
    setIsSubmitting,
    newConversation,
    setShowStopButton,
  });

  const { data: startupConfig } = useGetStartupConfig();
  const balanceQuery = useGetUserBalance({
    enabled: !!isAuthenticated && startupConfig?.balance?.enabled,
  });

  useEffect(() => {
    if (submission == null || Object.keys(submission).length === 0) {
      return;
    }

    let { userMessage } = submission;
    let sse: InstanceType<typeof SSE> | null = null;
    let cancelled = false;

    let textIndex = null;
    clearStepMaps();

    /**
     * Caladon SSE setup (SURGERY.md §B2 / §D4). Async because the seal + signature run in WASM:
     *   1. fail-closed gate — refuse to send unless the seed is unlocked (attestation already
     *      passed fail-closed during the handshake in AuthContext; an un-unlocked client has no
     *      session key, so there is nothing to seal with).
     *   2. seal the prompt text → `{ envelope, model }` (the gateway/shim never see plaintext).
     *   3. sign the request → `Authorization: Swifty …` (no Bearer JWT).
     *   4. open each sealed `token`/`reasoning` delta before handing plaintext to the handlers.
     */
    const setup = async () => {
      const payloadData = createPayload(submission);
      let { payload } = payloadData;
      payload = removeNullishValues(payload) as TPayload;

      if (!isUnlocked()) {
        errorHandler({
          data: { text: 'Locked: unlock your seed to start an attested session.' } as unknown as TResData,
          submission: { ...submission, userMessage } as EventSubmission,
        });
        setIsSubmitting(false);
        return;
      }

      const promptText = String((payload as { text?: string }).text ?? '');
      const model = (payload as { model?: string }).model;

      let wireBody: unknown;
      let authHeader: string;
      try {
        wireBody = await sealChat(promptText, model);
        authHeader = await signRequest('POST', CALADON_GATEWAY_CHAT_PATH);
      } catch (err) {
        const message =
          err instanceof CaladonError
            ? err.message
            : 'Failed to seal the prompt (crypto unavailable).';
        errorHandler({
          data: { text: message } as unknown as TResData,
          submission: { ...submission, userMessage } as EventSubmission,
        });
        setIsSubmitting(false);
        return;
      }

      if (cancelled) {
        return;
      }

      sse = new SSE(CALADON_CHAT_PATH, {
        payload: JSON.stringify(wireBody),
        headers: { 'Content-Type': 'application/json', Authorization: authHeader },
      });

      sse.addEventListener('attachment', (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          attachmentHandler({ data, submission: submission as EventSubmission });
        } catch (error) {
          console.error(error);
        }
      });

      /**
       * Caladon drives the whole message lifecycle CLIENT-SIDE (SURGERY.md §D4).
       *
       * The gateway's SSE for /v1/chat emits ONLY sealed `event: token | reasoning`
       * deltas, then `event: receipt`, then `event: done` — it never emits LibreChat's
       * normal `event: message` with `{created}`/`{final}`, a server conversationId, or a
       * server messageId. So the upstream lifecycle (createdHandler → streaming → finalHandler
       * persist) never completes and the streamed assistant bubble renders empty.
       *
       * Two more gaps fixed here:
       *   1. `useChatFunctions.ask()` seeds the assistant placeholder with `content: []`.
       *      An empty array is truthy, so `MultiMessage` routes the bubble to the
       *      content-parts renderer (which reads `message.content`, NOT `message.text`).
       *      `messageHandler` only sets `text`, leaving `content` empty → empty bubble.
       *      We therefore stream a real TEXT content part alongside `text`.
       *   2. There is no server message store (the shim stubs /api/convos + /api/messages
       *      empty). So we synthesize a stable client conversationId + assistant messageId,
       *      and on `done` write the finalized turn into the messages cache for BOTH the
       *      `new` key and the concrete conversationId key, then flip the conversation onto
       *      that id. Because the messages query is `refetchOnMount: false`, navigating to
       *      /c/<id> reads the seeded cache and does NOT refetch the empty shim response,
       *      so the local turn is not clobbered.
       */

      // Stable client-generated IDs (the gateway provides none).
      const startConvoId = submission.conversation?.conversationId;
      const isNewConvo =
        startConvoId == null ||
        startConvoId === Constants.NEW_CONVO ||
        startConvoId === Constants.PENDING_CONVO;
      const conversationId = isNewConvo ? v4() : (startConvoId as string);
      const baseResponse = submission.initialResponse as TMessage;
      const responseMessageId = baseResponse.messageId || v4();
      const parentMessageId =
        userMessage.messageId ?? baseResponse.parentMessageId ?? Constants.NO_PARENT;

      // Build the in-flight user message stamped with the resolved conversationId so the
      // messages-cache fan-out (getMessageCacheIds) keys it under the concrete convo too.
      const stampedUserMessage: TMessage = {
        ...userMessage,
        conversationId,
      };

      const buildResponseMessage = (text: string): TMessage => {
        const content: TMessageContentParts[] = [
          // Render via the content-parts path that the truthy `content: []` placeholder forces;
          // also carry `text` so the legacy text path renders if `content` is ever dropped.
          { type: ContentTypes.TEXT, [ContentTypes.TEXT]: { value: text } } as TMessageContentParts,
        ];
        return {
          ...baseResponse,
          messageId: responseMessageId,
          parentMessageId,
          conversationId,
          isCreatedByUser: false,
          text,
          content,
          unfinished: false,
          error: false,
        };
      };

      let accumulatedText = '';
      const onSealedDelta = async (e: MessageEvent) => {
        try {
          const { envelope } = JSON.parse(e.data) as { envelope: import('@caladon/protocol').Envelope };
          // Sealed deltas are INCREMENTAL; accumulate the cumulative plaintext and re-render the
          // full assistant message on each token (mirrors upstream token streaming, which replaces).
          accumulatedText += await openDelta(envelope);
          setIsSubmitting(true);
          setMessages([
            ...submission.messages,
            stampedUserMessage,
            buildResponseMessage(accumulatedText),
          ]);
        } catch (error) {
          console.error('Error opening sealed delta:', error);
        }
      };
      sse.addEventListener('token', onSealedDelta);
      sse.addEventListener('reasoning', onSealedDelta);

      /** Per-response attestation receipt (SURGERY.md §D3.5) — verify; drop + stop on mismatch. */
      sse.addEventListener('receipt', () => {
        // P3: re-verify the per-response attestation here against the pinned set; on mismatch
        // mark the session untrusted and stop. The handshake already gated the channel fail-closed.
      });

      sse.addEventListener('done', () => {
        clearAllDrafts(submission.conversation?.conversationId);
        try {
          // FINALIZE client-side: synthesize the `final` data shape upstream's finalHandler
          // expects, so the turn persists in the messages cache (both `new` and the concrete
          // convo id, via setMessages' cache fan-out) and the conversation flips onto the id.
          finalHandler(
            {
              requestMessage: stampedUserMessage,
              responseMessage: buildResponseMessage(accumulatedText),
              conversation: {
                ...(submission.conversation ?? {}),
                conversationId,
              },
            } as unknown as Parameters<typeof finalHandler>[0],
            { ...submission, userMessage: stampedUserMessage } as EventSubmission,
          );
        } catch (error) {
          console.error('Error finalizing sealed response:', error);
          // Fail-safe: at minimum keep the rendered message and stop the UI.
          setMessages([
            ...submission.messages,
            stampedUserMessage,
            buildResponseMessage(accumulatedText),
          ]);
          setIsSubmitting(false);
          setShowStopButton(false);
        }
        (startupConfig?.balance?.enabled ?? false) && balanceQuery.refetch();
      });

      sse.addEventListener('message', (e: MessageEvent) => {
        const data = JSON.parse(e.data);

        if (data.final != null) {
          clearAllDrafts(submission.conversation?.conversationId);
          try {
            finalHandler(data, submission as EventSubmission);
          } catch (error) {
            console.error('Error in finalHandler:', error);
            setIsSubmitting(false);
            setShowStopButton(false);
          }
          (startupConfig?.balance?.enabled ?? false) && balanceQuery.refetch();
          return;
        } else if (data.created != null) {
          const runId = v4();
          setActiveRunId(runId);
          userMessage = {
            ...userMessage,
            ...data.message,
            overrideParentMessageId: userMessage.overrideParentMessageId,
          };

          createdHandler(data, { ...submission, userMessage } as EventSubmission);
        } else if (data.event === 'title') {
          titleHandler(data);
        } else if (data.event != null) {
          stepHandler(data, { ...submission, userMessage } as EventSubmission);
        } else if (data.sync != null) {
          const runId = v4();
          setActiveRunId(runId);
          syncHandler(data, { ...submission, userMessage } as EventSubmission);
        } else if (data.type != null) {
          const { text, index } = data;
          if (text != null && index !== textIndex) {
            textIndex = index;
          }

          contentHandler({ data, submission: submission as EventSubmission });
        }
      });

      sse.addEventListener('open', () => {
        setAbortScroll(false);
      });

      sse.addEventListener('cancel', async () => {
        const streamKey = (submission as TSubmission | null)?.['initialResponse']?.messageId;
        if (completed.has(streamKey)) {
          setIsSubmitting(false);
          setCompleted((prev) => {
            prev.delete(streamKey);
            return new Set(prev);
          });
          return;
        }

        setCompleted((prev) => new Set(prev.add(streamKey)));
        const latestMessages = getMessages();
        const conversationId = latestMessages?.[latestMessages.length - 1]?.conversationId;
        try {
          await abortConversation(
            conversationId ??
              userMessage.conversationId ??
              submission.conversation?.conversationId ??
              '',
            submission as EventSubmission,
            latestMessages,
          );
        } catch (error) {
          console.error('Error during abort:', error);
          setIsSubmitting(false);
          setShowStopButton(false);
        }
      });

      sse.addEventListener('error', async (e: MessageEvent) => {
        /**
         * Caladon auth (SURGERY.md §A3): no refresh-token dance. A 401 is almost always clock
         * skew on the signed timestamp — re-sign and retry once; otherwise surface "re-unlock".
         */
        // @ts-ignore — sse.js attaches responseCode on the event
        if (e.responseCode === 401) {
          try {
            const resigned = await signRequest('POST', CALADON_GATEWAY_CHAT_PATH);
            if (sse) {
              sse.headers = { 'Content-Type': 'application/json', Authorization: resigned };
              sse.stream();
              return;
            }
          } catch (error) {
            console.log('re-sign failed; re-unlock required', error);
          }
        }

        (startupConfig?.balance?.enabled ?? false) && balanceQuery.refetch();

        let data: TResData | undefined = undefined;
        try {
          data = JSON.parse(e.data) as TResData;
        } catch (error) {
          console.error(error);
          setIsSubmitting(false);
        }

        errorHandler({ data, submission: { ...submission, userMessage } as EventSubmission });
      });

      setIsSubmitting(true);
      sse.stream();
    };

    void setup();

    return () => {
      cancelled = true;
      if (!sse) {
        return;
      }
      const isCancelled = sse.readyState <= 1;
      sse.close();
      if (isCancelled) {
        const e = new Event('cancel');
        // @ts-ignore
        sse.dispatchEvent(e);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [submission]);
}
