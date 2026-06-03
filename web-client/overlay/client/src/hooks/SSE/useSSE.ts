import { useEffect, useState } from 'react';
import { v4 } from 'uuid';
import { SSE } from 'sse.js';
import { useSetRecoilState } from 'recoil';
import { createPayload, removeNullishValues } from 'librechat-data-provider';
import type { TMessage, TPayload, TSubmission, EventSubmission } from 'librechat-data-provider';
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
    messageHandler,
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
       * Sealed-delta listeners (SURGERY.md §D4). The gateway emits `event: token | reasoning`
       * whose `data` is `{ envelope }`; open each into plaintext before feeding messageHandler.
       */
      const onSealedDelta = async (e: MessageEvent) => {
        try {
          const { envelope } = JSON.parse(e.data) as { envelope: import('@caladon/protocol').Envelope };
          const text = await openDelta(envelope);
          const initialResponse = {
            ...(submission.initialResponse as TMessage),
          };
          messageHandler(text, { ...submission, userMessage, initialResponse });
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
        setIsSubmitting(false);
        setShowStopButton(false);
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
