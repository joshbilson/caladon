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
  TConversation,
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
import { augmentPromptWithRAG } from '~/lib/rag/retrieval';
import { injectMemoriesIntoPrompt } from '~/lib/memory/inject';
import { injectArtifactsIntoPrompt } from '~/lib/artifacts/inject';
import { injectActiveSkillIntoPrompt } from '~/lib/skills/inject';
import { orchestrateSubagents, collectSubagentIds } from '~/lib/subagents/orchestrate';
import { getStoreProxy } from '~/lib/store';
import type { StoredConversation, StoredMessage } from '~/lib/store';
import store from '~/store';

type ChatHelpers = Pick<
  EventHandlerParams,
  'setMessages' | 'getMessages' | 'setConversation' | 'setIsSubmitting' | 'newConversation'
>;

/** The shim opener path → gateway POST /v1/chat. Signed against the upstream /v1 path. */
const CALADON_CHAT_PATH = '/api/caladon/chat';
const CALADON_GATEWAY_CHAT_PATH = '/v1/chat';

/** CS-3: cap the 401 re-sign/re-stream retries so a persistent 401 can't loop forever. */
const MAX_401_RETRIES = 1;

/** Coerce a TMessage ISO/Date/undefined timestamp to epoch ms (the store's numeric column). */
function toEpochMs(value: unknown): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const t = Date.parse(value);
    if (!Number.isNaN(t)) return t;
  }
  if (value instanceof Date) return value.getTime();
  return Date.now();
}

/**
 * Map a LibreChat `TMessage` onto the device store's `StoredMessage`. `contentJson` is the lossless
 * JSON of `TMessage.content` (so rich content survives the round-trip; useHydrateConversation
 * prefers it). `text` is the plain rendered text the FTS index tokenizes.
 */
function toStoredMessage(msg: TMessage, conversationId: string): StoredMessage {
  return {
    messageId: msg.messageId,
    conversationId,
    parentMessageId: msg.parentMessageId ?? null,
    isCreatedByUser: msg.isCreatedByUser === true,
    text: typeof msg.text === 'string' ? msg.text : '',
    contentJson: msg.content != null ? JSON.stringify(msg.content) : null,
    model: (msg as { model?: string | null }).model ?? null,
    createdAt: toEpochMs((msg as { createdAt?: unknown }).createdAt),
    updatedAt: toEpochMs((msg as { updatedAt?: unknown }).updatedAt),
  };
}

/**
 * Map a LibreChat `TConversation` onto the device store's `StoredConversation`. `convoJson` is the
 * lossless serialized conversation so hydration is byte-for-byte faithful.
 */
function toStoredConversation(convo: TConversation, conversationId: string): StoredConversation {
  return {
    conversationId,
    title: (convo.title as string | null | undefined) ?? null,
    endpoint: (convo.endpoint as string | null | undefined) ?? null,
    model: (convo.model as string | null | undefined) ?? null,
    createdAt: toEpochMs((convo as { createdAt?: unknown }).createdAt),
    updatedAt: toEpochMs((convo as { updatedAt?: unknown }).updatedAt) || Date.now(),
    convoJson: JSON.stringify(convo),
  };
}

/**
 * Fire-and-forget persistence of one finalized turn (user + assistant) into the on-device encrypted
 * store. OFF the chat hot path; never awaited by the SSE handler. Skips when the store isn't open
 * and swallows every error so persistence can never affect the rendered/streamed turn.
 */
function persistTurnToStore(
  conversationId: string,
  userMessage: TMessage,
  assistantMessage: TMessage,
  conversation: TConversation,
): void {
  const proxy = getStoreProxy();
  if (!proxy.isOpen) return;
  void proxy
    .persistTurn(
      conversationId,
      toStoredMessage(userMessage, conversationId),
      toStoredMessage(assistantMessage, conversationId),
      toStoredConversation(conversation, conversationId),
    )
    .catch((err) => console.error('[caladon] persistTurn failed (turn still rendered):', err));
}

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
    // CS-3: per-submission 401 retry budget (resets each time this effect re-runs for a new
    // submission), so the re-sign/re-stream path below cannot loop indefinitely.
    let retry401Count = 0;

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

      const rawPromptText = String((payload as { text?: string }).text ?? '');
      let model = (payload as { model?: string }).model;
      // Subagent steps (if the active agent delegates to a chain) — rendered above the final reply.
      let subagentStepsText = '';

      // RAG (trust-critical): retrieve relevant on-device chunks and PREPEND a <context> block to
      // the prompt BEFORE it is sealed, so the gateway only ever sees the sealed envelope — the
      // retrieved document/history text is injected inside the trust boundary and sealed with the
      // rest of the prompt. augmentPromptWithRAG fails OPEN to the original prompt (and never to a
      // remote service), so this can only ever add local context, never block the send.
      const ragPromptText = await augmentPromptWithRAG(rawPromptText);

      // MEMORY (trust-critical): prepend the user's persistent on-device memories the same way —
      // inside the trust boundary, sealed with the prompt. Fails OPEN to the un-augmented prompt.
      let promptText = await injectMemoriesIntoPrompt(ragPromptText);

      // SKILLS (trust-critical): if a reusable skill is active, prepend its instruction body the
      // same way — inside the trust boundary, sealed with the prompt. Fails OPEN. Device-only.
      promptText = await injectActiveSkillIntoPrompt(promptText);

      // AGENTS (trust-critical): if this turn targets a user agent (endpoint 'agents' → payload
      // carries agent_id), resolve the agent from the DEVICE store and apply its config CLIENT-SIDE
      // before sealing: prepend its instructions as a system prefix and route the turn to the
      // agent's model (the per-turn model the gateway honours). The gateway never sees the agent
      // config — only the sealed prompt. Fails OPEN (a missing/closed store → a normal turn).
      const agentId = (payload as { agent_id?: string }).agent_id;
      if (agentId) {
        try {
          const agent = await getStoreProxy().getAgent(agentId);
          if (agent) {
            if (agent.model) {
              model = agent.model;
            }
            // SUBAGENTS (trust-critical, client-orchestrated): if this agent delegates to a chain
            // (agent_ids in its config), run each subagent as a headless sealed completion FIRST and
            // prepend their synthesised context so the main agent composes the final answer. Each
            // sub-call is a normal sealed round-trip — no new trust surface, no gateway change.
            // The builder persists a subagent chain in one of THREE shapes depending on which
            // Advanced control was used: the flat `agent_ids` (AgentChain), the nested
            // `subagents.agent_ids` (AgentSubagents "Beta" toggle), or `edges` (AgentHandoffs
            // graph). Read all of them and union the targets so orchestration fires regardless of
            // which control the user touched. `subagents` is only honoured when `enabled !== false`.
            const agentIds: unknown[] = collectSubagentIds(agent.configJson, agentId);
            if (agentIds.length) {
              try {
                const { steps, context } = await orchestrateSubagents(agentIds, promptText);
                if (context) {
                  promptText = `${context}\n\n${promptText}`;
                  subagentStepsText = steps
                    .map((s) => `> 🤝 **${s.name}** consulted\n\n`)
                    .join('');
                }
              } catch {
                /* fail open: proceed without subagents */
              }
            }
            if (agent.instructions && agent.instructions.trim()) {
              promptText = `${agent.instructions.trim()}\n\n${promptText}`;
            }
          }
        } catch {
          /* fail open: send as a normal turn */
        }
      }

      // ARTIFACTS (client-side): when the conversation's artifacts toggle is on, prepend the
      // artifact authoring instructions so the model emits :::artifact{}::: markup that our
      // trust-no-one renderer (ArtifactPreview overlay) displays. Injected inside the trust boundary
      // and sealed with the prompt; the gateway never sees a separate system prompt. No-op when off.
      promptText = injectArtifactsIntoPrompt(
        promptText,
        (submission.conversation as { artifacts?: string } | undefined)?.artifacts,
      );

      // TOOLS (in-CVM MCP loop): opt-in via the composer "Tools" toggle (localStorage). When on, the
      // sealed body carries tools:true so the gateway runs the in-CVM tool loop; yolo bypasses the
      // egress allowlist for the turn. No-op when off (a normal turn's body is unchanged).
      let toolsEnabled = false;
      let toolsYolo = false;
      try {
        toolsEnabled = localStorage.getItem('caladon:toolsEnabled') === 'true';
        toolsYolo = localStorage.getItem('caladon:toolsYolo') === 'true';
      } catch {
        /* default off */
      }

      let wireBody: unknown;
      let authHeader: string;
      try {
        wireBody = await sealChat(promptText, model, { tools: toolsEnabled, toolsYolo });
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
      // In-CVM tool steps (MCP) arrive sealed as `event: tool` BEFORE the final token; we render them
      // as a small prefix above the answer so the user sees what ran inside the CVM. Seeded with any
      // subagent-consultation steps computed pre-send (client-orchestrated subagent chain).
      let toolStepsText = subagentStepsText;
      const render = () =>
        setMessages([
          ...submission.messages,
          stampedUserMessage,
          buildResponseMessage(toolStepsText + accumulatedText),
        ]);
      // Serialize delta processing into a chain so (a) accumulation order is preserved under the
      // async openDelta, and (b) the 'done' handler can AWAIT all in-flight deltas before it
      // finalizes/persists. ROOT CAUSE of "assistant replies blank after reload": 'done' fires when
      // the SSE stream ends, but the trailing deltas are still inside `await openDelta` — reading
      // accumulatedText synchronously in 'done' snapshots an EMPTY/partial reply into the cache + the
      // on-device store. The LIVE view self-heals (the deltas re-render after), masking the bug.
      let deltaChain: Promise<void> = Promise.resolve();
      const onSealedDelta = (e: MessageEvent) => {
        deltaChain = deltaChain.then(async () => {
          try {
            const { envelope } = JSON.parse(e.data) as { envelope: import('@caladon/protocol').Envelope };
            // Sealed deltas are INCREMENTAL; accumulate the cumulative plaintext and re-render the
            // full assistant message on each token (mirrors upstream token streaming, which replaces).
            accumulatedText += await openDelta(envelope);
            setIsSubmitting(true);
            render();
          } catch (error) {
            console.error('Error opening sealed delta:', error);
          }
        });
      };
      sse.addEventListener('token', onSealedDelta);
      sse.addEventListener('reasoning', onSealedDelta);

      // Sealed in-CVM tool step: plaintext is JSON {tool, args, result}. Render as a compact line.
      sse.addEventListener('tool', (e: MessageEvent) => {
        deltaChain = deltaChain.then(async () => {
          try {
            const { envelope } = JSON.parse(e.data) as { envelope: import('@caladon/protocol').Envelope };
            const step = JSON.parse(await openDelta(envelope)) as {
              tool?: string;
              args?: unknown;
              result?: string;
            };
            const argStr = (() => {
              try {
                return JSON.stringify(step.args ?? {});
              } catch {
                return '{}';
              }
            })();
            const result = String(step.result ?? '').slice(0, 500);
            toolStepsText += `> 🔧 **${step.tool ?? 'tool'}**(\`${argStr}\`) → \`${result}\`\n\n`;
            setIsSubmitting(true);
            render();
          } catch (error) {
            console.error('Error opening sealed tool step:', error);
          }
        });
      });

      /** Per-response attestation receipt (SURGERY.md §D3.5) — verify; drop + stop on mismatch. */
      sse.addEventListener('receipt', () => {
        // P3: re-verify the per-response attestation here against the pinned set; on mismatch
        // mark the session untrusted and stop. The handshake already gated the channel fail-closed.
      });

      sse.addEventListener('done', async () => {
        clearAllDrafts(submission.conversation?.conversationId);
        // Wait for all in-flight sealed deltas to finish decrypting + accumulating BEFORE snapshotting
        // accumulatedText into the cache (finalHandler) and the on-device store (persistTurnToStore).
        // Without this, a fast stream finalizes/persists an empty/partial reply (see deltaChain above).
        await deltaChain;
        try {
          // FINALIZE client-side: synthesize the `final` data shape upstream's finalHandler
          // expects, so the turn persists in the messages cache (both `new` and the concrete
          // convo id, via setMessages' cache fan-out) and the conversation flips onto the id.
          finalHandler(
            {
              requestMessage: stampedUserMessage,
              responseMessage: buildResponseMessage(toolStepsText + accumulatedText),
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
            buildResponseMessage(toolStepsText + accumulatedText),
          ]);
          setIsSubmitting(false);
          setShowStopButton(false);
        }

        // Persist this turn to the on-device encrypted store (history + FTS + RAG source). This is
        // strictly AFTER the cache write above and FULLY fire-and-forget: it is off the chat hot
        // path and a store failure must never affect the rendered turn. We skip TEMPORARY chats
        // (the user opted out of persistence) and skip when the store isn't open. The persisted
        // text is the user's ORIGINAL message — never the RAG-augmented prompt (that augmentation
        // is sealed for the gateway only and is not part of the user's history).
        // The authoritative opt-out flag is the TOP-LEVEL submission.isTemporary (from the
        // store.isTemporary atom — exactly what upstream useEventHandlers gates on); it is NOT
        // reliably stamped onto submission.conversation. Gate on both (top-level is the real one).
        const isTemporaryChat =
          (submission as { isTemporary?: boolean }).isTemporary === true ||
          (submission.conversation as { isTemporary?: boolean } | undefined)?.isTemporary === true;
        if (!isTemporaryChat) {
          persistTurnToStore(
            conversationId,
            stampedUserMessage,
            buildResponseMessage(toolStepsText + accumulatedText),
            { ...(submission.conversation ?? {}), conversationId } as TConversation,
          );
        }

        (startupConfig?.balance?.enabled ?? false) && balanceQuery.refetch();
      });

      sse.addEventListener('message', (e: MessageEvent) => {
        // CS-6: a malformed SSE frame must not throw uncaught — log-safe and drop the frame.
        let data;
        try {
          data = JSON.parse(e.data);
        } catch (error) {
          console.error('Ignoring malformed SSE message frame:', error);
          return;
        }

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
         *
         * CS-3: bound the re-sign/re-stream so a PERSISTENT 401 cannot spin forever (each retry
         * re-streams, which re-fires `error`). Allow at most MAX_401_RETRIES attempts, then fall
         * through to the normal error surface.
         */
        // @ts-ignore — sse.js attaches responseCode on the event
        if (e.responseCode === 401 && retry401Count < MAX_401_RETRIES) {
          retry401Count += 1;
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
