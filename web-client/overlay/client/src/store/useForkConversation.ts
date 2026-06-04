/**
 * Caladon — useForkConversation (Batch 1 client foundation, device-side fork).
 *
 * Upstream LibreChat forks a conversation by POSTing to the gateway (`useForkConvoMutation`), which
 * copies the message subtree server-side. Caladon has NO server-side conversation record — the chat
 * history lives ONLY in the on-device encrypted SQLite store (StoreProxy / @evolu/sqlite-wasm). So
 * forking is a purely client-side operation: ask the store to copy the lineage from the root down to
 * `fromMessageId` into a fresh `conversationId`, then seed the react-query cache (conversation list +
 * `[QueryKeys.messages, newId]`) and navigate so the new branch opens instantly — no network, no
 * gateway round-trip, no plaintext ever leaving the device.
 *
 * This is the device-side analogue of `useForkConvoMutation`; it intentionally has no `option`
 * (DIRECT_PATH / branches / target level) — the store fork copies the direct ancestor path, which is
 * the lineage `StoreProxy.forkConversation(conversationId, fromMessageId)` produces. The mutation
 * shape (mutate / isLoading / onSuccess|onError callbacks) mirrors the upstream hook so the calling
 * component (`ForkButton`) reads like the upstream `Fork` component.
 *
 * Trust model (LOCKED): the store key never leaves the worker; the fork happens inside the worker's
 * SQLite transaction; this hook only ever sees opaque `StoredConversation` / `StoredMessage` rows it
 * already had the right to read. Nothing here touches the network.
 */

import { useCallback, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { QueryKeys, Constants } from 'librechat-data-provider';
import type { TConversation, TMessage } from 'librechat-data-provider';
import { useNavigateToConvo } from '~/hooks';
import { addConvoToAllQueries } from '~/utils';
import { getStoreProxy } from '~/lib/store';
import type { StoredConversation, StoredMessage } from '~/lib/store';

/** Inputs to a fork: the source conversation and the message the new branch ends at (inclusive). */
export interface ForkConversationVariables {
  conversationId: string;
  /** The message id the forked lineage ends at (inclusive). */
  fromMessageId: string;
}

export interface UseForkConversationOptions {
  /** Called with the new conversationId once the fork is persisted, cached and navigated to. */
  onSuccess?: (newConversationId: string, conversation: TConversation | null) => void;
  onError?: (error: unknown) => void;
  /** Called synchronously when the fork starts (e.g. to show a "forking…" toast). */
  onMutate?: (variables: ForkConversationVariables) => void;
}

/**
 * Rehydrate a lossless `TConversation` from a stored row. `convoJson` is the byte-faithful
 * serialized `TConversation` written at persist time; we parse it and force the new id/title so the
 * fork is unmistakably a new conversation even if the JSON predates the rename in the store.
 */
function toTConversation(row: StoredConversation | null): TConversation | null {
  if (!row) {
    return null;
  }
  try {
    const convo = JSON.parse(row.convoJson) as TConversation;
    return { ...convo, conversationId: row.conversationId, title: row.title ?? convo.title };
  } catch {
    // Fall back to the flat columns if the lossless JSON is somehow unparseable.
    return {
      conversationId: row.conversationId,
      title: row.title,
      endpoint: row.endpoint,
      model: row.model,
      createdAt: new Date(row.createdAt).toISOString(),
      updatedAt: new Date(row.updatedAt).toISOString(),
    } as unknown as TConversation;
  }
}

/**
 * Rehydrate a lossless `TMessage` from a stored row. `contentJson` is the serialized
 * `TMessage.content`; we restore it (and the rich `content` parts) so the forked thread renders
 * identically to the source.
 */
function toTMessage(row: StoredMessage): TMessage {
  const createdAt = new Date(row.createdAt).toISOString();
  const updatedAt = new Date(row.updatedAt).toISOString();
  let content: TMessage['content'];
  if (row.contentJson != null) {
    try {
      content = JSON.parse(row.contentJson) as TMessage['content'];
    } catch {
      content = undefined;
    }
  }
  const message: TMessage = {
    messageId: row.messageId,
    conversationId: row.conversationId,
    parentMessageId: row.parentMessageId,
    text: row.text,
    isCreatedByUser: row.isCreatedByUser,
    model: row.model,
    createdAt,
    updatedAt,
  } as TMessage;
  if (content !== undefined) {
    message.content = content;
  }
  return message;
}

/**
 * Device-side fork. Returns a mutation-like handle: `forkConversation(variables)` runs the fork and
 * resolves to the new conversationId; `isLoading` tracks the in-flight fork for button state.
 */
export function useForkConversation(options: UseForkConversationOptions = {}) {
  const { onSuccess, onError, onMutate } = options;
  const queryClient = useQueryClient();
  const { navigateToConvo } = useNavigateToConvo();
  const [isLoading, setIsLoading] = useState(false);

  const forkConversation = useCallback(
    async (variables: ForkConversationVariables): Promise<string | null> => {
      const { conversationId, fromMessageId } = variables;
      if (!conversationId || !fromMessageId) {
        return null;
      }
      setIsLoading(true);
      onMutate?.(variables);
      try {
        const store = getStoreProxy();
        // 1) Copy the lineage (root → fromMessageId, inclusive) into a new conversationId.
        const newConversationId = await store.forkConversation(conversationId, fromMessageId);

        // 2) Pull the freshly forked conversation + messages back out of the store so we can seed
        //    the react-query cache without a refetch (there is no server to fetch from).
        const { conversation, messages } = await store.hydrate(newConversationId);
        const convo = toTConversation(conversation);
        const tMessages = messages.map(toTMessage);

        // 3) Seed the messages cache for the new conversation so the chat pane renders immediately.
        queryClient.setQueryData<TMessage[]>([QueryKeys.messages, newConversationId], tMessages);

        // 4) Insert the new conversation at the top of every conversation-list query.
        if (convo) {
          addConvoToAllQueries(queryClient, convo);
        }

        // 5) Navigate into the new branch (clears NEW_CONVO state, focuses the chat input).
        if (convo) {
          navigateToConvo(convo, { currentConvoId: conversationId });
        } else {
          navigateToConvo(
            { conversationId: newConversationId } as TConversation,
            { currentConvoId: conversationId },
          );
        }

        onSuccess?.(newConversationId, convo);
        return newConversationId;
      } catch (error) {
        onError?.(error);
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [queryClient, navigateToConvo, onMutate, onSuccess, onError],
  );

  return { forkConversation, isLoading, NEW_CONVO: Constants.NEW_CONVO };
}

export default useForkConversation;
