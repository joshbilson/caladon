/* Memories — Caladon overlay (trust-no-one, device-only).
 *
 * Upstream these hooks hit /api/memories (a server MongoDB store). In Caladon, memory MUST live on
 * the device — never server-plaintext — so every hook here reads/writes the SQLCipher-encrypted
 * device store (StoreProxy) instead. The exported names + signatures match upstream exactly so the
 * MemoryPanel / MemoryEditDialog / MemoryCreateDialog components work unchanged. At chat time the
 * stored memories are injected into the prompt BEFORE it is sealed (see lib/memory/inject.ts +
 * useSSE), mirroring how RAG context is injected. Nothing here touches the network.
 */
import { QueryKeys, MutationKeys } from 'librechat-data-provider';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import type {
  UseQueryOptions,
  UseMutationOptions,
  QueryObserverResult,
} from '@tanstack/react-query';
import type { TUserMemory, MemoriesResponse } from 'librechat-data-provider';
import { getStoreProxy } from '~/lib/store';
import type { StoredMemory } from '~/lib/store';

/** Estimate ~4 chars/token — matches the worker's estimate; only feeds the usage meter. */
function estimateTokens(s: string): number {
  return Math.max(1, Math.ceil(s.length / 4));
}

function toUserMemory(m: StoredMemory): TUserMemory {
  return {
    key: m.key,
    value: m.value,
    tokenCount: m.tokenCount,
    updated_at: new Date(m.updatedAt).toISOString(),
  };
}

async function readMemories(): Promise<MemoriesResponse> {
  const store = getStoreProxy();
  if (!store.isOpen) {
    return { memories: [], totalTokens: 0, tokenLimit: null, usagePercentage: null };
  }
  const rows = await store.listMemories();
  const memories = rows.map(toUserMemory);
  const totalTokens = memories.reduce((sum, m) => sum + (m.tokenCount || 0), 0);
  // No artificial cap on a device store: tokenLimit null → the panel shows count, not a % meter.
  return { memories, totalTokens, tokenLimit: null, usagePercentage: null };
}

export const useMemoriesQuery = (
  config?: UseQueryOptions<MemoriesResponse>,
): QueryObserverResult<MemoriesResponse> => {
  return useQuery<MemoriesResponse>([QueryKeys.memories], () => readMemories(), {
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchOnMount: false,
    ...config,
  });
};

export const useDeleteMemoryMutation = () => {
  const queryClient = useQueryClient();
  return useMutation(
    async (key: string) => {
      await getStoreProxy().deleteMemory(key);
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries([QueryKeys.memories]);
      },
    },
  );
};

export type UpdateMemoryParams = { key: string; value: string; originalKey?: string };
export const useUpdateMemoryMutation = (
  options?: UseMutationOptions<TUserMemory, Error, UpdateMemoryParams>,
) => {
  const queryClient = useQueryClient();
  return useMutation<TUserMemory, Error, UpdateMemoryParams>(
    async ({ key, value, originalKey }: UpdateMemoryParams) => {
      await getStoreProxy().upsertMemory(key, value, originalKey);
      return { key, value, tokenCount: estimateTokens(value), updated_at: new Date().toISOString() };
    },
    {
      ...options,
      onSuccess: (...params) => {
        queryClient.invalidateQueries([QueryKeys.memories]);
        options?.onSuccess?.(...params);
      },
    },
  );
};

export type UpdateMemoryPreferencesParams = { memories: boolean };
export type UpdateMemoryPreferencesResponse = {
  updated: boolean;
  preferences: { memories: boolean };
};

export const useUpdateMemoryPreferencesMutation = (
  options?: UseMutationOptions<
    UpdateMemoryPreferencesResponse,
    Error,
    UpdateMemoryPreferencesParams
  >,
) => {
  const queryClient = useQueryClient();
  return useMutation<UpdateMemoryPreferencesResponse, Error, UpdateMemoryPreferencesParams>(
    [MutationKeys.updateMemoryPreferences],
    // Device-only: the "use memory" preference is a local toggle; persist it in localStorage so the
    // injection step can honor it. No network call.
    async (preferences: UpdateMemoryPreferencesParams) => {
      try {
        localStorage.setItem('caladon:memoryEnabled', preferences.memories ? '1' : '0');
      } catch {
        /* ignore storage errors */
      }
      return { updated: true, preferences };
    },
    {
      ...options,
      onSuccess: (...params) => {
        queryClient.invalidateQueries([QueryKeys.user]);
        options?.onSuccess?.(...params);
      },
    },
  );
};

export type CreateMemoryParams = { key: string; value: string };
export type CreateMemoryResponse = { created: boolean; memory: TUserMemory };

export const useCreateMemoryMutation = (
  options?: UseMutationOptions<CreateMemoryResponse, Error, CreateMemoryParams>,
) => {
  const queryClient = useQueryClient();
  return useMutation<CreateMemoryResponse, Error, CreateMemoryParams>(
    async ({ key, value }: CreateMemoryParams) => {
      await getStoreProxy().upsertMemory(key, value);
      const memory: TUserMemory = {
        key,
        value,
        tokenCount: estimateTokens(value),
        updated_at: new Date().toISOString(),
      };
      return { created: true, memory };
    },
    {
      ...options,
      onSuccess: (...params) => {
        queryClient.invalidateQueries([QueryKeys.memories]);
        options?.onSuccess?.(...params);
      },
    },
  );
};
