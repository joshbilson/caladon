import { useQuery, useInfiniteQuery, useQueryClient } from '@tanstack/react-query';
import { QueryKeys, dataService, EModelEndpoint, PermissionBits } from 'librechat-data-provider';
import type {
  QueryObserverResult,
  UseQueryOptions,
  UseInfiniteQueryOptions,
} from '@tanstack/react-query';
import type t from 'librechat-data-provider';
import { isEphemeralAgent } from '~/common';
import { getStoreProxy } from '~/lib/store';
import type { StoredAgent } from '~/lib/store';

/**
 * AGENTS — Caladon overlay: agents live ONLY in the encrypted device store (trust-no-one), never on
 * a server. The list/get hooks below read the device store (via StoreProxy); CRUD is in the sibling
 * mutations.ts overlay. Marketplace/tools/actions/version hooks are unchanged (they hit the shim's
 * empty stubs). At chat time the selected agent's instructions + model are applied client-side
 * (see hooks/SSE/useSSE) — the gateway never sees the agent config.
 */
export const defaultAgentParams: t.AgentListParams = {
  limit: 10,
  requiredPermission: PermissionBits.EDIT,
};

/** Reconstruct a full LibreChat Agent from a stored row (configJson is the lossless object). */
export function storedToAgent(s: StoredAgent): t.Agent {
  let cfg: Record<string, unknown> = {};
  try {
    cfg = JSON.parse(s.configJson) as Record<string, unknown>;
  } catch {
    /* fall back to salient columns */
  }
  return {
    created_at: s.createdAt,
    avatar: null,
    model_parameters: {},
    description: s.description,
    ...(cfg as Partial<t.Agent>),
    // Identity columns ALWAYS win over a possibly-stale configJson copy.
    id: s.agentId,
    name: s.name,
    instructions: s.instructions,
    model: s.model,
    provider: (s.provider as t.Agent['provider']) ?? ('caladon' as unknown as t.Agent['provider']),
    tools: s.tools ? (JSON.parse(s.tools) as string[]) : (cfg.tools as string[] | undefined),
  } as unknown as t.Agent;
}

/** Read all agents from the device store as an AgentListResponse (no server pagination). */
async function fetchAllAgentPages(_params: t.AgentListParams): Promise<t.AgentListResponse> {
  const store = getStoreProxy();
  for (let i = 0; i < 40 && !store.isOpen; i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const rows = store.isOpen ? await store.listAgents() : [];
  const data = rows.map(storedToAgent);
  return {
    object: 'list',
    data,
    has_more: false,
    after: null,
    first_id: data[0]?.id ?? null,
    last_id: data[data.length - 1]?.id ?? null,
  } as unknown as t.AgentListResponse;
}

/**
 * Hook for getting all available tools for A
 */
export const useAvailableAgentToolsQuery = (): QueryObserverResult<t.TPlugin[]> => {
  const queryClient = useQueryClient();
  const endpointsConfig = queryClient.getQueryData<t.TEndpointsConfig>([QueryKeys.endpoints]);

  const enabled = !!endpointsConfig?.[EModelEndpoint.agents];
  return useQuery<t.TPlugin[]>([QueryKeys.tools], () => dataService.getAvailableAgentTools(), {
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchOnMount: false,
    enabled,
  });
};

/**
 * Hook for listing all Agents the user has access to. Follows cursor
 * pagination internally and resolves with every page concatenated.
 * Cache key shape matches `allAgentViewAndEditQueryKeys` in `./mutations.ts`.
 */
export const useListAgentsQuery = <TData = t.AgentListResponse>(
  params: t.AgentListParams = defaultAgentParams,
  config?: UseQueryOptions<t.AgentListResponse, unknown, TData>,
): QueryObserverResult<TData> => {
  const queryClient = useQueryClient();
  const endpointsConfig = queryClient.getQueryData<t.TEndpointsConfig>([QueryKeys.endpoints]);

  const enabled = !!endpointsConfig?.[EModelEndpoint.agents];
  return useQuery<t.AgentListResponse, unknown, TData>(
    [QueryKeys.agents, params],
    () => fetchAllAgentPages(params),
    {
      staleTime: 0,
      refetchOnWindowFocus: true,
      refetchOnReconnect: false,
      // Poll the device store so the list reflects create/update/delete promptly (device store has
      // no server events; cross-component invalidation is unreliable — same pattern as memory).
      refetchOnMount: 'always',
      refetchInterval: 1500,
      retry: false,
      ...config,
      enabled: config?.enabled !== undefined ? config.enabled && enabled : enabled,
    },
  );
};

/**
 * Hook for retrieving basic details about a single agent (VIEW permission)
 */
export const useGetAgentByIdQuery = (
  agent_id: string | null | undefined,
  config?: UseQueryOptions<t.Agent>,
): QueryObserverResult<t.Agent> => {
  const isValidAgentId = !!agent_id && !isEphemeralAgent(agent_id);

  return useQuery<t.Agent>(
    [QueryKeys.agent, agent_id],
    () => fetchStoredAgent(agent_id as string),
    {
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
      refetchOnMount: false,
      retry: false,
      enabled: isValidAgentId && (config?.enabled ?? true),
      ...config,
    },
  );
};

/** Read one agent from the device store (throws if absent, matching the upstream not-found shape). */
async function fetchStoredAgent(agent_id: string): Promise<t.Agent> {
  const store = getStoreProxy();
  for (let i = 0; i < 40 && !store.isOpen; i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const row = store.isOpen ? await store.getAgent(agent_id) : null;
  if (!row) {
    throw new Error(`agent not found: ${agent_id}`);
  }
  return storedToAgent(row);
}

/**
 * Hook for retrieving full agent details including sensitive configuration (EDIT permission)
 */
export const useGetExpandedAgentByIdQuery = (
  agent_id: string,
  config?: UseQueryOptions<t.Agent>,
): QueryObserverResult<t.Agent> => {
  return useQuery<t.Agent>(
    [QueryKeys.agent, agent_id, 'expanded'],
    () => fetchStoredAgent(agent_id),
    {
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
      refetchOnMount: false,
      retry: false,
      ...config,
    },
  );
};

/**
 * MARKETPLACE
 */
/**
 * Hook for getting agent categories for marketplace tabs
 */
export const useGetAgentCategoriesQuery = (
  config?: UseQueryOptions<t.TMarketplaceCategory[]>,
): QueryObserverResult<t.TMarketplaceCategory[]> => {
  return useQuery<t.TMarketplaceCategory[]>(
    [QueryKeys.agentCategories],
    () => dataService.getAgentCategories(),
    {
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
      refetchOnMount: false,
      staleTime: 5 * 60 * 1000, // Cache for 5 minutes
      ...config,
    },
  );
};

/**
 * Hook for infinite loading of marketplace agents with cursor-based pagination
 */
export const useMarketplaceAgentsInfiniteQuery = (
  params: {
    requiredPermission: number;
    category?: string;
    search?: string;
    limit?: number;
    promoted?: 0 | 1;
    cursor?: string; // For pagination
  },
  config?: UseInfiniteQueryOptions<t.AgentListResponse, unknown>,
) => {
  return useInfiniteQuery<t.AgentListResponse>({
    queryKey: [QueryKeys.marketplaceAgents, params],
    queryFn: ({ pageParam }) => {
      const queryParams = { ...params };
      if (pageParam) {
        queryParams.cursor = pageParam.toString();
      }
      return dataService.getMarketplaceAgents(queryParams);
    },
    getNextPageParam: (lastPage) => lastPage?.after ?? undefined,
    enabled: !!params.requiredPermission,
    keepPreviousData: true,
    staleTime: 2 * 60 * 1000, // 2 minutes
    cacheTime: 10 * 60 * 1000, // 10 minutes
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchOnMount: false,
    ...config,
  });
};
