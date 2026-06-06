import { useMutation, useQueryClient } from '@tanstack/react-query';
import { dataService, MutationKeys, PermissionBits, QueryKeys } from 'librechat-data-provider';
import type * as t from 'librechat-data-provider';
import type { QueryClient, UseMutationResult } from '@tanstack/react-query';
import { getStoreProxy } from '~/lib/store';
import type { StoredAgent } from '~/lib/store';
import { storedToAgent } from './queries';

/**
 * AGENTS — Caladon overlay: create/update/delete write to the encrypted DEVICE store (trust-no-one,
 * never a server). The cache-update onSuccess logic below is upstream's (kept so the UI updates
 * optimistically); only the mutationFns are re-pointed at the device store. The list query polls the
 * store too (see queries.ts). Avatar/actions/version/duplicate mutations are unchanged (shim stubs).
 */
export const allAgentViewAndEditQueryKeys: t.AgentListParams[] = [
  { requiredPermission: PermissionBits.VIEW },
  { requiredPermission: PermissionBits.EDIT },
];

/** A short, stable agent id (LibreChat uses `agent_<random>`). */
function newAgentId(): string {
  const rnd =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().replace(/-/g, '')
      : Math.random().toString(36).slice(2);
  return `agent_${rnd.slice(0, 24)}`;
}

/** Build a StoredAgent row from a full Agent object. */
function agentToStored(agent: t.Agent): StoredAgent {
  const now = Date.now();
  return {
    agentId: agent.id,
    name: agent.name ?? 'Agent',
    description: agent.description ?? null,
    instructions: agent.instructions ?? null,
    model: agent.model ?? null,
    provider: (agent.provider as unknown as string) ?? null,
    tools: agent.tools ? JSON.stringify(agent.tools) : null,
    configJson: JSON.stringify(agent),
    createdAt: typeof agent.created_at === 'number' ? agent.created_at : now,
    updatedAt: now,
  };
}

/** CREATE: assemble a full Agent from the create params, persist to the device store, return it. */
async function createAgentInStore(params: t.AgentCreateParams): Promise<t.Agent> {
  const id = newAgentId();
  const agent = {
    id,
    name: params.name ?? 'New Agent',
    description: params.description ?? null,
    instructions: params.instructions ?? null,
    model: params.model ?? null,
    provider: (params.provider as unknown) ?? 'caladon',
    tools: (params.tools as unknown as string[]) ?? [],
    model_parameters: params.model_parameters ?? {},
    avatar: params.avatar ?? null,
    created_at: Date.now(),
    ...(params as Record<string, unknown>),
  } as unknown as t.Agent;
  agent.id = id; // ensure the spread didn't clobber it
  await getStoreProxy().upsertAgent(agentToStored(agent));
  return agent;
}

/** UPDATE: merge the patch into the stored agent, persist, return the merged Agent. */
async function updateAgentInStore(agent_id: string, data: t.AgentUpdateParams): Promise<t.Agent> {
  const store = getStoreProxy();
  const existing = await store.getAgent(agent_id);
  const base = existing ? storedToAgent(existing) : ({ id: agent_id } as t.Agent);
  const merged = { ...(base as Record<string, unknown>), ...(data as Record<string, unknown>), id: agent_id } as unknown as t.Agent;
  await store.upsertAgent(agentToStored(merged));
  return merged;
}
/**
 * Create a new agent
 */
export const useCreateAgentMutation = (
  options?: t.CreateAgentMutationOptions,
): UseMutationResult<t.Agent, Error, t.AgentCreateParams> => {
  const queryClient = useQueryClient();
  return useMutation((newAgentData: t.AgentCreateParams) => createAgentInStore(newAgentData), {
    onMutate: (variables) => options?.onMutate?.(variables),
    onError: (error, variables, context) => options?.onError?.(error, variables, context),
    onSuccess: (newAgent, variables, context) => {
      ((keys: t.AgentListParams[]) => {
        keys.forEach((key) => {
          const listRes = queryClient.getQueryData<t.AgentListResponse>([QueryKeys.agents, key]);
          if (!listRes) {
            return options?.onSuccess?.(newAgent, variables, context);
          }
          const currentAgents = [newAgent, ...JSON.parse(JSON.stringify(listRes.data))];

          queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], {
            ...listRes,
            data: currentAgents,
          });
        });
      })(allAgentViewAndEditQueryKeys);
      invalidateAgentMarketplaceQueries(queryClient);

      return options?.onSuccess?.(newAgent, variables, context);
    },
  });
};

/**
 * Hook for updating an agent
 */
export const useUpdateAgentMutation = (
  options?: t.UpdateAgentMutationOptions,
): UseMutationResult<t.Agent, Error, { agent_id: string; data: t.AgentUpdateParams }> => {
  const queryClient = useQueryClient();
  return useMutation(
    ({ agent_id, data }: { agent_id: string; data: t.AgentUpdateParams }) => {
      return updateAgentInStore(agent_id, data);
    },
    {
      onMutate: (variables) => options?.onMutate?.(variables),
      onError: (error, variables, context) => {
        return options?.onError?.(error, variables, context);
      },
      onSuccess: (updatedAgent, variables, context) => {
        ((keys: t.AgentListParams[]) => {
          keys.forEach((key) => {
            const listRes = queryClient.getQueryData<t.AgentListResponse>([QueryKeys.agents, key]);

            if (!listRes) {
              return options?.onSuccess?.(updatedAgent, variables, context);
            }

            queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], {
              ...listRes,
              data: listRes.data.map((agent) => {
                if (agent.id === variables.agent_id) {
                  return updatedAgent;
                }
                return agent;
              }),
            });
          });
        })(allAgentViewAndEditQueryKeys);

        queryClient.setQueryData<t.Agent>([QueryKeys.agent, variables.agent_id], updatedAgent);
        queryClient.setQueryData<t.Agent>(
          [QueryKeys.agent, variables.agent_id, 'expanded'],
          updatedAgent,
        );
        invalidateAgentMarketplaceQueries(queryClient);

        return options?.onSuccess?.(updatedAgent, variables, context);
      },
    },
  );
};

/**
 * Hook for deleting an agent
 */
export const useDeleteAgentMutation = (
  options?: t.DeleteAgentMutationOptions,
): UseMutationResult<void, Error, t.DeleteAgentBody> => {
  const queryClient = useQueryClient();
  return useMutation(
    ({ agent_id }: t.DeleteAgentBody) => {
      return getStoreProxy().deleteAgent(agent_id);
    },
    {
      onMutate: (variables) => options?.onMutate?.(variables),
      onError: (error, variables, context) => options?.onError?.(error, variables, context),
      onSuccess: (_data, variables, context) => {
        const data = ((keys: t.AgentListParams[]) => {
          let data: t.Agent[] = [];
          keys.forEach((key) => {
            const listRes = queryClient.getQueryData<t.AgentListResponse>([QueryKeys.agents, key]);

            if (!listRes) {
              return options?.onSuccess?.(_data, variables, context);
            }

            data = listRes.data.filter((agent) => agent.id !== variables.agent_id);

            queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], {
              ...listRes,
              data,
            });
          });
          return data;
        })(allAgentViewAndEditQueryKeys);

        queryClient.removeQueries([QueryKeys.agent, variables.agent_id]);
        queryClient.removeQueries([QueryKeys.agent, variables.agent_id, 'expanded']);
        invalidateAgentMarketplaceQueries(queryClient);

        return options?.onSuccess?.(_data, variables, data);
      },
    },
  );
};

/**
 * Hook for duplicating an agent
 */
export const useDuplicateAgentMutation = (
  options?: t.DuplicateAgentMutationOptions,
): UseMutationResult<{ agent: t.Agent; actions: t.Action[] }, Error, t.DuplicateAgentBody> => {
  const queryClient = useQueryClient();

  return useMutation<{ agent: t.Agent; actions: t.Action[] }, Error, t.DuplicateAgentBody>(
    (params: t.DuplicateAgentBody) => dataService.duplicateAgent(params),
    {
      onMutate: options?.onMutate,
      onError: options?.onError,
      onSuccess: ({ agent, actions }, variables, context) => {
        ((keys: t.AgentListParams[]) => {
          keys.forEach((key) => {
            const listRes = queryClient.getQueryData<t.AgentListResponse>([QueryKeys.agents, key]);
            if (listRes) {
              const currentAgents = [agent, ...listRes.data];
              queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], {
                ...listRes,
                data: currentAgents,
              });
            }
          });
        })(allAgentViewAndEditQueryKeys);

        const existingActions = queryClient.getQueryData<t.Action[]>([QueryKeys.actions]) || [];

        queryClient.setQueryData<t.Action[]>([QueryKeys.actions], existingActions.concat(actions));
        invalidateAgentMarketplaceQueries(queryClient);

        return options?.onSuccess?.({ agent, actions }, variables, context);
      },
    },
  );
};

/**
 * Hook for uploading an agent avatar
 */
export const useUploadAgentAvatarMutation = (
  options?: t.UploadAgentAvatarOptions,
): UseMutationResult<
  t.Agent, // response data
  unknown, // error
  t.AgentAvatarVariables, // request
  unknown // context
> => {
  const queryClient = useQueryClient();
  return useMutation<t.Agent, unknown, t.AgentAvatarVariables>({
    mutationKey: [MutationKeys.agentAvatarUpload],
    mutationFn: (variables: t.AgentAvatarVariables) => dataService.uploadAgentAvatar(variables),
    onMutate: (variables) => options?.onMutate?.(variables),
    onError: (error, variables, context) => options?.onError?.(error, variables, context),
    onSuccess: (updatedAgent, variables, context) => {
      ((keys: t.AgentListParams[]) => {
        keys.forEach((key) => {
          const listRes = queryClient.getQueryData<t.AgentListResponse>([QueryKeys.agents, key]);
          if (!listRes) {
            return;
          }

          queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], {
            ...listRes,
            data: listRes.data.map((agent) => {
              if (agent.id === variables.agent_id) {
                return updatedAgent;
              }
              return agent;
            }),
          });
        });
      })(allAgentViewAndEditQueryKeys);

      queryClient.setQueryData<t.Agent>([QueryKeys.agent, variables.agent_id], updatedAgent);
      queryClient.setQueryData<t.Agent>(
        [QueryKeys.agent, variables.agent_id, 'expanded'],
        updatedAgent,
      );
      invalidateAgentMarketplaceQueries(queryClient);

      return options?.onSuccess?.(updatedAgent, variables, context);
    },
  });
};

/**
 * Hook for updating Agent Actions
 */
export const useUpdateAgentAction = (
  options?: t.UpdateAgentActionOptions,
): UseMutationResult<
  t.UpdateAgentActionResponse, // response data
  unknown, // error
  t.UpdateAgentActionVariables, // request
  unknown // context
> => {
  const queryClient = useQueryClient();
  return useMutation([MutationKeys.updateAgentAction], {
    mutationFn: (variables: t.UpdateAgentActionVariables) =>
      dataService.updateAgentAction(variables),

    onMutate: (variables) => options?.onMutate?.(variables),
    onError: (error, variables, context) => options?.onError?.(error, variables, context),
    onSuccess: (updateAgentActionResponse, variables, context) => {
      const updatedAgent = updateAgentActionResponse[0];
      ((keys: t.AgentListParams[]) => {
        keys.forEach((key) => {
          const listRes = queryClient.getQueryData<t.AgentListResponse>([QueryKeys.agents, key]);

          if (!listRes) {
            return options?.onSuccess?.(updateAgentActionResponse, variables, context);
          }
          queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], {
            ...listRes,
            data: listRes.data.map((agent) => {
              if (agent.id === variables.agent_id) {
                return updatedAgent;
              }
              return agent;
            }),
          });
        });
      })(allAgentViewAndEditQueryKeys);

      queryClient.setQueryData<t.Action[]>([QueryKeys.actions], (prev) => {
        if (!prev) {
          return [updateAgentActionResponse[1]];
        }

        if (variables.action_id) {
          return prev.map((action) => {
            if (action.action_id === variables.action_id) {
              return updateAgentActionResponse[1];
            }
            return action;
          });
        }

        return [...prev, updateAgentActionResponse[1]];
      });

      queryClient.setQueryData<t.Agent>([QueryKeys.agent, variables.agent_id], updatedAgent);
      queryClient.setQueryData<t.Agent>(
        [QueryKeys.agent, variables.agent_id, 'expanded'],
        updatedAgent,
      );
      return options?.onSuccess?.(updateAgentActionResponse, variables, context);
    },
  });
};

/**
 * Hook for deleting an Agent Action
 */

export const useDeleteAgentAction = (
  options?: t.DeleteAgentActionOptions,
): UseMutationResult<void, Error, t.DeleteAgentActionVariables, unknown> => {
  const queryClient = useQueryClient();
  return useMutation([MutationKeys.deleteAgentAction], {
    mutationFn: (variables: t.DeleteAgentActionVariables) => {
      return dataService.deleteAgentAction({
        ...variables,
      });
    },

    onMutate: (variables) => options?.onMutate?.(variables),
    onError: (error, variables, context) => options?.onError?.(error, variables, context),
    onSuccess: (_data, variables, context) => {
      let domain: string | undefined = '';
      queryClient.setQueryData<t.Action[]>([QueryKeys.actions], (prev) => {
        return prev?.filter((action) => {
          domain = action.metadata.domain;
          return action.action_id !== variables.action_id;
        });
      });
      ((keys: t.AgentListParams[]) => {
        keys.forEach((key) => {
          queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], (prev) => {
            if (!prev) {
              return prev;
            }

            return {
              ...prev,
              data: prev.data.map((agent) => {
                if (agent.id === variables.agent_id) {
                  return {
                    ...agent,
                    tools: agent.tools?.filter((tool) => !tool.includes(domain ?? '')),
                  };
                }
                return agent;
              }),
            };
          });
        });
      })(allAgentViewAndEditQueryKeys);
      const updaterFn = (prev) => {
        if (!prev) {
          return prev;
        }

        return {
          ...prev,
          tools: prev.tools?.filter((tool) => !tool.includes(domain ?? '')),
        };
      };
      queryClient.setQueryData<t.Agent>([QueryKeys.agent, variables.agent_id], updaterFn);
      queryClient.setQueryData<t.Agent>(
        [QueryKeys.agent, variables.agent_id, 'expanded'],
        updaterFn,
      );
      return options?.onSuccess?.(_data, variables, context);
    },
  });
};

/**
 * Hook for reverting an agent to a previous version
 */
export const useRevertAgentVersionMutation = (
  options?: t.RevertAgentVersionOptions,
): UseMutationResult<t.Agent, Error, { agent_id: string; version_index: number }> => {
  const queryClient = useQueryClient();
  return useMutation(
    ({ agent_id, version_index }: { agent_id: string; version_index: number }) => {
      return dataService.revertAgentVersion({
        agent_id,
        version_index,
      });
    },
    {
      onMutate: (variables) => options?.onMutate?.(variables),
      onError: (error, variables, context) => options?.onError?.(error, variables, context),
      onSuccess: (revertedAgent, variables, context) => {
        queryClient.setQueryData<t.Agent>([QueryKeys.agent, variables.agent_id], revertedAgent);

        ((keys: t.AgentListParams[]) => {
          keys.forEach((key) => {
            const listRes = queryClient.getQueryData<t.AgentListResponse>([QueryKeys.agents, key]);

            if (listRes) {
              queryClient.setQueryData<t.AgentListResponse>([QueryKeys.agents, key], {
                ...listRes,
                data: listRes.data.map((agent) => {
                  if (agent.id === variables.agent_id) {
                    return revertedAgent;
                  }
                  return agent;
                }),
              });
            }
          });
        })(allAgentViewAndEditQueryKeys);

        return options?.onSuccess?.(revertedAgent, variables, context);
      },
    },
  );
};

export const invalidateAgentMarketplaceQueries = (queryClient: QueryClient) => {
  queryClient.invalidateQueries([QueryKeys.marketplaceAgents]);
};
