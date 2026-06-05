import React from 'react';
import { VisuallyHidden } from '@ariakit/react';
import { CheckCircle2, EarthIcon, Pin, PinOff, ShieldCheck, Cloud } from 'lucide-react';
import { isAgentsEndpoint, isAssistantsEndpoint } from 'librechat-data-provider';
import type { Endpoint } from '~/common';
import { useFavorites, useLocalize, useIsActiveItem } from '~/hooks';
import { useModelSelectorContext } from '../ModelSelectorContext';
import { CustomMenuItem as MenuItem } from '../CustomMenu';
import { cn } from '~/utils';

/**
 * Caladon overlay of EndpointModelItem. Upstream renders the raw model slug. Caladon's "caladon"
 * custom endpoint lists the full RedPill catalog, so each model is tagged for trust:
 *   - `phala/*`  → runs in a hardware TEE (Intel TDX + GPU-CC): CONFIDENTIAL end-to-end.
 *   - everything else → the gateway opens the sealed prompt in-CVM then forwards it to a third-party
 *     CLOUD model in the clear: NOT confidential.
 * We strip the provider prefix for a readable name, keep the full slug in the title, and show a
 * shield (confidential) or cloud (not confidential) badge so the user always chooses knowingly.
 * Everything else (favorites, selection, avatar) is upstream behavior, unchanged.
 */

interface EndpointModelItemProps {
  modelId: string | null;
  endpoint: Endpoint;
}

/** True for a plain model endpoint (not agents/assistants) where the phala/ trust split applies. */
function isCaladonModelEndpoint(endpoint: Endpoint): boolean {
  return !isAgentsEndpoint(endpoint.value) && !isAssistantsEndpoint(endpoint.value);
}

export function EndpointModelItem({ modelId, endpoint }: EndpointModelItemProps) {
  const localize = useLocalize();
  const { handleSelectModel, selectedValues } = useModelSelectorContext();
  const {
    endpoint: selectedEndpoint,
    model: selectedModel,
    modelSpec: selectedSpec,
  } = selectedValues;
  const isSelected =
    !selectedSpec && selectedEndpoint === endpoint.value && selectedModel === modelId;
  const { isFavoriteModel, toggleFavoriteModel, isFavoriteAgent, toggleFavoriteAgent } =
    useFavorites();

  const { ref: itemRef, isActive } = useIsActiveItem<HTMLDivElement>();

  let isGlobal = false;
  let modelName = modelId;
  const avatarUrl = endpoint?.modelIcons?.[modelId ?? ''] || null;

  // Use custom names if available
  if (endpoint && modelId && isAgentsEndpoint(endpoint.value) && endpoint.agentNames?.[modelId]) {
    modelName = endpoint.agentNames[modelId];

    const modelInfo = endpoint?.models?.find((m) => m.name === modelId);
    isGlobal = modelInfo?.isGlobal ?? false;
  } else if (
    endpoint &&
    modelId &&
    isAssistantsEndpoint(endpoint.value) &&
    endpoint.assistantNames?.[modelId]
  ) {
    modelName = endpoint.assistantNames[modelId];
  }

  const isAgent = isAgentsEndpoint(endpoint.value);
  const isFavorite = isAgent
    ? isFavoriteAgent(modelId ?? '')
    : isFavoriteModel(modelId ?? '', endpoint.value);

  // Caladon trust tagging — only for plain model endpoints (the catalog), never agents/assistants.
  const isCaladonModel = !!modelId && isCaladonModelEndpoint(endpoint);
  const isConfidential = isCaladonModel && modelId!.startsWith('phala/');
  const isCloud = isCaladonModel && !modelId!.startsWith('phala/');
  // Readable display name: strip the provider prefix ("phala/kimi-k2.6" → "kimi-k2.6"); keep the
  // full slug in the title. Non-Caladon endpoints keep the upstream (possibly custom) name.
  const displayName =
    isCaladonModel && modelName && modelName.includes('/')
      ? modelName.slice(modelName.indexOf('/') + 1)
      : modelName;

  const handleFavoriteToggle = () => {
    if (!modelId) {
      return;
    }

    if (isAgent) {
      toggleFavoriteAgent(modelId);
    } else {
      toggleFavoriteModel({ model: modelId, endpoint: endpoint.value });
    }
  };

  const handleFavoriteClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    handleFavoriteToggle();
  };

  const renderAvatar = () => {
    const isAgentOrAssistant =
      isAgentsEndpoint(endpoint.value) || isAssistantsEndpoint(endpoint.value);
    const showEndpointIcon = isAgentOrAssistant && endpoint.icon;

    const getContent = () => {
      if (avatarUrl) {
        return <img src={avatarUrl} alt={modelName ?? ''} className="h-full w-full object-cover" />;
      }
      if (showEndpointIcon) {
        return endpoint.icon;
      }
      return null;
    };

    const content = getContent();
    if (!content) {
      return null;
    }

    return (
      <div className="flex h-5 w-5 flex-shrink-0 items-center justify-center overflow-hidden rounded-full">
        {content}
      </div>
    );
  };

  return (
    <MenuItem
      ref={itemRef}
      onClick={() => handleSelectModel(endpoint, modelId ?? '')}
      aria-selected={isSelected || undefined}
      className="group flex w-full cursor-pointer items-center justify-between rounded-lg px-2 text-sm"
    >
      <div className="flex w-full min-w-0 items-center gap-2 px-1 py-1" title={modelId ?? undefined}>
        {renderAvatar()}
        {isConfidential && (
          <ShieldCheck
            className="size-4 shrink-0 text-emerald-500"
            aria-label="Confidential — runs in a TEE"
          />
        )}
        {isCloud && (
          <Cloud className="size-4 shrink-0 text-amber-500" aria-label="Cloud — not confidential" />
        )}
        <span className="truncate">{displayName}</span>
        {isCloud && (
          <span className="ml-1 shrink-0 rounded bg-amber-500/15 px-1 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-600 dark:text-amber-400">
            cloud
          </span>
        )}
        {isGlobal && <EarthIcon className="ml-1 size-4 text-surface-submit" />}
      </div>
      <button
        type="button"
        tabIndex={isActive ? 0 : -1}
        onClick={handleFavoriteClick}
        aria-label={isFavorite ? localize('com_ui_unpin') : localize('com_ui_pin')}
        className={cn(
          'rounded-md p-1 hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring-primary',
          isFavorite
            ? 'visible'
            : 'invisible group-focus-within:visible group-hover:visible group-data-[active-item]:visible',
        )}
      >
        {isFavorite ? (
          <PinOff className="h-4 w-4 text-text-secondary" aria-hidden="true" />
        ) : (
          <Pin className="h-4 w-4 text-text-secondary" aria-hidden="true" />
        )}
      </button>
      {isSelected && (
        <>
          <CheckCircle2 className="size-4 shrink-0 text-text-primary" aria-hidden="true" />
          <VisuallyHidden>{localize('com_a11y_selected')}</VisuallyHidden>
        </>
      )}
    </MenuItem>
  );
}

export function renderEndpointModels(
  endpoint: Endpoint | null,
  models: Array<{ name: string; isGlobal?: boolean }>,
  filteredModels?: string[],
  endpointIndex?: number,
) {
  const modelsToRender = filteredModels || models.map((model) => model.name);
  const indexSuffix = endpointIndex != null ? `-${endpointIndex}` : '';

  return modelsToRender.map(
    (modelId, modelIndex) =>
      endpoint && (
        <EndpointModelItem
          key={`${endpoint.value}${indexSuffix}-${modelId}-${modelIndex}`}
          modelId={modelId}
          endpoint={endpoint}
        />
      ),
  );
}
