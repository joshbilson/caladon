/**
 * Pure helpers for extracting a subagent chain from a stored agent's `configJson`. Kept dependency-
 * free (no store/seal imports) so they are trivially unit-testable. See orchestrate.ts for the
 * runtime that consumes the ids.
 */

/** Pull a plain agent-id string out of a string or an {id}/{agent_id}/{agentId} object. */
export function idOf(v: unknown): string {
  if (typeof v === 'string') {
    return v;
  }
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    for (const k of ['id', 'agent_id', 'agentId']) {
      if (typeof o[k] === 'string') {
        return o[k] as string;
      }
    }
  }
  return '';
}

/**
 * Extract the subagent chain from a stored agent's `configJson`. The Agent Builder persists the
 * chain in one of THREE shapes depending on which Advanced control the user touched:
 *   1. `agent_ids: string[]`                    — the AgentChain control
 *   2. `subagents: { enabled, agent_ids: [] }`  — the AgentSubagents "Beta" toggle (DEFAULT control)
 *   3. `edges: [{ to }]`                          — the AgentHandoffs graph
 * We union all three (honouring `subagents.enabled !== false`), drop self-references, and dedupe so
 * orchestration fires regardless of which control was used. Returns clean id strings.
 */
export function collectSubagentIds(
  configJson: string | null | undefined,
  selfId?: string,
): string[] {
  if (!configJson) {
    return [];
  }
  let cfg: Record<string, unknown>;
  try {
    cfg = JSON.parse(configJson) as Record<string, unknown>;
  } catch {
    return [];
  }
  const out: string[] = [];
  const push = (v: unknown) => {
    const id = idOf(v);
    if (id && id !== selfId) {
      out.push(id);
    }
  };
  if (Array.isArray(cfg.agent_ids)) {
    cfg.agent_ids.forEach(push);
  }
  const sub = cfg.subagents as { enabled?: boolean; agent_ids?: unknown[] } | undefined;
  if (sub && sub.enabled !== false && Array.isArray(sub.agent_ids)) {
    sub.agent_ids.forEach(push);
  }
  if (Array.isArray(cfg.edges)) {
    for (const e of cfg.edges) {
      push((e as { to?: unknown })?.to);
    }
  }
  return Array.from(new Set(out));
}
