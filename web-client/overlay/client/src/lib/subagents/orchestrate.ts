import { sealChat, openDelta, signRequest } from '~/lib/caladon';
import { getStoreProxy } from '~/lib/store';
import { storedToAgent } from '~/data-provider/Agents/queries';
import type { Envelope } from '@caladon/protocol';

/**
 * Caladon subagents — CLIENT-ORCHESTRATED (trust-no-one, no gateway change / no re-pin).
 *
 * When the active agent has `agent_ids` (its subagent chain, set in the Agent Builder), the client
 * runs each subagent as a headless sealed completion against the SAME attested gateway, collects
 * their answers, and feeds them to the main agent as context so it synthesises a final reply. Every
 * sub-call is a normal sealed round-trip (prompt sealed in-browser, opened only in the CVM), so the
 * orchestration adds NO new trust surface — it's just extra sealed turns. The gateway never learns
 * the agent graph; it only ever sees individual sealed prompts.
 */
const CHAT_PATH = '/api/caladon/chat';
const GATEWAY_CHAT_PATH = '/v1/chat';

export interface SubagentStep {
  name: string;
  output: string;
}

/**
 * One headless sealed completion: seal `prompt` (optionally on `model`), POST it, and accumulate the
 * sealed token deltas back into plaintext. No streaming UI — returns the full text. Throws on a
 * transport/HTTP error so the caller can fail soft (skip that subagent).
 */
export async function runSealedCompletion(prompt: string, model?: string): Promise<string> {
  const body = await sealChat(prompt, model);
  const auth = await signRequest('POST', GATEWAY_CHAT_PATH);
  const resp = await fetch(CHAT_PATH, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: auth },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(`subagent completion failed: ${resp.status}`);
  }
  const raw = await resp.text();
  let text = '';
  // The gateway streams `event: token` SSE lines whose data is `{ envelope }` (sealed); other events
  // (receipt/done/tool) are ignored here. Parse line-by-line and open each token envelope under SK.
  for (const block of raw.split('\n\n')) {
    if (!/^event:\s*token/m.test(block)) {
      continue;
    }
    const dataLine = block.split('\n').find((l) => l.startsWith('data:'));
    if (!dataLine) {
      continue;
    }
    try {
      const env = JSON.parse(dataLine.slice(dataLine.indexOf(':') + 1).trim()).envelope as Envelope;
      text += await openDelta(env);
    } catch {
      /* skip a malformed delta */
    }
  }
  return text.trim();
}

/**
 * Run the main agent's subagent chain. Returns the per-subagent outputs (for display) and a context
 * block to prepend to the main agent's prompt. Fails soft per subagent (a failed/empty sub-call is
 * skipped). `agentIds` come from the main agent's config; each is resolved from the device store.
 */
export async function orchestrateSubagents(
  agentIds: unknown[],
  userPrompt: string,
): Promise<{ steps: SubagentStep[]; context: string }> {
  const store = getStoreProxy();
  if (!store.isOpen || !agentIds?.length) {
    return { steps: [], context: '' };
  }
  // agent_ids items are normally plain id strings, but be robust to {id}/{agent_id} object shapes.
  const ids = agentIds
    .map((it) =>
      typeof it === 'string'
        ? it
        : ((it as { id?: string; agent_id?: string; agentId?: string })?.id ??
          (it as { agent_id?: string })?.agent_id ??
          (it as { agentId?: string })?.agentId ??
          ''),
    )
    .filter(Boolean);
  // eslint-disable-next-line no-console
  console.debug('[caladon subagents] orchestrate ids:', ids);
  // Resolve once; fall back to a full list scan if a direct id lookup misses (id-shape drift).
  let all: Awaited<ReturnType<typeof store.listAgents>> = [];
  try {
    all = await store.listAgents();
  } catch {
    /* ignore */
  }
  const steps: SubagentStep[] = [];
  for (const id of ids.slice(0, 5)) {
    // cap at 5 to bound latency/cost
    try {
      const row = (await store.getAgent(id)) ?? all.find((a) => a.agentId === id) ?? null;
      if (!row) {
        // eslint-disable-next-line no-console
        console.debug('[caladon subagents] subagent not found in store:', id);
        continue;
      }
      const sub = storedToAgent(row);
      const instr = (sub.instructions || '').trim();
      const subPrompt = `${instr}\n\nUser request:\n${userPrompt}`.trim();
      const output = await runSealedCompletion(subPrompt, sub.model);
      if (output) {
        steps.push({ name: sub.name || 'subagent', output });
      }
    } catch {
      /* skip this subagent (fail soft) */
    }
  }
  if (!steps.length) {
    return { steps: [], context: '' };
  }
  const context =
    'You coordinate specialist subagents. Their responses to the user request are below — ' +
    'synthesise them into one cohesive final answer.\n\n' +
    steps.map((s) => `<subagent name="${s.name}">\n${s.output}\n</subagent>`).join('\n\n');
  return { steps, context };
}
