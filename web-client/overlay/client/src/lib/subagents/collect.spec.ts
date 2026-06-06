import { collectSubagentIds, idOf } from './collect';

describe('idOf', () => {
  it('returns plain strings unchanged', () => {
    expect(idOf('agent_abc')).toBe('agent_abc');
  });
  it('reads id / agent_id / agentId object shapes', () => {
    expect(idOf({ id: 'a' })).toBe('a');
    expect(idOf({ agent_id: 'b' })).toBe('b');
    expect(idOf({ agentId: 'c' })).toBe('c');
  });
  it('returns "" for junk', () => {
    expect(idOf(null)).toBe('');
    expect(idOf(42)).toBe('');
    expect(idOf({})).toBe('');
  });
});

describe('collectSubagentIds', () => {
  it('reads the flat agent_ids (AgentChain) shape', () => {
    expect(collectSubagentIds(JSON.stringify({ agent_ids: ['a', 'b'] }), 'self')).toEqual([
      'a',
      'b',
    ]);
  });

  it('reads the nested subagents.agent_ids (Beta toggle) shape when enabled', () => {
    expect(
      collectSubagentIds(JSON.stringify({ subagents: { enabled: true, agent_ids: ['x', 'y'] } })),
    ).toEqual(['x', 'y']);
  });

  it('honours subagents.enabled === false (skips the chain)', () => {
    expect(
      collectSubagentIds(JSON.stringify({ subagents: { enabled: false, agent_ids: ['x'] } })),
    ).toEqual([]);
  });

  it('treats a missing enabled key as enabled', () => {
    expect(collectSubagentIds(JSON.stringify({ subagents: { agent_ids: ['z'] } }))).toEqual(['z']);
  });

  it('reads edges[].to (AgentHandoffs) targets', () => {
    expect(
      collectSubagentIds(JSON.stringify({ edges: [{ from: 'self', to: 'e1' }, { to: 'e2' }] })),
    ).toEqual(['e1', 'e2']);
  });

  it('unions all three shapes, drops self-refs, and dedupes', () => {
    const cfg = JSON.stringify({
      agent_ids: ['a', 'self'],
      subagents: { enabled: true, agent_ids: ['a', 'c'] },
      edges: [{ to: 'd' }, { to: 'self' }],
    });
    expect(collectSubagentIds(cfg, 'self')).toEqual(['a', 'c', 'd']);
  });

  it('reads object-shaped ids inside agent_ids', () => {
    expect(
      collectSubagentIds(JSON.stringify({ agent_ids: [{ id: 'o1' }, { agent_id: 'o2' }] })),
    ).toEqual(['o1', 'o2']);
  });

  it('returns [] for null/empty/malformed config', () => {
    expect(collectSubagentIds(null)).toEqual([]);
    expect(collectSubagentIds('')).toEqual([]);
    expect(collectSubagentIds('not json')).toEqual([]);
  });
});
