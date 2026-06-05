import { memo, useCallback, useEffect, useRef, useState } from 'react';
import { Sparkles, Plus, Check, Trash2 } from 'lucide-react';
import { getStoreProxy } from '~/lib/store';
import type { StoredSkill } from '~/lib/store';

/**
 * Caladon Skills control (composer). A skill is a reusable instruction snippet stored ONLY in the
 * encrypted device store (trust-no-one). Selecting one makes it "active"
 * (localStorage `caladon:activeSkillId`); useSSE then prepends its body to the next prompts BEFORE
 * sealing (see lib/skills/inject.ts). Create/list/delete all hit the device store; nothing uploads.
 */
const ACTIVE_KEY = 'caladon:activeSkillId';

function newSkillId(): string {
  const rnd = new Uint8Array(8);
  crypto.getRandomValues(rnd);
  return 'skill_' + Array.from(rnd, (b) => b.toString(16).padStart(2, '0')).join('');
}

export default memo(function SkillsControl() {
  const [open, setOpen] = useState(false);
  const [skills, setSkills] = useState<StoredSkill[]>([]);
  const [activeId, setActiveId] = useState<string | null>(() => {
    try {
      return localStorage.getItem(ACTIVE_KEY);
    } catch {
      return null;
    }
  });
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [body, setBody] = useState('');
  const rootRef = useRef<HTMLDivElement | null>(null);

  const refresh = useCallback(async () => {
    try {
      const store = getStoreProxy();
      for (let i = 0; i < 40 && !store.isOpen; i++) {
        await new Promise((r) => setTimeout(r, 100));
      }
      if (store.isOpen) {
        setSkills(await store.listSkills());
      }
    } catch {
      /* device store not ready */
    }
  }, []);

  useEffect(() => {
    if (open) {
      void refresh();
    }
  }, [open, refresh]);

  // Close on outside click.
  useEffect(() => {
    if (!open) {
      return;
    }
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
        setCreating(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const setActive = (id: string | null) => {
    setActiveId(id);
    try {
      if (id) {
        localStorage.setItem(ACTIVE_KEY, id);
      } else {
        localStorage.removeItem(ACTIVE_KEY);
      }
    } catch {
      /* ignore */
    }
  };

  const save = async () => {
    if (!name.trim() || !body.trim()) {
      return;
    }
    const now = Date.now();
    const skill: StoredSkill = {
      skillId: newSkillId(),
      name: name.trim(),
      description: null,
      body: body.trim(),
      createdAt: now,
      updatedAt: now,
    };
    try {
      await getStoreProxy().upsertSkill(skill);
      setActive(skill.skillId);
      setName('');
      setBody('');
      setCreating(false);
      await refresh();
    } catch {
      /* ignore */
    }
  };

  const remove = async (id: string) => {
    try {
      await getStoreProxy().deleteSkill(id);
      if (activeId === id) {
        setActive(null);
      }
      await refresh();
    } catch {
      /* ignore */
    }
  };

  const activeName = skills.find((s) => s.skillId === activeId)?.name;

  return (
    <div className="relative inline-flex" ref={rootRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        title="Apply a reusable on-device skill (instruction) to your messages."
        className={
          'inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs transition-colors hover:bg-surface-tertiary ' +
          (activeId ? 'text-violet-500' : 'text-text-secondary hover:text-text-primary')
        }
      >
        <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
        {activeName ? `Skill: ${activeName}` : 'Skills'}
      </button>

      {open && (
        <div className="absolute bottom-full left-0 z-50 mb-1 w-72 rounded-xl border border-border-light bg-surface-primary p-2 shadow-lg">
          <div className="max-h-48 overflow-auto">
            <button
              type="button"
              onClick={() => setActive(null)}
              className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-xs hover:bg-surface-tertiary"
            >
              <span className="text-text-secondary">None (off)</span>
              {!activeId && <Check className="h-3.5 w-3.5 text-violet-500" />}
            </button>
            {skills.map((s) => (
              <div
                key={s.skillId}
                className="group flex w-full items-center justify-between rounded-md px-2 py-1.5 text-xs hover:bg-surface-tertiary"
              >
                <button
                  type="button"
                  onClick={() => setActive(s.skillId)}
                  className="flex flex-1 items-center gap-1.5 text-left text-text-primary"
                  title={s.body}
                >
                  {activeId === s.skillId ? (
                    <Check className="h-3.5 w-3.5 shrink-0 text-violet-500" />
                  ) : (
                    <span className="h-3.5 w-3.5 shrink-0" />
                  )}
                  <span className="truncate">{s.name}</span>
                </button>
                <button
                  type="button"
                  onClick={() => remove(s.skillId)}
                  className="ml-1 hidden shrink-0 text-text-secondary hover:text-red-500 group-hover:block"
                  title="Delete skill"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
            {skills.length === 0 && (
              <div className="px-2 py-1.5 text-xs text-text-secondary">No skills yet.</div>
            )}
          </div>

          <div className="mt-1 border-t border-border-light pt-1">
            {!creating ? (
              <button
                type="button"
                onClick={() => setCreating(true)}
                className="flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-text-secondary hover:bg-surface-tertiary hover:text-text-primary"
              >
                <Plus className="h-3.5 w-3.5" /> New skill
              </button>
            ) : (
              <div className="flex flex-col gap-1.5 p-1">
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Skill name (e.g. Summarise)"
                  className="rounded-md border border-border-light bg-surface-secondary px-2 py-1 text-xs text-text-primary"
                />
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder="Instruction the model should follow (e.g. 'Summarise the user's text as 5 concise bullet points.')"
                  rows={3}
                  className="rounded-md border border-border-light bg-surface-secondary px-2 py-1 text-xs text-text-primary"
                />
                <div className="flex justify-end gap-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      setCreating(false);
                      setName('');
                      setBody('');
                    }}
                    className="rounded-md px-2 py-1 text-xs text-text-secondary hover:bg-surface-tertiary"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={save}
                    disabled={!name.trim() || !body.trim()}
                    className="rounded-md bg-violet-600 px-2 py-1 text-xs text-white disabled:opacity-50"
                  >
                    Save
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
});
