import { getStoreProxy } from '~/lib/store';

/**
 * Caladon skills — client-side prompt injection.
 *
 * A "skill" is a user-authored, reusable instruction snippet stored ONLY in the encrypted device
 * store (trust-no-one). When the user marks a skill active (composer Skills control → localStorage
 * `caladon:activeSkillId`), its body is prepended to the prompt BEFORE sealing — inside the trust
 * boundary, exactly like RAG/memory/artifacts (see [[lib/memory/inject]]). The gateway only ever
 * sees the sealed envelope; it never stores or learns the skill. Fails OPEN (a missing/closed store,
 * or no active skill, → the un-augmented prompt).
 */
const ACTIVE_SKILL_KEY = 'caladon:activeSkillId';

export function activeSkillId(): string | null {
  try {
    return localStorage.getItem(ACTIVE_SKILL_KEY);
  } catch {
    return null;
  }
}

/** Prepend the active skill's body to the prompt, if one is selected. */
export async function injectActiveSkillIntoPrompt(promptText: string): Promise<string> {
  const id = activeSkillId();
  if (!id) {
    return promptText;
  }
  try {
    const store = getStoreProxy();
    if (!store.isOpen) {
      return promptText;
    }
    const skill = await store.getSkill(id);
    if (!skill || !skill.body.trim()) {
      return promptText;
    }
    return `${skill.body.trim()}\n\n${promptText}`;
  } catch {
    return promptText; // fail open
  }
}
