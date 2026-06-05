/**
 * Caladon memory injection (trust-no-one). Reads the user's on-device memories from the encrypted
 * store and prepends them as a compact <memory> block to the prompt BEFORE it is sealed — exactly
 * like RAG context (lib/rag/retrieval.augmentPromptWithRAG). The gateway only ever sees the sealed
 * envelope; the memory text never leaves the device unencrypted.
 *
 * Fail-OPEN: any error (store not open, read failure) returns the original prompt unchanged so a
 * memory hiccup never blocks a send. Honors a local "memory enabled" toggle (default ON).
 */
import { getStoreProxy } from '~/lib/store';

const MEMORY_PREF_KEY = 'caladon:memoryEnabled';

function memoryEnabled(): boolean {
  try {
    return localStorage.getItem(MEMORY_PREF_KEY) !== '0'; // default ON unless explicitly disabled
  } catch {
    return true;
  }
}

/**
 * Prepend the user's stored memories to `promptText`. Returns the original prompt unchanged when
 * memory is disabled, the store is closed, or there are no memories.
 */
export async function injectMemoriesIntoPrompt(promptText: string): Promise<string> {
  try {
    if (!memoryEnabled()) {
      return promptText;
    }
    const store = getStoreProxy();
    if (!store.isOpen) {
      return promptText;
    }
    const memories = await store.listMemories();
    if (!memories.length) {
      return promptText;
    }
    const lines = memories.map((m) => `- ${m.key}: ${m.value}`).join('\n');
    const block =
      'The following are persistent facts the user has asked you to remember about them. ' +
      'Use them when relevant; do not mention this block explicitly.\n<memory>\n' +
      lines +
      '\n</memory>\n\n';
    return block + promptText;
  } catch {
    return promptText; // fail-open: memory must never block a send
  }
}
