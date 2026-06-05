import { memo, useState } from 'react';
import { Paperclip } from 'lucide-react';
import AddedConvo from './AddedConvo';
import RagFileAttach from '~/components/Caladon/RagFileAttach';
import type { TConversation } from 'librechat-data-provider';
import type { SetterOrUpdater } from 'recoil';

/**
 * Caladon overlay of TextareaHeader. Upstream renders only the AddedConvo strip (multi-convo). We
 * KEEP that and ALSO mount the on-device document-retrieval (RAG) attach surface here — directly
 * above the composer textarea, the natural, discoverable place to attach files for grounding.
 *
 * It is collapsed behind a small toggle so the composer stays clean; expanding reveals
 * `RagFileAttach`, which parses → chunks → embeds → stores the chosen files ENTIRELY on this device
 * (see ~/store/useRag). At chat time `augmentPromptWithRAG` (wired in useSSE) retrieves the relevant
 * chunks and injects them into the prompt BEFORE it is sealed, so the gateway never sees the document
 * text. Trust-no-one: nothing here uploads anything.
 */
export default memo(function TextareaHeader({
  addedConvo,
  setAddedConvo,
}: {
  addedConvo: TConversation | null;
  setAddedConvo: SetterOrUpdater<TConversation | null>;
}) {
  const [ragOpen, setRagOpen] = useState(false);

  return (
    <>
      {addedConvo && (
        <div className="m-1.5 flex flex-col divide-y overflow-hidden rounded-b-lg rounded-t-2xl bg-surface-secondary-alt">
          <AddedConvo addedConvo={addedConvo} setAddedConvo={setAddedConvo} />
        </div>
      )}

      <div className="mx-1.5 mt-1.5">
        <button
          type="button"
          onClick={() => setRagOpen((v) => !v)}
          aria-expanded={ragOpen}
          className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs text-text-secondary transition-colors hover:bg-surface-tertiary hover:text-text-primary"
        >
          <Paperclip className="h-3.5 w-3.5" aria-hidden="true" />
          {ragOpen ? 'Hide document retrieval' : 'Attach documents (on-device retrieval)'}
        </button>
        {ragOpen && (
          <div className="mt-1.5 rounded-2xl border border-border-light bg-surface-secondary-alt p-3">
            <RagFileAttach compact />
          </div>
        )}
      </div>
    </>
  );
});
