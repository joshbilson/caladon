import { memo, useState } from 'react';
import { Paperclip, Wrench } from 'lucide-react';
import AddedConvo from './AddedConvo';
import RagFileAttach from '~/components/Caladon/RagFileAttach';
import type { TConversation } from 'librechat-data-provider';
import type { SetterOrUpdater } from 'recoil';

const readFlag = (k: string) => {
  try {
    return localStorage.getItem(k) === 'true';
  } catch {
    return false;
  }
};
const writeFlag = (k: string, v: boolean) => {
  try {
    localStorage.setItem(k, v ? 'true' : 'false');
  } catch {
    /* ignore */
  }
};

/**
 * Caladon "Tools" toggle. When ON, a chat turn runs the in-CVM tool loop (MCP): the gateway routes
 * it to a function-calling attested model and executes tools INSIDE the CVM behind a fail-closed
 * egress allowlist (see gateway/app/mcp_broker). "Yolo" bypasses the host allowlist for the turn
 * (the SSRF guard still blocks internal targets). Flags are read by useSSE → sealChat. Opt-in
 * (default off) because tool turns are routed to a specific model and run slower.
 */
function ToolsToggle() {
  const [on, setOn] = useState(() => readFlag('caladon:toolsEnabled'));
  const [yolo, setYolo] = useState(() => readFlag('caladon:toolsYolo'));
  return (
    <span className="inline-flex items-center gap-2">
      <button
        type="button"
        onClick={() => {
          const next = !on;
          setOn(next);
          writeFlag('caladon:toolsEnabled', next);
        }}
        aria-pressed={on}
        title="Run this chat through the in-CVM tool loop (MCP). Tools execute inside the attested CVM."
        className={
          'inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs transition-colors hover:bg-surface-tertiary ' +
          (on ? 'text-emerald-500' : 'text-text-secondary hover:text-text-primary')
        }
      >
        <Wrench className="h-3.5 w-3.5" aria-hidden="true" />
        {on ? 'Tools: on' : 'Tools: off'}
      </button>
      {on && (
        <label className="inline-flex cursor-pointer items-center gap-1 text-xs text-text-secondary" title="Bypass the egress allowlist for tool web access (SSRF-internal targets still blocked).">
          <input
            type="checkbox"
            checked={yolo}
            onChange={(e) => {
              setYolo(e.target.checked);
              writeFlag('caladon:toolsYolo', e.target.checked);
            }}
          />
          yolo
        </label>
      )}
    </span>
  );
}

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
        <span className="ml-1 inline-flex align-middle">
          <ToolsToggle />
        </span>
        {ragOpen && (
          <div className="mt-1.5 rounded-2xl border border-border-light bg-surface-secondary-alt p-3">
            <RagFileAttach compact />
          </div>
        )}
      </div>
    </>
  );
});
