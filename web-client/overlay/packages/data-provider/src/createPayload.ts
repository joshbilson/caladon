import type * as t from './types';
import { EndpointURLs } from './config';
import * as s from './schemas';

/**
 * Caladon surgery (SURGERY.md §B2 / §D): `server` collapses to the single shim chat route
 * (`/api/caladon/chat`) for every endpoint — all LibreChat per-provider/assistant routes are
 * amputated (§A2). The returned `payload` is still the LibreChat submission shape so the existing
 * composer/regenerate/edit logic is untouched; useSSE seals the prompt text into an envelope and
 * replaces the wire body with `{ envelope, model }` immediately before POST (the seal is async —
 * WASM — and createPayload is synchronous, so the seal lives at the SSE call site, not here).
 */
export default function createPayload(submission: t.TSubmission) {
  const {
    isEdited,
    addedConvo,
    userMessage,
    isContinued,
    isTemporary,
    isRegenerate,
    conversation,
    editedContent,
    ephemeralAgent,
    endpointOption,
    manualSkills,
  } = submission;
  const { conversationId } = s.tConvoUpdateSchema.parse(conversation);
  const { endpoint: _e } = endpointOption as {
    endpoint: s.EModelEndpoint;
    endpointType?: s.EModelEndpoint;
  };

  const endpoint = _e as s.EModelEndpoint;
  // Every endpoint routes to the one Caladon chat opener on the shim. The attested CVM is the
  // only thing that runs inference; the model slug is honoured only if attested.
  const server = EndpointURLs[s.EModelEndpoint.agents];

  const payload: t.TPayload = {
    ...userMessage,
    ...endpointOption,
    endpoint,
    addedConvo,
    isTemporary,
    isRegenerate,
    editedContent,
    conversationId,
    isContinued: !!(isEdited && isContinued),
    ephemeralAgent: s.isAssistantsEndpoint(endpoint) ? undefined : ephemeralAgent,
    manualSkills: s.isAssistantsEndpoint(endpoint) ? undefined : manualSkills,
  };

  return { server, payload };
}
