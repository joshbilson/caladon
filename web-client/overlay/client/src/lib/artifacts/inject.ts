/**
 * Caladon artifacts — client-side system-prompt injection.
 *
 * Upstream LibreChat builds the artifact system prompt server-side (api/.../createRunBody.js) and
 * appends it to the model request. Caladon bypasses that server entirely — chat is sealed in the
 * browser and sent straight to the attested gateway — so the instruction that teaches the model the
 * `:::artifact{}:::` markup must be injected CLIENT-SIDE before sealing, exactly like the RAG and
 * memory injections (see [[lib/memory/inject]]). This is gated on the per-conversation artifacts
 * toggle (`conversation.artifacts`, set by the composer ToolsDropdown), so it costs zero tokens when
 * the user hasn't asked for artifacts.
 *
 * The supported type list is deliberately the trust-no-one subset our renderer (ArtifactPreview
 * overlay) can display with ZERO network egress: text/html (single file, inline CSS/JS, NO external
 * scripts/images), application/vnd.mermaid, image/svg+xml, text/markdown. React/JSX is intentionally
 * NOT offered — a live React preview would require an external bundler + npm fetches, which the
 * sealed/attested model forbids; the model is told to use HTML instead.
 */

const ARTIFACT_INSTRUCTIONS = `# Artifacts

When the user asks for substantial, self-contained, reusable content (a web page, a diagram, a
drawing, a document), output it as an "artifact" so it renders in a side panel. Use this exact
format — the triple backticks are required:

:::artifact{identifier="kebab-case-id" type="<mime-type>" title="Short Title"}
\`\`\`
<the complete content>
\`\`\`
:::

Reuse the same identifier when updating an existing artifact. Supported types (use ONLY these):

- "text/html" — a single self-contained HTML page. Put ALL CSS and JS inline in the one file. It
  runs in a locked-down sandbox with NO network access: do NOT reference external scripts,
  stylesheets, fonts, or images (no CDNs, no <img src="http...">). Inline SVG and data: URIs are fine.
- "application/vnd.mermaid" — a Mermaid diagram (flowcharts, sequence, etc.). Content is Mermaid syntax.
- "image/svg+xml" — a self-contained SVG document.
- "text/markdown" — a Markdown document.

Do NOT use React/JSX artifacts — they are not supported here; build interactive content as a single
"text/html" artifact with inline JavaScript instead. Provide complete content with no placeholders or
"rest of code unchanged" comments. For short snippets or one-off answers, reply normally instead of
using an artifact.`;

/** Read the persisted artifacts toggle as a fallback when the conversation field isn't populated. */
function artifactsFlagOn(): boolean {
  try {
    return localStorage.getItem('caladon:artifactsEnabled') === 'true';
  } catch {
    return false;
  }
}

/**
 * Prepend the artifact instructions to the prompt when artifacts are enabled for this turn.
 * `mode` is the conversation's `artifacts` field (empty string = off). Fails open to the original
 * prompt on any unexpected input.
 */
export function injectArtifactsIntoPrompt(promptText: string, mode?: string | null): string {
  const enabled = (typeof mode === 'string' && mode.trim() !== '') || artifactsFlagOn();
  if (!enabled) {
    return promptText;
  }
  return `${ARTIFACT_INSTRUCTIONS}\n\n${promptText}`;
}

export { ARTIFACT_INSTRUCTIONS };
