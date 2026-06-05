import React, { memo, useContext, useEffect, useMemo, useRef, type MutableRefObject } from 'react';
import { ThemeContext, isDark } from '@librechat/client';
import type { SandpackProviderProps, SandpackPreviewRef } from '@codesandbox/sandpack-react/unstyled';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { TStartupConfig } from 'librechat-data-provider';
import type { Artifact, ArtifactFiles } from '~/common';

/**
 * Caladon artifact preview — trust-no-one renderer (SURGERY.md §C, revised 2026-06).
 *
 * Upstream renders EVERY artifact type through a Sandpack `static`/`react-ts` iframe whose bundler is
 * fetched from `bundlerURL` and which resolves npm packages from esm.sh/unpkg at runtime. That is an
 * exfiltration surface (the toolchain itself calls out), incompatible with the sealed/attested model
 * where the client must never talk to a third party. We therefore BYPASS Sandpack entirely and render
 * only self-contained types with zero network egress:
 *
 *   - text/html, application/vnd.code-html  → a hardened <iframe srcDoc> (sandbox="allow-scripts",
 *     NO allow-same-origin → opaque origin → can't read our cookies/storage/DOM; + a CSP
 *     `connect-src 'none'` injected into the document so script that runs still cannot open a socket).
 *   - image/svg+xml                         → same hardened iframe (SVG can carry script).
 *   - application/vnd.mermaid                → MermaidDiagram (mermaid renders SVG in-process,
 *     securityLevel:'sandbox', no external fetch — already bundled).
 *   - text/markdown / md / plain            → react-markdown (markdown→React; no iframe, no fetch).
 *   - application/vnd.react / vnd.code / office / anything else → NO live preview. React/JSX preview
 *     would require the Sandpack bundler + npm fetches (egress), so we honestly disable it and point
 *     the user at the Code tab. This is a deliberate trust trade-off, not a gap.
 *
 * NEVER add `allow-same-origin` to the iframe sandbox, and NEVER restore a remote bundlerURL — either
 * one re-opens the egress hole this file exists to close.
 */

const TRUSTED_CSP =
  "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; " +
  "connect-src 'none'; img-src 'self' data: blob:; media-src 'self' data: blob:; " +
  "font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval';";

const CSP_META = `<meta http-equiv="Content-Security-Policy" content="${TRUSTED_CSP}">`;

/** Build a complete, CSP-hardened HTML document string from raw artifact content. */
function buildHtmlDoc(content: string): string {
  const hasHtmlShell = /<html[\s>]/i.test(content);
  if (hasHtmlShell) {
    // Inject the CSP meta as the first thing in <head> (or synthesize a head if absent).
    if (/<head[\s>]/i.test(content)) {
      return content.replace(/<head([^>]*)>/i, `<head$1>${CSP_META}`);
    }
    return content.replace(/<html([^>]*)>/i, `<html$1><head>${CSP_META}</head>`);
  }
  // Bare fragment: wrap it.
  return `<!DOCTYPE html><html><head><meta charset="utf-8">${CSP_META}<style>html,body{margin:0;padding:12px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;}</style></head><body>${content}</body></html>`;
}

function buildSvgDoc(content: string): string {
  return `<!DOCTYPE html><html><head><meta charset="utf-8">${CSP_META}<style>html,body{margin:0;height:100%;display:flex;align-items:center;justify-content:center;background:transparent;}svg{max-width:100%;max-height:100%;}</style></head><body>${content}</body></html>`;
}

/**
 * Mermaid renderer — dynamically imports the bundled `mermaid` package and renders to inline SVG in
 * process (securityLevel:'sandbox', no external fetch). We render it ourselves rather than reuse the
 * upstream Mermaid.tsx because that component also pulls in `react-zoom-pan-pinch`, which isn't a
 * Caladon dependency. No zoom/pan — just the diagram.
 */
const MermaidView = memo(function MermaidView({
  content,
  isDarkMode,
}: {
  content: string;
  isDarkMode: boolean;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const mermaid = (await import('mermaid')).default;
        mermaid.initialize({
          startOnLoad: false,
          theme: isDarkMode ? 'dark' : 'neutral',
          securityLevel: 'sandbox',
        });
        const { svg } = await mermaid.render('caladon-mermaid-' + Math.abs(hashString(content)), content);
        if (!cancelled && ref.current) {
          ref.current.innerHTML = svg;
          const el = ref.current.querySelector('svg');
          if (el) {
            el.style.maxWidth = '100%';
            el.style.height = 'auto';
          }
        }
      } catch (err) {
        if (!cancelled && ref.current) {
          ref.current.textContent = 'Could not render diagram.';
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [content, isDarkMode]);
  return <div ref={ref} className="flex h-full w-full items-center justify-center overflow-auto p-4" />;
});

/** Tiny stable hash so each diagram render gets a unique mermaid element id. */
function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (h << 5) - h + s.charCodeAt(i);
    h |= 0;
  }
  return h;
}

const HardenedFrame = memo(function HardenedFrame({ doc }: { doc: string }) {
  return (
    <iframe
      title="artifact-preview"
      srcDoc={doc}
      // allow-scripts WITHOUT allow-same-origin → opaque origin (no access to our cookies/storage/DOM).
      sandbox="allow-scripts"
      className="h-full w-full border-0 bg-white"
    />
  );
});

const CodeOnlyNotice = memo(function CodeOnlyNotice({ type }: { type: string }) {
  return (
    <div className="flex h-full w-full items-center justify-center p-6 text-center">
      <div className="max-w-md text-sm text-text-secondary">
        <p className="mb-2 font-medium text-text-primary">Live preview unavailable</p>
        <p>
          Rendering <code className="rounded bg-surface-tertiary px-1">{type || 'this type'}</code>{' '}
          would require an external bundler and npm fetches, which Caladon blocks to keep your session
          confidential (trust-no-one). The full source is in the <strong>Code</strong> tab.
        </p>
      </div>
    </div>
  );
});

export const ArtifactPreview = memo(function ArtifactPreview({
  artifact,
  currentCode,
}: {
  // The first group is kept for API compatibility with the upstream call site; unused here.
  files?: ArtifactFiles;
  fileKey?: string;
  template?: SandpackProviderProps['template'];
  sharedProps?: Partial<SandpackProviderProps>;
  previewRef?: MutableRefObject<SandpackPreviewRef>;
  artifact?: Artifact;
  currentCode?: string;
  startupConfig?: TStartupConfig;
}) {
  const { theme } = useContext(ThemeContext);
  const isDarkMode = isDark(theme);

  const type = (artifact?.type ?? '').toLowerCase();
  const content = currentCode ?? artifact?.content ?? '';

  const node = useMemo(() => {
    if (!content) {
      return null;
    }
    if (type.includes('mermaid')) {
      return <MermaidView content={content} isDarkMode={isDarkMode} />;
    }
    if (type === 'image/svg+xml' || (type.includes('svg') && content.includes('<svg'))) {
      return <HardenedFrame doc={buildSvgDoc(content)} />;
    }
    if (
      type === 'text/html' ||
      type === 'application/vnd.code-html' ||
      type === 'application/vnd.ant.html'
    ) {
      return <HardenedFrame doc={buildHtmlDoc(content)} />;
    }
    if (type === 'text/markdown' || type === 'text/md' || type === 'text/plain' || type === '') {
      return (
        <div className="markdown-body h-full w-full overflow-auto p-4 text-text-primary">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
        </div>
      );
    }
    return <CodeOnlyNotice type={type} />;
  }, [type, content, isDarkMode]);

  if (!node) {
    return null;
  }
  return (
    <div className="h-full w-full" data-caladon-artifact-preview={type || 'unknown'}>
      {node}
    </div>
  );
});

export default ArtifactPreview;
