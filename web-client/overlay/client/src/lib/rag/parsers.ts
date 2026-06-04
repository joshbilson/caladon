/**
 * Caladon RAG — in-browser document parsers (Batch 1 client foundation).
 *
 * Turns an attached file into plain text ENTIRELY on the device. Nothing here ever uploads a file
 * or its text: plaintext documents are part of the user's trust boundary, so they are parsed locally
 * and only their on-device embeddings (and, at chat time, a retrieved <context> block sealed BEFORE
 * it leaves the browser) ever reach the gateway.
 *
 * Supported inputs:
 *  - text / markdown / source code  → TextDecoder over the raw bytes (UTF-8, fatal=false).
 *  - PDF                            → pdfjs-dist v6, lazily imported, with its ES-module worker.
 *  - DOCX                           → mammoth (extractRawText) in the browser.
 *
 * Everything is lazy-imported so the (heavy) PDF/DOCX engines are only pulled into the bundle when a
 * matching file is actually attached. The libraries are added by the librechat build, so the only
 * tsc diagnostics in the overlay-only tree are the expected TS2307s for the dynamic imports.
 */

/* ------------------------------------------------------------------ *
 * Public types
 * ------------------------------------------------------------------ */

/** A parsed document: its extracted plain text + light provenance for chunk attribution. */
export interface ParsedDocument {
  /** Original file name (for display / chunk source labelling). */
  name: string;
  /** Detected kind, after sniffing extension + MIME. */
  kind: DocKind;
  /** Extracted UTF-8 plain text (page/paragraph breaks preserved as `\n`). */
  text: string;
}

export type DocKind = 'text' | 'pdf' | 'docx' | 'unsupported';

/** A file-like input: a real `File`/`Blob`, or a `{ name, mime, bytes }` from a worker/transfer. */
export interface FileInput {
  name: string;
  mime?: string;
  bytes: ArrayBuffer;
}

/* ------------------------------------------------------------------ *
 * Kind detection
 * ------------------------------------------------------------------ */

const TEXT_EXTENSIONS = new Set([
  'txt', 'md', 'markdown', 'mdx', 'rst', 'csv', 'tsv', 'log', 'json', 'jsonl', 'yaml', 'yml',
  'toml', 'ini', 'env', 'xml', 'html', 'htm', 'css', 'scss', 'less',
  // source code
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'py', 'rb', 'go', 'rs', 'java', 'kt', 'kts', 'c', 'h',
  'cc', 'cpp', 'hpp', 'cs', 'swift', 'm', 'mm', 'php', 'pl', 'lua', 'sh', 'bash', 'zsh', 'fish',
  'sql', 'r', 'jl', 'scala', 'clj', 'ex', 'exs', 'erl', 'hs', 'dart', 'vue', 'svelte', 'gradle',
  'dockerfile', 'makefile', 'cmake', 'proto', 'graphql', 'gql',
]);

function extOf(name: string): string {
  const dot = name.lastIndexOf('.');
  if (dot < 0 || dot === name.length - 1) {
    // Handle extensionless well-known names (Dockerfile, Makefile).
    return name.toLowerCase();
  }
  return name.slice(dot + 1).toLowerCase();
}

/** Classify a file by extension first, then MIME as a fallback. */
export function detectKind(name: string, mime?: string): DocKind {
  const ext = extOf(name);
  const m = (mime ?? '').toLowerCase();

  if (ext === 'pdf' || m === 'application/pdf') return 'pdf';
  if (
    ext === 'docx' ||
    m === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ) {
    return 'docx';
  }
  if (TEXT_EXTENSIONS.has(ext)) return 'text';
  if (m.startsWith('text/')) return 'text';
  if (m === 'application/json' || m === 'application/xml' || m.endsWith('+json') || m.endsWith('+xml')) {
    return 'text';
  }
  return 'unsupported';
}

/** Human-facing list of what we accept (drives the file picker `accept` + validation copy). */
export const ACCEPTED_DESCRIPTION =
  'Plain text, Markdown, source code, PDF, and Word (.docx) documents';

/* ------------------------------------------------------------------ *
 * Decoders
 * ------------------------------------------------------------------ */

/** Decode raw bytes as UTF-8 text. `fatal: false` so a stray byte never aborts the whole parse. */
function decodeText(bytes: ArrayBuffer): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

/* ------------------------------------------------------------------ *
 * PDF (pdfjs-dist v6, ES-module worker, lazy)
 * ------------------------------------------------------------------ */

/** Narrowed pdfjs surface (v6 ESM build). Typed locally; the lib is added by the librechat build. */
interface PdfTextItem {
  str?: string;
  /** pdf.js marks a hard line break with `hasEOL`. */
  hasEOL?: boolean;
}
interface PdfTextContent {
  items: PdfTextItem[];
}
interface PdfPage {
  getTextContent(): Promise<PdfTextContent>;
}
interface PdfDocument {
  numPages: number;
  getPage(n: number): Promise<PdfPage>;
  destroy(): Promise<void>;
}
interface PdfJsModule {
  GlobalWorkerOptions: { workerSrc: string | URL };
  getDocument(src: { data: ArrayBuffer } | ArrayBuffer): { promise: Promise<PdfDocument> };
}

let pdfjsPromise: Promise<PdfJsModule> | null = null;

/** Lazily import pdfjs-dist v6 and wire its ES-module worker (same-origin, bundled by Vite). */
async function loadPdfjs(): Promise<PdfJsModule> {
  if (pdfjsPromise) return pdfjsPromise;
  pdfjsPromise = (async () => {
    const pdfjs = (await import('pdfjs-dist')) as unknown as PdfJsModule;
    // v6 ships the worker as an ES module; `?url` makes Vite emit it and give us the hashed URL.
    // It is served same-origin from our own bundle — no CDN, no cross-origin worker.
    const workerUrl = (await import('pdfjs-dist/build/pdf.worker.min.mjs?url')) as unknown as {
      default: string;
    };
    pdfjs.GlobalWorkerOptions.workerSrc = workerUrl.default;
    return pdfjs;
  })();
  return pdfjsPromise;
}

async function parsePdf(bytes: ArrayBuffer): Promise<string> {
  const pdfjs = await loadPdfjs();
  // pdf.js may detach the buffer; pass a copy so the caller's bytes stay usable.
  const data = bytes.slice(0);
  const doc = await pdfjs.getDocument({ data }).promise;
  try {
    const pages: string[] = [];
    for (let p = 1; p <= doc.numPages; p++) {
      const page = await doc.getPage(p);
      const content = await page.getTextContent();
      let line = '';
      const lines: string[] = [];
      for (const item of content.items) {
        line += item.str ?? '';
        if (item.hasEOL) {
          lines.push(line);
          line = '';
        }
      }
      if (line) lines.push(line);
      pages.push(lines.join('\n'));
    }
    // Form-feed between pages so the chunker can treat page boundaries as soft breaks.
    return pages.join('\n\n');
  } finally {
    await doc.destroy().catch(() => undefined);
  }
}

/* ------------------------------------------------------------------ *
 * DOCX (mammoth, lazy)
 * ------------------------------------------------------------------ */

interface MammothResult {
  value: string;
}
interface MammothModule {
  extractRawText(input: { arrayBuffer: ArrayBuffer }): Promise<MammothResult>;
}

let mammothPromise: Promise<MammothModule> | null = null;

async function loadMammoth(): Promise<MammothModule> {
  if (mammothPromise) return mammothPromise;
  mammothPromise = (async () => {
    const mod = (await import('mammoth')) as unknown as MammothModule & { default?: MammothModule };
    return (mod.default ?? mod) as MammothModule;
  })();
  return mammothPromise;
}

async function parseDocx(bytes: ArrayBuffer): Promise<string> {
  const mammoth = await loadMammoth();
  const result = await mammoth.extractRawText({ arrayBuffer: bytes });
  return result.value ?? '';
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

/** Max bytes we'll attempt to parse in-browser (guards against OOM on a giant attachment). */
export const MAX_PARSE_BYTES = 25 * 1024 * 1024; // 25 MiB

/** Thrown for an unsupported kind or an oversized file — the UI surfaces `.message`. */
export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

/**
 * Parse a file to plain text, all on-device. Detects the kind, dispatches to the right decoder, and
 * normalizes line endings. Never uploads. Throws `ParseError` for unsupported kinds / oversized input.
 */
export async function parseFile(input: FileInput): Promise<ParsedDocument> {
  if (input.bytes.byteLength > MAX_PARSE_BYTES) {
    throw new ParseError(
      `File is too large to process on-device (${Math.round(
        input.bytes.byteLength / (1024 * 1024),
      )} MB; max ${Math.round(MAX_PARSE_BYTES / (1024 * 1024))} MB).`,
    );
  }

  const kind = detectKind(input.name, input.mime);
  let text: string;
  switch (kind) {
    case 'text':
      text = decodeText(input.bytes);
      break;
    case 'pdf':
      text = await parsePdf(input.bytes);
      break;
    case 'docx':
      text = await parseDocx(input.bytes);
      break;
    default:
      throw new ParseError(`Unsupported file type. ${ACCEPTED_DESCRIPTION}.`);
  }

  return { name: input.name, kind, text: normalizeText(text) };
}

/** Convenience: parse a browser `File`/`Blob` (reads its bytes first). */
export async function parseBlob(file: File | Blob, name?: string): Promise<ParsedDocument> {
  const bytes = await file.arrayBuffer();
  const fileName = name ?? ((file as File).name || 'document');
  const mime = (file as File).type || undefined;
  return parseFile({ name: fileName, mime, bytes });
}

/** Normalize CRLF/CR to LF and collapse runs of 3+ blank lines so chunking is stable. */
function normalizeText(text: string): string {
  return text.replace(/\r\n?/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}
