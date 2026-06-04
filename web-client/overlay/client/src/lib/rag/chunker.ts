/**
 * Caladon RAG — text chunker (Batch 1 client foundation).
 *
 * Splits a parsed document's plain text into overlapping, embedding-sized chunks. The embedding
 * model (Xenova/all-MiniLM-L6-v2) has a 256-wordpiece input window; anything longer is silently
 * truncated by the tokenizer, so we chunk to comfortably fit that window and add a small overlap so
 * a fact that straddles a boundary is still fully present in at least one chunk.
 *
 * We don't run the real tokenizer here (it lives in the embed worker, off the main thread). Instead
 * we use a cheap, deterministic "token-ish" heuristic: ~4 characters per token for English/code,
 * which tracks the BPE/WordPiece average closely enough to size chunks well below the model's limit.
 * Chunking is structure-aware: it prefers to break on paragraph, then sentence, then word boundaries
 * so chunks stay semantically coherent rather than cutting mid-word.
 *
 * Pure + synchronous (no I/O, no network) so it can run on the main thread or inside a worker.
 */

/* ------------------------------------------------------------------ *
 * Tuning (token-ish; ~4 chars/token). MiniLM-L6 caps at 256 wordpieces.
 * ------------------------------------------------------------------ */

/** Approx characters per token — the heuristic that maps char budgets to the model's token window. */
const CHARS_PER_TOKEN = 4;

/** Target chunk size in tokens (well under the 256-wordpiece model limit, leaving headroom). */
export const DEFAULT_CHUNK_TOKENS = 200;

/** Overlap between consecutive chunks in tokens (carries cross-boundary context). */
export const DEFAULT_OVERLAP_TOKENS = 40;

/** Drop chunks shorter than this many characters (noise: stray page numbers, blank fragments). */
const MIN_CHUNK_CHARS = 16;

export interface ChunkOptions {
  /** Target chunk size in (approximate) tokens. */
  chunkTokens?: number;
  /** Overlap in (approximate) tokens between adjacent chunks. */
  overlapTokens?: number;
}

/* ------------------------------------------------------------------ *
 * Chunking
 * ------------------------------------------------------------------ */

/**
 * Split `text` into overlapping chunks of roughly `chunkTokens` tokens each, breaking on the most
 * natural available boundary (paragraph > sentence > word) so chunks stay coherent. Returns the
 * chunk strings in document order; near-empty/too-short chunks are dropped.
 */
export function chunkText(text: string, options: ChunkOptions = {}): string[] {
  const chunkTokens = Math.max(32, options.chunkTokens ?? DEFAULT_CHUNK_TOKENS);
  const overlapTokens = Math.max(0, Math.min(options.overlapTokens ?? DEFAULT_OVERLAP_TOKENS, chunkTokens - 1));

  const maxChars = chunkTokens * CHARS_PER_TOKEN;
  const overlapChars = overlapTokens * CHARS_PER_TOKEN;

  const normalized = text.replace(/\r\n?/g, '\n').trim();
  if (!normalized) return [];

  // Split into atomic segments we never break across mid-unit: paragraphs, then sentences within an
  // over-long paragraph, then hard word splits within an over-long sentence.
  const segments = splitIntoSegments(normalized, maxChars);

  const chunks: string[] = [];
  let current = '';

  const flush = () => {
    const trimmed = current.trim();
    if (trimmed.length >= MIN_CHUNK_CHARS) chunks.push(trimmed);
    // Seed the next chunk with the tail of this one for overlap (keeps cross-boundary context).
    current = overlapChars > 0 ? tail(trimmed, overlapChars) : '';
  };

  for (const seg of segments) {
    // +1 for the separating space/newline we add when joining segments.
    if (current && current.length + seg.length + 1 > maxChars) {
      flush();
    }
    current = current ? `${current}\n${seg}` : seg;

    // A single segment can still exceed maxChars after a fresh start (e.g. one huge word run);
    // hard-split it so no chunk overruns the budget.
    while (current.length > maxChars) {
      const head = current.slice(0, maxChars).trim();
      if (head.length >= MIN_CHUNK_CHARS) chunks.push(head);
      const carry = overlapChars > 0 ? tail(head, overlapChars) : '';
      current = carry + current.slice(maxChars);
    }
  }
  if (current.trim().length >= MIN_CHUNK_CHARS) chunks.push(current.trim());

  return chunks;
}

/* ------------------------------------------------------------------ *
 * Segmentation helpers
 * ------------------------------------------------------------------ */

/**
 * Break text into segments no larger than `maxChars`. Start with paragraphs (blank-line separated);
 * any paragraph over the budget is split into sentences; any sentence still over the budget is split
 * on word boundaries; a single word longer than the budget is hard-cut.
 */
function splitIntoSegments(text: string, maxChars: number): string[] {
  const out: string[] = [];
  for (const para of text.split(/\n{2,}/)) {
    const p = para.trim();
    if (!p) continue;
    if (p.length <= maxChars) {
      out.push(p);
      continue;
    }
    for (const sentence of splitSentences(p)) {
      if (sentence.length <= maxChars) {
        out.push(sentence);
        continue;
      }
      out.push(...splitWords(sentence, maxChars));
    }
  }
  return out;
}

/** Sentence split on `.?!` (plus newlines), keeping the terminator. Good enough for chunk sizing. */
function splitSentences(text: string): string[] {
  return text
    .split(/(?<=[.?!])\s+|\n+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Greedily pack words into ≤maxChars segments; hard-cut any single word longer than maxChars. */
function splitWords(text: string, maxChars: number): string[] {
  const out: string[] = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (word.length > maxChars) {
      if (line) {
        out.push(line);
        line = '';
      }
      for (let i = 0; i < word.length; i += maxChars) {
        out.push(word.slice(i, i + maxChars));
      }
      continue;
    }
    if (line && line.length + word.length + 1 > maxChars) {
      out.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) out.push(line);
  return out;
}

/** Return the last `n` characters of `s`, snapped to a word boundary when one is reasonably close. */
function tail(s: string, n: number): string {
  if (s.length <= n) return s;
  const slice = s.slice(s.length - n);
  const space = slice.indexOf(' ');
  // Snap to the first word boundary inside the tail (avoids starting overlap mid-word) unless that
  // would throw away most of the overlap.
  return space > 0 && space < n / 2 ? slice.slice(space + 1) : slice;
}

/** Rough token estimate for a string (for budgeting / telemetry). */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}
