/**
 * The stateless relay. Given an incoming Hono request and an upstream URL, forward it to the
 * gateway and stream the response straight back. CRITICAL invariants (the whole security story):
 *
 *  - NO body inspection. The body is an opaque envelope (sealed in the browser). We never parse,
 *    log, or transform it. We pass `request.body` (a ReadableStream) through untouched.
 *  - The client's `Authorization: Swifty …` header is forwarded VERBATIM. The shim holds no key
 *    and signs nothing; the gateway verifies (gateway/app/deps.py:require_account).
 *  - SSE passthrough: `text/event-stream` responses are streamed delta-by-delta with no buffering,
 *    so the chat stream stays live and the shim never accumulates plaintext (there is none to
 *    accumulate — deltas are sealed envelopes).
 *  - We strip hop-by-hop and cookie headers in both directions so the gateway's auth model (a
 *    signed header, not a cookie) is never confused by a browser cookie, and the shim's own
 *    session cookie never leaks upstream.
 */

import type { Context } from 'hono';
import { config } from './config.js';

/** Headers we must NOT forward upstream (hop-by-hop, or shim-local concerns). */
const STRIP_TO_UPSTREAM = new Set([
  'host',
  'connection',
  'keep-alive',
  'proxy-authorization',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'te',
  'trailer',
  // The browser's cookie (incl. our HttpOnly session cookie) is shim-local; the gateway auths
  // on the signed `Authorization` header, never a cookie. Do not leak it upstream.
  'cookie',
  // Let fetch set content-length/encoding for the re-issued request.
  'content-length',
]);

/** Headers we must NOT copy back to the browser from the upstream response. */
const STRIP_FROM_UPSTREAM = new Set([
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'trailer',
  // Never let the gateway set cookies in the browser through the shim; the shim owns the
  // (keyless) session cookie and nothing else should.
  'set-cookie',
  // CORS headers are re-issued by the shim's own cors middleware for the browser origin.
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-headers',
  'access-control-allow-methods',
  'content-encoding',
  'content-length',
]);

function buildUpstreamHeaders(c: Context): Headers {
  const out = new Headers();
  c.req.raw.headers.forEach((value, key) => {
    if (!STRIP_TO_UPSTREAM.has(key.toLowerCase())) {
      out.set(key, value);
    }
  });
  return out;
}

function buildClientHeaders(upstream: Response): Headers {
  const out = new Headers();
  upstream.headers.forEach((value, key) => {
    if (!STRIP_FROM_UPSTREAM.has(key.toLowerCase())) {
      out.set(key, value);
    }
  });
  return out;
}

/**
 * Forward `c`'s request to `upstreamUrl` and return the upstream Response, streamed.
 * `isStream` skips the abort timeout so SSE chat can run indefinitely.
 */
export async function relay(c: Context, upstreamUrl: string, isStream = false): Promise<Response> {
  const method = c.req.method;
  const headers = buildUpstreamHeaders(c);

  const init: RequestInit = { method, headers };

  // Forward the request body for methods that carry one. The body is a small OPAQUE sealed
  // envelope; we BUFFER it (arrayBuffer) rather than stream it. Streaming a Web ReadableStream with
  // `duplex: 'half'` can make undici throw when the upstream answers with an SSE stream before the
  // request body is fully flushed (observed on /v1/chat → "gateway_unreachable"). Buffering the
  // tiny request body avoids that edge case; the shim still never reads/decrypts it, and the
  // no-buffering invariant that matters (the streamed SSE RESPONSE) is unaffected below.
  if (method !== 'GET' && method !== 'HEAD') {
    init.body = await c.req.raw.arrayBuffer();
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  if (!isStream) {
    const ac = new AbortController();
    timer = setTimeout(() => ac.abort(), config.upstreamTimeoutMs);
    init.signal = ac.signal;
  }

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, init);
  } catch (err) {
    if (timer) clearTimeout(timer);
    const reason = err instanceof Error && err.name === 'AbortError' ? 'gateway_timeout' : 'gateway_unreachable';
    return c.json({ error: 'bad_gateway', reason }, 502);
  }
  if (timer) clearTimeout(timer);

  const respHeaders = buildClientHeaders(upstream);

  // Stream the upstream body straight through (SSE or JSON). No buffering, no inspection.
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
}
