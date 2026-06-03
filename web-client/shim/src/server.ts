/**
 * Caladon web shim — a stateless Hono proxy. NO DB. NO keys.
 *
 *   browser  ──/api/caladon/{chat,messages,attestation,session,whoami}──▶  shim  ──▶  gw.caladon.ai
 *   browser  ──/pcs-collateral/*──────────────────────────────────────▶  shim  ──▶  Intel PCS
 *
 * Why the shim exists at all (it does almost nothing on purpose):
 *  1. CORS: the browser can't call gw.caladon.ai or Intel PCS cross-origin; the shim adds the
 *     headers for our own origin only.
 *  2. Cookie hygiene: the shim issues one opaque HttpOnly session cookie (no key, no PII) so a
 *     tab can be pinned to a logical session, while the *gateway* auth stays a signed header that
 *     the browser sends and the shim forwards verbatim.
 *  3. A single same-origin base for the SPA, decoupling it from the gateway hostname.
 *
 * What the shim NEVER does: hold a key, decrypt an envelope, read a prompt, persist anything,
 * sign a gateway request. All of that is the browser's job (caladon-core WASM) or the gateway's.
 */

import { randomBytes } from 'node:crypto';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import type { Context } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, setCookie } from 'hono/cookie';
import { config, ROUTE_MAP } from './config.js';
import { relay } from './proxy.js';

const app = new Hono();

/** CORS for the SPA origin only; credentials on (so the HttpOnly session cookie rides along). */
app.use(
  '*',
  cors({
    origin: (origin) => (config.allowedOrigins.includes(origin) ? origin : null),
    credentials: true,
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Accept', 'Last-Event-ID'],
    maxAge: 600,
  }),
);

/**
 * Issue the opaque, keyless HttpOnly session cookie if the browser doesn't have one yet. The value
 * is 32 random bytes (base64url) and means nothing on its own — there is no server-side session
 * store to look it up in (NO DB). It exists only to pin a tab and to be a future CSRF anchor. The
 * real identity is the client's signed `Authorization: Swifty …` header.
 */
app.use('/api/caladon/*', async (c, next) => {
  if (!getCookie(c, config.sessionCookieName)) {
    setCookie(c, config.sessionCookieName, randomBytes(32).toString('base64url'), {
      httpOnly: true,
      sameSite: 'Lax',
      secure: config.cookieSecure,
      path: '/',
      maxAge: config.sessionMaxAgeS,
    });
  }
  await next();
});

/** Liveness: also surfaces the live gateway's /health so the SPA can prove reachability end to end. */
app.get('/health', async (c) => {
  let gateway: unknown = { reachable: false };
  try {
    const r = await fetch(`${config.gatewayBase}/health`, {
      signal: AbortSignal.timeout(config.upstreamTimeoutMs),
    });
    gateway = { reachable: r.ok, status: r.status, body: await r.json().catch(() => null) };
  } catch {
    gateway = { reachable: false };
  }
  return c.json({ shim: 'ok', gatewayBase: config.gatewayBase, gateway });
});

/**
 * The gateway relay. `/api/caladon/<name>` → gateway `<ROUTE_MAP[name]>`, query string preserved.
 * `chat` is the streaming (SSE) turn — relayed with no body timeout.
 */
const handleCaladon = (c: Context) => {
  const name = c.req.param('name') ?? '';
  const upstreamPath = ROUTE_MAP[name];
  if (!upstreamPath) {
    return c.json({ error: 'not_found', reason: 'unknown caladon route' }, 404);
  }
  const qs = new URL(c.req.url).search;
  const upstreamUrl = `${config.gatewayBase}${upstreamPath}${qs}`;
  return relay(c, upstreamUrl, name === 'chat');
};

app.get('/api/caladon/:name', handleCaladon);
app.post('/api/caladon/:name', handleCaladon);

/**
 * Intel PCS collateral proxy (CORS fix). The browser's WASM attestation verifier (P3) needs TDX
 * quote collateral (TCB info, QE identity, PCK CRL) from Intel PCS, which sends no CORS headers.
 * We pass the path through to `pcsBase` and let the shim's cors middleware add the headers.
 * Read-only GET; no auth (PCS collateral is public).
 */
app.get('/pcs-collateral/*', (c) => {
  const tail = c.req.path.replace(/^\/pcs-collateral/, '');
  const qs = new URL(c.req.url).search;
  return relay(c, `${config.pcsBase}${tail}${qs}`, false);
});

/** Boot the standalone node server. Exported so tests/smoke can start it on a chosen port; the
 * `import.meta.main`-style guard keeps importing `app` (e.g. from smoke.ts) side-effect-free. */
export function startServer(port: number = config.port): ReturnType<typeof serve> {
  return serve({ fetch: app.fetch, port }, (info) => {
    // eslint-disable-next-line no-console
    console.log(
      `[caladon-shim] listening on :${info.port} → gateway ${config.gatewayBase} (NO DB, NO keys)`,
    );
  });
}

// Only auto-start when run directly (`tsx src/server.ts`), not when imported by smoke.ts.
const invokedDirectly =
  process.argv[1] != null && /(?:^|[\\/])server\.[cm]?ts$/.test(process.argv[1]);
if (invokedDirectly) {
  startServer();
}

export { app };
