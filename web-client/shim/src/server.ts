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
import { serveStatic } from '@hono/node-server/serve-static';
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
/**
 * Intel SGX Root CA CRL — special-cased because it lives on a DIFFERENT host than the PCS API
 * (the root cert's CRL distribution point, certificates.trustedservices.intel.com) and is binary
 * DER. We fetch it server-side and return it HEX so the SDK's fetch().text() collateral path does
 * not corrupt the bytes. Registered BEFORE the generic /pcs-collateral/* wildcard so it wins.
 */
app.get('/pcs-collateral/root-ca-crl', async (c) => {
  try {
    const r = await fetch(config.rootCaCrlUrl, { signal: AbortSignal.timeout(config.upstreamTimeoutMs) });
    if (!r.ok) return c.json({ error: 'root_ca_crl_upstream', status: r.status }, 502);
    const der = new Uint8Array(await r.arrayBuffer());
    let hex = '';
    for (const b of der) hex += b.toString(16).padStart(2, '0');
    return c.text(hex);
  } catch {
    return c.json({ error: 'root_ca_crl_fetch_failed' }, 502);
  }
});

app.get('/pcs-collateral/*', (c) => {
  const tail = c.req.path.replace(/^\/pcs-collateral/, '');
  const qs = new URL(c.req.url).search;
  return relay(c, `${config.pcsBase}${tail}${qs}`, false);
});

/* ---------------------------------------------------------------------------------------------
 * Boot /api/* stubs (G4). The bundled LibreChat SPA fires a handful of un-skippable boot queries
 * on first paint; if any returns a non-JSON / 404 / HTML body the app crashes to a white screen
 * before the unlock screen can render. The shim is the SPA's same-origin "front door", so it must
 * answer these — but it is NOT LibreChat's Node API: there is NO DB and NO keys. Each responder is
 * STATIC JSON shaped to match the exact librechat-data-provider type the SPA expects, holding
 * nothing. (The real identity/chat path is /api/caladon/* → gateway; these only get the shell up.)
 *
 * Ordering: these are registered AFTER /api/caladon/* and /pcs-collateral/* (so those still win)
 * and BEFORE the SPA history-mode fallback (so /api/* never falls through to index.html).
 * ------------------------------------------------------------------------------------------- */

/**
 * GET /api/config → TStartupConfig (data-provider/src/config.ts). Gates the whole boot:
 * useGetStartupConfig must resolve before the auth/unlock screen renders, and every other boot
 * query is enabled only once this returns. We turn OFF every account-server feature the shim
 * cannot back (registration, all social logins, email, password reset, balance) and leave
 * `serverDomain` empty so the SPA induces no server-side-login side effects — identity is the
 * local seed (Caladon fork: /login renders CaladonUnlock). Booleans below are the REQUIRED
 * (non-optional) TStartupConfig fields; omitting any would throw in strict consumers.
 */
app.get('/api/config', (c) =>
  c.json({
    appTitle: 'Caladon',
    // No server-issued accounts: registration + every social/SSO provider OFF.
    registrationEnabled: false,
    emailLoginEnabled: false,
    socialLoginEnabled: false,
    socialLogins: [],
    passwordResetEnabled: false,
    emailEnabled: false,
    discordLoginEnabled: false,
    facebookLoginEnabled: false,
    githubLoginEnabled: false,
    googleLoginEnabled: false,
    openidLoginEnabled: false,
    appleLoginEnabled: false,
    samlLoginEnabled: false,
    openidLabel: '',
    openidImageUrl: '',
    openidAutoRedirect: false,
    samlLabel: '',
    samlImageUrl: '',
    // Empty serverDomain → no absolute-URL/login redirect side-effects (front-door is same-origin).
    serverDomain: '',
    showBirthdayIcon: false,
    helpAndFaqURL: '',
    // Balance disabled → useGetUserBalance stays disabled (it is gated on balance.enabled), so the
    // shim never has to serve a credits ledger it does not have.
    balance: { enabled: false },
    sharedLinksEnabled: false,
    publicSharedLinksEnabled: false,
    allowAccountDeletion: false,
    // Minimal interface: all fields optional in interfaceSchema; an empty object is valid and lets
    // the SPA apply its own defaults.
    interface: {},
  }),
);

/**
 * GET /api/banner → TBannerResponse (= TBanner | null). No banner to show; `null` is the canonical
 * "no active banner" value. (Returning {} would also type-check as the SPA reads optional fields,
 * but null is the precise no-banner signal.)
 */
app.get('/api/banner', (c) => c.body(null, 200, { 'Content-Type': 'application/json' }));

/**
 * GET /api/user → 401. There is no server session (identity is the in-memory local seed). A 401
 * makes AuthContext treat the user as logged-out, so the router sends them to /login — which in
 * the Caladon fork renders the unlock screen (Create / Restore identity). Anything 2xx here would
 * wrongly mark them authenticated and route into the chat shell with no session.
 */
app.get('/api/user', (c) => c.json({ message: 'unauthenticated' }, 401));

/**
 * GET /api/roles/:role → TRole ({ name, permissions }). useGetRole does NOT schema-parse the
 * response (data-provider/client roles.ts), it returns the raw JSON typed as TRole and consumers
 * read `permissions[TYPE][PERMISSION]`. So we return every PermissionTypes key as an object (here
 * all-false / locked-down: this is a keyless static front door, not a permission authority) so any
 * `permissions.X.USE`-style read resolves to a defined object instead of throwing on undefined.
 */
app.get('/api/roles/:role', (c) =>
  c.json({
    name: c.req.param('role'),
    permissions: {
      PROMPTS: { USE: false, CREATE: false, SHARE: false, SHARE_PUBLIC: false },
      BOOKMARKS: { USE: false },
      MEMORIES: { USE: false, CREATE: false, UPDATE: false, READ: false, OPT_OUT: false },
      AGENTS: { USE: false, CREATE: false, SHARE: false, SHARE_PUBLIC: false },
      MULTI_CONVO: { USE: false },
      TEMPORARY_CHAT: { USE: false },
      RUN_CODE: { USE: false },
      WEB_SEARCH: { USE: false },
      PEOPLE_PICKER: { VIEW_USERS: false, VIEW_GROUPS: false, VIEW_ROLES: false },
      MARKETPLACE: { USE: false },
      FILE_SEARCH: { USE: false },
      FILE_CITATIONS: { USE: false },
      MCP_SERVERS: { USE: false, CREATE: false, SHARE: false, SHARE_PUBLIC: false, CONFIGURE_OBO: false },
      REMOTE_AGENTS: { USE: false, CREATE: false, SHARE: false, SHARE_PUBLIC: false },
      SKILLS: { USE: false, CREATE: false, SHARE: false, SHARE_PUBLIC: false },
      SHARED_LINKS: { USE: false, CREATE: false, SHARE: false, SHARE_PUBLIC: false },
    },
  }),
);

/**
 * The single Caladon endpoint key. We expose ONE LibreChat-style endpoint of type `custom` (not
 * `agents`/`assistants`) because `custom` is the lowest-friction path to a rendering composer:
 *
 *  - The composer's textarea and SendButton are gated on a TRUTHY `conversation.endpoint`
 *    (client/src/components/Chat/Input/ChatForm.tsx: `{endpoint && (<TextareaAutosize .../>)}` and
 *    `endpoint && (<SendButton .../>)`, where `endpoint = conversation?.endpointType ??
 *    conversation?.endpoint`). With the old empty `{}` endpointsConfig, useNewConvo →
 *    switchToConversation → buildDefaultConvo finds NO default endpoint (getDefaultEndpoint and the
 *    `Object.keys(endpointsConfig).find(...)` fallback both return undefined), so the conversation
 *    is built with `endpoint: null` and the composer renders blank. One endpoint here gives
 *    getDefinedEndpoint(endpointsConfig) a hit → the new convo gets `endpoint: 'caladon'` → composer.
 *  - `custom` needs NO role permission. The `agents` endpoint is explicitly dropped as a default
 *    when the user lacks AGENTS.USE (useNewConvo.ts lines ~130-153, useEndpoints.ts line ~66), and
 *    our /api/roles stub locks AGENTS.USE to false; choosing `custom` avoids touching the roles
 *    authority. `custom` is in defaultEndpoints + modularEndpoints and parses via openAISchema, so
 *    parseConvo/buildDefaultConvo accept a `model` cleanly.
 *  - `userProvide` is unset (falsy) so useRequiresKey() returns requiresKey=false → inputs are NOT
 *    disabled (no "provide your API key" gate). The shim holds no key by design; the attested
 *    gateway is the only thing that runs inference.
 *
 * Routing is unaffected: the surgery's createPayload always POSTs to EndpointURLs[agents] =
 * /api/caladon/chat regardless of the conversation's endpoint, and the gateway honours the model
 * slug only if attested (else falls back to its default model). So the endpoint key/model list here
 * is purely what the SPA needs to render and to populate the model picker — it carries no secret.
 */
const CALADON_ENDPOINT = 'caladon';
const CALADON_MODELS = ['caladon'];

/**
 * GET /api/endpoints → TEndpointsConfig (Record<endpoint, TConfig|null|undefined>). One `custom`
 * endpoint named "Caladon". `order` is the only non-optional TConfig field; `type: 'custom'`
 * makes getEndpointField(...,'type') resolve and keeps it in getAvailableEndpoints. `modelDisplayLabel`
 * labels the picker. The query is NOT schema-parsed by the client (dataService.getAIEndpoints
 * returns raw JSON), so this shape passes through verbatim.
 */
app.get('/api/endpoints', (c) =>
  c.json({
    [CALADON_ENDPOINT]: {
      type: 'custom',
      order: 0,
      modelDisplayLabel: 'Caladon',
      userProvide: false,
    },
  }),
);

/**
 * GET /api/models → TModelsConfig (Record<string, string[]>). The model picker for a non-agents,
 * non-assistants endpoint reads modelsQuery.data[endpoint] (useEndpoints.ts lines ~171-180) and
 * buildDefaultConvo seeds conversation.model from this list, so the key MUST match the endpoint key
 * above. A single "caladon" slug is enough to render a usable picker; the gateway honours/falls back
 * to its attested default regardless of the slug sent.
 *
 * CRITICAL: do NOT include an `initial` key. ChatRoute.tsx gates new-conversation setup on
 * `!modelsQuery.data?.initial` (it treats an `initial` key as "models are still loading"). An empty
 * array `[]` is TRUTHY in JS, so `initial: []` makes `!data.initial` false forever → the conversation
 * is never created → ChatView returns null → blank main pane, no composer. Omitting it lets the
 * conversation initialize and the composer render.
 */
app.get('/api/models', (c) =>
  c.json({
    [CALADON_ENDPOINT]: CALADON_MODELS,
  }),
);

/* ---------------------------------------------------------------------------------------------
 * Chat-UI boot queries (G4, second wave). After auth the chat shell fires these; if any 404s or
 * returns a non-JSON body the console fills with errors and some lists spin forever. Each responder
 * is STATIC JSON shaped to the exact librechat-data-provider type, representing an EMPTY/disabled
 * state — there is NO DB, so there is nothing to list. (Real chat is /api/caladon/* → gateway.)
 * ------------------------------------------------------------------------------------------- */

/**
 * GET /api/convos → ConversationListResponse ({ conversations, nextCursor }). Consumed by
 * useConversationsInfiniteQuery; getNextPageParam reads `nextCursor ?? undefined`, so `null` ends
 * pagination cleanly. Empty history (no DB).
 */
app.get('/api/convos', (c) => c.json({ conversations: [], nextCursor: null }));

/**
 * GET /api/projects → ProjectListResponse ({ projects, nextCursor }). useProjectsInfiniteQuery,
 * same nextCursor pagination contract. No projects (no DB). Matches `?sortBy=...&limit=25`.
 */
app.get('/api/projects', (c) => c.json({ projects: [], nextCursor: null }));

/**
 * GET /api/user/settings/favorites → TUserFavorite[] (getFavorites). No starred models/agents.
 */
app.get('/api/user/settings/favorites', (c) => c.json([]));

/**
 * GET /api/agents/chat/active → ActiveJobsResponse ({ activeJobIds }). Consumed by useActiveJobs
 * (`activeJobsData?.activeJobIds ?? []`). No resumable jobs without a server-side store.
 */
app.get('/api/agents/chat/active', (c) => c.json({ activeJobIds: [] }));

/**
 * GET /api/files → TFile[] (getFiles). No uploaded files (no DB / no storage).
 */
app.get('/api/files', (c) => c.json([]));

/**
 * GET /api/search/enable → boolean (getSearchEnabled). Conversation search is a server-DB feature
 * the shim cannot back, so it is disabled.
 */
app.get('/api/search/enable', (c) => c.json(false));

/* ---------------------------------------------------------------------------------------------
 * Static SPA front door (G3). Only when CALADON_STATIC_DIR is set (prod / single-origin deploy).
 * Unset (dev default) → no static handlers are registered at all, so dev stays API-only and the
 * Vite dev server keeps serving the SPA. serveStatic is read-only file serving — NO DB, NO keys.
 * Registered LAST so /api/* and /pcs-collateral/* always take precedence.
 * ------------------------------------------------------------------------------------------- */
if (config.staticDir) {
  // 1. Serve real files (JS/CSS/assets/index.html) from the built bundle.
  app.use('/*', serveStatic({ root: config.staticDir }));

  // 2. SPA history-mode fallback: any GET that is NOT /api/* and NOT /pcs-collateral/* and did not
  //    match a real static file returns index.html, so client-side routes (/login, /c/new, …)
  //    deep-link correctly. serveStatic above already returned the file for real assets; this only
  //    fires when nothing matched (it calls next()), so we serve index.html as the SPA entry.
  app.get('*', (c, next) => {
    const p = c.req.path;
    if (p.startsWith('/api/') || p.startsWith('/pcs-collateral/')) return next();
    // path: 'index.html' makes serveStatic serve that file regardless of the request path.
    return serveStatic({ root: config.staticDir, path: 'index.html' })(c, next);
  });
}

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
