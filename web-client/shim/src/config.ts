/**
 * Shim configuration. Everything is env-driven; there are NO secrets and NO keys here by design
 * — the shim never holds a credential (the client signs every gateway request itself with its
 * seed-derived key, see /contracts/gateway-api.md §1). The only "state" the shim issues is an
 * opaque HttpOnly session cookie that pins a browser tab to a logical session; it carries no key
 * and no PII (see server.ts).
 */

const env = (key: string, fallback: string): string => {
  const v = process.env[key];
  return v == null || v === '' ? fallback : v;
};

export const config = {
  /** The live Caladon gateway. The shim is a dumb relay in front of this. */
  gatewayBase: env('CALADON_GATEWAY_BASE', 'https://gw.caladon.ai'),

  /** Intel PCS (Provisioning Certification Service) — TDX quote collateral the browser cannot
   * fetch directly because PCS sends no CORS headers. The shim proxies it and adds them. */
  pcsBase: env('CALADON_PCS_BASE', 'https://api.trustedservices.intel.com'),

  /** The Intel SGX Root CA CRL lives on a DIFFERENT host than the PCS API (the root cert's CRL
   * distribution point) and is served as binary DER. The shim fetches it server-side and returns
   * it HEX-encoded under /pcs-collateral/root-ca-crl, because binary DER cannot survive the
   * browser's fetch().text(). */
  rootCaCrlUrl: env(
    'CALADON_ROOT_CA_CRL_URL',
    'https://certificates.trustedservices.intel.com/IntelSGXRootCA.der',
  ),

  /** Port for the standalone node server (dev / container). */
  port: Number.parseInt(env('PORT', '8787'), 10),

  /** Allowed browser origin(s) for CORS on /api/caladon/* and /pcs-collateral. Comma-separated.
   * Defaults to the LibreChat dev frontend + the shim's own dev port. Tighten in production. */
  allowedOrigins: env('CALADON_ALLOWED_ORIGINS', 'http://localhost:3090,http://localhost:8787')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  /** Per-request upstream timeout (ms). Streaming /v1/chat is exempt (no body timeout). */
  upstreamTimeoutMs: Number.parseInt(env('CALADON_UPSTREAM_TIMEOUT_MS', '30000'), 10),

  /** HttpOnly session-cookie name + max-age (seconds). Opaque value only; no key material. */
  sessionCookieName: env('CALADON_SESSION_COOKIE', 'caladon_sid'),
  sessionMaxAgeS: Number.parseInt(env('CALADON_SESSION_MAX_AGE_S', '86400'), 10),

  /** Set true behind TLS (production) so the session cookie is Secure. */
  cookieSecure: env('CALADON_COOKIE_SECURE', 'false') === 'true',

  /** Built SPA directory to serve as the single-origin "front door" (G3). When SET, the shim
   * serves the static bundle from here AND falls back to index.html for SPA history-mode routes
   * (any GET that is not /api/* and not /pcs-collateral/*). When UNSET (the dev default) static
   * serving is OFF — in dev the SPA is served by its own Vite dev server and the shim is API-only,
   * so the existing dev workflow is unchanged. NO DB, NO keys: this is read-only file serving. */
  staticDir: env('CALADON_STATIC_DIR', ''),
} as const;

/**
 * The client → shim public surface, and the shim → gateway upstream path each maps to. The shim
 * forwards the body and the `Authorization: Swifty …` header VERBATIM (it does not sign, it does
 * not decrypt). The gateway is the verifier and the ciphertext router.
 */
export const ROUTE_MAP: Readonly<Record<string, string>> = {
  // public path (mounted under /api/caladon)  ->  gateway path
  //
  // These are the relay names the SDK's signedFetch() actually calls (web-client/caladon/
  // src/client.ts): 'accounts' (onboard), 'attestation', 'session', 'chat', plus 'models' for the
  // model picker. The name is appended to shimBase as `${shimBase}/${relayName}` and signed as
  // `/v1/${relayName}`, so each public name maps 1:1 to its `/v1/...` gateway path here.
  accounts: '/v1/accounts', // POST onboard (CaladonClient.onboard → signedFetch('POST','accounts')).
  // Was MISSING: onboarding hit /api/caladon/accounts → 404 at the shim and never reached the
  // gateway, so no client could register through the shim. This unblocks onboarding (front door).
  chat: '/v1/chat',
  messages: '/v1/messages',
  attestation: '/v1/attestation',
  session: '/v1/session',
  models: '/v1/models', // model picker (SDK lists gateway-attested models via signedFetch('models')).
  whoami: '/v1/whoami',
};
