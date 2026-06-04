# syntax=docker/dockerfile:1.7
# ──────────────────────────────────────────────────────────────────────────────
# Caladon WEB container — the single-origin "front door".
#
# WHAT THIS SHIPS: the stateless shim (web-client/shim, run via tsx — NO build) serving the built
# LibreChat SPA (client/dist) from one origin AND relaying /api/caladon/* + /pcs-collateral/* to
# the gateway. The shim holds NO keys and NO DB — the browser is the only place a key or plaintext
# ever exists; the shim forwards opaque envelopes and the gateway is the verifier (see
# web-client/shim/src/config.ts + SURGERY.md §0).
#
# BUILD CONTEXT = the REPO ROOT (the parent of web-client/), NOT web-client/ itself. This is
# load-bearing: web-client/caladon/build-wasm.sh reaches up to ../../caladon-core (a sibling of
# web-client/), and the client's vite alias resolves @caladon/protocol → web-client/caladon/. Both
# trees must be inside the context. Build it from the repo root:
#
#   docker build -f web-client/Dockerfile \
#     --build-arg VITE_CALADON_PINNED="$(cat measurements.pinned.json)" \
#     -t caladon-web .
#
# Layout reproduced INSIDE the image (so the relative paths above resolve unchanged):
#   /build/caladon-core/              ← Rust crate (WASM source)
#   /build/web-client/caladon/        ← @caladon/protocol SDK + built wasm/ (sibling of librechat)
#   /build/web-client/librechat/      ← vendored LibreChat (re-cloned at the pinned commit) + overlay
#
# Reproducibility: base images are pinned by manifest-list digest (multi-arch). No secrets are
# baked in — VITE_CALADON_PINNED is a build ARG (the per-deploy measurement set, public data);
# the gateway base, allowed origins and TLS flag are RUNTIME env (see stage C).
# ──────────────────────────────────────────────────────────────────────────────


# ==============================================================================
# Stage A — WASM: build caladon-core → web-client/caladon/wasm/ (wasm-pack --target web).
#   Rust stable + wasm32-unknown-unknown target + a pinned wasm-pack. Output ~948KB binary.
# ==============================================================================
FROM rust:1.90-bookworm@sha256:3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207 AS wasm

# wasm32 target + pinned wasm-pack (matches the version that produced the proven build).
ARG WASM_PACK_VERSION=0.15.0
RUN rustup target add wasm32-unknown-unknown \
 && curl -fsSL "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
      -o /tmp/wasm-pack.tgz 2>/dev/null \
      && tar -xzf /tmp/wasm-pack.tgz -C /tmp \
      && install -m 0755 /tmp/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack /usr/local/cargo/bin/wasm-pack \
      && rm -rf /tmp/wasm-pack* \
   || cargo install wasm-pack --version "${WASM_PACK_VERSION}" --locked
# (The prebuilt musl binary is x86_64-only; on arm64 the `||` falls back to `cargo install`.)

WORKDIR /build

# The crate source (sibling of web-client) and the SDK package that drives the build.
# Copy caladon-core first so a SDK-only change does not invalidate the crate's cargo cache.
COPY caladon-core/ ./caladon-core/
# build-wasm.sh + the SDK package metadata (the script writes into web-client/caladon/wasm/).
COPY web-client/caladon/build-wasm.sh ./web-client/caladon/build-wasm.sh
COPY web-client/caladon/.gitignore   ./web-client/caladon/.gitignore

# build-wasm.sh resolves CORE=../../caladon-core and OUT=./wasm relative to web-client/caladon/.
# wasm-pack lives at $HOME/.cargo/bin by default; in this image that's /usr/local/cargo/bin.
ENV WASM_PACK=/usr/local/cargo/bin/wasm-pack
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/caladon-core/target \
    bash web-client/caladon/build-wasm.sh
# → /build/web-client/caladon/wasm/{caladon_core_bg.wasm, caladon_core.js, *.d.ts, package.json}


# ==============================================================================
# Stage B — SPA: clone the PINNED LibreChat, apply the overlay, build packages + client.
#   Node 24 (matches LibreChat's .nvmrc 24.16.0; satisfies the "Node 22+" floor). git is needed
#   by setup.sh's partial clone of the pinned commit d680763.
# ==============================================================================
FROM node:24.16.0-bookworm@sha256:bdcebf8f693f755ced9b881c5ad02a702cf0e2b73757c7d961df0076657dacc3 AS spa

# git: setup.sh does a `--filter=tree:0 --no-checkout` clone then checks out the pinned commit.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── 1. The @caladon/protocol SDK (src + the COMMITTED glue) AND the WASM binary from stage A. ──
# The client's vite alias resolves @caladon/protocol → ../../caladon/src/index.ts and
# @caladon/protocol/wasm → ../../caladon/wasm (relative to web-client/librechat/client). So the
# SDK must sit at /build/web-client/caladon as a sibling of /build/web-client/librechat.
COPY web-client/caladon/ ./web-client/caladon/
# Overwrite the (git-ignored) binary with the freshly built one from stage A.
COPY --from=wasm /build/web-client/caladon/wasm/ ./web-client/caladon/wasm/

# ── 2. The overlay apply script + the overlay tree (the committed surgery edits). ──
COPY web-client/apply-overlay.sh ./web-client/apply-overlay.sh
COPY web-client/overlay/         ./web-client/overlay/

# ── 3. Clone the PINNED LibreChat (commit d680763) and copy the overlay on top. ──
# apply-overlay.sh clones LibreChat and checks out the EXACT pinned commit (it carries the same
# pin as setup.sh), then copies every overlay/<rel> onto librechat/<rel>. The pin is load-bearing:
# a newer commit silently bypasses the overlay's useSSE re-point → chat sent UNSEALED → gateway 401.
#
# NOTE: we deliberately use apply-overlay.sh and NOT setup.sh here. setup.sh's step 2 does
# `cd web-client/shim && npm install && npm run typecheck`, which is for local dev — in this SPA
# stage the shim dir is not present (it lives in stage C), and `set -e` would fail the build.
# apply-overlay.sh performs the identical pinned clone + overlay and nothing else, so it is the
# correct in-image materialiser.
RUN bash web-client/apply-overlay.sh

# ── 4. Install the monorepo deps + build the shared packages. ──
WORKDIR /build/web-client/librechat
RUN --mount=type=cache,target=/root/.npm \
    npm install --no-audit --no-fund
RUN npm run build:packages   # data-provider → data-schemas → api → client-package

# ── 5. Build the SPA with the Caladon build-time env. ──
# The pinned measurement set is captured per-deploy → accepted as a build ARG (public data, no
# secret). ATTESTATION=strict is fail-closed; SHIM_BASE=/api/caladon is the single-origin relay.
# client/vite.config.ts loads env from envDir '../' (the librechat root) with envPrefix VITE_, so
# these MUST be present as ENV (not just ARG) when `vite build` runs in client/.
ARG VITE_CALADON_PINNED=""
ARG VITE_CALADON_ATTESTATION=strict
ARG VITE_CALADON_SHIM_BASE=/api/caladon
ENV VITE_CALADON_PINNED=${VITE_CALADON_PINNED} \
    VITE_CALADON_ATTESTATION=${VITE_CALADON_ATTESTATION} \
    VITE_CALADON_SHIM_BASE=${VITE_CALADON_SHIM_BASE} \
    NODE_ENV=production
WORKDIR /build/web-client/librechat/client
RUN npm run build
# → /build/web-client/librechat/client/dist  (index.html + assets/, single-origin SPA)


# ==============================================================================
# Stage C — RUNTIME: slim Node, run the shim (tsx) serving dist + relaying to the gateway.
#   No build step for the shim by design (it runs TS directly via tsx). No keys, no DB.
# ==============================================================================
FROM node:24.16.0-bookworm-slim@sha256:cbd8bcbdfd0d148205c9449dff3ca3c9c94d73f393a0e03ef1c8d3846c5038bf AS runtime

ENV NODE_ENV=production
WORKDIR /app

# ── The shim: package metadata first (cached layer), then deps, then source. ──
COPY web-client/shim/package.json web-client/shim/package-lock.json ./
# tsx is a devDependency of the shim, but it's the RUNTIME for `npm start` (tsx src/server.ts),
# so install ALL deps (hono + @hono/node-server + tsx). --include=dev is LOAD-BEARING: NODE_ENV is
# 'production' above, which makes `npm install` imply --omit=dev and would drop tsx → `npm start`
# crashes. `npm ci` uses the committed lockfile for a reproducible, exact-version install.
RUN --mount=type=cache,target=/root/.npm \
    npm ci --include=dev --no-audit --no-fund \
 && npm cache clean --force
COPY web-client/shim/tsconfig.json ./tsconfig.json
COPY web-client/shim/src/ ./src/

# ── The built SPA from stage B → served read-only by the shim's serveStatic. ──
COPY --from=spa /build/web-client/librechat/client/dist/ ./client-dist/

# Drop to the unprivileged user that the node image ships with.
USER node

# ── Runtime config (env-driven; NO secrets baked in — set per-deploy). ──
# CALADON_STATIC_DIR  : the built SPA the shim serves single-origin (set to the copied dist).
# CALADON_GATEWAY_BASE: the live gateway the shim relays to (override per environment).
# CALADON_ALLOWED_ORIGINS / CALADON_COOKIE_SECURE: tighten for the hosted TLS origin at run time.
# PORT                : the shim listen port (the shim's default is 8787; we standardise on 8080).
ENV CALADON_STATIC_DIR=/app/client-dist \
    CALADON_GATEWAY_BASE=https://gw.caladon.ai \
    CALADON_ALLOWED_ORIGINS=https://app.caladon.ai \
    CALADON_COOKIE_SECURE=true \
    PORT=8080

EXPOSE 8080

# Liveness: the shim serves the SPA index at / (serveStatic fallback) once up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# `npm start` → `tsx src/server.ts`. server.ts auto-starts when run directly (not when imported).
CMD ["npm", "start"]
