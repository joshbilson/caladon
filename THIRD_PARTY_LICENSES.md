# Third-Party Licenses

Caladon is licensed under the Apache License, Version 2.0 (see `LICENSE` and
`NOTICE`). This document collects attributions and license texts/pointers for
third-party software used by Caladon. It is a companion to `NOTICE`.

License obligations are honored as follows: permissive licenses (MIT, BSD, ISC,
Apache-2.0) require preservation of copyright and permission notices, which are
preserved in this file and in the upstream files referenced below.

---

## 1. LibreChat — web client (DERIVED WORK)

The `web-client/librechat/` directory is a fork/derivative of **LibreChat**
(https://github.com/danny-avila/LibreChat), version v0.8.6, by Danny Avila and
contributors. Caladon's changes are applied as an overlay
(`web-client/overlay/` via `web-client/apply-overlay.sh`; see
`web-client/SURGERY.md`). The upstream checkout is fetched at build time via `web-client/setup.sh` (not
vendored here); its original MIT license is reproduced verbatim below:

```
MIT License

Copyright (c) 2026 LibreChat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The complete set of LibreChat's transitive npm dependencies and their
individual licenses is recorded in `web-client/librechat/package-lock.json`.
Notable direct dependencies of the LibreChat client include React and react-dom
(MIT), Vite (MIT), and @tanstack/react-query (MIT).

---

## 2. Caladon-authored components (this repository)

| Component | Path | License |
|---|---|---|
| Repository default | (root) | Apache-2.0 |
| @caladon/protocol | `web-client/caladon/` | Apache-2.0 |
| @caladon/web-shim | `web-client/shim/` | Apache-2.0 |
| caladon-core (Rust → WASM + UniFFI) | `caladon-core/` | Apache-2.0 |
| SwiftyKit (Apple client) | `apple/` | Apache-2.0 |
| Gateway (Python) | `gateway/` | Apache-2.0 |

`caladon-core` and the web `@caladon/*` packages are Apache-2.0, like the rest
of the repository — Apache-2.0 composes cleanly with the MIT LibreChat client.

---

## 3. Rust dependencies — `caladon-core` (`Cargo.toml` / `Cargo.lock`)

| Crate | Version | License |
|---|---|---|
| dcap-qvl | 0.5.2 | MIT OR Apache-2.0 |
| argon2 | 0.5.3 | MIT OR Apache-2.0 |
| hkdf | 0.12 | MIT OR Apache-2.0 |
| sha2 | 0.10 | MIT OR Apache-2.0 |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| x25519-dalek | 2.0.1 | BSD-3-Clause |
| chacha20poly1305 | 0.10.1 | MIT OR Apache-2.0 |
| zeroize | 1.x | MIT OR Apache-2.0 |
| base64 | 0.22 | MIT OR Apache-2.0 |
| hex | 0.4 | MIT OR Apache-2.0 |
| wasm-bindgen | 0.2.122 | MIT OR Apache-2.0 |
| serde-wasm-bindgen | 0.6 | MIT OR Apache-2.0 |
| getrandom | 0.2 | MIT OR Apache-2.0 |
| uniffi | 0.28.3 | MPL-2.0 |
| serde / serde_json | 1.x | MIT OR Apache-2.0 |

Notes:
- **uniffi** (Mozilla) is MPL-2.0 (file-level copyleft); it is used as an
  unmodified build/binding-generation dependency and is not modified by Caladon.
- The dual MIT/Apache-2.0 crates are used under their terms; their full texts
  are the standard MIT and Apache-2.0 texts.
- For the authoritative, complete transitive list, see `caladon-core/Cargo.lock`
  (e.g. `cargo tree` / `cargo about`).

The Apache-2.0 text for the dual-licensed crates is the same as Caladon's own
`LICENSE`. The MIT text is identical to the LibreChat MIT text reproduced in
§1 (modulo copyright holder).

---

## 4. Swift dependencies — Apple client (`apple/Package.swift`)

| Package | Version | License | Upstream |
|---|---|---|---|
| swift-sodium (libsodium binding) | >= 0.9.1 | ISC (libsodium: ISC) | https://github.com/jedisct1/swift-sodium |
| dcap-qvl-swift | >= 0.5.2 | MIT | https://github.com/Phala-Network/dcap-qvl-swift |

`dcap-qvl-swift` ships a bundled Rust DCAP core (from `dcap-qvl`, MIT/Apache-2.0)
exposed via a UniFFI xcframework. The resolved transitive set lives in the
package's `Package.resolved`.

### ISC License (libsodium / swift-sodium)
```
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
```

---

## 5. Python dependencies — gateway (`gateway/pyproject.toml`)

| Package | Version | License |
|---|---|---|
| fastapi | >= 0.115 | MIT |
| starlette (via fastapi) | — | BSD-3-Clause |
| uvicorn[standard] | >= 0.32 | BSD-3-Clause |
| httpx | >= 0.27 | BSD-3-Clause |
| pydantic / pydantic-settings | >= 2.5 | MIT |
| cryptography (pyca) | >= 43 | Apache-2.0 OR BSD-3-Clause (bundles OpenSSL, Apache-2.0) |
| pynacl (pyca) | >= 1.5 | Apache-2.0 (bundles libsodium, ISC) |

Dev-only: pytest (MIT), pytest-asyncio (Apache-2.0), ruff (MIT).

---

## 6. Web dependencies — Caladon packages

| Package | Version | License | Used by |
|---|---|---|---|
| hono | >= 4.6 | MIT | @caladon/web-shim |
| @hono/node-server | >= 1.13 | MIT | @caladon/web-shim |
| typescript | ^5.7 | Apache-2.0 | both (dev) |
| vitest | ^2.1 | MIT | @caladon/protocol (dev) |
| tsx | ^4.19 | MIT | both (dev) |
| @types/node | ^22 | MIT | both (dev) |

---

## 7. External services (deployed alongside; NOT bundled)

These are separately-deployed, independently-licensed services that Caladon
integrates with over the network. Their source is not vendored here.

| Service | License | Role |
|---|---|---|
| Letta (formerly MemGPT) | Apache-2.0 | Agentic-memory backend the gateway proxies (httpx) |
| RedPill / Phala attested inference | service / SDK | OpenAI-compatible attested (TDX+GPU-CC) inference endpoint |
| litellm | MIT | Planned in-CVM provider abstraction (per `docs/oss-reuse-map.md`); not a current manifest dependency |

---

## 8. Referenced but not bundled

| Project | License | Status |
|---|---|---|
| tinfoil-swift | AGPL-3.0 | **Not a dependency.** Referenced in source comments and `docs/oss-reuse-map.md` as a PLANNED SEV-SNP/Sigstore attestation adapter to be injected behind SwiftyKit's `QuoteVerifier` protocol. Not imported, vendored, or distributed. Imposes no obligation on the current codebase; this file will be updated if it is ever adopted. |
| Enchanted (gluonfield/enchanted) | Apache-2.0 | Identified as a fork starting-point for the native Apple UI shell. Any derived code is Apache-2.0, compatible with this repository. |

---

## Full license texts

The full texts of the licenses referenced above are the canonical, unmodified
texts:

- **Apache-2.0** — see this repository's `LICENSE`, or
  https://www.apache.org/licenses/LICENSE-2.0
- **MIT** — see §1 above (LibreChat) for the canonical text.
- **BSD-3-Clause** — https://opensource.org/license/bsd-3-clause
- **ISC** — see §4 above.
- **MPL-2.0** — https://www.mozilla.org/MPL/2.0/

For machine-generated, exhaustive transitive license reports, run the resolver
tools against the committed lockfiles (`cargo about` / `cargo deny` for
`caladon-core/Cargo.lock`; `pip-licenses` for the gateway; `license-checker`
for each `web-client/*/package-lock.json`; and inspect `Package.resolved` for
the Apple package).
