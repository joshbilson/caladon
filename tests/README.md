# Caladon test layering

TDD discipline (Sprint 1 / Phase 0): acceptance and leak tests are written
**first**, from the frozen contracts in `/contracts`, so implementation agents
build to green. This directory holds the **repo-root** suites that span
components or guard cross-cutting properties. Component-local unit tests live with
their component (e.g. `gateway/tests/`).

## Layers

| Layer | Location | Runs when | Status |
|-------|----------|-----------|--------|
| Unit (gateway) | `gateway/tests/` | now (13 tests) | GREEN |
| Leak — claims lint | `tests/leak/test_claims_lint.py` | now | GREEN |
| Leak — no plaintext logging | `tests/leak/test_no_plaintext_logging.py` | now (static) | GREEN (runtime probe TODO Phase 1) |
| Crypto contract | `tests/crypto/test_identity_envelope_contract.py` | Phase 2 (the team) | SKIP until `swifty_crypto` lands |
| Attestation contract | `tests/attestation/test_fail_closed_contract.py` | Phase 3 (verifier) | SKIP until `swifty_attestation` lands |
| Integration / E2E | (later) | post-M1c | not yet written |

### Leak suites (highest leverage, run on every commit)
- **claims lint** — walks `git ls-files` and fails if any FORBIDDEN over-claim
  phrase (the exact list lives in `docs/security/claims-register.md`) appears in a
  tracked text file. An allowlist exempts the docs that legitimately quote those
  phrases to say we do NOT claim them. Includes a self-test proving the detector
  catches a synthetic forbidden string.
  Mirror of the list: `docs/security/claims-register.md`.
- **no plaintext logging** — AST scan of `gateway/app/` for logging/print calls
  that reference message-content variables. GREEN today (gateway logs nothing).
  A runtime log-capture probe is a skipped Phase-1 placeholder.

### Contract suites (write-first specs, skipped until impl exists)
These encode the contracts' "test obligations" sections as executable assertions
against the *intended* interface, and `pytest.importorskip` the not-yet-existing
implementation module so collection never errors:
- **crypto** — `identity-envelope.md §12`: KDF determinism + domain separation,
  account_id non-reversibility & zero-PII, envelope AAD tamper fails closed,
  two-user cross-decrypt impossible. Unskips when the team ships `swifty_crypto`.
- **attestation** — `attestation.md §10`: tamper each evidence field => refuse to
  send, replay vs fresh `eph_pub` => binding failure, mid-session compose-hash
  change => drop + mark untrusted, MITM => abort. Unskips when the verifier ships
  `swifty_attestation`.

When the implementation lands, the author updates the `importorskip` target (or
the module simply becomes importable) and the assertions run for real — no test
rewrite required.

## Running locally

Root leak suites (pure Python, no gateway deps needed):

    uv run --with pytest pytest tests/ -q

Gateway unit suite:

    cd gateway
    uv venv --python 3.12 && uv pip install -e ".[dev]"
    uv run pytest -q        # 13 tests

Everything (from repo root, gateway env active):

    uv run --with pytest pytest tests/ gateway/tests/ -q

## CI (`.github/workflows/ci.yml`)
Three jobs, triggered on push to `main` and on pull_request:
- **gateway-tests** — installs `gateway` dev extras with uv (Python 3.12),
  runs `uv run pytest -q` in `gateway/`.
- **leak-tests** — runs the root suites: `uv run --with pytest pytest tests/ -q`.
  Skipped/xfail contract tests collect cleanly (importorskip), so the job is
  green before the crypto/attestation impls exist.
- **lint** — `ruff check` over the tree, configured conservatively so the current
  tree passes (see `gateway/pyproject.toml [tool.ruff]` for the enabled rule set
  and the rationale for anything disabled).
