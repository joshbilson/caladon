# Contributing to Caladon

Thanks for your interest in contributing. Caladon is a privacy-first AI assistant
built on attested confidential computing, and we welcome contributions of code,
documentation, tests, and — especially — security findings.

This project is licensed under the **Apache License, Version 2.0** (see
[`LICENSE`](LICENSE)).

---

## Licensing of contributions: inbound = outbound, under a DCO (not a CLA)

Contributions are accepted on an **inbound = outbound** basis: whatever you
contribute is licensed to the project under the **same Apache-2.0 license** that
covers the project itself. There is **no separate Contributor License Agreement
(CLA)** and **no copyright assignment** — you keep the copyright to your work.

Instead, every contribution must carry a **Developer Certificate of Origin (DCO)
1.1 sign-off**.

**Why a DCO and not a CLA?** A DCO is a lightweight, per-commit provenance
attestation: it lets contributors certify they have the right to submit their work
without assigning any rights to a company or signing a separate legal agreement.
It keeps the project community-friendly and low-friction while still giving us a
clear, auditable chain of provenance for every line of code.

### Signing off your commits

The mechanism is a `Signed-off-by` line in every commit message. Git adds it for
you when you pass `-s`:

```sh
git commit -s -m "your commit message"
```

This appends a trailer using the name and email from your Git config:

```
Signed-off-by: Your Name <you@example.com>
```

By adding that line, you certify the DCO below. The name and email must be real and
must match your Git `user.name` / `user.email`. Use the same identity consistently.

If you forgot to sign off, amend the most recent commit:

```sh
git commit --amend -s --no-edit
```

To sign off a range of existing commits on your branch (e.g. the last 3):

```sh
git rebase --signoff HEAD~3
```

> **CI enforces the sign-off.** A pull request whose commits are missing a valid
> `Signed-off-by` trailer will fail the DCO check and cannot be merged until every
> commit is signed off.

### Developer Certificate of Origin 1.1

The full text of the DCO is reproduced below. It is also available at
<https://developercertificate.org/>.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

---

## Pull request workflow

1. **Fork** the repository and **clone** your fork.
2. **Create a branch** off `main` for your change:
   ```sh
   git checkout -b my-feature
   ```
3. **Make your change.** Keep PRs focused — one logical change per PR is easier to
   review. Add or update tests for any behavior you change.
4. **Run the checks locally** before pushing (see [Running the checks](#running-the-checks-locally)).
5. **Commit with a sign-off** (`git commit -s`). Write clear, descriptive commit
   messages.
6. **Push** to your fork and **open a pull request** against `main`.
7. **Pass CI.** Every PR must be green. CI runs the unit/contract test suites,
   `ruff` lint, the Swift (Apple) tests, the **DCO sign-off check**, and the
   **claims-lint** (see below). PRs that fail any required check will not be merged.
8. **Address review feedback.** A maintainer will review your PR. Push follow-up
   commits (signed off) or amend/rebase as appropriate; keep the branch up to date
   with `main`.

By submitting a pull request, you confirm your contribution is offered under
Apache-2.0 (inbound = outbound) and that each commit carries a valid DCO sign-off.

---

## Claims discipline (CI-enforced)

Caladon is **attested confidential computing**, not the same thing as the stronger
privacy guarantees some products advertise. Getting a privacy claim's wording wrong
is a substantive defect — a wrong claim can fail an independent security review on
its own, before any code is examined. To prevent anyone (human or agent) from
accidentally overstating the privacy posture, **CI runs a claims-lint** that scans
every git-tracked text, source, and UI-string file.

- The claims-lint **rejects a fixed set of forbidden privacy phrases** (for
  example, marketing-style absolutes and inapplicable cryptographic terms). The
  canonical list, the rationale for why each phrase is forbidden, the **approved**
  claim strings you _should_ use instead, and the file allowlist all live in
  [`docs/security/claims-register.md`](docs/security/claims-register.md). That
  register is the single source of truth; the enforcing test lives in
  [`tests/leak/`](tests/leak/).
- **Before adding any user-facing or marketing copy** (README text, app strings,
  docs), check it against the claims register. A positive privacy claim must be one
  of the approved strings there, or a clearly-equivalent qualified variant approved
  in review.
- A small set of docs (the register itself, the threat model, etc.) is allowlisted
  precisely because their job is to enumerate and refute the forbidden phrases. If
  you legitimately need to quote a forbidden phrase in order to refute or document
  it, raise it in review so the file can be added to the allowlist in the register.

### Security findings are welcome contributions

We treat the privacy posture as a falsifiable, testable property. **Finding an
overclaim, or a plaintext-exposure path that contradicts our stated guarantees, is
an explicitly welcome contribution** — not an annoyance. If you find:

- a privacy/security **overclaim** in any doc, string, or marketing line that
  contradicts [`docs/security/claims-register.md`](docs/security/claims-register.md), or
- a **plaintext-exposure path** (a place where user data could be exposed in the
  clear) that is not already documented in
  [`docs/security/plaintext-exposure-map.md`](docs/security/plaintext-exposure-map.md),

please report it. For corrections to wording or docs, open a PR or an issue. For a
substantive plaintext-exposure or attestation-bypass finding, please follow the
responsible-disclosure process in [`SECURITY.md`](SECURITY.md) if one is present, or
open a minimal private report before filing a public issue. Either way, this kind of
adversarial review is among the most valuable contributions you can make.

---

## Running the checks locally

These mirror what CI runs; running them before you push saves a round trip.

```sh
# Python unit + contract + leak suites (incl. the claims-lint)
uv run --python 3.12 --with pytest --with pyyaml --with pynacl --with cryptography pytest tests/ -q

# Gateway suite
uv run --python 3.12 --extra dev pytest -q   # from gateway/

# Lint
uv run --with ruff ruff check .
```

The claims-lint runs as part of the `tests/` suite; you can target it directly:

```sh
uv run --with pytest --with pyyaml pytest tests/leak/test_claims_lint.py -q
```

---

## Code of conduct & questions

Be respectful and constructive. If you are unsure whether a change fits the
project's direction — especially anything touching the privacy posture, the
attestation flow, or user-facing claims — open an issue to discuss before investing
significant effort. We would rather talk early than ask you to redo work.

Thank you for contributing to Caladon.
