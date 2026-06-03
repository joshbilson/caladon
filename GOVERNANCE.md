# Governance

This document describes how the **Caladon** project is licensed, how it is
maintained, and how to contribute. It is meant to be read in full before you
file your first issue or pull request. The goal is to be honest and unambiguous
about what is open, what is not, and why.

---

## 1. License posture — genuinely open source

**The entire contents of this repository are licensed under the
[Apache License 2.0](LICENSE).** There is no separate "community edition," no
delayed-open license (no BSL/SSPL/Commons Clause), and no copyleft.

What that means in practice — for individuals, companies, and autonomous AI
agents alike — is that you may, royalty-free and without asking permission:

- **Download, run, and self-host** the whole platform for any purpose, including
  commercial use.
- **Modify** any part of it and run your modified version privately or publicly.
- **Redistribute** it, modified or unmodified, including inside a closed-source
  product.
- **Embed** it in your own software or service and ship that to your own users.

Apache-2.0 also gives you an **express patent grant** from contributors, which
is a deliberate choice for a security/cryptography project: it protects
downstream users from patent claims by contributors on the code they
contributed.

Your only obligations under Apache-2.0 are the usual permissive ones: keep the
license and copyright notices, state significant changes you make to the files,
and don't use the project's trademarks to imply endorsement. (Trademark use is
*not* granted by the code license — see §1.1.)

If you ever find a file in this repository that is *not* under Apache-2.0, or a
dependency whose license is more restrictive, that is a bug. Please open an
issue; we will fix it or remove the dependency.

### 1.1 Trademarks (the one thing the license doesn't cover)

Apache-2.0 covers the **code**, not the **name and marks** ("Caladon," the logo,
`caladon.ai`). You may absolutely run, fork, and redistribute the software. If
you distribute a *modified* build, please don't present it as the official
Caladon distribution in a way that confuses users about who stands behind it.
Forking is welcome; impersonation is not. This is the standard
"do whatever you want with the code, just don't claim to be us" boundary.

---

## 2. Open-core posture — stated honestly

Caladon is **open core**, and we want to be precise about where the line is,
because a privacy project that is vague about its own incentives has failed at
the first hurdle.

**Everything required to run the full platform yourself is in this repository,
under Apache-2.0, with nothing withheld.** The gateway, the cryptographic data
plane, the attestation verifier, the apps, the enclave/CVM provisioning, and the
deployment tooling are all here. A self-hosted Caladon is not a crippled demo or
a "free tier" — it is the real thing, and it does not phone home to anything we
operate. You can run it for yourself, for your family, or for your company's
employees, and you never have to talk to us to do it.

**What is *not* in this repository** is the maintainers' **hosted SaaS**: the
proprietary code we use to *operate Caladon as a paid managed service*. That
lives in a **separate, private repository** and includes:

- **Billing and metering** (subscriptions, usage accounting, payment
  integration).
- **Multi-tenant orchestration** — provisioning and lifecycle management of
  many users' isolated enclaves at scale.
- **Operator admin / console** — the internal dashboards and tooling our team
  uses to run the fleet.
- **The managed T1 fleet** — the actual hosted infrastructure and its
  operational glue.

This split is intentional and, we hope, fair: **the hosted SaaS is how the
maintainers fund the work, not a tax on the software.** None of it is required
to self-host. None of it gates a feature of the open platform behind a paywall.
The private repo is operational and commercial plumbing for *our* deployment; it
is not a withheld piece of *your* deployment.

We commit to the following so this stays honest over time:

- **No bait-and-switch on the license.** Code that is published here under
  Apache-2.0 stays Apache-2.0. We will not relicense it out from under you.
- **No "open-core creep" of core function.** Security- and
  privacy-relevant functionality — anything that affects the confidentiality or
  attestation guarantees described in the README — stays in this open
  repository. We will not move a security primitive behind the SaaS boundary.
- **The line is operational, not functional.** If something is genuinely useful
  for running *your own* instance, it belongs here. The private repo is for
  running *our* business.

---

## 3. Maintainers and decisions

### How decisions are made

Caladon uses a lightweight **maintainer / lazy-consensus** model rather than a
formal foundation:

- **Most changes** proceed by lazy consensus: a pull request that has been open
  for review, has no unresolved objections from a maintainer, and passes CI can
  be merged by any maintainer.
- **Substantial changes** — anything touching the security model, the
  attestation logic, the cryptographic data plane, the frozen interface
  contracts in `contracts/`, or the public claims the project makes — require
  **explicit approval from at least two maintainers**, and should start as an
  issue or design note in `docs/` before code.
- **Disagreements** are resolved by discussion and, failing that, by a simple
  majority vote of maintainers. The project lead holds a tie-breaking vote and
  acts as the final escalation point, but is expected to use that power rarely
  and to explain it when used.

The current project lead and maintainer set are listed in **`MAINTAINERS.md`**
(authoritative). If that file does not yet exist, the repository owner is the
acting lead until it does.

### What maintainers are accountable for

Maintainers are responsible for review quality, for keeping releases honest
about their security status (no overclaiming — see the README's privacy model),
and for upholding the license and open-core commitments in §1 and §2. A
maintainer who repeatedly acts against these is subject to removal by majority
vote of the remaining maintainers.

### How to become a maintainer

There is no application form and no time-served requirement. Maintainership is
earned through **a sustained track record of good contributions and good
judgment**, typically:

- A history of merged, high-quality pull requests, *or* substantive review and
  security analysis of others' work.
- Demonstrated care for the project's central value — **not overclaiming**.
  Contributors who catch overclaims, plaintext-exposure paths, or attestation
  gaps are exactly the people we want as maintainers.
- Reliability and constructive conduct in issues and reviews.

Any existing maintainer may nominate a contributor. Nomination passes by
majority of maintainers with no veto from the lead. New maintainers are added to
`MAINTAINERS.md` in the same PR that grants access.

---

## 4. Contributing

### Inbound = Outbound (no CLA)

We do **not** require a Contributor License Agreement. Following the Apache-2.0
norm (and the GitHub default), **all contributions are made under the same
Apache-2.0 license that covers the project** — your inbound contribution is
licensed to the project, and to everyone downstream, on exactly the same terms
as the rest of the code (Apache-2.0 §5, "inbound = outbound"). You keep your
copyright; you grant the same permissive rights you received.

We deliberately avoid a CLA because we have no intent to relicense the open code
(see §2). Keeping inbound = outbound is the structural guarantee of that
promise: there is no mechanism by which contributed code could be quietly taken
proprietary.

### Developer Certificate of Origin (DCO) — sign-off required

Instead of a CLA, we use the **[Developer Certificate of Origin](https://developercertificate.org/)**.
Every commit must be signed off, certifying that you wrote the code (or
otherwise have the right to submit it under Apache-2.0). Add the sign-off with:

```
git commit -s
```

which appends a trailer to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

CI checks for the trailer. If you forget it, amend with
`git commit --amend -s` (or `git rebase --signoff` for a series) and force-push
your branch.

### How to contribute, in short

1. Open an issue or discussion first for anything non-trivial, especially
   anything touching the security model or the frozen `contracts/`.
2. Branch, make your change, and **sign off every commit** (`-s`).
3. Keep PRs focused and ensure CI is green.
4. Be honest in the PR description about what the change does and does not
   guarantee. The single most valued contribution to this project is one that
   makes our claims *more* precise, not less.

By submitting a contribution you agree it is licensed under Apache-2.0 and you
certify it under the DCO. That's the whole agreement — no CLA, no assignment,
nothing signed away.
