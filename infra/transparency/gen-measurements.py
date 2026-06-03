#!/usr/bin/env python3
"""Generate docs/security/measurements.md from the source-of-truth JSON.

`docs/security/measurements.md` is the **mapping table the iOS client pins**
(`contracts/attestation.md §6`). It must be machine-generated from a single
source of truth so it cannot drift or be hand-edited undetectably — that is the
Apple-PCC req #5 (transparency) + Confer property: every published measurement
is reproducible from a committed source and is checkable by a stranger.

  SOURCE OF TRUTH:  infra/transparency/measurements.source.json
  GENERATED DOC:    docs/security/measurements.md

Usage:
    python3 infra/transparency/gen-measurements.py            # write the doc
    python3 infra/transparency/gen-measurements.py --check    # exit 1 if stale
    python3 infra/transparency/gen-measurements.py --stdout   # print, don't write

The companion test `tests/transparency/test_measurements_generated.py` runs
`--check` semantics in CI: if the committed doc != render(source), CI is red.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "infra" / "transparency" / "measurements.source.json"
DOC = REPO_ROOT / "docs" / "security" / "measurements.md"

# Marker emitted at the top of the generated doc. Its presence is how a reader
# (and the lint) knows the file is generated, not hand-authored.
GENERATED_MARKER = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Source of truth: infra/transparency/measurements.source.json\n"
    "     Regenerate:      python3 infra/transparency/gen-measurements.py\n"
    "     Verified in CI:  tests/transparency/test_measurements_generated.py -->"
)


def load_source() -> dict:
    return json.loads(SOURCE.read_text(encoding="utf-8"))


def _empty_row(d: dict, cols: int = 8) -> str:
    """A measurements row with `tier`/`component` filled and the rest `_(empty)_`."""
    rest = " | ".join(["_(empty)_"] * (cols - 2))
    return f"| {d['tier']} | {d['component']} | {rest} |"


def render(src: dict) -> str:
    gw = src["agent_cvm"]["chat_gateway_v1"]
    full = src["agent_cvm"]["chat_full_backbone"]
    coding = src["agent_cvm"]["coding"]
    inf = src["inference_enclave"]
    lines: list[str] = []
    w = lines.append

    w(GENERATED_MARKER)
    w("")
    w("# Swifty — Pinned-Measurement Registry")
    w("")
    w(f"**Status:** {src['doc_status']}")
    w(f"**Owner:** {src['owner']}")
    w(f"**Referenced by:** {src['referenced_by']}")
    w("")
    w("> This is the **mapping table** the iOS client pins. The client ships a pinned set")
    w("> of allowed `{mrtd, rtmr[*], compose_hash, app_id}` tuples for both enclaves; each")
    w("> tuple maps to a reproducible build a reviewer can rebuild from public source and")
    w("> confirm the measurement matches (`attestation.md §6`, `reproducible-builds.md`).")
    w("")
    w("---")
    w("")
    w("## 1. Registry schema")
    w("")
    w("| Column | Meaning |")
    w("|---|---|")
    w("| `tier` | `chat` \\| `coding` |")
    w("| `component` | `Agent CVM` \\| `Inference enclave` |")
    w("| `mrtd` | Intel TDX measurement of the TD (boot measurement) |")
    w("| `rtmr[0..3]` | Runtime measurement registers (extend the boot chain) |")
    w("| `compose_hash` | dstack compose hash identifying the exact workload image |")
    w("| `app_id` | dstack application id (inference: model slug bound) |")
    w("| `reproducible-build-ref` | Pointer to the build recipe / artifact that reproduces this measurement (`reproducible-builds.md`) |")
    w("| `source-ref` | Git ref / tag of the public source that the build was produced from |")
    w("")
    w("---")
    w("")
    w("## 2. Pinned set")
    w("")
    w("### 2.1 Agent CVM (Phala dstack, Intel TDX)")
    w("")
    w(f"**{gw['label']}**")
    w(gw["captured"])
    w("")
    w("| field | value |")
    w("|---|---|")
    w(f"| tier / component | `{gw['tier']}` / {gw['component']} |")
    w(f"| mrtd | `{gw['mrtd']}` |")
    w(f"| rtmr0 | `{gw['rtmr0']}` |")
    w(f"| rtmr1 | `{gw['rtmr1']}` |")
    w(f"| rtmr2 | `{gw['rtmr2']}` |")
    w(f"| rtmr3 | `{gw['rtmr3']}` |")
    w(f"| compose_hash | `{gw['compose_hash']}` |")
    w(f"| os-image-hash | `{gw['os_image_hash']}` ({gw['os_image_hash_note']}) |")
    w(f"| app_id | `{gw['app_id']}` |")
    w(f"| OS image | {gw['os_image_note']} |")
    w(f"| domain | {gw['domain']} |")
    w(f"| reproducible-build-ref | {gw['reproducible_build_ref']} |")
    w(f"| source-ref | {gw['source_ref']} |")
    w("")
    w("> Confirmed across THREE deploys (incl. the `--no-dev-os` production redeploy): **`mrtd` + `rtmr0..2`")
    w("> are stable** (`f06dfda6…` / `68102e7b…` / `07e6f51a…` / `a2a58c9a…`) — stable EVEN across the")
    w("> dev→production OS image; **`app_id` + `rtmr3` change per deploy** (…→6643c22f, …→3e88269c);")
    w("> `compose_hash` (`47bae919`) is stable while the compose file is unchanged. **Pinning policy:** pin")
    w("> `mrtd` + `rtmr0..2` + `compose_hash` + `os-image-hash`; treat `app_id`/`rtmr3` as per-instance")
    w("> (advisory). The `--no-dev-os` redeploy added the no-SSH property without changing the stable four.")
    w("")
    w("> ⚠ **rtmr3 + app_id are deploy-specific.** dstack derives `app_id` per deployment (not purely")
    w("> from compose_hash), and rtmr3 binds the app-id/compose-hash/instance-id event log — so a")
    w("> **redeploy changes app_id + rtmr3** even with an identical compose. `mrtd`/`rtmr0..2` +")
    w("> `compose_hash` + `os-image-hash` are the stable identity; pin those and treat app_id/rtmr3 as")
    w("> per-instance. (This also drives the gw.caladon.ai custom-domain churn noted in the internal status notes.)")
    w("")
    w(f"**{full['label']}**:")
    w("")
    w("| tier | component | mrtd | rtmr[0..3] | compose_hash | app_id | reproducible-build-ref | source-ref |")
    w("|---|---|---|---|---|---|---|---|")
    w(_empty_row(full))
    w(_empty_row(coding))
    w("")
    w(f"### 2.2 Inference enclave ({inf['_section_note']})")
    w("")
    w("| tier | component | mrtd | rtmr[0..3] | compose_hash | app_id | reproducible-build-ref | source-ref |")
    w("|---|---|---|---|---|---|---|---|")
    w(_empty_row(inf["chat"]))
    w(_empty_row(inf["coding"]))
    w("")
    w("> The coding tier uses a **separate** Agent CVM with **scoped keys** — identical")
    w("> contract, **different `app_id` and measurement** (`attestation.md §1`). Fallback")
    w("> inference adapters (Tinfoil/NEAR) must emit an equivalent receipt and have their")
    w("> own pinned tuple, or they are rejected (`attestation.md §2.2`).")
    w("")
    w("---")
    w("")
    w("## 3. Interim pinning policy (until reproducible builds exist — Phase 5)")
    w("")
    w("Reproducible builds do not exist until Phase 5. Until then:")
    w("")
    w("- **Dev builds are measured and recorded here**, each row explicitly flagged")
    w("  **`dev-pinned / not-yet-reproducible`** in the `reproducible-build-ref` column.")
    w("  This documents provenance honestly: the measurement is real, but it has not yet")
    w("  been independently reproducible from public source.")
    w("- **Runtime NEVER accepts an unpinned measurement.** No TOFU. No accept-new. A")
    w("  measurement not present in this pinned set → the client **refuses to send**")
    w("  (`attestation.md §4.3, §6`; fail-closed per `attestation.md §8`).")
    w("- **The pinned set updates ONLY via a signed client app update** — never at runtime,")
    w("  never via a server-pushed list. This is what closes the \"operator swaps the")
    w("  binary\" hole: a swapped workload produces an unpinned measurement and the client")
    w("  refuses (`attestation.md §6`).")
    w("- **Phase-5 graduation:** when reproducible builds land, each `dev-pinned` row is")
    w("  replaced by a reproducible tuple whose `reproducible-build-ref` points to a recipe")
    w("  a reviewer can rebuild from `source-ref` and confirm the measurement matches")
    w("  (`reproducible-builds.md`).")
    w("")
    w("> The interim flag is a **provenance label, not a relaxation** of fail-closed")
    w("> behavior. A `dev-pinned` measurement is still pinned; an *unpinned* measurement is")
    w("> still always refused.")
    w("")
    w("---")
    w("")
    w("## 4. Transparency log (Apple-PCC req #5 + Confer)")
    w("")
    w("Each pinned tuple above + its reproducible-build hashes are published as a")
    w("**signed, append-only Sigstore Rekor entry** so the registry is publicly")
    w("auditable and tamper-evident: a stranger can fetch the entry, verify the")
    w("signature, and confirm an **inclusion proof** against the log's signed tree")
    w("head — establishing that this exact measurement set was published and has not")
    w("been silently changed. Tooling + procedure: `infra/transparency/` (`publish.sh`,")
    w("`verify.sh`, `README.md`). The log is the *transparency* leg; the *non-targetability*")
    w("leg (Apple-PCC req #4 — the client cannot be steered to a specific compromised")
    w("node) is designed in `docs/security/non-targetability.md`.")
    w("")
    w("---")
    w("")
    w("## 5. Cross-references")
    w("")
    w("- `contracts/attestation.md §4, §6, §8` — verification algorithm, pinning policy,")
    w("  failure modes.")
    w("- `docs/security/reproducible-builds.md` — how a row graduates from `dev-pinned` to")
    w("  reproducible.")
    w("- `docs/security/non-targetability.md` — Apple-PCC req #4 design (OHTTP relay / IP")
    w("  hiding / single-use credentials).")
    w("- `infra/transparency/` — Sigstore Rekor publish/verify tooling for this registry.")
    w("- `docs/security/threat-model.md §3, §5` — malicious-binary-swap adversary;")
    w("  \"pinned == audited source\" as residual trust.")
    w("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed doc is stale (does not write)")
    ap.add_argument("--stdout", action="store_true",
                    help="print the rendered doc to stdout (does not write)")
    args = ap.parse_args()

    rendered = render(load_source())

    if args.stdout:
        sys.stdout.write(rendered)
        return 0

    if args.check:
        current = DOC.read_text(encoding="utf-8") if DOC.exists() else ""
        if current == rendered:
            print(f"OK: {DOC.relative_to(REPO_ROOT)} is up to date with source.")
            return 0
        print(
            f"STALE: {DOC.relative_to(REPO_ROOT)} does not match "
            f"render({SOURCE.relative_to(REPO_ROOT)}).\n"
            "Run: python3 infra/transparency/gen-measurements.py",
            file=sys.stderr,
        )
        return 1

    DOC.write_text(rendered, encoding="utf-8")
    print(f"Wrote {DOC.relative_to(REPO_ROOT)} from {SOURCE.relative_to(REPO_ROOT)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
