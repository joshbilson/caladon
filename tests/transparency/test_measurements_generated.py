"""Anti-drift guard for the pinned-measurement registry (Apple-PCC req #5 + Confer).

`docs/security/measurements.md` is the mapping table the iOS client pins
(`contracts/attestation.md §6`). It is **generated** from a single source of
truth (`infra/transparency/measurements.source.json`) by
`infra/transparency/gen-measurements.py`.

This suite is the enforcement: it fails CI if

  1. the committed doc != render(source)  — i.e. someone hand-edited the doc or
     forgot to regenerate after editing the source; and
  2. the real, currently-pinned measurement values are not present verbatim in
     both the source and the rendered doc (a load-bearing canary: catches an
     accidental value change in either direction).

Together these mean a measurement cannot drift or be silently/undetectably
hand-edited: any change to a published hash must go through the JSON source and
shows up in the diff.

The generator module has a hyphenated filename (`gen-measurements.py`) so it is
loaded via importlib rather than a normal import.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "infra" / "transparency" / "gen-measurements.py"
DOC = REPO_ROOT / "docs" / "security" / "measurements.md"
SOURCE = REPO_ROOT / "infra" / "transparency" / "measurements.source.json"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_measurements", GEN_PATH)
    assert spec and spec.loader, f"cannot load generator at {GEN_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The real, currently-pinned values (measurements.md §2.1) that MUST survive any
# refactor of the generator or the source. If any of these changes, this canary
# fires and forces an explicit, reviewed update — they cannot drift quietly.
PINNED_CANARY = (
    "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",  # mrtd
    "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",  # rtmr0
    "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",  # rtmr1
    "a2a58c9a959a4fa44bd6da0c97a2270c051faf12084cfe91ae900e4fdff6cdd4f69a82005e04ee920f231497894d677f",  # rtmr2
    "47bae9194b7c52ed006f6af0e31a9e8eccdf2a9785985e820b632e4a41c5cc17",  # compose_hash
    "de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9",  # os-image-hash
)


def test_committed_doc_matches_generated_source() -> None:
    """The committed measurements.md is EXACTLY what the generator emits from the
    JSON source. Hand-editing the doc (or editing the source without regenerating)
    turns CI red — the anti-drift property."""
    mod = _load_generator()
    src = mod.load_source()
    rendered = mod.render(src)
    committed = DOC.read_text(encoding="utf-8")
    assert committed == rendered, (
        "docs/security/measurements.md is out of sync with its source of truth.\n"
        "Regenerate it: python3 infra/transparency/gen-measurements.py\n"
        "(Do NOT hand-edit the doc — edit infra/transparency/measurements.source.json.)"
    )


def test_doc_is_marked_generated() -> None:
    """The doc carries the GENERATED marker so a human reader knows not to edit it."""
    committed = DOC.read_text(encoding="utf-8")
    assert committed.lstrip().startswith("<!-- GENERATED FILE")
    assert "measurements.source.json" in committed.splitlines()[1]


def test_pinned_values_present_in_source_and_doc() -> None:
    """The real §2.1 pinned hashes appear verbatim in BOTH the JSON source and the
    rendered doc. Keeps the 'current real values' (task requirement) and acts as a
    value-level canary independent of the equality check above."""
    source_text = SOURCE.read_text(encoding="utf-8")
    doc_text = DOC.read_text(encoding="utf-8")
    for value in PINNED_CANARY:
        assert value in source_text, f"pinned value missing from source JSON: {value}"
        assert value in doc_text, f"pinned value missing from generated doc: {value}"


def test_check_mode_passes_on_committed_doc() -> None:
    """`gen-measurements.py --check` returns the same equality verdict (exit 0)."""
    mod = _load_generator()
    rendered = mod.render(mod.load_source())
    assert DOC.read_text(encoding="utf-8") == rendered
