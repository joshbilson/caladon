"""Claims lint: fail CI if any forbidden marketing/security phrase appears in
git-tracked text files.

Swifty's system is **attested confidential computing**, NEVER "client-side E2E",
"zero-knowledge", "no possibility of leaks", or an unqualified "we can't read your
data". The coding tier is "attested", never "E2E". See the frozen contracts
(`contracts/identity-envelope.md`, `contracts/attestation.md`) for the honest
claims discipline; `docs/security/claims-register.md` is the human-readable mirror
of the FORBIDDEN list below (keep the two in sync).

This is the highest-leverage guard in the repo: it prevents anyone (human or agent)
from accidentally over-claiming the privacy posture in any tracked text file.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# FORBIDDEN phrases (case-insensitive substring match).
#
# Human-readable mirror / rationale: docs/security/claims-register.md
# Keep this list and that register in sync; this test is the enforcement.
# ---------------------------------------------------------------------------
FORBIDDEN_PHRASES: tuple[str, ...] = (
    "client-side e2e",
    "client-side end-to-end",
    "end-to-end encrypted",
    "zero-knowledge",
    "zero knowledge",
    "no possibility of leaks",
    "we can't read your data",
    "we cannot read your data",
    "impossible to leak",
)

# ---------------------------------------------------------------------------
# ALLOWLIST: files that legitimately CONTAIN the forbidden phrases precisely
# because they describe what we do NOT claim (the claims register, the threat
# model, the honest-claims discipline in the top-level docs, and this test
# itself which hardcodes the list). Anything under docs/superpowers/ is planning
# material and is exempt.
#
# Paths are repo-relative (POSIX). A path matches if it equals an allowed file
# OR is under an allowed directory prefix.
# ---------------------------------------------------------------------------
ALLOWED_FILES: frozenset[str] = frozenset(
    {
        "docs/security/claims-register.md",
        "docs/security/threat-model.md",
        "README.md",
        "the internal status notes",
        "internal handover notes",
        "the internal build plan",
        "tests/leak/test_claims_lint.py",
        # The frozen contracts define the claims discipline itself — they quote the
        # forbidden phrases in negation context ("attested, not E2E"). Legitimate.
        "contracts/attestation.md",
        "contracts/identity-envelope.md",
    }
)
ALLOWED_DIR_PREFIXES: tuple[str, ...] = ("docs/superpowers/",)

REPO_ROOT = Path(__file__).resolve().parents[2]

# Extensions we treat as text. Anything else (or anything that fails to decode as
# UTF-8) is skipped as binary.
_BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
    ".zip", ".gz", ".tar", ".tgz", ".whl", ".so", ".dylib", ".o",
    ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mov",
    ".lock",  # uv.lock etc. — machine-generated dependency pins, not prose
}


def _is_allowed(rel_path: str) -> bool:
    if rel_path in ALLOWED_FILES:
        return True
    return any(rel_path.startswith(prefix) for prefix in ALLOWED_DIR_PREFIXES)


def _git_tracked_files() -> list[str]:
    """Repo-relative POSIX paths of all git-tracked files."""
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


_SEPARATORS = re.compile(r"[-_\s]+")


def _normalize(s: str) -> str:
    """Lowercase + collapse runs of hyphen/underscore/whitespace to a single space, so
    'end-to-end-encrypted', 'end to end encrypted', and 'end_to_end  encrypted' all
    match the canonical 'end-to-end encrypted'. Closes the separator-evasion gap."""
    return _SEPARATORS.sub(" ", s.lower())


# Precompute normalized needles once (paired with their original spelling for reporting).
_NORMALIZED_PHRASES: tuple[tuple[str, str], ...] = tuple(
    (phrase, _normalize(phrase)) for phrase in FORBIDDEN_PHRASES
)


def scan_text(text: str) -> list[tuple[int, str]]:
    """Return (1-based line number, matched original phrase) for every forbidden hit.

    Matching is **separator-insensitive** (see _normalize): hyphen/underscore/whitespace
    variants are all caught. Pure function over a string so the detector itself is
    unit-testable without planting a phrase in a real tracked file.
    """
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        norm_line = _normalize(line)
        for original, norm_phrase in _NORMALIZED_PHRASES:
            if norm_phrase in norm_line:
                hits.append((lineno, original))
    return hits


def _scan_file(abs_path: Path) -> list[tuple[int, str]]:
    if abs_path.suffix.lower() in _BINARY_SUFFIXES:
        return []
    try:
        text = abs_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable -> skip
    return scan_text(text)


def test_no_forbidden_claims_in_tracked_files() -> None:
    violations: list[str] = []
    for rel in _git_tracked_files():
        if _is_allowed(rel):
            continue
        abs_path = REPO_ROOT / rel
        if not abs_path.is_file():
            continue
        for lineno, phrase in _scan_file(abs_path):
            violations.append(f"{rel}:{lineno}: forbidden claim {phrase!r}")

    assert not violations, (
        "Forbidden over-claim(s) found in tracked files. Swifty is "
        '"attested confidential computing", never "E2E"/"zero-knowledge". '
        "See docs/security/claims-register.md.\n  " + "\n  ".join(violations)
    )


def test_detector_catches_phrase() -> None:
    """Self-test: prove the detector works WITHOUT planting a phrase in a real
    tracked file. Feed a synthetic in-memory string and assert it is caught."""
    synthetic = (
        "line one is fine\n"
        "Our product is end-to-end encrypted and zero-knowledge!\n"
        "line three is also fine\n"
    )
    hits = scan_text(synthetic)
    matched_phrases = {phrase for _, phrase in hits}
    assert "end-to-end encrypted" in matched_phrases
    assert "zero-knowledge" in matched_phrases
    # both forbidden phrases are on line 2
    assert all(lineno == 2 for lineno, _ in hits)


def test_detector_is_case_insensitive() -> None:
    assert scan_text("This is ZERO-KNOWLEDGE storage.")  # uppercase still caught
    assert scan_text("Totally Client-Side E2E here.")


def test_detector_catches_separator_variants() -> None:
    """Separator-evasion is closed: hyphen/underscore/space variants all match."""
    assert scan_text("our app is end-to-end-encrypted")  # hyphenated (was a gap)
    assert scan_text("fully end_to_end encrypted")        # underscore
    assert scan_text("a zero   knowledge system")         # extra whitespace
    assert scan_text("clean attested confidential text") == []


def test_detector_clean_string_passes() -> None:
    clean = "Swifty uses attested confidential computing. No forbidden phrases here."
    assert scan_text(clean) == []


def test_allowlist_paths_are_recognized() -> None:
    assert _is_allowed("docs/security/claims-register.md")
    assert _is_allowed("README.md")
    assert _is_allowed("docs/superpowers/plans/anything.md")
    assert not _is_allowed("gateway/app/main.py")
    assert not _is_allowed("docs/some-other-doc.md")
