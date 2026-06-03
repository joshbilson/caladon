"""Leak guard (skeleton): the gateway must never log prompt/response bodies.

The gateway is a *ciphertext router* in the target architecture
(`contracts/identity-envelope.md §4`); even in today's M1b plaintext-over-tailnet
form it must not write user message content to logs. This is a STATIC check over
`gateway/app/`: it flags any logging/print call whose arguments reference message
content (the variables/fields that carry prompts or responses).

Today the gateway uses NO logging at all (verified), so this test is GREEN. Deeper
runtime probes — capturing actual log output during a streamed chat and asserting
no plaintext appears — are deferred to Phase 1 (see the skipped placeholder).
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATEWAY_APP = REPO_ROOT / "gateway" / "app"

# Call targets we treat as "emits to a log/stdout sink".
_LOG_CALL_NAMES = {"print"}
_LOG_METHOD_NAMES = {
    "debug", "info", "warning", "warn", "error", "exception", "critical", "log",
}

# Identifiers/attribute names that denote user message content. If any of these
# appear inside a logging call's arguments, that is a potential plaintext leak.
_CONTENT_TOKENS = {
    "text",       # ChatRequest.text, token {"text": ...}
    "content",    # Letta/Message content
    "message",    # generic body
    "messages",   # request payload list
    "prompt",
    "response",
    "reasoning",  # model reasoning deltas
    "body",
    "payload",
    "req",        # the ChatRequest object
    "evt",        # streamed Letta event dict
}


def _iter_py_files() -> list[Path]:
    return sorted(GATEWAY_APP.rglob("*.py"))


def _names_in(node: ast.AST) -> set[str]:
    """Collect identifier and attribute names referenced anywhere under node."""
    found: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            found.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            found.add(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            # a dict key like {"text": content} shows up as a string constant
            found.add(sub.value)
    return found


def _is_logging_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in _LOG_CALL_NAMES
    if isinstance(func, ast.Attribute):
        # logger.info(...), logging.debug(...), log.error(...)
        return func.attr in _LOG_METHOD_NAMES
    return False


def find_content_logging(source: str) -> list[tuple[int, str]]:
    """Return (lineno, snippet) for logging calls that reference content tokens.

    Pure function over source text so the detector is itself testable.
    """
    tree = ast.parse(source)
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_logging_call(node):
            continue
        arg_names: set[str] = set()
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            arg_names |= _names_in(arg)
        leaked = arg_names & _CONTENT_TOKENS
        if leaked:
            hits.append((node.lineno, ", ".join(sorted(leaked))))
    return hits


def test_gateway_does_not_log_message_content() -> None:
    violations: list[str] = []
    for py in _iter_py_files():
        source = py.read_text(encoding="utf-8")
        for lineno, tokens in find_content_logging(source):
            rel = py.relative_to(REPO_ROOT)
            violations.append(f"{rel}:{lineno}: logging call references {tokens}")
    assert not violations, (
        "Gateway logs message content (potential plaintext leak):\n  "
        + "\n  ".join(violations)
    )


def test_detector_catches_content_logging() -> None:
    """Self-test: synthetic source that DOES log a prompt is flagged."""
    bad = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def handle(req):\n"
        "    logger.info('got prompt: %s', req.text)\n"
    )
    hits = find_content_logging(bad)
    assert hits, "detector failed to flag a logging call referencing req.text"


def test_detector_ignores_benign_logging() -> None:
    benign = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def handle():\n"
        "    logger.info('stream started')\n"
        "    logger.warning('upstream %d', 503)\n"
    )
    assert find_content_logging(benign) == []


import pytest  # noqa: E402  (placeholder import kept near its sole use below)


@pytest.mark.skip(reason="runtime log-capture probe lands in Phase 1")
def test_no_plaintext_in_runtime_logs() -> None:
    """TODO (Phase 1): drive a streamed /v1/chat with a known sentinel prompt,
    capture all log/stdout output for the request, and assert the sentinel never
    appears in any emitted log record."""
    raise NotImplementedError
