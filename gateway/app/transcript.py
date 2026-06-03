"""Per-tenant ciphertext transcript store — append-only opaque envelopes.

`gateway-api.md §2` (`GET /v1/messages`) + `identity-envelope.md §5.1`: the chat transcript
is a forward-secret, client-ratcheted append-only log. The CLIENT encrypts each entry and
hands over only ciphertext; the gateway stores and serves **opaque envelopes** keyed by
`account_id` and NEVER decrypts (it holds no key). This store is the gateway's transcript
back-end.

Tenant isolation is structural: every read/write is keyed by the *authenticated*
`account_id` (from seed-auth), so one tenant can never address another's log. Only
well-formed `Envelope`s are accepted (no plaintext can be stored). File-backed JSON with
atomic writes for now; the Postgres-backed multi-tenant store on the CVM's encrypted disk
lands with the CVM cutover (same interface).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from app.envelope import Envelope
from app.ids import validate_account_id


class TranscriptStore:
    """Thread-safe, file-backed, append-only ciphertext store: `account_id -> [envelope…]`.

    Construct ONE instance per store path per process (it owns the file). Writes are atomic
    (temp + rename) so a crash or concurrent reader never observes a truncated store."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        with self._lock:
            self._cache: dict[str, list[dict]] = self._load()

    def _load(self) -> dict[str, list[dict]]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        # Fail closed on a corrupt/unexpected on-disk shape rather than 500-ing later with a
        # path-leaking traceback (a truncated/tampered store must not look like usable data).
        if not isinstance(data, dict):
            raise ValueError("transcript store corrupt: expected a JSON object")
        return data

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")
        tmp.replace(self._path)  # atomic on POSIX (same filesystem)

    def append(self, account_id: str, envelope: Envelope) -> None:
        """Append one ciphertext envelope to the tenant's log. Validates the account_id and
        that `envelope` is a well-formed Envelope (the type guarantees it). Fail-closed: a
        bad account_id or non-Envelope raises before any write."""
        validate_account_id(account_id)
        if not isinstance(envelope, Envelope):
            raise TypeError("only Envelope instances may be stored (no plaintext)")
        row = envelope.model_dump()
        with self._lock:
            self._cache.setdefault(account_id, []).append(row)
            self._flush()

    def list(self, account_id: str, limit: int = 50) -> list[dict]:
        """Return up to `limit` of the tenant's envelopes, **newest-last** (chronological
        tail). Only the caller's own account_id is ever addressable (isolation)."""
        validate_account_id(account_id)
        if limit < 0:
            raise ValueError("limit must be >= 0")
        with self._lock:
            rows = self._cache.get(account_id, [])
            # Copy each row so a caller mutating a returned dict can't alias/corrupt the cache.
            return [dict(r) for r in rows[-limit:]] if limit else []
