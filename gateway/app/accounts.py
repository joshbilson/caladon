"""Account registry: `account_id -> {ed25519_pub, kem_pub, agent_id}`.

`account_id` is a routing identifier only — 256-bit, zero PII (`identity-envelope.md §3`).
The gateway stores the account's Ed25519 public key (for `seed_auth.verify`) and the KEM
public key (for delivering the working-memory key into the CVM, later), plus which Letta
agent serves the tenant. File-backed JSON for now; the Postgres-backed multi-tenant store
lands with the CVM (`contracts/gateway-api.md`). No plaintext user data is ever stored here.
"""

from __future__ import annotations

import base64
import json
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

from app.ids import validate_account_id


@dataclass
class Account:
    account_id: str
    ed25519_pub_b64: str
    kem_pub_b64: str
    agent_id: str | None = None

    def ed25519_pub(self) -> bytes:
        return base64.b64decode(self.ed25519_pub_b64, validate=True)


class AccountRegistry:
    """Thread-safe, file-backed account store. Registration is idempotent and refuses a
    silent key rebind (a different Ed25519 key for an existing account is an error).

    Precondition: construct ONE instance per process (it owns the file). Writes are atomic
    (temp + rename) so a crash or a concurrent reader can never observe a truncated store
    — a truncated read would otherwise look like an empty registry and defeat the
    key-rebind guard."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        with self._lock:
            self._cache: dict[str, Account] = self._load()

    def _load(self) -> dict[str, Account]:
        if not self._path.exists():
            return {}
        rows = json.loads(self._path.read_text(encoding="utf-8"))
        return {r["account_id"]: Account(**r) for r in rows}

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(
            json.dumps([asdict(a) for a in self._cache.values()], indent=2),
            encoding="utf-8",
        )
        tmp.replace(self._path)  # atomic on POSIX (same filesystem)

    def register(
        self,
        account_id: str,
        ed25519_pub_b64: str,
        kem_pub_b64: str,
        agent_id: str | None = None,
    ) -> tuple[Account, bool]:
        """Returns (account, created). `created` is False for an idempotent re-register.
        The existence check, key-rebind guard, and insert are one locked transaction."""
        validate_account_id(account_id)
        # Validate the key material decodes before storing.
        if len(base64.b64decode(ed25519_pub_b64, validate=True)) != 32:
            raise ValueError("ed25519 public key must be 32 bytes")
        base64.b64decode(kem_pub_b64, validate=True)
        with self._lock:
            existing = self._cache.get(account_id)
            if existing is not None:
                if existing.ed25519_pub_b64 != ed25519_pub_b64:
                    raise ValueError("account exists with a different signing key")
                return existing, False  # idempotent
            account = Account(account_id, ed25519_pub_b64, kem_pub_b64, agent_id)
            self._cache[account_id] = account
            self._flush()
            return account, True

    def get(self, account_id: str) -> Account | None:
        return self._cache.get(account_id)

    def agent_for(self, account_id: str) -> str | None:
        acct = self._cache.get(account_id)
        return acct.agent_id if acct else None
