"""Forward-secret transcript ratchet (contracts/identity-envelope.md §5.1; names the
interface amendment B5 called for).

A libsignal-style symmetric KDF chain held CLIENT-SIDE. Each `advance()` derives the next
entry's message key and replaces the chain key with its successor, discarding the prior
chain key — so a compromise of the *current* state cannot recover PAST message keys
(forward secrecy vs device-at-rest / server compromise). The CVM never holds these keys;
it only stores the resulting ciphertext envelopes.

Reading old transcript entries on a NEW device (restored from the same seed) is a replay
from `transcript_root`: ratchet forward to the entry's step via `message_key_at()` (O(n)).
This is the seed-recoverability of the transcript (so the FS holds vs device/server
compromise, but NOT vs seed compromise — §5.2/§8.2, by design).
"""

from __future__ import annotations

from swifty_crypto.kdf import hkdf

_MSG_LABEL = "swifty/transcript/msg/v1"
_CHAIN_LABEL = "swifty/transcript/chain/v1"
_DEVICE_LABEL = "swifty/transcript/device/v1"  # per-device sub-ratchet seed (MD1)

_KID_PREFIX = "t"  # transcript-entry kid: f"t{step}" or f"t{device_id}:{step}" (multi-device)


def _validate_device_id(device_id: str) -> None:
    # ':' is the kid separator; '/' is the HKDF-label separator — both would break parsing /
    # domain separation, so reject them.
    if not device_id or ":" in device_id or "/" in device_id:
        raise ValueError("device_id must be non-empty and contain no ':' or '/'")


def device_transcript_root(transcript_root: bytes, device_id: str) -> bytes:
    """Per-device transcript chain seed (multi-device FS ratchet, MD1 / Sesame-style).

    Each of a user's devices derives an INDEPENDENT forward-secret chain from the shared
    `transcript_root` + its `device_id`, so devices append CONCURRENTLY without coordination
    (no shared mutable chain). Any device — all share the seed -> the same `transcript_root`
    -> every per-device root — can replay every device's chain to read the full transcript;
    cross-device ordering is by the entry timestamp carried in the envelope. FS is per the
    §5.2 limitation: holds vs server / device-RAM compromise, not vs seed compromise."""
    _validate_device_id(device_id)
    return hkdf(transcript_root, f"{_DEVICE_LABEL}/{device_id}")


def transcript_kid(step: int, device_id: str | None = None) -> str:
    """Encode a transcript step (+ optional device, multi-device) into the envelope `kid`
    (identity-envelope §4/B5). Single-device: `t{step}`; multi-device: `t{device_id}:{step}`."""
    if step < 0:
        raise ValueError("step must be >= 0")
    if device_id is None:
        return f"{_KID_PREFIX}{step}"
    _validate_device_id(device_id)
    return f"{_KID_PREFIX}{device_id}:{step}"


def parse_transcript_kid(kid: str) -> tuple[str | None, int]:
    """Inverse of transcript_kid -> (device_id|None, step). Raises ValueError on a non-kid."""
    if not kid.startswith(_KID_PREFIX):
        raise ValueError(f"not a transcript kid: {kid!r}")
    body = kid[len(_KID_PREFIX):]
    if ":" in body:
        device_id, step = body.rsplit(":", 1)
        if not device_id:
            raise ValueError(f"transcript kid has empty device_id: {kid!r}")
        return device_id, int(step)
    return None, int(body)


def step_from_kid(kid: str) -> int:
    """Convenience: the step component only (ignores device). Raises on a non-kid."""
    return parse_transcript_kid(kid)[1]


def message_key_at(transcript_root: bytes, step: int) -> bytes:
    """Re-derive the message key for entry `step` by ratcheting the chain forward from
    `transcript_root` (replay-from-root read path; O(step))."""
    if step < 0:
        raise ValueError("step must be >= 0")
    chain_key = transcript_root
    for _ in range(step):
        chain_key = hkdf(chain_key, _CHAIN_LABEL)
    return hkdf(chain_key, _MSG_LABEL)


class TranscriptRatchet:
    """Append-side, forward-secret. `advance()` -> (step, message_key); the prior chain key
    is overwritten (not retained) on each advance."""

    def __init__(self, transcript_root: bytes) -> None:
        self._chain_key = transcript_root
        self._step = -1

    @property
    def step(self) -> int:
        return self._step

    def advance(self) -> tuple[int, bytes]:
        self._step += 1
        message_key = hkdf(self._chain_key, _MSG_LABEL)
        # Advance + DISCARD the prior chain key (no reference kept -> unrecoverable on-device).
        self._chain_key = hkdf(self._chain_key, _CHAIN_LABEL)
        return self._step, message_key
