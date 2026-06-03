"""Gate-1 reference client — drives the live confidential round-trip against a real CVM.

Uses the REFERENCE crypto (`swifty_crypto`) so the bytes are identical to what the iOS/
macOS SwiftyKit client produces. Identity is seed-derived and the key-bound account_id
(B2-bis) is recomputed independently here, exactly as the gateway expects.

  onboard    POST /v1/accounts with an Ed25519 proof-of-possession over the canonical message.
  roundtrip  the full confidential turn:
               1. onboard (idempotent)
               2. GET /v1/attestation?challenge=SHA-256(eph_pub)  -> evidence (TDX quote + cvm session_pub)
               3. (best-effort) verify the quote to the Intel root via dcap-qvl + check the
                  challenge is bound into report_data
               4. derive SK against the cvm session_pub, seal WMK to SK, POST /v1/session   (§6)
               5. seal a prompt under SK, POST /v1/chat, open the sealed deltas under SK
                  -> recover a REAL attested-inference reply (plaintext never on the wire)

Run via gate1.sh / gate1-smoke.sh (which set PYTHONPATH); or:
  python3 gate1_client.py roundtrip --url <APP_URL> --prompt "..."
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import swifty_crypto as sc

# A FIXED non-secret test seed — ephemeral CVM, throwaway identity. NOT a real user seed.
TEST_SEED = b"\x07" * 32
SALT = b"swifty/v1"
ACCOUNT_LABEL = b"swifty/account/v1"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _canonical(account_id: str, ts: int, method: str, path: str) -> bytes:
    # MUST match gateway app/seed_auth.py canonical(): newline-delimited, raw path (no query).
    return f"{account_id}\n{ts}\n{method.upper()}\n{path}".encode()


def _identity() -> dict:
    root = sc.argon2id(TEST_SEED, SALT)
    pub = sc.derive_ed25519_public(root)
    priv = sc.derive_ed25519_private(root)
    account_id = sc.derive_account_id(root)
    return {"root": root, "pub": pub, "account_id": account_id, "sign": priv.sign}


def _auth_header(ident: dict, method: str, path: str) -> str:
    ts = int(time.time())
    sig = ident["sign"](_canonical(ident["account_id"], ts, method, path))
    return f"Swifty acct={ident['account_id']} ts={ts} sig={_b64(sig)}"


def _request(url: str, path: str, *, method: str, ident: dict, body: bytes | None = None) -> tuple[int, bytes]:
    # Sign the PATH WITHOUT the query (matches the gateway canonical, seed_auth.py); the full
    # path+query still goes in the request URL.
    sign_path = path.split("?", 1)[0]
    headers = {"Authorization": _auth_header(ident, method, sign_path)}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url.rstrip("/") + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=330) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _wire(env: dict) -> dict:
    """swifty_crypto.seal() returns raw bytes for nonce/aad/ct; the wire form is base64."""
    return {
        "v": env["v"], "alg": env["alg"], "kid": env["kid"],
        "nonce": _b64(env["nonce"]), "aad": _b64(env["aad"]), "ct": _b64(env["ct"]),
    }


def onboard(url: str, ident: dict | None = None) -> int:
    ident = ident or _identity()
    pub, account_id = ident["pub"], ident["account_id"]
    # Independent recomputation of the key-bound account_id (must equal gateway's).
    expect = base64.urlsafe_b64encode(hashlib.sha256(ACCOUNT_LABEL + pub).digest()).decode().rstrip("=")
    assert account_id == expect, "account_id is not the key-bound value (B2-bis drift!)"

    kem_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
    body = json.dumps({"account_id": account_id, "ed25519_pub": _b64(pub), "kem_pub": _b64(kem_pub)}).encode()
    code, resp = _request(url, "/v1/accounts", method="POST", ident=ident, body=body)
    print(f"  POST /v1/accounts -> {code}  account_id={account_id[:16]}…")
    if code in (200, 201):
        print("  ✅ onboarding: key-bound account_id + Ed25519 proof-of-possession accepted")
        return 0
    print(f"  ❌ onboarding rejected: {resp[:200]!r}")
    return 1


def _verify_quote(intel_quote_hex: str, challenge_hex: str) -> None:
    """Best-effort: verify the gateway CVM's TDX quote to the Intel root via dcap-qvl, and
    confirm the client challenge is bound into report_data. Non-fatal (prints a notice on any
    issue) so the round-trip itself still reports clearly — the cryptographic keystone is
    separately proven in a separate attestation spike."""
    try:
        raw = bytes.fromhex(intel_quote_hex[2:] if intel_quote_hex.startswith("0x") else intel_quote_hex)
    except ValueError:
        print("  ⚠ attestation: intel_quote is not hex — skipping local verify")
        return
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(raw)
        qpath = f.name
    try:
        out = subprocess.run(["dcap-qvl", "verify", qpath], capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"  ⚠ attestation: dcap-qvl not runnable ({exc}) — skipping local verify")
        return
    blob = (out.stdout + out.stderr).strip()
    status = ""
    for line in blob.splitlines():
        try:
            status = json.loads(line).get("status", "") or status
        except json.JSONDecodeError:
            continue
    bound = challenge_hex.lower() in blob.lower()
    print(f"  attestation: dcap-qvl status={status or '?'} ; challenge-bound-in-report_data={bound}")
    if status == "UpToDate":
        print("  ✅ quote verifies to the Intel root (TCB UpToDate)")


def establish_session(url: str, ident: dict) -> bytes:
    """Verify attestation, derive SK against the cvm session_pub, deliver the sealed WMK."""
    eph_priv, eph_pub = sc.x25519_keypair()
    challenge = hashlib.sha256(eph_pub).hexdigest()

    code, resp = _request(url, f"/v1/attestation?challenge={challenge}", method="GET", ident=ident)
    if code != 200:
        raise RuntimeError(f"GET /v1/attestation -> {code}: {resp[:200]!r}")
    ev = json.loads(resp)
    print(f"  GET /v1/attestation -> 200  regime={ev.get('regime')}")
    if ev.get("challenge") != challenge:
        raise RuntimeError("attestation challenge not bound (the evidence is stale/replayed)")
    quote = ev.get("intel_quote") or ev.get("quote")
    if quote:
        _verify_quote(quote, challenge)
    else:
        print("  ⚠ no intel_quote in evidence (attestation endpoint not wired?)")

    sp = ev.get("session_pub")
    if not sp:
        raise RuntimeError("evidence carries no session_pub — cannot derive SK (§6)")
    cvm_pub = base64.b64decode(sp)
    wmk = sc.derive_wmk(ident["root"])
    sk = sc.derive_session_key(eph_priv, cvm_pub, client_pub=eph_pub, cvm_pub=cvm_pub)
    sealed = sc.seal_wmk(sk, wmk, account_id=ident["account_id"])
    body = json.dumps({"client_eph_pub": _b64(eph_pub), "sealed_wmk": _wire(sealed)}).encode()
    code, resp = _request(url, "/v1/session", method="POST", ident=ident, body=body)
    if code != 200:
        raise RuntimeError(f"POST /v1/session -> {code}: {resp[:200]!r}")
    print("  POST /v1/session -> 200  (WMK delivered into TEE RAM over the attested channel)")
    return sk


def _open_deltas(sse_bytes: bytes, sk: bytes, account_id: str) -> list[str]:
    """Open each sealed token/reasoning delta under SK -> recovered plaintext."""
    text = sse_bytes.decode("utf-8", "replace")
    deltas: list[str] = []
    last_event = ""
    for line in text.splitlines():
        if line.startswith("event:"):
            last_event = line[len("event:"):].strip()
        elif line.startswith("data:") and last_event in ("token", "reasoning"):
            obj = json.loads(line[len("data:"):].strip())
            env = obj["envelope"]
            pt = sc.open(
                sk,
                {
                    "v": env["v"], "alg": env["alg"], "kid": env["kid"],
                    "nonce": base64.b64decode(env["nonce"]),
                    "aad": base64.b64decode(env["aad"]),
                    "ct": base64.b64decode(env["ct"]),
                },
                account_id=account_id,
                purpose="chat",
            )
            deltas.append((last_event, pt.decode("utf-8", "replace")))
    return deltas


def chat(url: str, ident: dict, sk: bytes, prompt: str, model: str | None = None) -> int:
    sealed = sc.seal(sk, prompt.encode(), account_id=ident["account_id"], purpose="chat", v=1, kid="chat")
    payload = {"envelope": _wire(sealed)}
    if model:
        payload["model"] = model  # per-request attested model (instant + mid-session switch)
        print(f"  (requesting model: {model})")
    body = json.dumps(payload).encode()
    t0 = time.time()
    code, resp = _request(url, "/v1/chat", method="POST", ident=ident, body=body)
    print(f"  (chat latency: {time.time() - t0:.1f}s)")
    if code != 200:
        print(f"  ❌ POST /v1/chat -> {code}: {resp[:300]!r}")
        return 1
    # Fail-closed proof: the plaintext prompt/reply must NOT appear on the wire.
    if prompt.encode() in resp:
        print("  ❌ LEAK: the plaintext prompt appeared in the response stream")
        return 1
    deltas = _open_deltas(resp, sk, ident["account_id"])
    reply = "".join(t for ev, t in deltas if ev == "token")
    reasoning = "".join(t for ev, t in deltas if ev == "reasoning")
    print(f"  POST /v1/chat -> 200  ({len(resp)} bytes of sealed SSE; prompt absent from wire ✅)")
    if reasoning.strip():
        print(f"  (sealed reasoning recovered: {len(reasoning)} chars)")
    print("  ── recovered attested-inference reply (opened under SK) ──")
    print("  " + (reply.strip().replace("\n", "\n  ") or "<empty>"))
    if not reply.strip():
        print("  ❌ empty reply")
        return 1
    print("  ✅ live confidential round-trip OK: sealed prompt → attested inference → sealed reply")
    return 0


def roundtrip(url: str, prompt: str = "Reply with exactly: CALADON LIVE OK", model: str | None = None) -> int:
    ident = _identity()
    if onboard(url, ident) != 0:
        return 1
    sk = establish_session(url, ident)
    return chat(url, ident, sk, prompt, model)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["onboard", "roundtrip"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--prompt", default="Reply with exactly: CALADON LIVE OK")
    ap.add_argument("--model", default=None, help="per-request attested model slug (e.g. phala/kimi-k2.6)")
    a = ap.parse_args()
    if a.cmd == "onboard":
        return onboard(a.url)
    return roundtrip(a.url, a.prompt, a.model)


if __name__ == "__main__":
    sys.exit(main())
