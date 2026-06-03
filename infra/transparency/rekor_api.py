#!/usr/bin/env python3
"""Pure-stdlib Rekor REST client — publish + verify the measurement record without
needing the `rekor-cli` binary.

`publish.sh`/`verify.sh` prefer `rekor-cli` (the canonical Sigstore tool). On
hosts where rekor-cli is unavailable (e.g. arm64 dev boxes where the amd64-only
distroless image / Go cross-build is impractical), they fall back to this, which
talks the same Rekor REST API and performs the same operations:

  publish  — build canonical record, sign with an x509 (ECDSA P-256) key, POST a
             `rekord` v0.0.1 entry, print uuid + logIndex.
  verify   — fetch the entry, recompute the RFC-6962 Merkle inclusion proof up to
             the log's signed tree-head rootHash, and confirm the logged artifact
             hash equals the locally re-derived record sha256 (the doc->log
             binding). Fail-closed (non-zero) on any mismatch.

Requires only: python3, openssl (for the keypair/signature), a running Rekor.

Usage:
    python3 rekor_api.py publish --rekor-url http://localhost:3000 \\
        --record <file> --cert <pem> --sig <file>
    python3 rekor_api.py verify  --rekor-url http://localhost:3000 --record <file>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    return json.load(urllib.request.urlopen(req))


def _get(url: str) -> dict:
    # Rekor content-negotiates and defaults some endpoints (e.g.
    # GET /log/entries/{uuid}) to YAML; force JSON explicitly.
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    return json.load(urllib.request.urlopen(req))


def cmd_publish(args: argparse.Namespace) -> int:
    record = open(args.record, "rb").read()
    rec_sha = hashlib.sha256(record).hexdigest()
    sig_b64 = base64.b64encode(open(args.sig, "rb").read()).decode()
    cert_b64 = base64.b64encode(open(args.cert, "rb").read()).decode()
    entry = {
        "apiVersion": "0.0.1", "kind": "rekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": rec_sha},
                     "content": base64.b64encode(record).decode()},
            "signature": {"format": "x509", "content": sig_b64,
                          "publicKey": {"content": cert_b64}},
        },
    }
    try:
        out = _post(f"{args.rekor_url}/api/v1/log/entries", entry)
    except urllib.error.HTTPError as e:
        print(f"publish: Rekor rejected the entry ({e.code}): {e.read().decode()[:500]}",
              file=sys.stderr)
        return 2
    uuid = next(iter(out))
    log_index = out[uuid].get("logIndex")
    print(f"record_sha256={rec_sha}")
    print(f"uuid={uuid}")
    print(f"logIndex={log_index}")
    return 0


def _verify_inclusion(body_b64: str, proof: dict) -> str:
    """Recompute the RFC-6962 Merkle root from the leaf + audit path. Returns hex root."""
    node = hashlib.sha256(b"\x00" + base64.b64decode(body_b64)).digest()  # leaf hash
    idx = proof["logIndex"]
    for sib_hex in proof["hashes"]:
        sib = bytes.fromhex(sib_hex)
        if idx % 2 == 1:
            node = hashlib.sha256(b"\x01" + sib + node).digest()
        else:
            node = hashlib.sha256(b"\x01" + node + sib).digest()
        idx //= 2
    return node.hex()


def cmd_verify(args: argparse.Namespace) -> int:
    record = open(args.record, "rb").read()
    rec_sha = hashlib.sha256(record).hexdigest()

    if args.uuid:
        uuid = args.uuid
    else:
        uuids = _post(f"{args.rekor_url}/api/v1/index/retrieve", {"hash": f"sha256:{rec_sha}"})
        if not uuids:
            print(f"verify: no log entry found for record sha256={rec_sha} "
                  "(was it published?)", file=sys.stderr)
            return 2
        uuid = uuids[0]

    got = _get(f"{args.rekor_url}/api/v1/log/entries/{uuid}")[uuid]
    proof = (got.get("verification") or {}).get("inclusionProof") or {}
    if not proof.get("rootHash"):
        print("verify: entry has no inclusion proof yet", file=sys.stderr)
        return 2

    computed = _verify_inclusion(got["body"], proof)
    if computed != proof["rootHash"]:
        print(f"verify: FAIL — recomputed root {computed} != proof rootHash {proof['rootHash']}",
              file=sys.stderr)
        return 1

    sth = _get(f"{args.rekor_url}/api/v1/log")
    if sth.get("rootHash") != proof["rootHash"] and sth.get("treeSize") == proof.get("treeSize"):
        print("verify: FAIL — proof root does not match the current signed tree head",
              file=sys.stderr)
        return 1

    logged_sha = json.loads(base64.b64decode(got["body"]))["spec"]["data"]["hash"]["value"]
    if logged_sha != rec_sha:
        print(f"verify: FAIL — logged artifact sha256 {logged_sha} != local record {rec_sha}. "
              "The published measurement set differs from this repo.", file=sys.stderr)
        return 1

    print(f"OK uuid={uuid} logIndex={proof['logIndex']} treeSize={proof['treeSize']}")
    print(f"OK inclusion proof recomputes to rootHash={proof['rootHash']}")
    print(f"OK signed tree head treeSize={sth.get('treeSize')} rootHash={sth.get('rootHash')}")
    print(f"OK logged artifact hash == local record sha256 ({rec_sha})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("publish")
    p.add_argument("--rekor-url", required=True)
    p.add_argument("--record", required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--sig", required=True)
    p.set_defaults(func=cmd_publish)

    v = sub.add_parser("verify")
    v.add_argument("--rekor-url", required=True)
    v.add_argument("--record", required=True)
    v.add_argument("--uuid", default=None)
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
