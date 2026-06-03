#!/usr/bin/env python3
"""Emit the canonical transparency RECORD that gets published to Rekor.

The record is a deterministic, minified JSON object containing exactly the data
the transparency log is meant to make tamper-evident:

  - the pinned CVM measurement tuple (measurements.md §2.1: mrtd / rtmr0..3 /
    compose_hash / os_image_hash / app_id), and
  - the reproducible-build artifact hashes (image digests; Phase-5 rebuild
    hashes as they land),
  - provenance (which live CVM, which evidence files, when captured).

It is derived from the SAME source of truth as the doc
(`measurements.source.json`) so the published record and the human-readable
registry cannot disagree. `publish.sh` signs + posts this; `verify.sh` checks the
inclusion proof of (a re-derivation of) this record.

Deterministic output (sorted keys, no whitespace) so the same source always
hashes to the same record — re-running publish on an unchanged source is a
no-op (Rekor dedupes identical entries).

Usage:
    python3 infra/transparency/build-record.py            # print canonical record
    python3 infra/transparency/build-record.py --sha256   # print sha256 of record
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "infra" / "transparency" / "measurements.source.json"

RECORD_TYPE = "ai.caladon.measurements/v1"


def build_record() -> dict:
    src = json.loads(SOURCE.read_text(encoding="utf-8"))
    gw = src["agent_cvm"]["chat_gateway_v1"]
    return {
        "_type": RECORD_TYPE,
        "doc": "docs/security/measurements.md",
        "source": "infra/transparency/measurements.source.json",
        "pinned_measurements": {
            "agent_cvm.chat_gateway_v1": {
                "tier": gw["tier"],
                "component": gw["component"],
                "mrtd": gw["mrtd"],
                "rtmr0": gw["rtmr0"],
                "rtmr1": gw["rtmr1"],
                "rtmr2": gw["rtmr2"],
                "rtmr3": gw["rtmr3"],
                "compose_hash": gw["compose_hash"],
                "os_image_hash": gw["os_image_hash"],
                "app_id": gw["app_id"],
                "source_ref": gw["source_ref"],
                "reproducible_build_ref": gw["reproducible_build_ref"],
            }
        },
        "pinning_policy": src["pinning_policy_summary"],
        "reproducible_build_hashes": src["reproducible_build_hashes"],
        "provenance": src["provenance"],
    }


def canonical_bytes(record: dict) -> bytes:
    """Deterministic serialization: sorted keys, compact separators, trailing NL."""
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sha256", action="store_true",
                    help="print the sha256 of the canonical record instead of the record")
    args = ap.parse_args()

    blob = canonical_bytes(build_record())
    if args.sha256:
        print(hashlib.sha256(blob).hexdigest())
    else:
        import sys
        sys.stdout.buffer.write(blob)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
