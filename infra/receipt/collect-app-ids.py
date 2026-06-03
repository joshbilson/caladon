#!/usr/bin/env python3
"""Collect the serving-enclave identities each keep-warm `phala/` slug routes to.

RedPill load-balances a `phala/<model>` slug across multiple attested providers
(we observed `x-redpill-provider: phala` AND `near-ai`; internal spike notes (d)).
The per-response inference receipt the gateway emits is the
`GET /v1/attestation/report?model=<slug>` body — `{intel_quote, nvidia_payload,
signing_address, signing_algo, info:{app_id, compose_hash, ...}, no_log?}`.

To flip the gateway's receipt from OBSERVE -> ENFORCE we must first PIN the real
`app_id` / `compose_hash` set a slug can land on. Enforcing against a single
observation would fail-closed the moment the load balancer picks a sibling enclave.
So this script polls each slug REPEATEDLY, aggregates the DISTINCT
`(app_id, compose_hash, signing_address)` triples seen, records whether `no_log`
was ever asserted, and emits a PROPOSED allowlist into observed-app-ids.json.

This is the parse-side mirror of gateway/app/inference_backend.py:parse_report — it
reads exactly the fields the gateway surfaces, so the allowlist we emit is keyed the
same way the gateway enforces (GATEWAY_INFERENCE_ALLOWED_APP_IDS / _COMPOSE_HASHES).

Key handling: the RedPill key is resolved at runtime from
`op://$OP_VAULT/redpill.ai/api_key` (1Password) or $REDPILL_API_KEY. It is NEVER
printed, logged, or written to the output JSON.

Usage:
    python3 collect-app-ids.py [--rounds N] [--sleep SECONDS] [--out PATH] [--models a,b,c]

Exit 0 on success (data written), non-zero only on a hard failure (e.g. no key,
zero successful samples across all rounds).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The keep-warm slugs the gateway pings (gateway/app/config.py keepwarm_models /
# swifty_inference/models.py). Enforcing the receipt means pinning whatever THESE route to.
DEFAULT_MODELS = [
    "phala/qwen3.6-35b-a3b-uncensored",
    "phala/qwen3-30b-a3b-instruct-2507",
    "phala/deepseek-v3.2",
]

REDPILL_BASE = "https://api.redpill.ai/v1"
OP_KEY_REF = "op://$OP_VAULT/redpill.ai/api_key"


def resolve_key() -> str:
    """Resolve the RedPill key WITHOUT ever printing it. Prefer $REDPILL_API_KEY (e.g. CI),
    else `op read`. Returns the raw key; the caller must never log/emit it."""
    env = os.environ.get("REDPILL_API_KEY", "").strip()
    if env:
        return env
    try:
        out = subprocess.run(
            ["op", "read", OP_KEY_REF],
            check=True, capture_output=True, text=True,
        )
    except FileNotFoundError:
        sys.exit("ERROR: `op` CLI not found and $REDPILL_API_KEY unset. Cannot resolve the RedPill key.")
    except subprocess.CalledProcessError as exc:
        # stderr from op may mention the item name but never the secret; surface only a generic hint.
        sys.exit(f"ERROR: `op read {OP_KEY_REF}` failed (rc={exc.returncode}). Is 1Password unlocked?")
    key = out.stdout.strip()
    if not key:
        sys.exit("ERROR: resolved RedPill key is empty.")
    return key


def _read_no_log(*srcs: dict) -> bool | None:
    """Read the `no_log` posture from any of the given dicts. Only an explicit truthy
    assertion counts as True; absence stays None (unknown) — never silently True.
    Mirrors gateway/app/inference_backend.py:parse_report."""
    for k in ("no_log", "no-log", "nolog"):
        for src in srcs:
            if isinstance(src, dict) and k in src:
                return bool(src[k])
    return None


def _enclave_from(node: dict, model: str, schema: str) -> dict:
    """Project one attestation node ({info, signing_address, intel_quote, ...}) into the
    honest enclave-identity fields the gateway keys its allowlist on. `node` may be the
    whole flat report OR an element of all_attestations / model_attestations."""
    info = node.get("info") if isinstance(node.get("info"), dict) else {}
    return {
        "schema": schema,
        "model": model,
        "app_id": info.get("app_id") or node.get("app_id"),
        "compose_hash": info.get("compose_hash") or node.get("compose_hash"),
        "app_name": info.get("app_name"),
        "instance_id": info.get("instance_id") or node.get("instance_id"),
        "device_id": info.get("device_id"),
        "no_log": _read_no_log(node, info),
        "signing_address": node.get("signing_address"),
        "signing_algo": node.get("signing_algo"),
        "quote_present": bool(node.get("intel_quote") or node.get("quote")),
    }


def extract_enclaves(model: str, report: dict) -> tuple[str, list[dict]]:
    """Walk a RedPill /v1/attestation/report body — which RedPill serves in THREE distinct
    schemas depending on which provider the slug load-balanced to — and return
    (schema_label, [enclave, ...]). Every serving enclave the response describes is returned
    so the allowlist aggregation is complete (one slug can name several enclaves).

      A) `phala` flat        : top-level {info, signing_address, intel_quote, all_attestations}
                               (the original spike shape). Enclaves = all_attestations[*],
                               falling back to the flat top level.
      B) `near-ai` nested    : {gateway_attestation, model_attestations:[{info, signing_address,
                               intel_quote, ...}]}. The SERVING enclaves are model_attestations[*];
                               gateway_attestation is the relay's own enclave (also recorded).
      C) `chutes` nested     : {attestation_type:"chutes", all_attestations:[{instance_id,
                               intel_quote, gpu_evidence, e2e_pubkey, nonce}]}. These nodes carry
                               NO app_id / compose_hash / signing_address — they CANNOT be pinned
                               by the gateway's app_id/compose_hash allowlist. Recorded as
                               unenforceable so the README/operator sees it explicitly.
    """
    atype = report.get("attestation_type")

    # B) near-ai nested
    if "model_attestations" in report or "gateway_attestation" in report:
        out: list[dict] = []
        ma = report.get("model_attestations")
        if isinstance(ma, list):
            out += [_enclave_from(n, model, "near-ai/model") for n in ma if isinstance(n, dict)]
        ga = report.get("gateway_attestation")
        if isinstance(ga, dict):
            e = _enclave_from(ga, model, "near-ai/gateway")
            e["role"] = "gateway-relay"  # not the model-serving enclave; record but flag
            out.append(e)
        return "near-ai", out

    # C) chutes nested (no app_id/compose_hash anywhere)
    if atype == "chutes" or (
        "all_attestations" in report and "info" not in report and "signing_address" not in report
    ):
        out = []
        aa = report.get("all_attestations")
        if isinstance(aa, list):
            for n in aa:
                if isinstance(n, dict):
                    e = _enclave_from(n, model, "chutes")
                    e["enforceable"] = False  # no app_id/compose_hash to pin
                    out.append(e)
        return ("chutes" if atype == "chutes" else "unknown-nested"), out

    # A) phala flat (+ optional all_attestations siblings)
    out = []
    aa = report.get("all_attestations")
    if isinstance(aa, list) and aa:
        out += [_enclave_from(n, model, "phala/all_attestations") for n in aa if isinstance(n, dict)]
    # the flat top level is itself an enclave node; include it (de-duped later by app_id|compose)
    out.append(_enclave_from(report, model, "phala/flat"))
    return "phala", out


def fetch_report(base_url: str, key: str, model: str, timeout: float):
    """GET /v1/attestation/report?model=<slug>. Returns (schema, enclaves, headers, error).

    On any error returns (None, None, None, "<reason>") — the caller treats it as a missed
    sample, never fatal (a flaky LB endpoint must not abort the whole collection run).
    `strict=False` on the JSON parse: the event_log field can contain raw control chars."""
    qs = urllib.parse.urlencode({"model": model})
    url = f"{base_url.rstrip('/')}/attestation/report?{qs}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            report = json.loads(raw, strict=False)
    except urllib.error.HTTPError as exc:
        return None, None, None, f"http_{exc.code}"
    except (ValueError, json.JSONDecodeError):
        return None, None, None, "bad_json"
    except Exception as exc:  # noqa: BLE001 - URLError, socket.timeout, OSError, ssl errors:
        # a flaky/slow LB endpoint is a missed sample, never fatal to the whole run.
        return None, None, None, f"net_{type(exc).__name__}"
    if not isinstance(report, dict):
        return None, None, None, "not_object"
    # capture only the non-secret routing hint header (provider) — never auth/trace tokens we sent
    provider = hdrs.get("x-redpill-provider")
    schema, enclaves = extract_enclaves(model, report)
    return schema, enclaves, {"x-redpill-provider": provider}, None


def collect(models: list[str], rounds: int, sleep: float, timeout: float, key: str) -> dict:
    started = _dt.datetime.now(_dt.timezone.utc).isoformat()
    # per-model aggregation
    agg: dict[str, dict] = {
        m: {
            "samples": 0,                          # successful report fetches for this slug
            "errors": {},
            "schemas_seen": {},                    # phala | near-ai | chutes -> count
            "providers_seen": {},                  # x-redpill-provider header -> count
            "enclaves": {},                        # (app_id|compose_hash|instance_id) -> detail
        }
        for m in models
    }

    total_samples = 0
    for r in range(rounds):
        for m in models:
            schema, enclaves, hdrs, err = fetch_report(REDPILL_BASE, key, m, timeout)
            mstat = agg[m]
            if err is not None:
                mstat["errors"][err] = mstat["errors"].get(err, 0) + 1
                print(f"  round {r+1}/{rounds} {m}: MISS ({err})", file=sys.stderr)
                continue

            mstat["samples"] += 1
            total_samples += 1
            prov = (hdrs or {}).get("x-redpill-provider") or "(none)"
            mstat["providers_seen"][prov] = mstat["providers_seen"].get(prov, 0) + 1
            mstat["schemas_seen"][schema] = mstat["schemas_seen"].get(schema, 0) + 1

            ids = []
            for parsed in enclaves:
                # An enclave's stable IDENTITY is (app_id, compose_hash) — these are the fields
                # the gateway allowlist pins. instance_id rotates per quote (it is NOT an
                # identity), so dedup on it ONLY for the chutes schema, which exposes no
                # app_id/compose_hash and would otherwise collapse all 5 distinct GPUs into one.
                if parsed.get("app_id") or parsed.get("compose_hash"):
                    sig = f"{parsed.get('app_id')}|{parsed.get('compose_hash')}"
                else:
                    sig = f"|inst:{parsed.get('instance_id')}"
                enc = mstat["enclaves"].setdefault(sig, {
                    "app_id": parsed.get("app_id"),
                    "compose_hash": parsed.get("compose_hash"),
                    "instance_id": parsed.get("instance_id"),
                    "schema": parsed.get("schema"),
                    "role": parsed.get("role", "model-serving"),
                    "enforceable": parsed.get("enforceable", bool(parsed.get("app_id") or parsed.get("compose_hash"))),
                    "signing_addresses": {},
                    "app_names": set(),
                    "providers": set(),
                    "no_log_observed": set(),
                    "quote_present": parsed.get("quote_present"),
                    "count": 0,
                })
                enc["count"] += 1
                if parsed.get("signing_address"):
                    enc["signing_addresses"][parsed["signing_address"]] = \
                        enc["signing_addresses"].get(parsed["signing_address"], 0) + 1
                if parsed.get("app_name"):
                    enc["app_names"].add(parsed["app_name"])
                enc["providers"].add(prov)
                enc["no_log_observed"].add(parsed.get("no_log"))
                ids.append(parsed.get("app_id") or f"(no-app_id:{parsed.get('schema')})")

            print(
                f"  round {r+1}/{rounds} {m}: provider={prov} schema={schema} "
                f"enclaves={len(enclaves)} app_ids={ids}",
                file=sys.stderr,
            )
        if r < rounds - 1 and sleep > 0:
            time.sleep(sleep)

    finished = _dt.datetime.now(_dt.timezone.utc).isoformat()

    # ---- build the committable observation + PROPOSED allowlist ----
    def _nl(v) -> str:
        return "true" if v is True else "false" if v is False else "unknown"

    per_model = {}
    all_app_ids: set[str] = set()          # AGGREGATE allowlist (across every slug)
    all_compose_hashes: set[str] = set()
    any_no_log_asserted = False            # did ANY enclave ever assert no_log truthy?
    unenforceable_routes: list[dict] = []  # slugs/schemas with no pinnable identity
    for m, st in agg.items():
        enclaves = []
        model_app_ids: set[str] = set()
        for sig, enc in st["enclaves"].items():
            no_logs = {_nl(v) for v in enc["no_log_observed"]}
            if "true" in no_logs:
                any_no_log_asserted = True
            # Only MODEL-SERVING enclaves with a pinnable identity feed the allowlist
            # (skip the near-ai gateway-relay enclave + the chutes no-id nodes).
            if enc["role"] == "model-serving" and enc["enforceable"]:
                if enc["app_id"]:
                    all_app_ids.add(enc["app_id"])
                    model_app_ids.add(enc["app_id"])
                if enc["compose_hash"]:
                    all_compose_hashes.add(enc["compose_hash"])
            enclaves.append({
                "app_id": enc["app_id"],
                "compose_hash": enc["compose_hash"],
                "instance_id": enc["instance_id"] if not enc["app_id"] else None,
                "schema": enc["schema"],
                "role": enc["role"],
                "enforceable": bool(enc["enforceable"]),
                "app_names": sorted(enc["app_names"]),
                "signing_addresses": enc["signing_addresses"],
                "providers": sorted(enc["providers"]),
                "no_log_observed": sorted(no_logs),
                "quote_present": enc["quote_present"],
                "times_seen": enc["count"],
            })
        enclaves.sort(key=lambda e: -e["times_seen"])
        # A slug is unenforceable if NONE of its model-serving enclaves carry an app_id/compose_hash.
        if st["samples"] and not model_app_ids:
            unenforceable_routes.append({
                "model": m,
                "schemas_seen": st["schemas_seen"],
                "reason": "no app_id / compose_hash in any served attestation (e.g. chutes schema)",
            })
        per_model[m] = {
            "samples": st["samples"],
            "errors": st["errors"],
            "schemas_seen": st["schemas_seen"],
            "providers_seen": st["providers_seen"],
            "distinct_enclaves": len(enclaves),
            "enforceable_app_ids": sorted(model_app_ids),
            "enclaves": enclaves,
        }

    return {
        "_comment": (
            "OBSERVED serving-enclave identities for the keep-warm phala/ slugs, collected live "
            "from RedPill GET /v1/attestation/report. PROPOSED allowlist below; set the two GATEWAY_ "
            "envs on the CVM to flip the receipt OBSERVE -> ENFORCE. See README.md. "
            "NEVER contains the RedPill key."
        ),
        "schema_version": 2,
        "collected": {
            "started_utc": started,
            "finished_utc": finished,
            "rounds": rounds,
            "sleep_seconds": sleep,
            "endpoint": "GET https://api.redpill.ai/v1/attestation/report?model=<slug>",
            "total_successful_samples": total_samples,
            "key_source": "op://$OP_VAULT/redpill.ai/api_key (resolved at runtime, never stored)",
        },
        "models": per_model,
        "no_log_summary": {
            "any_enclave_asserted_no_log": any_no_log_asserted,
            "note": (
                "MEASURED: RedPill's /v1/attestation/report does NOT expose a `no_log` field in "
                "ANY of the three schemas (phala flat / near-ai nested / chutes nested). The "
                "gateway ENFORCE gate fails a turn CLOSED unless no_log is explicitly true, so "
                "enabling enforcement TODAY would reject every turn. Enforcement is therefore "
                "BLOCKED on either (a) RedPill asserting no_log in the report, or (b) relaxing the "
                "no_log gate to a non-blocking observation (a policy decision — do NOT silently "
                "drop a confidentiality claim). See README.md 'Blockers'."
            ),
        },
        "unenforceable_routes": unenforceable_routes,
        "proposed_allowlist": {
            "GATEWAY_INFERENCE_ALLOWED_APP_IDS": ",".join(sorted(all_app_ids)),
            "GATEWAY_INFERENCE_ALLOWED_COMPOSE_HASHES": ",".join(sorted(all_compose_hashes)),
            "note": (
                "AGGREGATE across all keep-warm slugs (RedPill load-balances, so one slug can hit "
                "several enclaves / providers). Setting EITHER env on the CVM flips the gateway to "
                "ENFORCE (gateway/app/config.py:receipt_enforce). PARTIAL: only the phala + near-ai "
                "routes expose app_id/compose_hash; the chutes route (deepseek-v3.2) does not and "
                "cannot be pinned this way (see unenforceable_routes). Review against the on-chain "
                "DstackApp registry + docs/security/measurements.md BEFORE enforcing. Re-run this "
                "collector periodically; RedPill may rotate enclaves."
            ),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=8, help="report polls per model (default 8)")
    ap.add_argument("--sleep", type=float, default=3.0, help="seconds between rounds (default 3)")
    ap.add_argument("--timeout", type=float, default=20.0, help="per-request timeout seconds (default 20)")
    ap.add_argument("--models", default="", help="comma-separated slugs (default: the 3 keep-warm models)")
    ap.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "observed-app-ids.json"),
        help="output JSON path",
    )
    args = ap.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()] or DEFAULT_MODELS
    print(f"Collecting {args.rounds} rounds x {len(models)} models from {REDPILL_BASE} ...", file=sys.stderr)

    key = resolve_key()
    result = collect(models, args.rounds, args.sleep, args.timeout, key)

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")

    n = result["collected"]["total_successful_samples"]
    print(f"\nWrote {args.out}", file=sys.stderr)
    print(f"  successful samples: {n}", file=sys.stderr)
    print(f"  proposed APP_IDS:        {result['proposed_allowlist']['GATEWAY_INFERENCE_ALLOWED_APP_IDS'] or '(none)'}", file=sys.stderr)
    print(f"  proposed COMPOSE_HASHES: {result['proposed_allowlist']['GATEWAY_INFERENCE_ALLOWED_COMPOSE_HASHES'] or '(none)'}", file=sys.stderr)
    print(f"  any enclave asserted no_log: {result['no_log_summary']['any_enclave_asserted_no_log']}", file=sys.stderr)
    if result["unenforceable_routes"]:
        ur = ", ".join(r["model"] for r in result["unenforceable_routes"])
        print(f"  UNENFORCEABLE routes (no app_id): {ur}", file=sys.stderr)

    if n == 0:
        print("ERROR: zero successful samples across all rounds — not flipping to enforce on empty data.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
