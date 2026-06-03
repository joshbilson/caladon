"""Structural validation of the deployment compose files (docs/deployment-tiers.md).

These are static checks (no docker) that the T1 CVM compose keeps plaintext in-CVM and the
T0 plain compose is configured for self-host. A real deploy + attestation test needs Phala
(spend) and runs as a separate integration step.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")  # added to the CI leak-tests job via --with pyyaml

ROOT = Path(__file__).resolve().parents[2]
CVM = ROOT / "infra" / "cvm" / "docker-compose.yml"
T0 = ROOT / "infra" / "compose" / "t0-plain.yml"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _ports(service: dict) -> list[str]:
    return [str(p) for p in service.get("ports", [])]


def test_both_compose_files_parse():
    for path in (CVM, T0):
        doc = _load(path)
        assert "services" in doc


def test_cvm_has_all_in_cvm_services():
    services = _load(CVM)["services"]
    assert {"postgres", "embeddings", "letta", "gateway"} <= set(services)


def test_cvm_gateway_runs_in_cvm_mode():
    gw = _load(CVM)["services"]["gateway"]
    assert gw["environment"]["GATEWAY_RUN_MODE"] == "cvm"


def test_cvm_only_gateway_exposes_a_port():
    """In the CVM, ONLY the gateway is reachable (TLS-in-CVM). Looping over every service
    (not a hardcoded list) so a future data service added with a host port is caught."""
    for name, svc in _load(CVM)["services"].items():
        if name == "gateway":
            assert _ports(svc) != [], "gateway must expose its port"
        else:
            assert _ports(svc) == [], f"{name} must NOT expose a host port in the CVM"


def test_cvm_all_services_disable_content_logging():
    """Fail-closed no-logging for EVERY service in the CVM (plaintext-exposure map row 5).
    Looped so a new service without `logging: driver none` is caught."""
    for name, svc in _load(CVM)["services"].items():
        assert svc.get("logging", {}).get("driver") == "none", (
            f"{name}: missing 'logging: driver: none' in the CVM compose"
        )


def test_cvm_embeddings_run_in_cvm_not_a_host():
    """Letta points at the in-CVM embeddings service, not a host/external Ollama."""
    letta = _load(CVM)["services"]["letta"]
    assert letta["environment"]["OLLAMA_BASE_URL"] == "http://embeddings:11434"


def test_t0_gateway_runs_in_plain_mode():
    gw = _load(T0)["services"]["gateway"]
    assert gw["environment"]["GATEWAY_RUN_MODE"] == "plain"


def test_no_compose_binds_a_service_to_all_interfaces():
    """Nothing should bind 0.0.0.0 (would expose a data service publicly). The CVM gateway
    is the one documented exception: it binds all-interfaces INSIDE the CVM, where
    dstack-gateway is the external boundary (deployment-tiers.md)."""
    for path in (CVM, T0):
        for name, svc in _load(path)["services"].items():
            if path == CVM and name == "gateway":
                continue  # intentional: in-CVM only; dstack provides external TLS
            for port in _ports(svc):
                assert not port.startswith("0.0.0.0:"), f"{path.name}:{name} binds 0.0.0.0"
