from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_PLACEHOLDERS = {"change-me", "changeme", "password"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATEWAY_", env_file=".env", extra="ignore")

    # Upstream Letta. Default is empty (set GATEWAY_LETTA_PASSWORD at runtime); a known
    # placeholder value is rejected so a misconfig fails loud instead of starting insecure.
    letta_base_url: str = "http://letta:8283"
    letta_password: str = ""
    agent_id: str = ""

    # v1 chat backend: direct attested inference (OpenAI-compatible, e.g. RedPill). When
    # `inference_base` is set, /v1/chat opens the sealed prompt in-CVM and calls this provider
    # directly (simpler than a full Letta deploy; agent-memory via Letta is a later upgrade).
    # The key is repr-excluded so it never lands in a log/traceback.
    inference_base: str = ""
    inference_key: str = Field(default="", repr=False)
    inference_model: str = "phala/qwen-2.5-7b-instruct"
    # Trust posture for per-request model switching.
    #   TRUE  (Caladon product default): honour a per-request CLOUD model too (any real slug in the
    #          provider catalog) — the gateway opens the sealed prompt in-CVM, then forwards it to
    #          that third-party model IN THE CLEAR. The app surfaces ALL models but LABELS the
    #          non-attested (non-`phala/`) ones as non-confidential so the choice is explicit
    #          (product decision 2026-06-05). The DEFAULT model + any unrequested turn stay attested.
    #   FALSE (strict trust-no-one; set GATEWAY_ALLOW_CLOUD_MODELS=false): only attested (`phala/`)
    #          models are honoured; a non-attested slug falls back to the attested default, so a
    #          prompt is NEVER routed to a non-confidential backend.
    # Note: this is a code default (not in the compose), so flipping the product default does NOT
    # change the CVM compose_hash / attestation pin. A self-hoster overrides it via env.
    allow_cloud_models: bool = True
    # Upstream completion timeout (s). Generous by default: attested models on Phala scale to
    # zero, so the FIRST request after idle pays a cold-start (~3-4 min for the 35B H200 enclave);
    # a short timeout would hard-fail that turn. Warm turns are far faster.
    inference_timeout: float = 300.0
    # Keep-warm: comma-separated attested model slugs the gateway pings on a timer so they stay
    # hot (no cold-start delay when a user picks them). Empty -> just `inference_model`. The
    # per-request `model` (in /v1/chat) lets the app switch models instantly + mid-session;
    # these are the ones we guarantee are always ready.
    keepwarm_models: str = ""
    keepwarm_interval: float = 120.0  # seconds between keep-warm pings (0 disables the pinger)

    def keepwarm_set(self) -> list[str]:
        models = [m.strip() for m in self.keepwarm_models.split(",") if m.strip()]
        if not models and self.inference_model:
            models = [self.inference_model]
        return models

    # Per-response inference receipt (RedPill GET /v1/attestation/report). When enabled, /v1/chat
    # fetches the serving enclave's attestation for each turn and emits it as the SSE `receipt`.
    # 2-PHASE ROLLOUT (spike-notes.md (d) — the RedPill provider VARIES, e.g. phala AND near-ai):
    #   OBSERVE (default): surface the receipt fields (provider/model/app_id/compose_hash/no_log/
    #     signing_address/quote_present) WITHOUT enforcing an allowlist — so we can collect the
    #     real app_ids/compose_hashes a `phala/` slug actually routes to before pinning them.
    #   ENFORCE (auto-derived when an allowlist is set): fail the turn CLOSED if the serving
    #     enclave's app_id/compose_hash is not in the allowlist OR `no_log` is not explicitly true.
    receipt_enabled: bool = True
    # Comma-separated allowlists of permitted serving-enclave identities. Setting EITHER one flips
    # the receipt into ENFORCE mode. Empty (both) -> OBSERVE mode.
    inference_allowed_app_ids: str = ""
    inference_allowed_compose_hashes: str = ""
    receipt_timeout: float = 15.0  # report-endpoint fetch timeout (s); fail-soft in observe mode

    def allowed_app_ids(self) -> set[str]:
        return {x.strip() for x in self.inference_allowed_app_ids.split(",") if x.strip()}

    def allowed_compose_hashes(self) -> set[str]:
        return {x.strip() for x in self.inference_allowed_compose_hashes.split(",") if x.strip()}

    def receipt_enforce(self) -> bool:
        """ENFORCE mode iff the receipt is enabled AND at least one allowlist is configured.
        Otherwise OBSERVE (surface honestly, never block)."""
        return self.receipt_enabled and bool(self.allowed_app_ids() or self.allowed_compose_hashes())

    # In-CVM tool loop (MCP / skills / subagents). When a /v1/chat turn asks for tools, the gateway
    # opens the prompt in-CVM and runs an OpenAI-style tool loop, EXECUTING each tool inside the CVM
    # (app/mcp_broker.py) — the model never executes anything. Tool turns are routed to a
    # function-calling-capable attested model (`tool_model`), since not every attested model supports
    # native tool_calls (verified: deepseek-v3.2 + gpt-oss-120b do; qwen3.6-uncensored does not).
    mcp_enabled: bool = True
    tool_model: str = "phala/deepseek-v3.2"
    tool_max_steps: int = 6
    # Egress allowlist for in-CVM tools (comma-separated hosts). FAIL-CLOSED: empty -> no external
    # network from any tool (only no-network tools like the calculator work). A per-request
    # `tools_yolo` flag (the app's "yolo mode" toggle) lets the user bypass THIS allowlist for a turn
    # — but the SSRF guard (loopback/private/link-local/metadata) stays on even in yolo, so a tool can
    # never reach the CVM's own internals. Operators add trusted hosts via GATEWAY_MCP_ALLOWED_HOSTS.
    mcp_allowed_hosts: str = ""

    def mcp_allowed_hosts_set(self) -> set[str]:
        return {h.strip().lower() for h in self.mcp_allowed_hosts.split(",") if h.strip()}

    @field_validator("letta_password")
    @classmethod
    def _reject_placeholder_password(cls, v: str) -> str:
        if v in _INSECURE_PLACEHOLDERS:
            raise ValueError("GATEWAY_LETTA_PASSWORD must not be a placeholder value")
        return v

    # Client auth: comma-separated device tokens (M1b legacy; messages/chat until cutover)
    device_tokens: str = ""

    # Multi-tenant seed-signature auth (contracts/gateway-api.md)
    accounts_store: str = "accounts.json"  # file-backed account registry path
    transcript_store: str = "transcripts.json"  # per-tenant ciphertext transcript store path

    # Deployment trust tier (docs/deployment-tiers.md): "cvm" (T1 attested) | "plain" (T0).
    # Literal so a typo / unset-with-wrong-value fails loud instead of silently serving the
    # wrong (plain) attestation mode in a hosted deployment.
    run_mode: Literal["cvm", "plain"] = "plain"

    # dstack guest-agent quote endpoint (T1). Empty -> attestation fails closed (503).
    # In a Phala Cloud dstack CVM the guest agent (dstack 0.5.x) is a UNIX-domain socket, not
    # a TCP host: POST http://dstack/GetQuote over /var/run/dstack.sock with
    # {"report_data": <hex>}. The URL host is cosmetic for a UDS. Set in the CVM compose.
    dstack_quote_url: str = ""
    # The guest-agent UDS path. When set, the quote/Info fetch uses an httpx UDS transport.
    # Set GATEWAY_DSTACK_SOCKET="" to force plain TCP (e.g. against the dev TEE simulator).
    dstack_socket: str = "/var/run/dstack.sock"

    # Server
    host: str = "127.0.0.1"
    port: int = 8088

    def token_set(self) -> set[str]:
        return {t.strip() for t in self.device_tokens.split(",") if t.strip()}


def get_settings() -> Settings:
    return Settings()
