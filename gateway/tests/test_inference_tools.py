"""Unit tests for the in-CVM tool loop (inference_backend.complete_with_tools).

These exercise the loop with httpx.MockTransport standing in for the RedPill provider — no network.
The loop is the foundation for MCP / skills / subagents: the model emits native structured
`tool_calls`, the gateway executes each tool IN-CVM via the injected `execute_tool`, feeds results
back, and repeats until a final content message. `execute_tool` is the egress trust boundary.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app import inference_backend


def _msg_with_tool_call(call_id: str, name: str, args: dict) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    }


def _msg_final(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}


@pytest.mark.asyncio
async def test_tool_loop_executes_and_returns_final():
    calls = {"n": 0}
    posted_bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        posted_bodies.append(body)
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=_msg_with_tool_call("c1", "calculator", {"expression": "23*17"}))
        return httpx.Response(200, json=_msg_final("The answer is 391."))

    async def execute_tool(name: str, args: dict) -> str:
        assert name == "calculator"
        assert args == {"expression": "23*17"}
        return "391"

    text, steps = await inference_backend.complete_with_tools(
        base_url="http://provider",
        api_key="k",
        model="phala/deepseek-v3.2",
        messages=[{"role": "user", "content": "What is 23*17? use calculator"}],
        tools=[{"type": "function", "function": {"name": "calculator", "parameters": {}}}],
        execute_tool=execute_tool,
        transport=httpx.MockTransport(handler),
    )

    assert text == "The answer is 391."
    assert steps == [{"tool": "calculator", "args": {"expression": "23*17"}, "result": "391"}]
    # Second request must carry the tool result back to the model as a role:tool message.
    assert calls["n"] == 2
    tool_msgs = [m for m in posted_bodies[1]["messages"] if m.get("role") == "tool"]
    assert tool_msgs and tool_msgs[0]["content"] == "391" and tool_msgs[0]["tool_call_id"] == "c1"


@pytest.mark.asyncio
async def test_tool_error_is_fed_back_not_fatal():
    """An execute_tool exception (e.g. egress-allowlist refusal) is reported to the model, not raised."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=_msg_with_tool_call("c1", "web_fetch", {"url": "http://evil"}))
        return httpx.Response(200, json=_msg_final("done"))

    async def execute_tool(name: str, args: dict) -> str:
        raise PermissionError("host not in egress allowlist")

    text, steps = await inference_backend.complete_with_tools(
        base_url="http://provider",
        api_key="k",
        model="phala/deepseek-v3.2",
        messages=[{"role": "user", "content": "fetch evil"}],
        tools=[{"type": "function", "function": {"name": "web_fetch", "parameters": {}}}],
        execute_tool=execute_tool,
        transport=httpx.MockTransport(handler),
    )
    assert text == "done"
    assert "tool error" in steps[0]["result"] and "allowlist" in steps[0]["result"]


@pytest.mark.asyncio
async def test_tool_loop_step_cap_raises():
    """A model that never stops calling tools hits max_steps and fails closed (no echo)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_msg_with_tool_call("c1", "loop", {}))

    async def execute_tool(name: str, args: dict) -> str:
        return "again"

    with pytest.raises(inference_backend.ToolLoopError):
        await inference_backend.complete_with_tools(
            base_url="http://provider",
            api_key="k",
            model="phala/deepseek-v3.2",
            messages=[{"role": "user", "content": "loop forever"}],
            tools=[{"type": "function", "function": {"name": "loop", "parameters": {}}}],
            execute_tool=execute_tool,
            max_steps=3,
            transport=httpx.MockTransport(handler),
        )


@pytest.mark.asyncio
async def test_empty_final_content_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_msg_final(""))

    async def execute_tool(name: str, args: dict) -> str:
        return ""

    with pytest.raises(inference_backend.ToolLoopError):
        await inference_backend.complete_with_tools(
            base_url="http://provider",
            api_key="k",
            model="phala/deepseek-v3.2",
            messages=[{"role": "user", "content": "hi"}],
            tools=[],
            execute_tool=execute_tool,
            transport=httpx.MockTransport(handler),
        )
