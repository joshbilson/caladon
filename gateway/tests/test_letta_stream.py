import httpx
import pytest

from app.letta_client import LettaClient


class _FakeStream:
    def __init__(self, lines): self._lines = lines
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    def raise_for_status(self): return None
    async def aiter_lines(self):
        for ln in self._lines:
            yield ln


@pytest.fixture
def patched_stream(monkeypatch):
    lines = [
        'data: {"message_type": "reasoning_message", "reasoning": "think"}',
        'data: {"message_type": "assistant_message", "content": "Hello"}',
        'data: {"message_type": "assistant_message", "content": " world"}',
        'data: [DONE]',
    ]

    def fake_stream(self, method, url, **kw):
        return _FakeStream(lines)

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)


async def test_stream_chat_yields_parsed_events(patched_stream):
    client = LettaClient("http://letta:8283", "pw", "agent-x")
    got = [evt async for evt in client.stream_chat("hi")]
    assert {"message_type": "assistant_message", "content": "Hello"} in got
    assert {"message_type": "assistant_message", "content": " world"} in got
    # [DONE] sentinel must NOT be yielded as an event
    assert all(isinstance(e, dict) for e in got)
