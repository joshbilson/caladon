import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.main import create_app
from app.schemas import Message


@pytest_asyncio.fixture
async def client():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class FakeLetta:
    def __init__(self):
        self.messages = [
            Message(id="1", role="user", content="hi", created_at="t0"),
            Message(id="2", role="assistant", content="hello", created_at="t1"),
        ]
        self.stream_events = []  # set per-test; list of raw Letta event dicts

    async def list_messages(self, limit: int = 50):
        return self.messages[-limit:]

    async def stream_chat(self, text: str):
        for evt in self.stream_events:
            yield evt
