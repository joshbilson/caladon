import json
from collections.abc import AsyncIterator

import httpx

from app.schemas import Message

# Letta wire-format constants (verified live against the running server, M1b G1)
ASSISTANT_TYPE = "assistant_message"
USER_TYPE = "user_message"
DONE_SENTINEL = "[DONE]"


class LettaClient:
    def __init__(self, base_url: str, password: str, agent_id: str):
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {password}"}
        self._agent_id = agent_id

    async def list_messages(self, limit: int = 50) -> list[Message]:
        url = f"{self._base}/v1/agents/{self._agent_id}/messages"
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(url, headers=self._headers, params={"limit": limit})
            resp.raise_for_status()
            raw = resp.json()
        out: list[Message] = []
        for m in raw:
            mtype = m.get("message_type") or m.get("role")
            if mtype == ASSISTANT_TYPE or mtype == "assistant":
                role = "assistant"
            elif mtype == USER_TYPE or mtype == "user":
                role = "user"
            else:
                continue  # skip reasoning/tool/system in the client history view
            content = m.get("content") or ""
            if isinstance(content, list):  # some Letta versions use content parts
                content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
            out.append(Message(id=str(m.get("id", "")), role=role, content=content,
                               created_at=m.get("created_at") or m.get("date")))
        return out

    async def stream_chat(self, text: str) -> AsyncIterator[dict]:
        url = f"{self._base}/v1/agents/{self._agent_id}/messages/stream"
        payload = {"messages": [{"role": "user", "content": text}], "stream_tokens": True}
        async with httpx.AsyncClient(timeout=None) as c:
            async with c.stream("POST", url, headers=self._headers, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if data == DONE_SENTINEL:
                        break
                    try:
                        yield json.loads(data)
                    except json.JSONDecodeError:
                        continue
