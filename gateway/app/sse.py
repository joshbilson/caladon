import json

ASSISTANT_TYPE = "assistant_message"
REASONING_TYPE = "reasoning_message"


def format_sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(', ', ': '))}\n\n"


def map_letta_event(evt: dict) -> tuple[str, dict] | None:
    mtype = evt.get("message_type")
    if mtype == ASSISTANT_TYPE:
        content = evt.get("content") or ""
        if isinstance(content, list):
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        return ("token", {"text": content})
    if mtype == REASONING_TYPE:
        reasoning = evt.get("reasoning") or evt.get("content") or ""
        if isinstance(reasoning, list):  # some Letta versions nest reasoning in content parts
            reasoning = "".join(p.get("text", "") for p in reasoning if isinstance(p, dict))
        return ("reasoning", {"text": reasoning})
    return None
