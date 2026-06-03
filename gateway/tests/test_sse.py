from app.sse import format_sse, map_letta_event


def test_format_sse():
    assert format_sse("token", {"text": "hi"}) == 'event: token\ndata: {"text": "hi"}\n\n'


def test_map_assistant_to_token():
    assert map_letta_event({"message_type": "assistant_message", "content": "yo"}) == ("token", {"text": "yo"})


def test_map_reasoning():
    assert map_letta_event({"message_type": "reasoning_message", "reasoning": "hmm"}) == ("reasoning", {"text": "hmm"})


def test_map_unknown_returns_none():
    assert map_letta_event({"message_type": "usage_statistics"}) is None
