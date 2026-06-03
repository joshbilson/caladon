from pydantic import BaseModel


class Message(BaseModel):
    id: str
    role: str          # "user" | "assistant"
    content: str
    created_at: str | None = None
    # NOTE: ChatRequest moved to routes/chat.py (now an envelope, not plaintext {text}) as
    # part of the confidential /v1/chat cutover.
