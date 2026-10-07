"""The Grail conformance scenarios, defined once for every candidate mode."""

from dataclasses import dataclass
from typing import Any


MODEL = "gpt-4o"
SESSION_ID = "grail-conformance-session"


@dataclass(frozen=True)
class Scenario:
    name: str
    method: str
    path: str
    body: Any
    needs_model: bool


def chat_body(user_input, **extra):
    return {"user_input": user_input, "session_id": SESSION_ID, **extra}


SCENARIOS = (
    Scenario("health agents", "GET", "/health", None, False),
    Scenario("echo", "POST", "/chat", chat_body("hello there"), True),
    Scenario("trims input", "POST", "/chat", chat_body("   padded   "), True),
    Scenario(
        "history counts",
        "POST",
        "/chat",
        chat_body(
            "third",
            conversation_history=[
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "second"},
            ],
        ),
        True,
    ),
    Scenario(
        "word stats agent",
        "POST",
        "/chat",
        chat_body('CALL WordStats {"text": "one two three."}'),
        True,
    ),
    Scenario(
        "python agent",
        "POST",
        "/chat",
        chat_body('CALL Echo {"text": "loud"}'),
        True,
    ),
    Scenario("multiple tool calls", "POST", "/chat", chat_body("MULTI tools"), True),
    Scenario("agent raises", "POST", "/chat", chat_body("CALL Boom {}"), True),
    Scenario("unknown agent", "POST", "/chat", chat_body("CALL Nobody {}"), True),
    Scenario("bad tool args", "POST", "/chat", chat_body("CALL Echo [1,2]"), True),
    Scenario("tool rounds run out", "POST", "/chat", chat_body("LOOP forever"), True),
    Scenario("tool fallback", "POST", "/chat", chat_body("FALLBACK empty"), True),
    Scenario("missing input", "POST", "/chat", {}, False),
    Scenario("blank input", "POST", "/chat", {"user_input": "   "}, False),
    Scenario("input not a string", "POST", "/chat", {"user_input": 5}, False),
    Scenario("body not an object", "POST", "/chat", [1, 2], False),
    Scenario("body not json", "POST", "/chat", b"not json", False),
    Scenario(
        "history not a list",
        "POST",
        "/chat",
        {"user_input": "x", "conversation_history": "nope"},
        False,
    ),
    Scenario(
        "history item not an object",
        "POST",
        "/chat",
        {"user_input": "x", "conversation_history": ["nope"]},
        False,
    ),
    Scenario(
        "history bad role",
        "POST",
        "/chat",
        {
            "user_input": "x",
            "conversation_history": [{"role": "system", "content": "x"}],
        },
        False,
    ),
    Scenario(
        "history bad content",
        "POST",
        "/chat",
        {
            "user_input": "x",
            "conversation_history": [{"role": "user", "content": 5}],
        },
        False,
    ),
    Scenario(
        "input type checked first",
        "POST",
        "/chat",
        {"user_input": 5, "conversation_history": "nope"},
        False,
    ),
    Scenario(
        "history checked before blank",
        "POST",
        "/chat",
        {"user_input": "   ", "conversation_history": "nope"},
        False,
    ),
    Scenario("version", "GET", "/version", None, False),
    Scenario("not found", "GET", "/nope", None, False),
)
