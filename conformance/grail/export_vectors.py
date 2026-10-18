#!/usr/bin/env python3
"""Write the 25 scenarios as language-neutral JSON so any implementer, in any
language, can read the lesson without Python.

    python3 conformance/grail/export_vectors.py          # writes vectors.json
    python3 conformance/grail/export_vectors.py --check  # fails if stale
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from scenarios import MODEL, SCENARIOS, SESSION_ID  # noqa: E402

OUT = HERE / "vectors.json"

# Plain-words lesson order: what a learner meets first.
LESSON = {
    "health agents": "1. A Brainstem answers GET /health with status and its agent names.",
    "version": "2. GET /version names the kernel version.",
    "not found": "3. An unknown path is a 404.",
    "echo": "4. POST /chat with user_input and session_id answers in the field `response`.",
    "trims input": "5. Spaces around the question are trimmed before the model sees it.",
    "history counts": "6. conversation_history turns are sent to the model in order.",
    "missing input": "7. No user_input is a 400 with an error sentence.",
    "blank input": "8. A blank user_input is the same 400.",
    "input not a string": "9. user_input must be a string.",
    "body not an object": "10. The body must be a JSON object.",
    "body not json": "11. A body that is not JSON is a clean JSON 400, never HTML.",
    "history not a list": "12. conversation_history must be a list.",
    "history item not an object": "13. Every history turn is an object.",
    "history bad role": "14. A history role is user or assistant.",
    "history bad content": "15. History content is a string.",
    "input type checked first": "16. Checks run in a fixed order: input type before history.",
    "history checked before blank": "17. History shape is checked before blank input.",
    "word stats agent": "18. A compiled agent in agents/ is a tool the model can call.",
    "python agent": "19. A *_agent.py file in agents/ is a tool the model can call.",
    "multiple tool calls": "20. Several tool calls in one turn all run and all log.",
    "agent raises": "21. An agent that crashes becomes a tool error, not a 500.",
    "unknown agent": "22. A tool call to a missing agent becomes a tool error.",
    "bad tool args": "23. Malformed tool arguments become a tool error.",
    "tool rounds run out": "24. Three tool rounds, then one final no-tools answer.",
    "tool fallback": "25. An empty final answer becomes the fixed fallback sentence.",
}


def build():
    vectors = []
    for scenario in SCENARIOS:
        body = scenario.body
        if isinstance(body, bytes):
            body = {"raw": body.decode("utf-8", "replace")}
        vectors.append({
            "id": scenario.name,
            "lesson": LESSON[scenario.name],
            "method": scenario.method,
            "path": scenario.path,
            "body": body,
            "needs_model": scenario.needs_model,
        })
    vectors.sort(key=lambda v: int(v["lesson"].split(".", 1)[0]))
    return {
        "kernel": json.loads((HERE / "kernel.json").read_text(encoding="utf-8")),
        "model": MODEL,
        "session_id": SESSION_ID,
        "fake_model": "fake_model.py (deterministic; see its source for the replies)",
        "compare": "run.py contract_view(): for 200 answers the keys, response, session_id, agent_logs, voice_mode, model, requested_model; for errors the status and keys and error text",
        "count": len(vectors),
        "vectors": vectors,
    }


def main(argv):
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print("vectors.json is stale; run export_vectors.py", file=sys.stderr)
            return 1
        print(f"vectors.json current: {build()['count']} vectors")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.name}: {build()['count']} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
