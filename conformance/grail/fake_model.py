"""Deterministic Copilot stand-in shared by every in-process Grail comparison."""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PORT = int(sys.argv[1])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, value, code=200):
        body = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/token"):
            return self.send_json(
                {
                    "token": "fake-copilot",
                    "expires_at": int(time.time()) + 3600,
                    "endpoints": {"api": f"http://127.0.0.1:{PORT}"},
                }
            )
        if self.path.startswith("/models"):
            return self.send_json(
                {
                    "data": [
                        {
                            "id": model,
                            "name": model,
                            "capabilities": {
                                "type": "chat",
                                "supports": {"tool_calls": True},
                            },
                            "model_picker_enabled": True,
                        }
                        for model in ("gpt-4.1", "gpt-4o")
                    ]
                }
            )
        return self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        last = messages[-1] if messages else {}
        first_user = next(
            (
                message.get("content") or ""
                for message in messages
                if message.get("role") == "user"
            ),
            "",
        )
        if first_user.startswith(("LOOP ", "FALLBACK ")) and body.get("tools"):
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_{len(messages)}",
                        "type": "function",
                        "function": {
                            "name": "Echo",
                            "arguments": '{"text": "again"}',
                        },
                    }
                ],
            }
        elif first_user.startswith("FALLBACK "):
            message = {"role": "assistant", "content": ""}
        elif last.get("role") == "tool":
            message = {
                "role": "assistant",
                "content": "RESULT: " + str(last.get("content")),
            }
        else:
            text = next(
                (
                    candidate.get("content") or ""
                    for candidate in reversed(messages)
                    if candidate.get("role") == "user"
                ),
                "",
            )
            if text.startswith("MULTI ") and body.get("tools"):
                message = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_echo",
                            "type": "function",
                            "function": {
                                "name": "Echo",
                                "arguments": '{"text": "first"}',
                            },
                        },
                        {
                            "id": "call_stats",
                            "type": "function",
                            "function": {
                                "name": "WordStats",
                                "arguments": '{"text": "one two"}',
                            },
                        },
                    ],
                }
            elif text.startswith("CALL ") and body.get("tools"):
                _, name, arguments = (text.split(" ", 2) + ["{}"])[:3]
                message = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": arguments,
                            },
                        }
                    ],
                }
            else:
                prior = sum(
                    1
                    for candidate in messages[:-1]
                    if candidate.get("role") in ("user", "assistant")
                )
                message = {
                    "role": "assistant",
                    "content": f"ECHO({prior}): {text}",
                }
        self.send_json(
            {
                "model": body.get("model", "gpt-4.1"),
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": (
                            "tool_calls" if message.get("tool_calls") else "stop"
                        ),
                    }
                ],
            }
        )


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
