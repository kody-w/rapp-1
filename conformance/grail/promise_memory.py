#!/usr/bin/env python3
"""The promise every lesson makes: tell it something, and tomorrow it still remembers.

Runs the pinned Grail, unchanged, with its own two memory agents and a scripted stand-in model:
1. asks what it remembers (nothing yet),
2. asks it to remember a favorite coffee (the model calls ManageMemory),
3. stops the program, as when the Terminal window closes,
4. starts it again and asks with an empty conversation.
Passes only if the memory was absent before and reaches the model after the restart.

    GRAIL_DIR=/path/to/pinned/rapp_brainstem python3 conformance/grail/promise_memory.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from run import (free_port, load_pin, prepare_grail, stop_process, verify_oracle,  # noqa: E402
                 wait_for_url)


def chat(port, text):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/chat",
        json.dumps({"user_input": text, "conversation_history": []}).encode(),
        {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(request, timeout=30)).get("response")


def main():
    grail_dir = os.environ.get("GRAIL_DIR")
    if not grail_dir:
        sys.exit("set GRAIL_DIR to the pinned rapp_brainstem directory")
    pin = load_pin()
    grail, blob = verify_oracle(grail_dir, pin)
    work = Path(tempfile.mkdtemp(prefix="promise-memory-"))
    kernel = prepare_grail(grail, work / "kernel")
    for name in ("manage_memory_agent.py", "context_memory_agent.py"):
        shutil.copy2(grail / "agents" / name, kernel / "agents" / name)
    home = work / "home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), GITHUB_TOKEN="ghu_fake", GITHUB_MODEL="gpt-4o",
               GRAIL_MODEL="gpt-4o", VOICE_MODE="false", GRAIL_BLOB=blob)
    model_port, port = free_port(), free_port()
    model = subprocess.Popen([sys.executable, str(HERE / "memory_fake_model.py"), str(model_port)])
    log = (work / "log.txt").open("a")

    def start():
        process = subprocess.Popen(
            [sys.executable, str(HERE / "run_grail.py"), str(kernel), str(port), str(model_port)],
            env=env, stdout=log, stderr=subprocess.STDOUT)
        if not wait_for_url(f"http://127.0.0.1:{port}/health"):
            stop_process(process)
            sys.exit("Grail did not start:\n" + (work / "log.txt").read_text()[-3000:])
        return process

    try:
        process = start()
        before = chat(port, "What do you remember about me?")
        saved = chat(port, "Remember that my favorite coffee is a flat white.")
        stop_process(process)
        process = start()
        after = chat(port, "What do you remember about me?")
        stop_process(process)
    finally:
        stop_process(model)
        log.close()
    files = sorted(str(p.relative_to(kernel)) for p in (kernel / ".brainstem_data").rglob("*.json"))
    print("before:", before)
    print("saved: ", saved)
    print("after a restart, empty conversation:", after)
    print("memory files in the Brainstem folder:", files)
    ok = before.endswith("False") and "flat white" in (saved or "") and after.endswith("True") and files
    shutil.rmtree(work, ignore_errors=True)
    print("PROMISE KEPT" if ok else "PROMISE BROKEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
