#!/usr/bin/env python3
"""Prove the Grail suite has teeth: break a copy of the kernel on purpose and
count how many breaks the 25 scenarios catch.

Each mutant is one exact text replacement in brainstem.py. A mutant the suite
catches shows a behavior the suite pins. A mutant that survives shows a
behavior the suite does NOT pin; survivors are listed, never hidden.

    GRAIL_DIR=/path/to/pinned/rapp_brainstem python3 conformance/grail/mutants.py
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORT = HERE / "mutants-report.json"

# (id, what the break means in plain words, old text, new text, expect_caught)
MUTANTS = [
    ("trim", "stop trimming spaces around the question",
     '    user_input = user_input.strip()\n', '    user_input = user_input\n', True),
    ("agent-logs", "drop the agent log from the answer",
     '"agent_logs": "\\n".join(all_logs),', '"agent_logs": "",', True),
    ("blank-status", "answer a blank question with 422 instead of 400",
     'return jsonify({"error": "user_input is required"}), 400',
     'return jsonify({"error": "user_input is required"}), 422', True),
    ("history-unchecked", "accept a malformed conversation history",
     '    if history_error:\n        return jsonify({"error": history_error}), 400',
     '    if False:\n        return jsonify({"error": history_error}), 400', True),
    ("tool-rounds", "allow two tool rounds instead of three",
     '        for _ in range(3):', '        for _ in range(2):', True),
    ("fallback-text", "reword the out-of-steps fallback sentence",
     "I couldn't finish that within the available tool steps. ",
     "I could not finish that within the available tool steps. ", True),
    ("session-id", "ignore the caller's session id",
     '    session_id = data.get("session_id") or str(uuid.uuid4())',
     '    session_id = str(uuid.uuid4())', True),
    ("version-key", "rename the version field",
     '    return jsonify({"version": VERSION})', '    return jsonify({"v": VERSION})', True),
    ("health-status", "report health as 'fine' instead of 'ok'",
     '        return jsonify({\n            "status": "ok",\n            "version": VERSION,\n            "model":  MODEL,\n            "voice_mode": VOICE_MODE,',
     '        return jsonify({\n            "status": "fine",\n            "version": VERSION,\n            "model":  MODEL,\n            "voice_mode": VOICE_MODE,', True),
    ("type-error-text", "reword the 'must be a string' error",
     '"user_input must be a string"', '"user_input has to be a string"', True),
    ("requested-model", "drop requested_model from the answer",
     '            "requested_model": MODEL,\n        }\n', '        }\n', True),
    ("history-roles", "forget assistant turns from the history",
     'messages += [m for m in history if m.get("role") in ("user", "assistant", "tool")]',
     'messages += [m for m in history if m.get("role") in ("user",)]', True),
    ("voice-flag", "flip the voice_mode flag in the answer",
     '            "voice_mode": VOICE_MODE,\n            # The model that actually answered.',
     '            "voice_mode": not VOICE_MODE,\n            # The model that actually answered.', True),
    # Expected survivors: behavior the 25 scenarios do not reach.
    ("model-502-text", "reword the model-failure error (needs a failing model)",
     'try again shortly or switch models.', 'try again soon or switch models.', False),
    ("health-dir", "blank brainstem_dir in /health (only status and agents are compared)",
     '            "brainstem_dir": os.path.dirname(os.path.abspath(__file__)),',
     '            "brainstem_dir": "",', False),
    ("soul-ignored", "stop sending soul.md to the model (fake model ignores it)",
     '        soul   = load_soul()\n        agents = load_agents()\n        # Build tools per-agent',
     '        soul   = ""\n        agents = load_agents()\n        # Build tools per-agent', False),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--grail", default=os.environ.get("GRAIL_DIR"))
    parser.add_argument("--python", default=os.environ.get("GRAIL_PYTHON", sys.executable))
    parser.add_argument("--only", help="comma-separated mutant ids")
    args = parser.parse_args()
    if not args.grail:
        sys.exit("set GRAIL_DIR or pass --grail")
    grail = Path(args.grail).expanduser().resolve()
    if not (grail / "brainstem.py").is_file():
        grail = grail / "rapp_brainstem"
    source = (grail / "brainstem.py").read_text(encoding="utf-8")
    wanted = set(args.only.split(",")) if args.only else None
    work = Path(tempfile.mkdtemp(prefix="grail-mutants-"))
    rows = []
    try:
        for mid, meaning, old, new, expect in MUTANTS:
            if wanted and mid not in wanted:
                continue
            count = source.count(old)
            if count == 0:
                rows.append({"id": mid, "meaning": meaning, "applied": False,
                             "caught": None, "expect_caught": expect,
                             "note": "anchor text not found; kernel changed?"})
                print(f"  SKIP   {mid}: anchor not found")
                continue
            target = work / mid
            shutil.copytree(grail, target,
                            ignore=shutil.ignore_patterns("__pycache__", ".venv", ".git"))
            (target / "brainstem.py").write_text(source.replace(old, new, 1), encoding="utf-8")
            env = dict(os.environ, GRAIL_DIR=str(grail), GRAIL_PYTHON=args.python)
            proc = subprocess.run(
                [sys.executable, str(HERE / "run.py"), "--candidate", f"grail:{target}"],
                env=env, capture_output=True, text=True)
            try:
                report = json.loads((HERE / "report.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                report = {}
            differs = [r["scenario"] for r in report.get("scenarios", []) if not r["same"]]
            caught = bool(report.get("unallowed_differences")) or proc.returncode == 2
            rows.append({"id": mid, "meaning": meaning, "applied": True,
                         "anchor_occurrences": count, "caught": caught,
                         "expect_caught": expect, "differing_scenarios": differs,
                         "exit": proc.returncode,
                         "error": report.get("error")})
            tag = "CAUGHT" if caught else "SURVIVED"
            flag = "" if caught == expect else "   <-- unexpected"
            print(f"  {tag:8} {mid}: {meaning}{flag}")
            if differs:
                print(f"           differs in: {', '.join(differs)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    applied = [r for r in rows if r["applied"]]
    caught = [r for r in applied if r["caught"]]
    survivors = [r for r in applied if not r["caught"]]
    unexpected = [r for r in applied if r["caught"] != r["expect_caught"]]
    summary = {"grail": str(grail), "attempted": len(applied), "caught": len(caught),
               "survived": len(survivors), "unexpected": [r["id"] for r in unexpected],
               "mutants": rows}
    REPORT.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"\n{len(caught)} of {len(applied)} mutants caught; survivors: "
          f"{', '.join(r['id'] for r in survivors) or 'none'}")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
