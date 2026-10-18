#!/usr/bin/env python3
"""Record what the pinned oracle answers for every scenario, so an implementer can
see the exact expected answer instead of learning it from the first DIFF.

Runs the suite with the pinned Grail against itself and writes expected.json:
the contract view the comparison uses, per scenario. --check fails if stale.

    GRAIL_DIR=/path/to/pinned/rapp_brainstem python3 conformance/grail/make_expected.py [--check]
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "expected.json"


def main(argv):
    grail = os.environ.get("GRAIL_DIR")
    if not grail:
        sys.exit("set GRAIL_DIR to the pinned rapp_brainstem directory")
    run = subprocess.run([sys.executable, str(HERE / "run.py"), "--candidate", f"grail:{grail}"],
                         capture_output=True, text=True)
    if run.returncode != 0:
        print(run.stdout[-2000:], run.stderr[-2000:], file=sys.stderr)
        return run.returncode
    report = json.loads((HERE / "report.json").read_text(encoding="utf-8"))
    expected = {
        "kernel": report["oracle"]["kernel"],
        "note": "The pinned oracle's answer per scenario, in the exact view run.py compares.",
        "scenarios": {row["scenario"]: row["oracle"] for row in report["scenarios"]},
    }
    text = json.dumps(expected, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if "--check" in argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print("expected.json is stale; run make_expected.py", file=sys.stderr)
            return 1
        print(f"expected.json current: {len(expected['scenarios'])} scenarios")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote expected.json: {len(expected['scenarios'])} scenarios")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
