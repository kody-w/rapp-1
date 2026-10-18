#!/usr/bin/env python3
"""Measure how much of the pinned Grail the 25 scenarios actually exercise.

Runs the suite (Grail against itself) with the Grail under branch coverage and
prints, per route, how many statements ran. Routes with only their `def` line
executed were never called: that is the unspecified surface, listed plainly.

Needs the `coverage` package in the Grail interpreter.

    GRAIL_DIR=/path/to/pinned/rapp_brainstem python3 conformance/grail/coverage_run.py
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORT = HERE / "coverage-report.json"

WRAPPER = """import runpy, signal, sys, coverage
cov = coverage.Coverage(config_file={rc!r})
cov.start()
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
sys.argv = sys.argv[1:]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
finally:
    cov.stop(); cov.save()
"""


def main() -> int:
    grail = Path(os.environ.get("GRAIL_DIR", "")).expanduser().resolve()
    if not (grail / "brainstem.py").is_file():
        grail = grail / "rapp_brainstem"
    if not (grail / "brainstem.py").is_file():
        sys.exit("set GRAIL_DIR to the pinned rapp_brainstem directory")
    python = os.environ.get("GRAIL_PYTHON", sys.executable)
    if subprocess.run([python, "-c", "import coverage"], capture_output=True).returncode:
        sys.exit(f"{python} lacks the coverage package (pip install coverage)")

    work = Path(tempfile.mkdtemp(prefix="grail-coverage-"))
    try:
        rc = work / ".coveragerc"
        rc.write_text(
            "[run]\nbranch = True\nparallel = True\n"
            f"data_file = {work / '.coverage'}\ninclude = */brainstem.py\n"
            f"[paths]\nsource =\n    {grail}\n    */grail-conformance-*/oracle\n"
            "    */grail-conformance-*/candidate\n",
            encoding="utf-8",
        )
        (work / "covrun.py").write_text(WRAPPER.format(rc=str(rc)), encoding="utf-8")
        wrapper = work / "covpy.sh"
        wrapper.write_text(f"#!/bin/sh\nexec {python} {work / 'covrun.py'} \"$@\"\n")
        wrapper.chmod(0o755)
        env = dict(os.environ, GRAIL_DIR=str(grail), GRAIL_PYTHON=str(wrapper))
        run = subprocess.run(
            [sys.executable, str(HERE / "run.py"), "--candidate", f"grail:{grail}"],
            env=env, capture_output=True, text=True,
        )
        last = (run.stdout.strip().splitlines() or ["(no output)"])[-1]
        print(f"suite: {last}")
        if run.returncode:
            print(run.stdout[-2000:], run.stderr[-2000:], file=sys.stderr)
            return run.returncode
        cov_env = dict(os.environ, COVERAGE_RCFILE=str(rc))
        subprocess.run([python, "-m", "coverage", "combine", "-q"], env=cov_env, check=True)
        out = work / "coverage.json"
        subprocess.run([python, "-m", "coverage", "json", "-q", "-o", str(out)],
                       env=cov_env, check=True)
        data = json.loads(out.read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    files = data["files"]
    entry = files[next(k for k in files if k.endswith("brainstem.py"))]
    summary = entry["summary"]
    executed = set(entry["executed_lines"])
    missing = set(entry["missing_lines"])
    source = (grail / "brainstem.py").read_text(encoding="utf-8")
    routes = []
    for node in ast.parse(source).body:
        if not isinstance(node, ast.FunctionDef):
            continue
        decorators = [ast.unparse(d) for d in node.decorator_list]
        route = next((d for d in decorators if d.startswith("app.route")), None)
        if not route:
            continue
        lines = set(range(node.lineno, node.end_lineno + 1))
        ran = len(lines & executed)
        total = ran + len(lines & missing)
        routes.append({"route": route[len("app.route("):-1], "function": node.name,
                       "executed": ran, "statements": total, "called": ran > 1})
    called = [r for r in routes if r["called"]]
    untouched = [r for r in routes if not r["called"]]
    print(f"brainstem.py: {summary['covered_lines']} of {summary['num_statements']} statements, "
          f"{summary['covered_branches']} of {summary['num_branches']} branches")
    print(f"routes: {len(called)} of {len(routes)} called by the suite")
    for r in called:
        print(f"  called    {r['route']:48} {r['executed']}/{r['statements']}")
    for r in untouched:
        print(f"  untouched {r['route']}")
    REPORT.write_text(json.dumps({
        "grail": str(grail), "summary": summary, "routes": routes}, indent=2) + "\n",
        encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
