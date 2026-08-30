#!/usr/bin/env python3
"""Append one anchor revision from the committed SPEC.md."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rapp as R


ANCHOR = pathlib.Path(__file__).resolve().parent
CHAIN = ANCHOR / "chain.jsonl"
ORIENT = ANCHOR / "orient.json"
REVISION = "rev-10"


def utc_now() -> str:
    value = datetime.now(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{value.microsecond // 1000:03d}Z"
    )


def main() -> None:
    if subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", "SPEC.md", "rapp.py"],
        cwd=ROOT,
    ).returncode != 0:
        raise SystemExit("commit SPEC.md and rapp.py before generating the anchor")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()
    commit_utc = subprocess.check_output(
        ["git", "show", "-s", "--format=%cI", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()
    spec_octets = (ROOT / "SPEC.md").read_bytes()
    observed_utc = utc_now()
    frames = [
        json.loads(line)
        for line in CHAIN.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    head = frames[-1]
    payload = json.loads(json.dumps(head["payload"]))
    payload["revision"] = REVISION
    payload["normative_sha256"] = hashlib.sha256(spec_octets).hexdigest()
    payload["normative_bytes"] = str(len(spec_octets))
    payload["commit"] = commit
    payload["commit_utc"] = commit_utc
    payload["observed_utc"] = observed_utc
    payload["vocabulary"]["sealed"] = {
        "status": "live",
        "where": "§9.2 sealed egg variant and §9.2.1 profile",
    }
    rule = {
        "t": "gotcha",
        "c": (
            "A sealed egg is public ciphertext, not password-protected hosting: "
            "the signed manifest binds AES-256-GCM data and a scoped key service; "
            "no shared DEK belongs in the egg, URL, client, log, or frame."
        ),
    }
    if rule not in payload["rules"]:
        payload["rules"].append(rule)
    frame = R.build_frame(
        "body.pulse",
        head["stream_id"],
        head["seq"] + 1,
        observed_utc,
        payload,
        head["payload_hash"],
    )
    with CHAIN.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(frame, ensure_ascii=False) + "\n")

    orient = json.loads(ORIENT.read_text(encoding="utf-8"))
    orient["generated_utc"] = observed_utc
    orient["head"] = {
        "seq": frame["seq"],
        "frame_hash": frame["frame_hash"],
        "payload_hash": frame["payload_hash"],
    }
    orient["spec"] = {
        "revision": REVISION,
        "normative_path": "SPEC.md",
        "normative_sha256": payload["normative_sha256"],
        "canonical_repo": payload["canonical_repo"],
        "commit": commit,
    }
    orient["vocabulary"] = payload["vocabulary"]
    ORIENT.write_text(
        json.dumps(orient, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
    )
    print(frame["frame_hash"])


if __name__ == "__main__":
    main()
