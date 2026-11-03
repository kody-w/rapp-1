#!/usr/bin/env python3
"""Verify RAPP Succession registration, real signatures, and refusal vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import unittest
from pathlib import Path

import rapp_succession as S
from anchor import update_anchor as U
from test_rapp_succession import RappSuccessionTests

ROOT = Path(__file__).resolve().parent


def check_registration() -> None:
    index = json.loads((ROOT / "protocols/index.json").read_text())
    profiles = [p for p in index["profiles"] if p["name"] == S.PROFILE]
    if len(profiles) != 1:
        raise ValueError("rapp-succession/1 must occur exactly once in the profile index")
    expected = {
        "name": S.PROFILE, "human_name": "RAPP Succession", "parent": "rapp/1",
        "spec_path": S.SPEC_PATH, "schema_path": "protocols/rapp-succession/1/schema.json",
        "conformance": "succession_conformance.py",
    }
    for key, value in expected.items():
        if profiles[0].get(key) != value:
            raise ValueError(f"profile index mismatch: {key}")
    for name in ("spec", "schema"):
        path = profiles[0][f"{name}_path"]
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != profiles[0][f"{name}_sha256"]:
            raise ValueError(f"profile {name} hash drift")
        if path not in U.INPUT_PATHS:
            raise ValueError(f"profile {name} missing from committed-input gate")
    schema = json.loads((ROOT / expected["schema_path"]).read_text())
    if (schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
            or len(schema.get("oneOf", [])) != 3):
        raise ValueError("profile schema must expose three draft 2020-12 payloads")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("chain", nargs="?", type=Path,
                        default=ROOT / "protocols/examples/succession-lifecycle.json")
    args = parser.parse_args()
    try:
        check_registration()
        frames = S.load_chain(args.chain)
        S.validate_chain(frames)
    except (OSError, ValueError) as error:
        parser.exit(1, f"succession conformance refused: {error}\n")
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RappSuccessionTests))
    if not result.wasSuccessful():
        return 1
    signed = sum(f["kind"] in S.KINDS for f in frames)
    print(f"{len(frames)} frames ok; {signed} succession signatures verified; "
          f"{result.testsRun} succession checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
