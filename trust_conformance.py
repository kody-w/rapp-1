#!/usr/bin/env python3
"""Check RAPP Trust registration, the refusal vectors, and one real ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import unittest
from pathlib import Path

import rapp_trust as T
from anchor import update_anchor as U
from test_rapp_trust import RappTrustTests

ROOT = Path(__file__).resolve().parent


def check_registration() -> None:
    index = json.loads((ROOT / "protocols/index.json").read_text())
    profiles = [p for p in index["profiles"] if p["name"] == T.PROFILE]
    if len(profiles) != 1:
        raise ValueError("rapp-trust/1 must occur exactly once in the profile index")
    expected = {
        "name": T.PROFILE, "human_name": "RAPP Trust", "parent": "rapp/1",
        "spec_path": T.SPEC_PATH, "schema_path": "protocols/rapp-trust/1/schema.json",
        "conformance": "trust_conformance.py",
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
    parser.add_argument("ledger", nargs="?", type=Path, default=ROOT / "protocols/examples/trust-lifecycle.json")
    parser.add_argument("--now", default=None)
    args = parser.parse_args()
    try:
        check_registration()
        led = T.load(args.ledger, args.now)
    except (OSError, ValueError) as error:
        parser.exit(1, f"trust conformance refused: {error}\n")
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RappTrustTests))
    if not result.wasSuccessful():
        return 1
    print(f"{len(led.frames)} frames ok; score {led.score} ({led.autonomy}); "
          f"{len(led.open)} open, {len(led.settled)} settled; {result.testsRun} trust checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
