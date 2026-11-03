#!/usr/bin/env python3
"""Check RAPP Layer registration, controlled vectors, and one real shape chain."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import unittest
from pathlib import Path

import rapp_layer as L
from anchor import update_anchor as U
from test_rapp_layer import RappLayerTests

ROOT = Path(__file__).resolve().parent


def check_registration() -> None:
    index = json.loads((ROOT / "protocols/index.json").read_text())
    profiles = [p for p in index["profiles"] if p["name"] == L.PROFILE]
    if len(profiles) != 1:
        raise ValueError("rapp-layer/1 must occur exactly once in the profile index")
    expected = {
        "name": L.PROFILE, "human_name": "RAPP Layer", "parent": "rapp/1",
        "spec_path": L.SPEC_PATH, "schema_path": "protocols/rapp-layer/1/schema.json",
        "conformance": "layer_conformance.py",
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
                        default=ROOT / "protocols/examples/layer-lifecycle.json")
    args = parser.parse_args()
    try:
        check_registration()
        chain = L.load_chain(args.chain)
    except (OSError, ValueError) as error:
        parser.exit(1, f"layer conformance refused: {error}\n")
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RappLayerTests))
    if not result.wasSuccessful():
        return 1
    if any(f["kind"] == "shape.tile"
           and f["payload"]["lens"]["sha256"] == L.RECORDED_LENS_SHA256
           for f in chain.frames):
        print("Lens note: historical source pin retained; reference transition replay "
              "does not prove possession of the historical source bytes.", file=sys.stderr)
    print(f"{len(chain.frames)} frames ok; every tile reproduces its object; "
          f"{result.testsRun} layer checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
