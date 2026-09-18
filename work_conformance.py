#!/usr/bin/env python3
"""Controlled positive and adversarial vectors for rapp-work/1."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

import rapp_work as W
from anchor import update_anchor as U
from test_rapp_work import RappWorkTests

ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


print("=" * 72)
print("RAPP Work - controlled conformance vectors")
print("=" * 72)

schema_path = ROOT / "protocols" / "rapp-work" / "1" / "schema.json"
spec_path = ROOT / W.SPEC_PATH
schema = json.loads(schema_path.read_text(encoding="utf-8"))
require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "wrong work schema draft")
require(len(schema.get("oneOf", [])) == len(W.KIND_SCHEMAS), "work schema does not expose seven payloads")

index = json.loads((ROOT / "protocols" / "index.json").read_text(encoding="utf-8"))
profiles = {profile["name"]: profile for profile in index.get("profiles", [])}
require(W.PROFILE in profiles, "rapp-work/1 is absent from the protocol index")
profile = profiles[W.PROFILE]
require(profile["parent"] == "rapp/1", "rapp-work/1 has the wrong parent")
require(profile["spec_path"] == W.SPEC_PATH, "rapp-work/1 has the wrong specification path")
require(profile["spec_sha256"] == sha256(spec_path), "rapp-work/1 specification hash drift")
require(profile["schema_path"] == "protocols/rapp-work/1/schema.json", "rapp-work/1 has the wrong schema path")
require(profile["schema_sha256"] == sha256(schema_path), "rapp-work/1 schema hash drift")
require(profile["conformance"] == "work_conformance.py", "rapp-work/1 has the wrong conformance entrypoint")
require(
    {profile["spec_path"], profile["schema_path"]} <= set(U.INPUT_PATHS),
    "rapp-work/1 is not protected by the specification-chain committed-input gate",
)

suite = unittest.defaultTestLoader.loadTestsFromTestCase(RappWorkTests)
result = unittest.TextTestRunner(verbosity=2).run(suite)
print("-" * 72)
print(
    f"{result.testsRun} work checks | "
    f"{result.testsRun - len(result.failures) - len(result.errors)} PASS | "
    f"{len(result.failures) + len(result.errors)} FAIL"
)
raise SystemExit(0 if result.wasSuccessful() else 1)
