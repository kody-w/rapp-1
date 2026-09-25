#!/usr/bin/env python3
"""Controlled positive and adversarial vectors for the §13 registry.

Runs every registry test module against the reference (`rapp_registry.py`) with the
detached-JWS boundary mocked, then checks the language-neutral registry vectors against
the same reference. Stdlib only. Exit 0 = every check passes.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "conformance"))
import make_vectors as MV  # noqa: E402

# Each §13 change appends its test module here.
MODULES = [
    "test_registry_lifecycle",
    "test_registry_container",
    "test_stream_signer",
]

print("=" * 72)
print("RAPP/1 §13 registry - controlled conformance vectors")
print("=" * 72)

committed = json.loads((ROOT / "conformance" / "registry-vectors.json").read_text(encoding="utf-8"))
derived = MV.registry_vectors()
vectors_ok = committed == derived
print(f"  [{'PASS' if vectors_ok else 'FAIL'}] registry-vectors.json reproduces from rapp_registry.py")

suite = unittest.TestSuite(
    unittest.defaultTestLoader.loadTestsFromName(name) for name in MODULES
)
result = unittest.TextTestRunner(verbosity=2).run(suite)
failed = len(result.failures) + len(result.errors) + (0 if vectors_ok else 1)
checks = result.testsRun + 1
print("-" * 72)
print(f"{checks} registry checks | {checks - failed} PASS | {failed} FAIL"
      + (f" | {len(result.skipped)} skipped (optional cryptography absent)" if result.skipped else ""))
raise SystemExit(0 if failed == 0 else 1)
