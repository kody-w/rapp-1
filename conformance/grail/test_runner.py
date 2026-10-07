#!/usr/bin/env python3
"""Focused tests for the generic in-process adapter."""

import sys
import tempfile
import types
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run as runner  # noqa: E402
from scenarios import SCENARIOS  # noqa: E402


class RunnerTests(unittest.TestCase):
    def test_module_factory_receives_context_and_returns_callable(self):
        module = types.ModuleType("grail_test_adapter")
        seen = {}

        def create_candidate(context):
            seen["context"] = context
            return lambda method, path, body: (
                400,
                '{"error": "expected test refusal"}',
            )

        module.create_candidate = create_candidate
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)

        with tempfile.TemporaryDirectory() as work:
            context = runner.ModuleContext(
                fake_model_url="http://127.0.0.1:1/v1",
                fake_token_url="http://127.0.0.1:1/token",
                model="test-model",
                agents_dir=HERE / "agents",
                work_dir=Path(work),
            )
            call = runner.load_module_candidate(
                f"{module.__name__}:create_candidate",
                context,
            )
            code, body = call(SCENARIOS[12])

        self.assertIs(seen["context"], context)
        self.assertEqual(code, 400)
        self.assertEqual(body, {"error": "expected test refusal"})


if __name__ == "__main__":
    unittest.main()
