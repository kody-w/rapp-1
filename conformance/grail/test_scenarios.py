#!/usr/bin/env python3
"""Structural checks for the shared Grail scenario and pin files."""

import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from scenarios import SCENARIOS  # noqa: E402


class ScenarioTests(unittest.TestCase):
    def test_scenario_counts_and_names(self):
        self.assertEqual(len(SCENARIOS), 25)
        self.assertEqual(sum(not scenario.needs_model for scenario in SCENARIOS), 14)
        self.assertEqual(len({scenario.name for scenario in SCENARIOS}), 25)
        self.assertEqual(
            {scenario.name for scenario in SCENARIOS if not scenario.needs_model},
            {
                "health agents",
                "missing input",
                "blank input",
                "input not a string",
                "body not an object",
                "body not json",
                "history not a list",
                "history item not an object",
                "history bad role",
                "history bad content",
                "input type checked first",
                "history checked before blank",
                "version",
                "not found",
            },
        )

    def test_kernel_pin_shape(self):
        pin = json.loads((HERE / "kernel.json").read_text(encoding="utf-8"))
        self.assertEqual(
            pin,
            {
                "kernel": "kody-w/rapp-installer",
                "sha": "0e43ee580e78c150b1c59002456822d2e779388e",
                "version": "0.6.16",
                "path": "rapp_brainstem/brainstem.py",
                "kernel_blob": "3f7102ff508c813bb6494511fc32a421a633e418",
                "pinned": "2026-10-07",
            },
        )


if __name__ == "__main__":
    unittest.main()
