#!/usr/bin/env python3
"""Offline regression tests for the seed verifier; run directly, not via pytest."""

import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SEED_ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "seed_refresh", os.environ.get("SEED_REFRESH_UNDER_TEST", str(SEED_ROOT / "refresh.py"))
)
refresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refresh)


class SeedChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seed-check-")
        self.addCleanup(self.temporary.cleanup)
        self.seed = Path(self.temporary.name) / "seed"
        self.seed.mkdir()
        for root in refresh.ROOTS:
            shutil.copytree(SEED_ROOT / root, self.seed / root)
        shutil.copyfile(SEED_ROOT / "SEED.json", self.seed / "SEED.json")
        self.manifest = json.loads((self.seed / "SEED.json").read_bytes())
        self.target = self.seed / "brainstem/brainstem.py"

    def write_manifest(self):
        (self.seed / "SEED.json").write_text(json.dumps(self.manifest))

    def check(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return refresh.check(self.seed)

    def test_clean_seed_is_offline_and_read_only(self):
        before = {p.relative_to(self.seed): p.read_bytes() for p in self.seed.rglob("*") if p.is_file()}
        with patch.object(refresh.subprocess, "check_output", side_effect=AssertionError("network/git used")):
            self.assertEqual(self.check(), 0)
        self.assertEqual(
            before, {p.relative_to(self.seed): p.read_bytes() for p in self.seed.rglob("*") if p.is_file()}
        )

    def test_changed_bytes_fail(self):
        self.target.write_bytes(self.target.read_bytes().replace(b"import os", b"import re", 1))
        self.assertEqual(self.check(), 1)

    def test_missing_file_fails(self):
        self.target.unlink()
        self.assertEqual(self.check(), 1)

    def test_extra_file_fails(self):
        (self.seed / "brainstem/unlisted.txt").write_text("extra")
        self.assertEqual(self.check(), 1)

    def test_removed_manifest_entry_fails(self):
        self.manifest["files"].pop()
        self.write_manifest()
        self.assertEqual(self.check(), 1)

    def test_removed_required_file_and_manifest_entry_fail(self):
        path = "rar-builder/build_registry.py"
        self.manifest["files"] = [e for e in self.manifest["files"] if e["path"] != path]
        (self.seed / path).unlink()
        self.write_manifest()
        self.assertEqual(self.check(), 1)

    def test_removed_transitive_helper_and_manifest_entry_fail(self):
        path = "rar-builder/scripts/static_api.py"
        self.manifest["files"] = [e for e in self.manifest["files"] if e["path"] != path]
        (self.seed / path).unlink()
        self.write_manifest()
        self.assertEqual(self.check(), 1)

    @unittest.skipUnless(os.name == "posix", "POSIX executable modes")
    def test_lost_executable_mode_fails(self):
        (self.seed / "brainstem/start.sh").chmod(0o644)
        self.assertEqual(self.check(), 1)

    def test_wrong_byte_count_fails(self):
        self.manifest["files"][0]["bytes"] += 1
        self.write_manifest()
        self.assertEqual(self.check(), 1)

    def test_missing_engine_pin_fails(self):
        self.manifest["files"] = [e for e in self.manifest["files"] if e["path"] != "brainstem/brainstem.py"]
        self.target.unlink()
        self.write_manifest()
        self.assertEqual(self.check(), 1)

    def test_manifest_validation_refuses_bad_shapes(self):
        mutations = (
            lambda m: m.update(schema="wrong"),
            lambda m: m.update(files=[]),
            lambda m: m["files"].append(copy.deepcopy(m["files"][0])),
            lambda m: m["files"][0].update(path="../escape"),
            lambda m: m["files"][0].update(path="/absolute"),
            lambda m: m["files"][0].update(source_path="../escape"),
            lambda m: m["files"][0].update(path="brainstem//repeated"),
            lambda m: m["files"][0].update(sha256="not-a-hash"),
            lambda m: m["files"][0].update(bytes=True),
            lambda m: m["sources"]["rar"].update(ref="main"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                manifest = copy.deepcopy(self.manifest)
                mutate(manifest)
                with self.assertRaises(ValueError):
                    refresh.validate_manifest(manifest)

    def test_file_symlink_fails_even_with_identical_bytes(self):
        original = self.target.read_bytes()
        other = self.seed.parent / "outside.py"
        other.write_bytes(original)
        self.target.unlink()
        self.target.symlink_to(other)
        with self.assertRaises(ValueError):
            self.check()

    def test_tree_symlink_fails(self):
        root = self.seed / "brainstem"
        other = self.seed.parent / "outside"
        root.rename(other)
        root.symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.check()

    def test_manifest_symlink_fails(self):
        manifest = self.seed / "SEED.json"
        other = self.seed.parent / "manifest.json"
        manifest.rename(other)
        manifest.symlink_to(other)
        with self.assertRaises(ValueError):
            self.check()

    def test_secret_is_refused_even_if_manifest_matches(self):
        target = self.seed / "brainstem/soul.md"
        body = b"token = '" + b"ghp_" + b"A" * 36 + b"'\n"
        target.write_bytes(body)
        entry = next(e for e in self.manifest["files"] if e["path"] == "brainstem/soul.md")
        entry.update(sha256=refresh.digest(body), bytes=len(body))
        self.write_manifest()
        with patch.object(refresh, "PINNED_INVENTORY_SHA256", refresh.inventory_fingerprint(self.manifest)):
            self.assertEqual(self.check(), 1)

    def test_exclusion_policy(self):
        for name in (".env", ".env.example", "a/.copilot_token", "a/__pycache__/x.pyc", "a/venv/x", "key.pem"):
            self.assertIsNotNone(refresh.exclusion(name, b""))
        self.assertIsNotNone(refresh.exclusion("large.bin", b"x" * (refresh.MAX_BYTES + 1)))
        self.assertIsNone(refresh.exclusion("source.py", b"os.environ.get('API_KEY')"))

    def test_reviewed_fixture_does_not_hide_other_credentials(self):
        body = b'RAW_SECRET_MARKER = "raw-403-internal-detail-should-never-leak"\n'
        path = "brainstem/tests/test_no_copilot_onboarding.py"
        reviewed = []
        self.assertEqual(refresh.secret_findings(path, body, reviewed), [])
        self.assertEqual(len(reviewed), 1)
        self.assertEqual(len(refresh.secret_findings("different.py", body)), 1)
        self.assertEqual(len(refresh.secret_findings(path, body + b"\nghp_" + b"A" * 36)), 1)

    def test_import_closure_follows_transitive_local_helpers(self):
        root = self.seed.parent / "closure"
        (root / "tools").mkdir(parents=True)
        (root / "entry.py").write_text("from tools.helper import run\nimport json\n")
        (root / "tools/helper.py").write_text("from tools import leaf\n")
        (root / "tools/leaf.py").write_text("import sys\n")
        (root / "unused.py").write_text("")
        self.assertEqual(
            refresh.import_closure(root, ("entry.py",)),
            ["entry.py", "tools/helper.py", "tools/leaf.py"],
        )

    def test_refresh_repairs_prunes_and_is_idempotent(self):
        files = {e["path"]: (self.seed / e["path"]).read_bytes() for e in self.manifest["files"]}
        self.target.write_text("changed")
        (self.seed / "brainstem/start.sh").chmod(0o644)
        (self.seed / "brainstem/stale.txt").write_text("stale")
        with patch.object(refresh, "fetch"), patch.object(refresh, "plan", return_value=(files, self.manifest)):
            with contextlib.redirect_stdout(io.StringIO()):
                refresh.refresh(self.seed)
                self.assertEqual(self.check(), 0)
                if os.name == "posix":
                    self.assertTrue((self.seed / "brainstem/start.sh").stat().st_mode & 0o111)
                before = {p.relative_to(self.seed): p.read_bytes() for p in self.seed.rglob("*") if p.is_file()}
                refresh.refresh(self.seed)
            self.assertEqual(
                before, {p.relative_to(self.seed): p.read_bytes() for p in self.seed.rglob("*") if p.is_file()}
            )
        self.assertFalse((self.seed / "brainstem/stale.txt").exists())

    def test_wrong_source_engine_pin_stops_before_writing(self):
        source = self.seed.parent / "source/rapp_brainstem"
        source.mkdir(parents=True)
        (source / "brainstem.py").write_text("wrong engine")
        with self.assertRaisesRegex(ValueError, "hash differs"):
            refresh.plan({"brainstem": source.parent})
        self.assertEqual(self.check(), 0)

    def test_refresh_refuses_symlink_without_writing(self):
        files = {e["path"]: (self.seed / e["path"]).read_bytes() for e in self.manifest["files"]}
        outside = self.seed.parent / "outside.txt"
        outside.write_text("untouched")
        self.target.unlink()
        self.target.symlink_to(outside)
        with patch.object(refresh, "fetch"), patch.object(refresh, "plan", return_value=(files, self.manifest)):
            with self.assertRaisesRegex(ValueError, "unsafe generated path"):
                refresh.refresh(self.seed)
        self.assertEqual(outside.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main(verbosity=1)
