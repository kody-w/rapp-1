import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import rapp as R
import realcheck


RID = "rappid:@test/observer:" + "1" * 64
UTC = "2026-09-06T00:00:00.000Z"


class RealcheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "example"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")

    def git(self, *args):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=" + os.devnull, *args],
            cwd=self.repo, env=env, capture_output=True, check=True,
        )
        return result.stdout.decode().strip()

    def write(self, name, value):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "--allow-empty", "-m", "fixture")
        return self.git("rev-parse", "HEAD")

    def frame(self, seq=0, prev=None):
        return R.build_frame("body.pulse", RID, seq, UTC, {"value": seq}, prev=prev)

    def observe(self):
        return realcheck.observe(self.root, ["example"], sync=False)

    def test_good_committed_chain_has_exact_commit_and_nonzero_coverage(self):
        first = self.frame()
        self.write("frames/0.json", first)
        self.write("frames/1.json", self.frame(1, first["payload_hash"]))
        self.write("rappid.json", {"schema": "rapp/1", "rappid": RID})
        commit = self.commit()
        result = self.observe()
        self.assertEqual(result["status"], "CONFORMANT_IN_SCOPE")
        self.assertEqual(result["repositories"][0]["commit"], commit)
        self.assertEqual(result["frames"]["conformant"], 2)
        self.assertFalse(result["working_tree_files_read"])
        self.assertEqual(result["protocol"]["revision"], realcheck.revision()["revision"])

    def test_dirty_or_untracked_files_cannot_repair_a_bad_committed_frame(self):
        frame = self.frame()
        frame["payload_hash"] = "f" * 64
        self.write("frames/0.json", frame)
        self.commit()
        self.write("frames/0.json", self.frame())
        self.write("frames/1.json", self.frame(1, self.frame()["payload_hash"]))
        result = self.observe()
        self.assertEqual(result["status"], "DRIFT")
        self.assertEqual(result["frames"]["total"], 1)
        self.assertTrue(result["drift"])

    def test_dirty_damage_does_not_poison_good_committed_data(self):
        self.write("frames/0.json", self.frame())
        self.commit()
        (self.repo / "frames" / "0.json").write_text("not json")
        self.assertEqual(self.observe()["status"], "CONFORMANT_IN_SCOPE")

    def test_cli_fails_on_drift_and_writes_explicit_report(self):
        frame = self.frame()
        frame["frame_hash"] = "0" * 64
        self.write("frames/0.json", frame)
        self.commit()
        output = self.root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = realcheck.main([
                "--estate-root", str(self.root), "--repo", "example",
                "--no-sync", "--json", "--output", str(output),
            ])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.read_text())["status"], "DRIFT")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(realcheck.main([
                "--estate-root", str(self.root), "--repo", "example",
                "--no-sync", "--output", str(output),
            ]), 2)

    def test_zero_artifacts_and_missing_repos_are_not_green(self):
        self.commit()
        self.assertEqual(self.observe()["status"], "INCOMPLETE")
        result = realcheck.observe(self.root, ["absent"], sync=False)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertTrue(result["observation_errors"])

    def test_truncated_json_duplicate_keys_and_nonobject_are_incomplete(self):
        path = self.repo / "frames" / "0.json"
        path.parent.mkdir()
        for content in ('{"spec":', '{"spec":"rapp/1","spec":"rapp/1"}', '[]'):
            with self.subTest(content=content):
                path.write_text(content)
                self.commit()
                result = self.observe()
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertEqual(result["frames"]["total"], 1)

    def test_nested_chains_are_observed_and_scopes_are_separate(self):
        self.write("lineage/one/frames/0.json", self.frame())
        self.write("lineage/two/frames/0.json", self.frame())
        self.commit()
        result = self.observe()
        self.assertEqual(result["status"], "CONFORMANT_IN_SCOPE")
        self.assertEqual(len(result["chain_scopes"]), 2)
        self.assertEqual(result["frames"]["total"], 2)

    def test_missing_genesis_or_duplicate_numbered_file_is_drift(self):
        first = self.frame()
        self.write("frames/0.json", first)
        self.write("frames/00.json", first)
        self.commit()
        self.assertEqual(self.observe()["status"], "DRIFT")
        (self.repo / "frames" / "00.json").unlink()
        (self.repo / "frames" / "0.json").unlink()
        self.write("frames/1.json", self.frame(1, first["payload_hash"]))
        self.commit()
        self.assertEqual(self.observe()["status"], "DRIFT")

    def test_identity_grammar_does_not_accept_name_hash_mint(self):
        tail = hashlib.sha256(b"test/observer").hexdigest()
        self.write("rappid.json", {"schema": "rapp/1", "rappid": "rappid:@test/observer:" + tail})
        self.commit()
        self.assertEqual(self.observe()["status"], "DRIFT")

    def test_legacy_bytes_remain_unchanged_and_are_not_current_conformance(self):
        value = {"spec": "rapp-frame/2.0", "seq": 0, "payload": {"legacy": True}}
        self.write("frames/0.json", value)
        commit = self.commit()
        before = (self.repo / "frames" / "0.json").read_bytes()
        result = self.observe()
        self.assertEqual(result["status"], "DRIFT")
        self.assertEqual(result["drift"][0]["category"], "legacy-envelope")
        self.assertEqual((self.repo / "frames" / "0.json").read_bytes(), before)
        self.assertEqual(self.git("rev-parse", "HEAD"), commit)

    def test_artifact_symlinks_are_not_followed(self):
        (self.repo / "rappid.json").symlink_to(self.root / "outside.json")
        self.commit()
        result = self.observe()
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("regular Git blob", result["observation_errors"][0]["error"])

    def test_oversize_blob_and_bad_object_binding_refuse(self):
        self.write("frames/0.json", self.frame())
        self.commit()
        with mock.patch.object(realcheck, "MAX_ARTIFACT_BYTES", 8):
            self.assertEqual(self.observe()["status"], "INCOMPLETE")
        with mock.patch.object(realcheck, "git", side_effect=[b"2\n", b"{}"]):
            with self.assertRaisesRegex(realcheck.ObservationError, "object identifier"):
                realcheck.read_artifact(self.repo, "0" * 40)

    def test_no_sync_never_fetches_and_import_has_no_side_effect(self):
        self.write("frames/0.json", self.frame())
        self.commit()
        with mock.patch.object(realcheck, "git", wraps=realcheck.git) as calls:
            self.observe()
            self.assertFalse(any(row.args[0] in ("clone", "fetch", "pull") for row in calls.call_args_list))
        result = subprocess.run(
            [sys.executable, "-c",
             "import subprocess; subprocess.run=lambda *a,**k: (_ for _ in ()).throw("
             "AssertionError('import executed git')); import realcheck"],
            cwd=realcheck.ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsafe_duplicate_and_empty_scope_refuse(self):
        for repos in ([], ["../outside"], ["example", "example"]):
            with self.subTest(repos=repos):
                with self.assertRaises(realcheck.ObservationError):
                    realcheck.observe(self.root, repos, sync=False)

    def test_nested_directory_cannot_impersonate_a_repository(self):
        self.write("frames/0.json", self.frame())
        self.commit()
        (self.repo / "impostor").mkdir()
        result = realcheck.observe(self.repo, ["impostor"], sync=False)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("root of the selected repository", result["observation_errors"][0]["error"])

    def test_replacement_ref_cannot_change_the_reported_commit_contents(self):
        bad = self.frame()
        bad["frame_hash"] = "0" * 64
        self.write("frames/0.json", bad)
        original = self.commit()
        self.write("frames/0.json", self.frame())
        replacement = self.commit()
        self.git("replace", original, replacement)
        self.git("update-ref", "HEAD", original)
        result = self.observe()
        self.assertEqual(result["repositories"][0]["commit"], original)
        self.assertEqual(result["status"], "DRIFT")

    def test_promisor_cache_cannot_lazy_fetch_during_offline_observation(self):
        self.write("frames/0.json", self.frame())
        self.commit()
        self.git("config", "remote.origin.promisor", "true")
        with mock.patch.object(realcheck, "git", wraps=realcheck.git) as calls:
            result = self.observe()
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("promisor", result["observation_errors"][0]["error"])
        self.assertFalse(any(row.args[0] in ("clone", "fetch", "pull", "cat-file") for row in calls.call_args_list))
        self.git("config", "remote.origin.promisor", "false")
        self.assertEqual(self.observe()["status"], "CONFORMANT_IN_SCOPE")


if __name__ == "__main__":
    unittest.main()
