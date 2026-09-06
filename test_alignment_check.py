import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import alignment_check as A


COMMIT = "e" * 40


def feed(commit=COMMIT):
    return (
        '<feed xmlns="http://www.w3.org/2005/Atom">'
        '<id>tag:github.com,2008:/kody-w/rapp-1/commits/main</id>'
        '<entry><id>tag:github.com,2008:Grit::Commit/' + commit + '</id>'
        '<link rel="alternate" href="https://github.com/kody-w/rapp-1/commit/'
        + commit + '"/></entry></feed>'
    ).encode()


class AlignmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "checkout"
        self.root.mkdir()
        for name in ("anchor", "protocols", "guide"):
            shutil.copytree(A.ROOT / name, self.root / name)
        for name in ("SPEC.md", "FOUNDATION.json", "PHILOSOPHY.md", "CONSTITUTION.md", "README.md", "index.html"):
            shutil.copyfile(A.ROOT / name, self.root / name)

    def check(self):
        return A.observe(self.root)

    def refused(self, name):
        result = self.check()
        self.assertEqual(result["status"], "REFUSED")
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn(name, result["checks"][-1]["error"])

    def test_complete_local_views_do_not_claim_live_freshness(self):
        result = self.check()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["freshness"]["state"], "NOT_OBSERVED")
        self.assertFalse(result["ecosystem_compatibility_measured"])
        self.assertFalse(result["ratification_authenticated"])
        self.assertEqual(len(result["checks"]), 3)
        self.assertIn("SPEC.md", result["measured_files"])

    def test_materialized_spec_cannot_drift(self):
        path = self.root / "SPEC.md"
        path.write_bytes(path.read_bytes() + b"\nchanged\n")
        self.refused("SPEC.md")

    def test_beacon_and_immutable_frame_mutations_refuse(self):
        orient = self.root / "anchor" / "orient.json"
        original = orient.read_bytes()
        data = json.loads(original)
        data["spec"]["revision"] = "rev-999"
        orient.write_text(json.dumps(data))
        self.refused("revision")
        orient.write_bytes(original)
        frame = next((self.root / "anchor" / "frames").glob("*.json"))
        frame.write_bytes(b"{}")
        self.assertNotEqual(self.check()["exit_code"], 0)

    def test_missing_label_is_not_a_vacuous_pass(self):
        (self.root / "index.html").write_text("<html>No current revision label.</html>")
        self.refused("label is absent")

    def test_historical_revision_mentions_are_not_current_label_drift(self):
        path = self.root / "README.md"
        with path.open("a") as stream:
            stream.write("\nHistorical rev-13 and rev-14 objects remain preserved.\n")
        self.assertEqual(self.check()["exit_code"], 0)

    def test_stale_current_front_door_refuses(self):
        path = self.root / "README.md"
        revision = json.loads((self.root / "anchor" / "orient.json").read_text())["spec"]["revision"]
        path.write_text(path.read_text().replace("current " + revision + " chain head", "current rev-0 chain head"))
        self.refused("stale current revision")

    def test_local_mirrors_and_foundation_must_match_chain(self):
        path = self.root / "PHILOSOPHY.md"
        original = path.read_bytes()
        path.write_bytes(original + b"x")
        self.refused("PHILOSOPHY.md")
        path.write_bytes(original)
        (self.root / "FOUNDATION.json").write_text("{}")
        self.refused("FOUNDATION.json")

    def test_operational_profile_bytes_are_bound(self):
        path = self.root / "protocols" / "rapp-cicd" / "1" / "schema.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.refused("schema.json")

    def test_unsafe_paths_missing_assets_and_symlinks_refuse(self):
        with self.assertRaises(A.AlignmentError):
            A.local_file(self.root, "../outside")
        path = self.root / "PHILOSOPHY.md"
        path.unlink()
        self.assertNotEqual(self.check()["exit_code"], 0)
        path.symlink_to(A.ROOT / "PHILOSOPHY.md")
        self.assertNotEqual(self.check()["exit_code"], 0)

    def test_live_discovery_is_commit_pinned_and_candidate_is_not_ratified(self):
        beacon = (self.root / "anchor" / "orient.json").read_bytes()
        seen = []

        def fetch(url):
            seen.append(url)
            return feed() if url == A.FEED else beacon

        with mock.patch.object(A.realcheck, "git", side_effect=[COMMIT.encode(), b" M realcheck.py\n"]):
            result = A.observe(self.root, True, fetch)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["freshness"]["state"], "CANDIDATE_ON_CURRENT_MAIN")
        self.assertEqual(seen, [A.FEED, A.RAW + COMMIT + "/anchor/orient.json"])
        self.assertFalse(result["ratification_authenticated"])

    def test_changed_main_is_not_hidden_by_unchanged_revision_label(self):
        beacon = (self.root / "anchor" / "orient.json").read_bytes()
        with mock.patch.object(A.realcheck, "git", side_effect=[b"f" * 40, b""]):
            result = A.observe(self.root, True, lambda url: feed() if url == A.FEED else beacon)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["freshness"]["state"], "STALE_OR_DIVERGENT")

    def test_wrong_feed_empty_feed_bad_id_and_200_sentinel_refuse(self):
        cases = [
            b"404: Not Found",
            b'<feed xmlns="http://www.w3.org/2005/Atom"></feed>',
            feed().replace(b"kody-w/rapp-1/commits/main", b"somebody/other/commits/main"),
            feed().replace(COMMIT.encode(), b"main"),
            b'<!DOCTYPE x [<!ENTITY a "x">]>' + feed(),
        ]
        for raw in cases:
            with self.subTest(raw=raw[:60]):
                result = A.observe(self.root, True, lambda url: raw)
                self.assertEqual(result["status"], "REFUSED")

    def test_transport_failure_is_not_freshness_success(self):
        def fail(url):
            raise OSError("network unavailable")
        result = A.observe(self.root, True, fail)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["checks"][-1]["name"], "live-canonical-main-observation")

    def test_git_timeout_is_an_explicit_incomplete_observation(self):
        beacon = (self.root / "anchor" / "orient.json").read_bytes()
        with mock.patch.object(A.realcheck, "git", side_effect=subprocess.TimeoutExpired("git", 300)):
            result = A.observe(self.root, True, lambda url: feed() if url == A.FEED else beacon)
        self.assertEqual(result["status"], "REFUSED")
        self.assertIn("timed out", result["checks"][-1]["error"])

    def test_report_refuses_overwriting_prior_evidence(self):
        output = Path(self.temp.name) / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(A.main(["--root", str(self.root), "--output", str(output)]), 0)
        original = output.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(A.main(["--root", str(self.root), "--output", str(output)]), 1)
        self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
