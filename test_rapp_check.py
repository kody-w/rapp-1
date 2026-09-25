import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import rapp as R
import rapp_check as C


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "tests" / "fixtures" / "rapp_check"


class RappCheckDiscoveryTests(unittest.TestCase):
    def fixture_repo(self, name):
        temporary = tempfile.TemporaryDirectory(
            prefix=".rapp-check-test-", dir=ROOT
        )
        self.addCleanup(temporary.cleanup)
        repository = Path(temporary.name)
        source_root = FIXTURES / name
        for source in source_root.rglob("*.fixture"):
            relative = source.relative_to(source_root)
            target = repository / str(relative)[: -len(".fixture")]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return repository

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def test_target_shaped_nonstandard_frames_are_discovered(self):
        repository = self.fixture_repo("nonstandard")
        verdict, findings, evidence = C.check_repo(repository)

        self.assertEqual(verdict, "COMPLIANT")
        self.assertEqual(findings, [])
        self.assertEqual(
            {item["artifact"] for item in evidence},
            {
                "rapp1/genesis-frame.json",
                "rapp1/publish/publish-frame.json",
            },
        )

    def test_repository_without_rapp_artifacts_remains_clean(self):
        verdict, findings, evidence = C.check_repo(self.fixture_repo("clean"))

        self.assertEqual((verdict, findings, evidence), ("CLEAN", [], []))

    def test_ordinary_json_with_similar_keys_is_not_a_frame(self):
        verdict, findings, evidence = C.check_repo(
            self.fixture_repo("lookalike")
        )

        self.assertEqual((verdict, findings, evidence), ("CLEAN", [], []))

    def test_duplicate_key_and_malformed_candidates_are_findings(self):
        verdict, findings, _ = C.check_repo(self.fixture_repo("malformed"))

        self.assertEqual(verdict, "DRIFT")
        self.assertEqual(
            {item["artifact"] for item in findings},
            {"frames/0.json", "frames/1.json"},
        )
        self.assertTrue(
            any("duplicate JSON member" in item["detail"] for item in findings)
        )

    def test_float_bearing_exact_frame_is_an_ambiguity_finding(self):
        repository = self.fixture_repo("nonstandard")
        target = repository / "rapp1" / "genesis-frame.json"
        target.write_text(
            target.read_text(encoding="utf-8").replace('"seq":0', '"seq":0.0'),
            encoding="utf-8",
        )

        verdict, findings, _ = C.check_repo(repository)

        self.assertEqual(verdict, "DRIFT")
        self.assertTrue(
            any("floats require full-JCS" in item["detail"] for item in findings)
        )

    def test_recognized_numeric_frame_directory_retains_behavior(self):
        verdict, findings, evidence = C.check_repo(
            self.fixture_repo("numeric")
        )

        self.assertEqual(verdict, "COMPLIANT")
        self.assertEqual(findings, [])
        self.assertEqual(
            evidence,
            [{"artifact": "frames", "ok": "2 frames conform to §7 envelope"}],
        )

    def test_signed_frames_are_unverified_without_trusted_verifier(self):
        repository = self.fixture_repo("nonstandard")
        kid = "rappid:@example/signer:" + "b" * 64
        header = {
            "alg": "EdDSA",
            "b64": False,
            "crit": ["b64"],
            "kid": kid,
        }
        protected = base64.urlsafe_b64encode(
            R.canonical(header).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        signature = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode(
            "ascii"
        )
        detached_jws = f"{protected}..{signature}"
        for path in repository.rglob("*-frame.json"):
            frame = json.loads(path.read_text(encoding="utf-8"))
            frame["sig"] = detached_jws
            self.write_json(path, frame)

        verdict, findings, evidence = C.check_repo(repository)
        self.assertEqual(verdict, "DRIFT")
        self.assertEqual(
            {item.get("status") for item in findings}, {"unverified"}
        )
        self.assertEqual(
            {item.get("status") for item in evidence}, {"unverified"}
        )

        trusted = lambda unsigned, sig: (sig == detached_jws, "test trust")
        trusted_verdict, trusted_findings, _ = C.check_repo(
            repository, signature_verifier=trusted
        )
        self.assertEqual(trusted_verdict, "COMPLIANT")
        self.assertEqual(trusted_findings, [])

    def test_chain_anomalies_and_index_head_are_findings(self):
        repository = self.fixture_repo("clean")
        (repository / "ordinary.json").unlink()
        stream_a = "rappid:@example/a:" + "a" * 64
        stream_b = "rappid:@example/b:" + "b" * 64
        stream_c = "rappid:@example/c:" + "c" * 64
        stream_d = "rappid:@example/d:" + "d" * 64
        a0 = R.build_frame(
            "memory.save",
            stream_a,
            0,
            "2026-09-17T20:00:00.000Z",
            {"n": 0},
            None,
        )
        a1 = R.build_frame(
            "memory.save",
            stream_a,
            1,
            "2026-09-17T20:00:01.000Z",
            {"n": 1},
            a0["payload_hash"],
        )
        a1_fork = R.build_frame(
            "memory.save",
            stream_a,
            1,
            "2026-09-17T20:00:01.000Z",
            {"n": "fork"},
            a0["payload_hash"],
        )
        b0 = R.build_frame(
            "memory.save",
            stream_b,
            0,
            "2026-09-17T20:00:00.000Z",
            {"n": 0},
            None,
        )
        c2 = R.build_frame(
            "memory.save",
            stream_c,
            2,
            "2026-09-17T20:00:02.000Z",
            {"n": 2},
            "f" * 64,
        )
        d0 = R.build_frame(
            "memory.save",
            stream_d,
            0,
            "2026-09-17T20:00:00.000Z",
            {"n": 0},
            None,
        )
        frames = {
            "a0.json": a0,
            "a1.json": a1,
            "a1-fork.json": a1_fork,
            "b0.json": b0,
            "c2.json": c2,
            "d0.json": d0,
            "d0-copy.json": d0,
        }
        for name, frame in frames.items():
            self.write_json(repository / name, frame)
        self.write_json(
            repository / "rapp-frame-index.json",
            {
                "schema": "rapp-frame-index/1",
                "stream_id": stream_a,
                "frames": list(frames),
                "head": {"seq": 0, "frame_hash": a0["frame_hash"]},
            },
        )

        verdict, findings, _ = C.check_repo(repository)
        rules = {item["rule"] for item in findings}

        self.assertEqual(verdict, "DRIFT")
        self.assertIn("§7.6 fork", rules)
        self.assertIn("§7.6 duplicate position", rules)
        self.assertIn("§7.4 chain gap", rules)
        self.assertIn("§7.5.1a mixed streams", rules)
        self.assertIn("§7.6 rollback-shaped head", rules)

    def test_controlled_mutation_turns_cli_gate_red(self):
        repository = self.fixture_repo("nonstandard")
        target = repository / "rapp1" / "publish" / "publish-frame.json"
        frame = json.loads(target.read_text(encoding="utf-8"))
        frame["payload"]["value"] = "mutated"
        self.write_json(target, frame)

        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "rapp_check.py"),
                str(repository),
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        report = json.loads(result.stdout)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(
            any("payload_hash mismatch" in item["detail"] for item in report["findings"])
        )

    def registry_document(self, **changes):
        der = b"synthetic SPKI bytes for a registry lint test"
        owner = R.mint_rappid("test", "estate-owner", spki_der=der)
        document = {
            "schema": "rapp/1-registry",
            "registry_seq": 3,
            "canonical_source": "https://registry.example.test/rapp-registry.json",
            "entries": [
                {"type": "estate_owner", "rappid": owner},
                {"type": "spki", "rappid": owner, "deprecated": False,
                 "spki_der_b64": base64.b64encode(der).decode("ascii")},
            ],
            "sig": None,
        }
        document.update(changes)
        return document

    def test_registry_documents_are_structural_evidence_never_authority(self):
        repository = self.fixture_repo("clean")
        self.write_json(repository / "estate" / "registry.json", self.registry_document())
        verdict, findings, evidence = C.check_repo(repository)

        self.assertEqual((verdict, findings), ("COMPLIANT", []))
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["status"], "unverified")
        self.assertIn("§13.1 registry structure OK", evidence[0]["ok"])
        self.assertIn("unsigned draft", evidence[0]["ok"])

    def test_registry_documents_that_fail_strict_parsing_are_findings(self):
        repository = self.fixture_repo("clean")
        text = json.dumps(self.registry_document(), sort_keys=True)
        duplicate = text[:-1] + ', "entries": []}'
        (repository / "dup").mkdir()
        (repository / "dup" / "registry.json").write_text(duplicate, encoding="utf-8")
        floating = text.replace('"registry_seq": 3', '"registry_seq": 3.5')
        (repository / "float").mkdir()
        (repository / "float" / "registry.json").write_text(floating, encoding="utf-8")
        verdict, findings, _ = C.check_repo(repository)

        self.assertEqual(verdict, "DRIFT")
        self.assertEqual(
            {(item["artifact"], item["rule"]) for item in findings},
            {
                ("dup/registry.json", "§13 registry document"),
                ("float/registry.json", "§13 registry document"),
            },
        )

    def test_a_registry_nested_inside_another_document_is_not_linted(self):
        repository = self.fixture_repo("clean")
        nested = {"schema": "example-vectors/1",
                  "cases": [{"document": self.registry_document(registry_seq=3.5)}]}
        (repository / "vectors.json").write_text(json.dumps(nested), encoding="utf-8")
        self.assertEqual(C.check_repo(repository), ("CLEAN", [], []))

    def test_malformed_registry_documents_are_findings(self):
        repository = self.fixture_repo("clean")
        broken = self.registry_document()
        del broken["canonical_source"]
        self.write_json(repository / "a" / "registry.json", broken)
        duplicate_owner = self.registry_document()
        duplicate_owner["entries"].append(dict(duplicate_owner["entries"][0]))
        self.write_json(repository / "b" / "registry.json", duplicate_owner)
        verdict, findings, _ = C.check_repo(repository)

        self.assertEqual(verdict, "DRIFT")
        self.assertEqual(
            {(item["artifact"], item["rule"]) for item in findings},
            {
                ("a/registry.json", "§13 registry document"),
                ("b/registry.json", "§13 registry document"),
            },
        )


if __name__ == "__main__":
    unittest.main()
