"""Deterministic, stdlib-only capture-adapter and evidence-honesty tests.

Fixtures reproduce the inspected materialized capture schemas and object layout.
They are generated beneath this checkout, never in an OS temporary directory.
No fixture repository source is executed.

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_estate_inventory
"""

import ast
import base64
import collections
import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest import mock

import estate_inventory as E
import rapp as R


UTC = "2026-09-05T00:00:00.000Z"
RID = "rappid:@owner/unit:" + "a" * 64


def json_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True).encode("ascii")


def frame(seq=0, prev=None, payload=None, sig=None):
    return R.build_frame("memory.save", RID, seq, UTC,
                         {"value": "original"} if payload is None else payload, prev, sig=sig)


def unverified_jws():
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": RID}
    encoded = base64.urlsafe_b64encode(R.canonical(header).encode("utf-8")).rstrip(b"=")
    # Well-formed transport only: no signature validity or trust is asserted.
    signature = base64.urlsafe_b64encode(bytes(range(64))).rstrip(b"=")
    return (encoded + b".." + signature).decode("ascii")


class CaptureFixture:
    """Small structurally faithful version of the full 489-repository capture."""

    def __init__(self, root):
        self.root = root
        self.capture = root / "materialized"
        self.scope_path = root / "source-scope.json"
        self.repos = []
        self.bodies = {}
        self.dependencies = []
        self.links = []
        (self.capture / "genome/objects").mkdir(parents=True)
        (self.capture / "genome/repositories").mkdir()

    def entry(self, path, body=b"", mode="100644", commit=None):
        raw = path.encode("utf-8") if isinstance(path, str) else path
        oid = commit or hashlib.sha1(("blob %s\0" % len(body)).encode("ascii") + body).hexdigest()
        if mode != "160000":
            self.bodies[oid] = body
        return {"mode": mode, "type": "commit" if mode == "160000" else "blob",
                "git_object": oid, "path_bytes_base64": base64.b64encode(raw).decode("ascii"),
                "path": raw.decode("utf-8", "surrogateescape")}

    def repo(self, name, files=(), fork=False, archived=False):
        entries = [self.entry(*file) for file in files]
        rid = 1000 + len(self.repos)
        commit = hashlib.sha1(("snapshot " + name).encode("ascii")).hexdigest() if entries else None
        row = {"schema": "rapp-source-genome-repository/1", "repository_id": rid,
               "repo": name, "public_url": "https://github.com/owner/" + name,
               "source_snapshot_commit": commit, "default_branch": "main" if entries else None,
               "rapp_metadata_match": "rapp" in name.lower(), "license_detection": "MIT",
               "entries": entries, "lfs_objects": [], "empty": not entries,
               "_fork": fork, "_archived": archived}
        self.repos.append(row)
        return row

    def write(self):
        for oid, body in self.bodies.items():
            path = self.capture / "genome/objects" / oid[:2] / oid[2:]
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(body)
        scope_rows = []
        for repo in self.repos:
            scope_rows.append({
                "name": repo["repo"], "repository_id": repo["repository_id"],
                "public_url": repo["public_url"], "git_url": repo["public_url"] + ".git",
                "captured_default_branch": repo["default_branch"],
                "captured_commit": repo["source_snapshot_commit"],
                "rapp_metadata_match": repo["rapp_metadata_match"],
                "fork": repo["_fork"], "archived": repo["_archived"],
                "license_detection": repo["license_detection"],
                "role": "source-preservation; not automatically activated"})
        scope = {
            "schema": "rapp-public-source-scope/1", "created_at": UTC, "owner": "owner",
            "public_repositories": len(scope_rows),
            "selection": "Every public repository in this synthetic fixture.",
            "reason": "No naming exclusions.",
            "baseline": {"repository": "owner/fixture", "commit": "0" * 40},
            "scope_boundary": "Frozen public source only.", "repositories": scope_rows}
        public_repos = [{k: v for k, v in repo.items() if not k.startswith("_")}
                        for repo in self.repos]
        owner_blobs = {entry["git_object"] for repo in public_repos for entry in repo["entries"]
                       if entry["type"] == "blob"}
        dep_blobs = {entry["git_object"] for dep in self.dependencies for entry in dep["entries"]
                     if entry["type"] == "blob"}
        tracked = sum(len(repo["entries"]) for repo in public_repos)
        links = [{"repository_id": repo["repository_id"], "repo": repo["repo"],
                  "path": entry["path"], "commit": entry["git_object"]}
                 for repo in public_repos for entry in repo["entries"] if entry["type"] == "commit"]
        blob_bytes = sum(len(self.bodies[oid]) for oid in owner_blobs)
        counts = {"repositories": len(public_repos), "tracked_entries": tracked,
                  "unique_blobs": len(owner_blobs), "source_blob_bytes": blob_bytes,
                  "lfs_objects": 0, "packed_files": len(owner_blobs) + len(public_repos) + 2}
        index = {
            "schema": "rapp-full-genome-index/1", "repositories": public_repos, "counts": counts,
            "source_scope": scope,
            "archive": {"file": "genome.tar.gz", "sha256": "0" * 64, "bytes": 1,
                        "format": "tar+gzip", "expanded_file_bytes": blob_bytes},
            "gitlinks": links, "complete_current_state": True, "no_size_or_naming_omissions": True}
        genome = {
            "schema": "rapp-full-public-genome/1", "created_at": UTC,
            "repositories": len(public_repos), "tracked_entries": tracked,
            "unique_current_state_blobs": len(owner_blobs), "blob_bytes": blob_bytes,
            "empty_repositories": sum(repo["empty"] for repo in public_repos), "gitlinks": links,
            "snapshot_scope": "Every frozen tracked entry.", "history_scope": "Separate archive.",
            "activation": "Public source preservation does not execute repositories."}
        dependency_index = {
            "schema": "rapp-public-gitlink-bodies/1", "links": self.links,
            "dependencies": self.dependencies, "extra_blob_count": len(dep_blobs - owner_blobs),
            "unavailable_count": sum(link["status"] == "pre-existing-unavailable"
                                     for link in self.links)}
        self.scope_path.write_bytes(json_bytes(scope))
        self.put_json("genome/source-scope.json", scope)
        self.put_json("genome-index.json", index)
        self.put_json("genome/genome.json", genome)
        self.put_json("dependency-index.json", dependency_index)
        for repo in public_repos:
            self.put_json("genome/repositories/%s.json" % repo["repository_id"], repo)

    def put_json(self, path, value):
        (self.capture / path).write_bytes(json_bytes(value))

    def get_json(self, path):
        return json.loads((self.capture / path).read_bytes())

    def blob_path(self, entry):
        oid = entry["git_object"]
        return self.capture / "genome/objects" / oid[:2] / oid[2:]


class EstateInventoryTests(unittest.TestCase):
    sequence = 0

    def setUp(self):
        type(self).sequence += 1
        self.scratch_base = Path(__file__).absolute().parent / ".estate-inventory-tests"
        self.scratch_base.mkdir(exist_ok=True)
        self.root = self.scratch_base / ("%s-%s" % (os.getpid(), self.sequence))
        self.root.mkdir()
        self.fixture = CaptureFixture(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)
        try:
            self.scratch_base.rmdir()
        except OSError:
            pass

    def report(self, limits=None):
        self.fixture.write()
        return E.collect(self.fixture.capture, self.fixture.scope_path, limits or E.Limits())

    def load(self):
        return E.load_capture(self.fixture.capture, self.fixture.scope_path, E.Limits())

    def artifacts(self, report):
        return [artifact for repo in report["repositories"] for item in repo["evidence"]
                for artifact in item.get("artifacts", [])]

    def test_real_current_frame_accepted_without_repository_green(self):
        self.fixture.repo("rapp-test", [("frames/0000.json", json_bytes(frame()))])
        report = self.report()
        artifact = self.artifacts(report)[0]
        self.assertEqual("accepted", artifact["validation"]["status"])
        self.assertEqual("rapp.verify_frame", artifact["validation"]["api"])
        self.assertEqual("not_established", report["compatibility_verdict"])
        self.assertEqual("not_established", report["repositories"][0]["compatibility"])
        self.assertEqual({"accepted_observed_chain": 1},
                         report["coverage"]["owner_stream_check_outcomes"])

    def test_bad_current_frame_refused(self):
        bad = frame()
        bad["payload"]["value"] = "tampered"
        self.fixture.repo("rapp-test", [("frames/0000.json", json_bytes(bad))])
        report = self.report()
        result = self.artifacts(report)[0]["validation"]
        self.assertEqual("refused", result["status"])
        self.assertEqual("2", result["step"])
        self.assertEqual("payload_hash mismatch", result["reason"])
        self.assertEqual("complete", report["report_status"])

    def test_unrelated_frame_directory_is_not_declared_rapp(self):
        self.fixture.repo("simulation", [("data/frames/sol-0001.json",
                                         json_bytes({"sol": 1, "events": [], "terrain": {}}))])
        report = self.report()
        row = report["repositories"][0]
        self.assertFalse(row["observed_rapp_evidence"])
        self.assertEqual({"unclaimed_or_other_protocol:frame:refused": 1},
                         row["artifact_declaration_outcomes"])
        artifact = self.artifacts(report)[0]
        self.assertIn("not a retroactive invalidation", artifact["validation_scope"])

    def test_actual_legacy_frame_declared_separately_from_current_rapp(self):
        value = {"schema": "rapp-frame/2.0", "seq": 0, "payload": {}, "sha256": "a" * 64}
        self.fixture.repo("legacy", [("frames/0.json", json_bytes(value))])
        report = self.report()
        declaration = self.artifacts(report)[0]["protocol_declaration"]
        self.assertEqual("declared_legacy_rapp", declaration["classification"])
        self.assertIn("no legacy validator run", declaration["original_protocol_validity"])
        self.assertEqual({"declared_legacy_rapp:frame:refused": 1},
                         report["coverage"]["owner_artifact_declaration_outcomes"])

    def test_historical_fixture_hint_does_not_excuse_refusal(self):
        bad = frame()
        bad["frame_hash"] = "b" * 64
        body = json_bytes(bad)
        self.fixture.repo("archive-fork", [
            ("legacy/fixtures/frame.json", body), ("current/frames/0000.json", body)],
            fork=True, archived=True)
        report = self.report()
        row = report["repositories"][0]
        self.assertTrue(row["fork"])
        self.assertTrue(row["archived"])
        self.assertEqual(2, row["artifact_outcomes"]["frame:refused"])
        historical = next(item for item in row["evidence"] if item["path_utf8"].startswith("legacy"))
        self.assertIn("historical", historical["location_hints"])
        self.assertIn("fixture", historical["location_hints"])
        self.assertEqual(1, report["coverage"]["owner_and_dependency_unique_blobs"])
        self.assertEqual(1, report["coverage"]["unique_artifact_outcomes"]["frame:refused"])

    def test_old_version_label_only_is_not_an_artifact_failure(self):
        self.fixture.repo("old-docs", [("README.md", b"Pin RAPP/1 rev-2; rapp-frame/2.0 was used.\n")])
        report = self.report()
        self.assertEqual([], self.artifacts(report))
        references = report["blobs"][0]["analysis"]["static_evidence"]["references"]
        self.assertIn("rev-2", [ref["value"] for ref in references])
        self.assertEqual({}, report["coverage"]["unique_artifact_outcomes"])

    def test_body_examples_do_not_become_executable_or_artifact_authority(self):
        bad = frame()
        bad["payload_hash"] = "c" * 64
        text = "RAPP/1 example, not an artifact:\n```json\n%s\n```\n" % json.dumps(bad)
        code = '"""RAPP/1 docs: verify_frame(x); build_frame(x)"""\nVALUE = 1\n'
        self.fixture.repo("docs", [("SPEC.md", text.encode()), ("agent.py", code.encode())])
        report = self.report()
        self.assertEqual([], self.artifacts(report))
        for blob in report["blobs"]:
            self.assertEqual([], blob["analysis"]["static_evidence"]["static_roles"])

    def test_rapp_discovery_and_feed_metadata_are_not_frame_envelopes(self):
        catalog = {"spec": "rapp/1", "kind": "catalog", "rules": [], "tiers": {}}
        feed = {"spec": "rapp/1", "kind": "body.feed", "stream_id": RID,
                "count": 1, "frames": [frame()], "head_hash": "b" * 64}
        self.fixture.repo("documents", [("tiers.json", json_bytes(catalog)),
                                        ("feed.json", json_bytes(feed))])
        report = self.report()
        self.assertEqual([], self.artifacts(report))
        self.assertTrue(report["repositories"][0]["observed_rapp_evidence"])
        self.assertTrue(all(blob["analysis"]["root_declarations"] for blob in report["blobs"]))

    def test_source_ast_names_are_only_static_hints(self):
        code = b"import rapp as R\n\ndef inspect(x):\n    return R.verify_frame(x)\n"
        self.fixture.repo("reader", [("reader.py", code)])
        report = self.report()
        roles = report["blobs"][0]["analysis"]["static_evidence"]["static_roles"]
        self.assertEqual({"canonical_module_name", "reader_name_hint"},
                         {role["role"] for role in roles})
        self.assertEqual([], self.artifacts(report))

    def test_structured_pins_distinct_from_textual_mentions(self):
        value = {"schema": "rapp/1-anchor", "spec": {
            "revision": "rev-15", "normative_sha256": "b" * 64,
            "canonical_repo": "https://github.com/kody-w/rapp-1"}}
        self.fixture.repo("pinned", [("orient.json", json_bytes(value))])
        report = self.report()
        declarations = report["blobs"][0]["analysis"]["root_declarations"]
        self.assertIn("spec.normative_sha256", {item["field"] for item in declarations})
        self.assertEqual([], self.artifacts(report))

    def test_large_python_ast_is_explicitly_unmeasured(self):
        self.fixture.repo("reader", [("reader.py", b"import rapp\n" + b"x = 1\n" * 30)])
        report = self.report(replace(E.Limits(), max_python_ast_bytes=100))
        source = report["blobs"][0]["analysis"]["static_evidence"]
        self.assertEqual("python_ast_unmeasured: max_python_ast_bytes", source["source_analysis"])
        self.assertIn(source["source_analysis"],
                      [item["reason"] for item in report["repositories"][0]["unmeasured"]])

    def test_empty_and_no_rapp_repositories_fully_accounted(self):
        self.fixture.repo("empty")
        self.fixture.repo("unrelated", [("hello.txt", b"hello world\n"), ("zero", b"")])
        report = self.report()
        coverage = report["coverage"]
        self.assertEqual(2, coverage["owner_repositories_accounted"])
        self.assertEqual(1, coverage["empty_owner_repositories"])
        self.assertEqual(2, coverage["owner_tracked_entries_accounted"])
        self.assertEqual(2, coverage["owner_repositories_without_observed_rapp_evidence"])
        self.assertEqual({"scanned_utf8": 2}, coverage["owner_entry_coverage"])

    def test_non_ascii_non_normalized_and_raw_paths_preserved(self):
        body = json_bytes({"schema": "rapp/1", "rappid": RID})
        paths = ["caf\u00e9/rappid.json".encode(), "cafe\u0301/rappid.json".encode(),
                 b"\xff/rappid.json", b"a\\b/rappid.json"]
        self.fixture.repo("paths", [(path, body) for path in paths])
        report = self.report()
        evidence = report["repositories"][0]["evidence"]
        self.assertEqual(set(paths), {base64.b64decode(item["path_bytes_base64"]) for item in evidence})
        self.assertEqual(4, len(evidence))
        self.assertEqual(1, sum(item["path_utf8"] is None for item in evidence))
        self.assertEqual(1, report["coverage"]["owner_unique_blobs"])

    def test_unsafe_raw_paths_refused_without_materializing_them(self):
        repo = self.fixture.repo("unsafe", [("safe.json", b"{}")])
        for raw in (b"../outside", b"/absolute", b"a//b", b"a/./b", b"a\0b"):
            with self.subTest(raw=raw):
                repo["entries"][0]["path"] = raw.decode()
                repo["entries"][0]["path_bytes_base64"] = base64.b64encode(raw).decode()
                self.fixture.write()
                with self.assertRaisesRegex(E.CaptureError, "unsafe raw Git path"):
                    self.load()

    def test_raw_path_display_mismatch_refused(self):
        repo = self.fixture.repo("paths", [("right", b"hello")])
        repo["entries"][0]["path"] = "wrong"
        self.fixture.write()
        with self.assertRaisesRegex(E.CaptureError, "binding mismatch"):
            self.load()

    def test_duplicate_raw_paths_and_prefix_conflicts_refused(self):
        repo = self.fixture.repo("paths", [("a", b"hello"), ("b", b"world")])
        for second in (b"a", b"a/child"):
            with self.subTest(path=second):
                repo["entries"][1]["path"] = second.decode()
                repo["entries"][1]["path_bytes_base64"] = base64.b64encode(second).decode()
                self.fixture.write()
                with self.assertRaises(E.CaptureError):
                    self.load()

    def test_git_symlink_target_is_hashed_never_followed(self):
        self.fixture.repo("symlink", [("rappid.json", b"../../outside", "120000")])
        report = self.report()
        self.assertEqual({"verified_git_blob": 1}, report["coverage"]["blob_integrity"])
        self.assertEqual([], self.artifacts(report))
        self.assertEqual({"symlink_target_not_dereferenced": 1},
                         report["repositories"][0]["entry_coverage"])

    def test_actual_object_symlink_refused(self):
        repo = self.fixture.repo("symlink", [("rappid.json", json_bytes({"rappid": RID}))])
        self.fixture.write()
        entry = repo["entries"][0]
        path = self.fixture.blob_path(entry)
        target = self.root / "outside-body"
        original = path.read_bytes()
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        report = E.collect(self.fixture.capture, self.fixture.scope_path)
        self.assertEqual("capture_invalid", report["report_status"])
        self.assertEqual({"missing_or_unsafe_blob": 1}, report["coverage"]["blob_integrity"])
        self.assertEqual(original, target.read_bytes())

    def test_symlinked_metadata_refused(self):
        self.fixture.repo("normal", [("plain", b"hello")])
        self.fixture.write()
        path = self.fixture.capture / "genome/repositories/1000.json"
        target = self.root / "metadata-outside.json"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(E.CaptureError):
            self.load()

    def test_symlinked_object_parent_refused(self):
        repo = self.fixture.repo("normal", [("plain", b"hello")])
        self.fixture.write()
        prefix = self.fixture.blob_path(repo["entries"][0]).parent
        outside = self.root / "object-directory"
        prefix.rename(outside)
        prefix.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(E.CaptureError):
            E.collect(self.fixture.capture, self.fixture.scope_path)

    def test_missing_scope_repository_refused(self):
        self.fixture.repo("one", [("plain", b"a")])
        self.fixture.repo("two", [("plain", b"b")])
        self.fixture.write()
        index = self.fixture.get_json("genome-index.json")
        index["repositories"].pop()
        self.fixture.put_json("genome-index.json", index)
        with self.assertRaisesRegex(E.CaptureError, "missing indexed repository"):
            self.load()

    def test_extra_scope_repository_refused(self):
        self.fixture.repo("one", [("plain", b"a")])
        self.fixture.write()
        index = self.fixture.get_json("genome-index.json")
        extra = copy.deepcopy(index["repositories"][0])
        extra["repository_id"] = 9999
        index["repositories"].append(extra)
        self.fixture.put_json("genome-index.json", index)
        with self.assertRaisesRegex(E.CaptureError, "unknown indexed repository"):
            self.load()

    def test_scope_commit_and_duplicate_key_tampering_refused(self):
        self.fixture.repo("one", [("plain", b"a")])
        self.fixture.write()
        scope = json.loads(self.fixture.scope_path.read_bytes())
        scope["repositories"][0]["captured_commit"] = "f" * 40
        self.fixture.scope_path.write_bytes(json_bytes(scope))
        with self.assertRaisesRegex(E.CaptureError, "source scopes differ"):
            self.load()
        self.fixture.write()
        body = self.fixture.scope_path.read_bytes()
        self.fixture.scope_path.write_bytes(b'{"owner":"wrong",' + body[1:])
        with self.assertRaisesRegex(E.CaptureError, "duplicate JSON member"):
            self.load()

    def test_missing_blob_reported_even_with_success_flags(self):
        repo = self.fixture.repo("one", [("frames/0.json", json_bytes(frame()))])
        self.fixture.write()
        self.fixture.blob_path(repo["entries"][0]).unlink()
        report = E.collect(self.fixture.capture, self.fixture.scope_path)
        self.assertEqual("capture_invalid", report["report_status"])
        self.assertEqual(1, report["coverage"]["owner_tracked_entries_accounted"])
        self.assertEqual({"missing_or_unsafe_blob": 1}, report["coverage"]["blob_integrity"])
        self.assertEqual([], self.artifacts(report))

    def test_corrupted_blob_refused_before_artifact_validation(self):
        repo = self.fixture.repo("one", [("plain", b"payload")])
        self.fixture.write()
        self.fixture.blob_path(repo["entries"][0]).write_bytes(b"PAYLOAD")
        report = E.collect(self.fixture.capture, self.fixture.scope_path)
        self.assertEqual("capture_invalid", report["report_status"])
        self.assertEqual({"git_blob_hash_mismatch": 1}, report["coverage"]["blob_integrity"])

    def test_unbound_extra_blob_and_metadata_count_tampering(self):
        self.fixture.repo("one", [("plain", b"a")])
        self.fixture.entry("unused", b"orphan")
        self.fixture.write()
        report = E.collect(self.fixture.capture, self.fixture.scope_path)
        self.assertEqual("unbound_objects", report["capture_errors"][0]["kind"])
        index = self.fixture.get_json("genome-index.json")
        index["counts"]["tracked_entries"] += 1
        self.fixture.put_json("genome-index.json", index)
        with self.assertRaisesRegex(E.CaptureError, "tracked_entries count mismatch"):
            self.load()

    def test_false_capture_success_flag_not_used_as_validation(self):
        self.fixture.repo("one", [("plain", b"a")])
        self.fixture.write()
        index = self.fixture.get_json("genome-index.json")
        index["complete_current_state"] = False
        index["no_size_or_naming_omissions"] = False
        self.fixture.put_json("genome-index.json", index)
        report = E.collect(self.fixture.capture, self.fixture.scope_path)
        self.assertEqual("complete", report["report_status"])
        self.assertFalse(report["capture"]["success_flags_used_as_evidence"])

    def test_standalone_non_genesis_not_mislabeled_as_bad_envelope(self):
        first = frame()
        second = frame(1, first["payload_hash"], {"value": "second"})
        self.fixture.repo("one", [("frame.json", json_bytes(second))])
        report = self.report()
        self.assertEqual("unverified_history", self.artifacts(report)[0]["validation"]["status"])
        self.assertEqual([], report["repositories"][0]["stream_checks"])

    def test_actual_predecessor_enables_distinct_stream_check(self):
        first = frame()
        second = frame(1, first["payload_hash"])
        self.fixture.repo("one", [("frames/0000.json", json_bytes(first)),
                                  ("frames/0001.json", json_bytes(second))])
        report = self.report()
        outcomes = report["coverage"]["owner_artifact_occurrence_outcomes"]
        self.assertEqual({"frame:accepted": 1, "frame:unverified_history": 1}, outcomes)
        chain = report["repositories"][0]["stream_checks"][0]
        self.assertEqual("accepted_observed_chain", chain["status"])
        self.assertTrue(all(check["validation"]["status"] == "accepted" for check in chain["checks"]))

    def test_streams_never_combined_across_repositories_or_directories(self):
        first = frame()
        second = frame(1, first["payload_hash"])
        self.fixture.repo("one", [("frames/0000.json", json_bytes(first))])
        self.fixture.repo("two", [("frames/0001.json", json_bytes(second)),
                                  ("fixtures/frames/0001.json", json_bytes(second))], fork=True)
        report = self.report()
        self.assertEqual({"accepted_observed_chain": 1, "unverified": 2},
                         report["coverage"]["owner_stream_check_outcomes"])
        self.assertEqual(2, report["coverage"]["owner_unique_blobs"])

    def test_repeated_sequence_is_ambiguous_not_silently_deduplicated(self):
        self.fixture.repo("one", [("frames/0000.json", json_bytes(frame())),
                                  ("frames/0001.json", json_bytes(frame()))])
        report = self.report()
        chain = report["repositories"][0]["stream_checks"][0]
        self.assertEqual("unverified", chain["status"])
        self.assertIn("repeated sequence", chain["reason"])
        self.assertEqual(2, chain["frames_observed"])

    def test_broken_linkage_refused_with_real_head(self):
        first = frame()
        second = frame(1, "f" * 64)
        self.fixture.repo("one", [("frames/0.json", json_bytes(first)),
                                  ("frames/1.json", json_bytes(second))])
        report = self.report()
        chain = report["repositories"][0]["stream_checks"][0]
        self.assertEqual("refused", chain["status"])
        self.assertEqual("prev != head payload_hash", chain["checks"][1]["validation"]["reason"])

    def test_json_lines_stream_order_and_mixed_record_boundary(self):
        first = frame()
        second = frame(1, first["payload_hash"])
        lines = json_bytes(first) + b"\n" + json_bytes(second) + b"\n"
        self.fixture.repo("one", [("chain.jsonl", lines),
                                  ("mixed.jsonl", lines + b'{"note":"not a frame"}\n')])
        report = self.report()
        self.assertEqual({"accepted_observed_chain": 1, "unverified": 1},
                         report["coverage"]["owner_stream_check_outcomes"])

    def test_single_json_line_has_explicit_stream_coverage(self):
        self.fixture.repo("one", [("chain.jsonl", json_bytes(frame()) + b"\n")])
        report = self.report()
        chain = report["repositories"][0]["stream_checks"][0]
        self.assertEqual("json_lines", chain["form"])
        self.assertEqual("accepted_observed_chain", chain["status"])

    def test_json_lines_parse_error_cap_is_not_silent(self):
        lines = json_bytes(frame()) + b"\n" + b"{broken}\n" * 5
        self.fixture.repo("one", [("chain.jsonl", lines)])
        report = self.report(replace(E.Limits(), max_evidence_per_blob=2))
        container = report["blobs"][0]["analysis"]["container"]
        self.assertEqual(5, container["parse_error_count"])
        self.assertEqual(2, len(container["parse_errors"]))
        self.assertEqual(3, container["parse_error_records_omitted"])
        self.assertEqual("unverified", report["repositories"][0]["stream_checks"][0]["status"])

    def test_json_lines_record_bound_reported(self):
        first = frame()
        second = frame(1, first["payload_hash"])
        self.fixture.repo("one", [("chain.jsonl", json_bytes(first) + b"\n" + json_bytes(second))])
        report = self.report(replace(E.Limits(), max_records_per_blob=1))
        self.assertEqual(1, report["blobs"][0]["analysis"]["container"]["omitted_records"])
        self.assertEqual("unverified", report["repositories"][0]["stream_checks"][0]["status"])

    def test_signed_frames_and_eggs_unverified_without_trust(self):
        sig = unverified_jws()
        signed = frame(sig=sig)
        egg = R.pack_egg("organism", RID, UTC, files={
            "rappid.json": json_bytes({"schema": "rapp/1", "rappid": RID}),
            "soul.md": b"Public fixture.\n"}, sig=sig)
        self.fixture.repo("one", [("frames/0.json", json_bytes(signed)), ("organism.egg", egg)])
        report = self.report()
        self.assertEqual({"unverified_trust"},
                         {item["validation"]["status"] for item in self.artifacts(report)})
        self.assertEqual("unverified", report["repositories"][0]["stream_checks"][0]["status"])

    def test_unsigned_session_egg_accepted_but_not_its_application(self):
        egg = R.pack_egg("session", RID, UTC, payload={"runtime": "fixture", "transcript": []})
        self.fixture.repo("one", [("session.egg", egg)])
        report = self.report()
        artifact = self.artifacts(report)[0]
        self.assertEqual("accepted", artifact["validation"]["status"])
        self.assertEqual("not_executed", artifact["embedded_application_behavior"])

    def test_real_zip_egg_found_without_egg_extension(self):
        egg = R.pack_egg("organism", RID, UTC, files={
            "rappid.json": json_bytes({"schema": "rapp/1", "rappid": RID}), "soul.md": b"fixture"})
        self.fixture.repo("one", [("capsule.zip", egg)])
        report = self.report()
        artifact = self.artifacts(report)[0]
        self.assertEqual("accepted", artifact["validation"]["status"])
        self.assertEqual("zip_manifest_declaration", artifact["origin"])
        self.assertEqual("declared_rapp1", artifact["protocol_declaration"]["classification"])
        self.assertTrue(report["repositories"][0]["observed_rapp_evidence"])

    def test_missing_required_swarm_signature_is_refusal_not_missing_trust(self):
        value = R.build_frame("swarm.echo", "net:fixture", 0, UTC, {}, None)
        self.fixture.repo("one", [("frames/0.json", json_bytes(value))])
        report = self.report()
        result = self.artifacts(report)[0]["validation"]
        self.assertEqual("refused", result["status"])
        self.assertEqual("swarm frame must be signed", result["reason"])

    def test_identity_grammar_only_and_old_schema_label_preserved(self):
        self.fixture.repo("one", [("rappid.json", json_bytes({
            "schema": "rapp-rappid-spec/2.0", "rappid": RID}))])
        report = self.report()
        result = self.artifacts(report)[0]["validation"]
        self.assertEqual("accepted_grammar_only", result["status"])
        self.assertEqual("rapp-rappid-spec/2.0", result["declared_schema"])
        self.assertIn("minting_provenance", result["missing_requirements"])

    def test_identity_template_path_not_an_exemption(self):
        self.fixture.repo("one", [("templates/rappid.json", json_bytes({
            "schema": "rapp/1", "rappid": "rappid:@owner/unit:__MINT_ME__"}))])
        report = self.report()
        self.assertEqual("refused", self.artifacts(report)[0]["validation"]["status"])
        self.assertIn("template", report["repositories"][0]["evidence"][0]["location_hints"])

    def test_canonical_api_exception_is_unverified_not_success(self):
        self.fixture.repo("one", [("frames/0.json", json_bytes(frame()))])
        with mock.patch.object(E.R, "verify_frame",
                               side_effect=ValueError("synthetic validator failure")):
            report = self.report()
        result = self.artifacts(report)[0]["validation"]
        self.assertEqual("unverified_validator_exception", result["status"])
        self.assertEqual("ValueError", result["exception"])
        self.assertIn("synthetic validator failure", result["reason"])

    def test_numeric_values_forwarded_without_imposing_old_reference_profile(self):
        value = frame()
        value["payload"] = {"fraction": 0.1, "exact_integer": 2**53}
        body = json_bytes(value)
        for ok, step, reason in ((True, None, "ok"), (False, "2", "synthetic hash outcome")):
            with self.subTest(ok=ok):
                with mock.patch.object(E.R, "_strict_json", return_value=value) as parser, \
                     mock.patch.object(E.R, "verify_frame",
                                       return_value=(ok, step, reason)) as verifier:
                    result = E.verify_frame(body)
                parser.assert_called_once_with(body)
                self.assertIs(value, verifier.call_args.args[0])
                self.assertEqual({"fraction": 0.1, "exact_integer": 2**53}, value["payload"])
                self.assertEqual("accepted" if ok else "refused", result["status"])
                self.assertEqual(reason, result["reason"])
                self.assertEqual("accepted", result["original_domain"]["status"])

    def test_discovery_preserves_number_lexemes_at_every_depth(self):
        body = (b'{"fraction":0.1,"exact":9007199254740992,"lossy":1.0000000000000001,'
                b'"negative_zero":-0,"underflow":1e-400,"nested":[{"n":1.0000000000000001}],'
                b'"text":"1.0000000000000001"}')
        value = E.strict_json(body, E.Limits())
        for key, lexeme in {
            "fraction": "0.1", "exact": "9007199254740992", "lossy": "1.0000000000000001",
            "negative_zero": "-0", "underflow": "1e-400",
        }.items():
            self.assertIsInstance(value[key], E.JsonNumber)
            self.assertEqual(lexeme, value[key].lexeme)
        self.assertEqual("1.0000000000000001", value["nested"][0]["n"].lexeme)
        self.assertIsInstance(value["text"], str)
        with self.assertRaises(TypeError):
            json.dumps(value)

    def test_array_extraction_preserves_original_octets_not_json_dumps(self):
        value = frame(payload={"n": 1, "nested": [{"text": '雪 ], [ "quotes" \\ path'}]})
        original = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
        original = original.replace(b'"n": 1', b'"n": 1.0000000000000001')
        body = b' \n["prefix ], [",\n' + original + b',\n[0.1,9007199254740992]]\n'
        E.strict_json(body, E.Limits(), preserve_numbers=True)
        records = list(E.array_record_octets(body, 100))
        self.assertEqual(3, len(records))
        self.assertEqual(original, records[1][1])
        self.assertEqual("1.0000000000000001", records[1][0]["payload"]["n"].lexeme)
        self.assertEqual(b"[0.1,9007199254740992]", records[2][1])

    def test_lossy_raw_numbers_block_permissive_native_verifier_on_all_routes(self):
        good = json_bytes(frame(payload={"n": 1}))
        lossy = good.replace(b'"n": 1', b'"n": 1.0000000000000001')
        nested = json_bytes(frame(payload={"nested": [{"n": 1}]}))
        nested = nested.replace(b'"n": 1', b'"n": 1.0000000000000001')
        self.fixture.repo("numbers", [
            ("root.json", lossy),
            ("records.jsonl", lossy + b'\n{"note":"nonframe"}\n'),
            ("array.json", b"[\n" + lossy + b"\n]"),
            ("nested-payload.json", nested),
            ("nested-payload-array.json", b"[" + nested + b"]"),
            ("legacy/fixtures/frame.json", lossy),
        ])

        def raw_parser_control(body):
            # A control for the reported loss, not a replacement JCS implementation.
            def number(token):
                if token == "1.0000000000000001":
                    raise ValueError("negative control: lossy original number token")
                return float(token)
            return json.loads(body, parse_float=number)

        with mock.patch.object(E.R, "_strict_json", side_effect=raw_parser_control) as parser, \
             mock.patch.object(E.R, "verify_frame", return_value=(True, None, "ok")) as verifier:
            report = self.report()
        verifier.assert_not_called()
        artifacts = self.artifacts(report)
        self.assertEqual(6, len(artifacts))
        self.assertTrue(parser.called)
        for artifact in artifacts:
            result = artifact["validation"]
            self.assertEqual("refused", result["status"])
            self.assertEqual("rapp._strict_json", result["api"])
            self.assertFalse(result["frame_api_called"])
            self.assertEqual("refused", result["original_domain"]["status"])
            self.assertIn(result["original_domain"]["sha256"], {
                hashlib.sha256(lossy).hexdigest(), hashlib.sha256(nested).hexdigest()})
        for row in report["repositories"]:
            self.assertNotIn("accepted_observed_chain",
                             {check["status"] for check in row["stream_checks"]})
        json.dumps(report, allow_nan=False)

    def test_stream_checks_retain_original_numeric_domain_for_each_link(self):
        first = frame(payload={"n": 1})
        second = frame(1, first["payload_hash"], payload={"n": 1})
        first_raw = json_bytes(first)
        second_raw = json_bytes(second).replace(b'"n": 1', b'"n": 1.0000000000000001')
        self.fixture.repo("stream", [("chain.jsonl", first_raw + b"\n" + second_raw + b"\n")])

        def raw_parser_control(body):
            if body == second_raw:
                raise ValueError("negative control: original number domain")
            self.assertEqual(first_raw, body)
            return json.loads(body)

        with mock.patch.object(E.R, "_strict_json", side_effect=raw_parser_control) as parser, \
             mock.patch.object(E.R, "verify_frame", return_value=(True, None, "ok")) as verifier:
            report = self.report()
        self.assertTrue(verifier.called)
        self.assertTrue(all(call.args[0]["seq"] == 0 for call in verifier.call_args_list))
        self.assertGreaterEqual(sum(call.args[0] == second_raw for call in parser.call_args_list), 2)
        chain = report["repositories"][0]["stream_checks"][0]
        self.assertEqual("refused", chain["status"])
        self.assertEqual(["accepted", "refused"], [row["validation"]["status"] for row in chain["checks"]])
        self.assertFalse(chain["checks"][1]["validation"]["frame_api_called"])

    def test_real_canonical_parser_refuses_lossy_original_frame(self):
        original = json_bytes(frame(payload={"n": 1}))
        lossy = original.replace(b'"n": 1', b'"n": 1.0000000000000001')
        self.assertEqual(1.0, json.loads(lossy)["payload"]["n"])
        result = E.verify_frame(lossy)
        self.assertEqual("refused", result["status"])
        self.assertEqual("rapp._strict_json", result["api"])
        self.assertFalse(result["frame_api_called"])
        self.assertEqual(hashlib.sha256(lossy).hexdigest(), result["original_domain"]["sha256"])

    def test_supported_numeric_domains_delegate_on_json_jsonl_and_array_routes(self):
        value = frame()
        value["payload"] = {"fraction": 0.1, "exact_integer": 2**53,
                            "nested": [{"fraction": 0.1, "exact_integer": 2**53}]}
        original = json_bytes(value)
        self.fixture.repo("numbers", [
            ("root.json", original),
            ("records.jsonl", original + b'\n{"note":"nonframe"}\n'),
            ("array.json", b"[" + original + b"]"),
        ])
        # These mocks test forwarding of valid-domain values, not their frame hashes.
        with mock.patch.object(E.R, "_strict_json", side_effect=json.loads) as parser, \
             mock.patch.object(E.R, "verify_frame", return_value=(True, None, "ok")) as verifier:
            report = self.report()
        self.assertEqual(3, len(self.artifacts(report)))
        self.assertTrue(verifier.called)
        for call in parser.call_args_list:
            self.assertEqual(original, call.args[0])
        for call in verifier.call_args_list:
            self.assertEqual(value["payload"], call.args[0]["payload"])
            self.assertIs(type(call.args[0]["payload"]["exact_integer"]), int)
        for artifact in self.artifacts(report):
            self.assertEqual("accepted", artifact["validation"]["status"])
            self.assertEqual("accepted", artifact["validation"]["original_domain"]["status"])
        self.assertEqual("not_established", report["compatibility_verdict"])

    def test_normalized_dictionary_without_original_octets_cannot_be_accepted(self):
        value = frame(payload={"n": 1})
        value["payload"]["n"] = 1.0
        with mock.patch.object(E.R, "_strict_json") as parser, \
             mock.patch.object(E.R, "verify_frame", return_value=(True, None, "ok")) as verifier:
            result = E.verify_frame(value)
        parser.assert_not_called()
        verifier.assert_not_called()
        self.assertEqual("unmeasured_original_domain", result["status"])
        self.assertFalse(result["canonical_called"])
        self.assertIn("original_json_record_octets", result["missing_requirements"])

    def test_nested_record_containers_are_explicitly_unmeasured_not_accepted(self):
        lossy = json_bytes(frame(payload={"n": 1})).replace(b'"n": 1', b'"n": 1.0000000000000001')
        self.fixture.repo("nested", [
            ("nested-array.json", b"[[" + lossy + b"]]"),
            ("wrapped.json", b'{"frame":' + lossy + b"}"),
            ("wrapped.jsonl", b'{"frame":' + lossy + b'}\n{"note":"nonframe"}\n'),
        ])
        with mock.patch.object(E.R, "_strict_json") as parser, \
             mock.patch.object(E.R, "verify_frame", return_value=(True, None, "ok")) as verifier:
            report = self.report()
        parser.assert_not_called()
        verifier.assert_not_called()
        self.assertEqual([], self.artifacts(report))
        boundaries = report["repositories"][0]["unmeasured"]
        self.assertEqual(3, sum("nested record containers are unmeasured" in item["reason"]
                                for item in boundaries))

    def test_metadata_discovery_never_uses_canonical_domain_parser(self):
        self.fixture.repo("unrelated", [("numbers.json", b'{"fraction":0.1,"exact":9007199254740992}')])
        with mock.patch.object(E.R, "_strict_json", side_effect=ValueError("not metadata")) as parser:
            report = self.report()
        parser.assert_not_called()
        self.assertEqual("complete", report["report_status"])
        self.assertEqual(1, report["coverage"]["owner_tracked_entries_accounted"])

    def test_expected_runtime_errors_remain_explicitly_unverified(self):
        body = json_bytes(frame())
        for api in ("_strict_json", "verify_frame"):
            with self.subTest(api=api):
                with mock.patch.object(E.R, api, side_effect=RuntimeError("controlled runtime failure")):
                    result = E.verify_frame(body)
                self.assertEqual("unverified_validator_exception", result["status"])
                self.assertEqual("RuntimeError", result["exception"])
                self.assertEqual("rapp." + api, result["api"])

    def test_unexpected_frame_and_parser_errors_propagate(self):
        body = json_bytes(frame())
        for api in ("_strict_json", "verify_frame"):
            with self.subTest(api=api):
                with mock.patch.object(E.R, api, side_effect=AttributeError("programming defect")):
                    with self.assertRaisesRegex(AttributeError, "programming defect"):
                        E.verify_frame(body)

    def test_unexpected_egg_api_errors_propagate(self):
        body = R.pack_egg("session", RID, UTC, payload={"runtime": "fixture", "transcript": []})
        with mock.patch.object(E.R, "verify_egg", side_effect=AttributeError("programming defect")):
            with self.assertRaisesRegex(AttributeError, "programming defect"):
                E.verify_egg(body, E.Limits())

    def test_cli_programming_errors_are_operational_failures_even_report_only(self):
        self.fixture.repo("one", [("frames/0.json", json_bytes(frame()))])
        self.fixture.write()
        for number, error in enumerate((AttributeError, TypeError, AssertionError)):
            with self.subTest(error=error.__name__):
                output = self.root / ("operational-%s.json" % number)
                with mock.patch.object(E.R, "verify_frame", side_effect=error("programming defect")), \
                     contextlib.redirect_stderr(io.StringIO()):
                    code = E.main(["--capture", str(self.fixture.capture),
                                   "--scope", str(self.fixture.scope_path),
                                   "--output", str(output), "--report-only", "--quiet"])
                result = json.loads(output.read_bytes())
                self.assertEqual(2, code)
                self.assertEqual("operational_failure", result["report_status"])
                self.assertEqual(error.__name__, result["operational_errors"][0]["kind"])
                self.assertFalse(result["coverage"]["accounting_completed"])

    def test_failed_report_write_removes_partial_without_swallowing_error(self):
        output = self.root / "bad-report.json"
        with self.assertRaises(TypeError):
            E.write_report(output, {"unserializable": object()},
                           self.fixture.capture, self.fixture.scope_path)
        self.assertFalse(output.exists())

    def test_cli_serialization_programming_error_fails_operationally(self):
        self.fixture.repo("one", [("plain", b"fixture")])
        self.fixture.write()
        output = self.root / "failed-write.json"
        with mock.patch.object(E.json, "dump", side_effect=AttributeError("serialization defect")), \
             contextlib.redirect_stderr(io.StringIO()):
            code = E.main(["--capture", str(self.fixture.capture),
                           "--scope", str(self.fixture.scope_path),
                           "--output", str(output), "--report-only", "--quiet"])
        self.assertEqual(2, code)
        self.assertFalse(output.exists())

    def test_owned_sources_have_no_catch_all_exception_handlers(self):
        for path in (Path(E.__file__), Path(__file__)):
            with self.subTest(path=path.name):
                tree = ast.parse(path.read_text())
                for node in ast.walk(tree):
                    if isinstance(node, ast.ExceptHandler):
                        self.assertIsNotNone(node.type)
                        names = {item.id for item in ast.walk(node.type) if isinstance(item, ast.Name)}
                        self.assertFalse(names & {"Exception", "BaseException"})

    def test_duplicate_json_members_refused_before_canonical_call(self):
        body = json_bytes(frame())
        body = b'{"kind":"wrong.kind",' + body[1:]
        self.fixture.repo("one", [("frames/0.json", body)])
        report = self.report()
        result = self.artifacts(report)[0]["validation"]
        self.assertEqual("refused", result["status"])
        self.assertFalse(result["canonical_called"])
        self.assertIn("duplicate JSON member", result["reason"])

    def test_overflowing_json_number_not_serialized_as_infinity(self):
        body = json_bytes(frame()).replace(b'"seq": 0', b'"seq": 1e9999')
        self.fixture.repo("one", [("frames/0.json", body)])
        report = self.report()
        result = self.artifacts(report)[0]["validation"]
        self.assertEqual("refused", result["status"])
        self.assertEqual("refused", result["original_domain"]["status"])
        self.assertFalse(result["frame_api_called"])
        json.dumps(report, allow_nan=False)

    def test_size_bounds_hash_all_bytes_but_do_not_claim_content_measured(self):
        self.fixture.repo("one", [("frames/0.json", json_bytes(frame()))])
        report = self.report(replace(E.Limits(), max_blob_bytes=10))
        self.assertEqual({"verified_git_blob": 1}, report["coverage"]["blob_integrity"])
        self.assertEqual({"unmeasured_size_bound": 1},
                         report["coverage"]["unique_blob_content_coverage"])
        self.assertEqual([], self.artifacts(report))
        self.assertEqual(1, report["coverage"]["owner_tracked_entries_accounted"])
        self.assertEqual("unmeasured_size_bound", report["repositories"][0]["unmeasured"][0]["reason"])

    def test_hash_budget_explicit_not_integrity_verified(self):
        self.fixture.repo("one", [("file", b"bounded body")])
        report = self.report(replace(E.Limits(), max_total_hash_bytes=2))
        self.assertEqual({"unmeasured_hash_bound": 1}, report["coverage"]["blob_integrity"])
        self.assertEqual(0, report["coverage"]["bytes_hashed"])

    def test_json_and_chain_cache_bounds_are_explicit(self):
        self.fixture.repo("one", [("frames/0.json", json_bytes(frame()))])
        report = self.report(replace(E.Limits(), max_json_nodes=3))
        self.assertEqual("unmeasured_bound", self.artifacts(report)[0]["validation"]["status"])
        report = E.collect(self.fixture.capture, self.fixture.scope_path,
                           replace(E.Limits(), max_chain_cache_bytes=1))
        chain = report["repositories"][0]["stream_checks"][0]
        self.assertEqual("unverified", chain["status"])
        self.assertEqual("unmeasured_bound", chain["checks"][0]["validation"]["status"])

    def test_expansion_bomb_bounded_before_canonical_egg_parser(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", b" " * 200000)
        body = buffer.getvalue()
        self.assertLess(len(body), 10000)
        self.fixture.repo("one", [("bomb.egg", body)])
        report = self.report(replace(E.Limits(), max_blob_bytes=10000))
        result = self.artifacts(report)[0]["validation"]
        self.assertEqual("unmeasured_bound", result["status"])
        self.assertFalse(result["canonical_called"])

    def test_available_and_unavailable_gitlink_accounting(self):
        commit, missing = "d" * 40, "e" * 40
        repo = self.fixture.repo("parent", [("plain", b"owner bytes")])
        repo["entries"].extend([
            self.fixture.entry("dependency", mode="160000", commit=commit),
            self.fixture.entry("missing", mode="160000", commit=missing)])
        dep_entry = self.fixture.entry("README.md", b"RAPP/1 dependency fixture")
        url = "https://github.com/other/dependency.git"
        self.fixture.dependencies = [{"commit": commit, "source_url": url, "entries": [dep_entry]}]
        self.fixture.links = [
            {"parent_repo": "parent", "path": "dependency", "commit": commit,
             "url": url, "status": "hydrated"},
            {"parent_repo": "parent", "path": "missing", "commit": missing,
             "url": None, "status": "pre-existing-unavailable"}]
        report = self.report()
        coverage = report["coverage"]
        self.assertEqual(1, coverage["owner_repositories_accounted"])
        self.assertEqual(3, coverage["owner_tracked_entries_accounted"])
        self.assertEqual(1, coverage["dependency_tracked_entries_accounted"])
        self.assertEqual(1, coverage["gitlinks_hydrated"])
        self.assertEqual(1, coverage["gitlinks_unavailable"])
        self.assertEqual(2, coverage["owner_and_dependency_unique_blobs"])

    def test_hydrated_claim_without_body_refused(self):
        commit = "d" * 40
        repo = self.fixture.repo("parent", [("plain", b"owner bytes")])
        repo["entries"].append(self.fixture.entry("dependency", mode="160000", commit=commit))
        self.fixture.links = [{
            "parent_repo": "parent", "path": "dependency", "commit": commit,
            "url": "https://github.com/other/dependency.git", "status": "hydrated"}]
        self.fixture.write()
        with self.assertRaisesRegex(E.CaptureError, "no bound dependency body"):
            self.load()

    def test_report_deterministic_and_accounting_exact(self):
        self.fixture.repo("two", [("docs/README.md", b"RAPP/1 rev-15\n"), ("empty.txt", b"")])
        self.fixture.repo("one", [("frames/0.json", json_bytes(frame()))])
        one = self.report()
        two = E.collect(self.fixture.capture, self.fixture.scope_path)
        self.assertEqual(one, two)
        coverage = collections.Counter(one["coverage"]["owner_entry_coverage"])
        self.assertEqual(3, sum(coverage.values()))
        self.assertEqual(3, one["coverage"]["owner_tracked_entries_expected"])

    def test_default_exit_not_green_and_explicit_report_only_is_collection_success(self):
        self.fixture.repo("one", [("frames/0.json", json_bytes(frame()))])
        self.fixture.write()
        args = ["--capture", str(self.fixture.capture), "--scope", str(self.fixture.scope_path),
                "--quiet"]
        with contextlib.redirect_stderr(io.StringIO()):
            default = E.main(args + ["--output", str(self.root / "default.json")])
            reporting = E.main(args + ["--output", str(self.root / "report-only.json"),
                                       "--report-only"])
        self.assertEqual(1, default)
        self.assertEqual(0, reporting)
        report = json.loads((self.root / "report-only.json").read_bytes())
        self.assertEqual("not_established", report["compatibility_verdict"])
        self.assertTrue(report["exit_semantics"]["report_only_requested"])

    def test_report_only_cannot_hide_missing_blob(self):
        repo = self.fixture.repo("one", [("plain", b"hello")])
        self.fixture.write()
        self.fixture.blob_path(repo["entries"][0]).unlink()
        output = self.root / "report.json"
        with contextlib.redirect_stderr(io.StringIO()):
            code = E.main(["--capture", str(self.fixture.capture),
                           "--scope", str(self.fixture.scope_path),
                           "--output", str(output), "--report-only", "--quiet"])
        self.assertEqual(2, code)
        self.assertEqual("capture_invalid", json.loads(output.read_bytes())["report_status"])

    def test_output_never_overwrites_capture_or_previous_report(self):
        self.fixture.repo("empty")
        self.fixture.write()
        for target in (self.fixture.capture / "new-report.json", self.fixture.scope_path):
            with self.subTest(target=target):
                with self.assertRaises(E.CaptureError):
                    E.write_report(target, {}, self.fixture.capture, self.fixture.scope_path)
        target = self.root / "report.json"
        E.write_report(target, {"first": True}, self.fixture.capture, self.fixture.scope_path)
        original = target.read_bytes()
        with self.assertRaises(E.CaptureError):
            E.write_report(target, {}, self.fixture.capture, self.fixture.scope_path)
        self.assertEqual(original, target.read_bytes())


if __name__ == "__main__":
    unittest.main()
