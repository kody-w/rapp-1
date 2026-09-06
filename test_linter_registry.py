"""Deterministic regressions for C06-C09; no network, signing, or application execution."""
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
import uuid

import rapp as R
import rapp_check as L
import rapp_registry as REG


ROOT = Path(__file__).resolve().parent
SID = "rappid:@test/body:" + "a" * 64
OTHER = "rappid:@test/other:" + "b" * 64
UTC = "2026-09-01T00:00:00.000Z"


def frame(seq=0, head=None, stream=SID, payload=None, kind="body.pulse", sig=None):
    return R.build_frame(kind, stream, seq, UTC, {"n": seq + 2} if payload is None else payload,
                         head["payload_hash"] if head else None, sig=sig)


def octets(value):
    return R.canonical(value).encode("utf-8")


class LinterTests(unittest.TestCase):
    def setUp(self):
        # Keep scratch inside the invoking checkout; never use a system temp directory.
        self.work = Path(".rapp-linter-test-" + uuid.uuid4().hex)
        self.work.mkdir()
        self.addCleanup(shutil.rmtree, self.work)

    def write(self, name, data):
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(octets(data) if not isinstance(data, bytes) else data)
        return path

    def scan(self):
        return L.scan_repo(self.work)

    def assert_scoped_pass(self, report):
        self.assertEqual(report["verdict"], "COMPLIANT", report["findings"])
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["scope"]["name"], "local-structural-hash")
        self.assertFalse(report["scope"]["authenticated_acceptance"])
        self.assertEqual(report["scope"]["consumer_conformance"], "not-measured")
        self.assertEqual(report["gates"]["consumer_authority"], "unmeasured")

    def assert_refused(self, report, artifact=None, step=None):
        self.assertNotEqual(report["exit_code"], 0, report)
        self.assertNotIn(report["verdict"], ("CLEAN", "COMPLIANT"))
        findings = report["findings"]
        if artifact is not None:
            findings = [f for f in findings if f["artifact"] == artifact]
        if step is not None:
            findings = [f for f in findings if f.get("step") == step]
        self.assertTrue(findings, report["findings"])
        return findings

    def test_strict_valid_identity_and_frame(self):
        self.write("rappid.json", {"schema": R.SPEC, "rappid": SID})
        self.write("frames/0.json", frame(payload={
            "n": 2, "text": "e\u0301 / \U0001f40f", "left": {"n": 1}, "right": {"n": 2},
        }))
        report = self.scan()
        self.assert_scoped_pass(report)
        self.assertEqual(report["counts"]["identities"], 1)
        self.assertEqual(report["counts"]["verified_frames"], 1)

    def test_seq_fraction_or_exponent_cannot_borrow_valid_copy_verification(self):
        valid = octets(frame())
        for spelling in (b"0.0", b"0e0", b"-0.0", b"0E+0"):
            for invalid_first in (False, True):
                with self.subTest(spelling=spelling, invalid_first=invalid_first):
                    invalid = valid.replace(b'"seq":0', b'"seq":' + spelling)
                    self.assertNotEqual(invalid, valid)
                    folder = self.work / ("case-" + uuid.uuid4().hex)
                    folder.mkdir()
                    (folder / "a.json").write_bytes(invalid if invalid_first else valid)
                    (folder / "b.json").write_bytes(valid if invalid_first else invalid)
                    report = L.scan_repo(folder)
                    self.assert_refused(report, "a.json" if invalid_first else "b.json", "1")
                    self.assertEqual(report["counts"]["verified_frames"], 1)
            with self.subTest(spelling=spelling, jsonl=True):
                folder = self.work / ("lines-" + uuid.uuid4().hex)
                folder.mkdir()
                invalid = valid.replace(b'"seq":0', b'"seq":' + spelling)
                (folder / "records.jsonl").write_bytes(valid + b"\n" + invalid + b"\n")
                self.assert_refused(L.scan_repo(folder), "records.jsonl:2", "1")

    def test_valid_fractional_payload_spellings_remain_equivalent_copies(self):
        valid = octets(frame(payload={"value": 0}))
        alternate = valid.replace(b'"value":0', b'"value":0.0')
        self.write("a.json", valid)
        self.write("b.json", alternate)
        report = self.scan()
        self.assert_scoped_pass(report)
        self.assertEqual(report["counts"]["unique_frames"], 1)
        self.assertEqual(report["counts"]["duplicate_frame_copies"], 1)
        self.assertEqual(report["counts"]["verified_frames"], 1)

    def test_c06_duplicate_payload_refused_with_original_bytes_and_path(self):
        raw = octets(frame()).replace(b'{"n":2}', b'{"n":1,"n":2}')
        path = self.write("frames/0.json", raw)
        with self.assertRaises(ValueError):
            R._strict_json(raw)
        report = self.scan()
        finding = self.assert_refused(report, "frames/0.json", "parse")[0]
        self.assertIn("duplicate", finding["detail"])
        self.assertEqual(finding["path"], str(path.absolute()))
        self.assertEqual(finding["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(finding["size_bytes"], len(raw))
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(report["counts"]["documents_attempted"], 1)
        self.assertEqual(report["counts"]["documents_parsed"], 0)
        self.assertEqual(report["counts"]["verified_frames"], 0)

    def test_duplicate_identity_members_refused(self):
        raw = b'{"schema":"rapp/1","rappid":"wrong","rappid":"' + SID.encode() + b'"}'
        self.write("rappid.json", raw)
        self.assert_refused(self.scan(), "rappid.json", "parse")

    def test_duplicate_named_frame_members_refused(self):
        raw = octets(frame()).replace(b'"seq":0', b'"seq":3,"seq":0')
        self.write("named.json", raw)
        finding = self.assert_refused(self.scan(), "named.json", "parse")[0]
        self.assertEqual(finding["sha256"], hashlib.sha256(raw).hexdigest())

    def test_invalid_json_and_domain_tokens_never_normalized(self):
        raw_frame = octets(frame())
        cases = {
            "truncated": raw_frame[:-1],
            "invalid-utf8": b'{"text":"\xff"}',
            "surrogate": raw_frame.replace(b'{"n":2}', b'{"text":"\\ud800"}'),
            "overflow": raw_frame.replace(b'{"n":2}', b'{"n":1e999}'),
            "nan": raw_frame.replace(b'{"n":2}', b'{"n":NaN}'),
            "infinity": raw_frame.replace(b'{"n":2}', b'{"n":Infinity}'),
            "rounded-integer": raw_frame.replace(b'{"n":2}', b'{"n":9007199254740993}'),
            "nested-duplicate": raw_frame.replace(b'{"n":2}', b'{"a":[{"n":1,"n":2}]}'),
            "escaped-duplicate": raw_frame.replace(b'{"n":2}', b'{"n":1,"\\u006e":2}'),
        }
        for name, raw in cases.items():
            self.write("frames/" + name + ".json", raw)
        report = self.scan()
        for name in cases:
            with self.subTest(case=name):
                self.assert_refused(report, "frames/" + name + ".json", "parse")
        self.assertEqual(report["counts"]["verified_frames"], 0)

    def test_shared_strict_parser_receives_each_ingress_without_reencoding(self):
        identity = octets({"schema": R.SPEC, "rappid": SID})
        genesis = b"  " + octets(frame()) + b"\n"
        log = octets(frame()) + b"\n"
        egg = R.pack_egg("session", SID, UTC, payload={"runtime": "test", "transcript": []})
        self.write("rappid.json", identity)
        self.write("frames/named.json", genesis)
        self.write("events/frames.jsonl", log)
        self.write("saved.json", egg)
        with mock.patch.object(R, "_strict_json", wraps=R._strict_json) as parse:
            report = self.scan()
        self.assert_scoped_pass(report)
        inputs = [call.args[0] for call in parse.call_args_list]
        for raw in (identity, genesis, log, egg):
            self.assertIn(raw, inputs)
        self.assertEqual(report["counts"]["eggs"], 1)

    def test_c07_same_stream_successor_passes_with_fixed_inferred_identity(self):
        genesis = frame()
        self.write("frames/0.json", genesis)
        self.write("frames/1.json", frame(1, genesis))
        report = self.scan()
        self.assert_scoped_pass(report)
        self.assertEqual(report["counts"]["verified_frames"], 2)
        self.assertEqual(report["containers"][0]["stream_id"], SID)
        self.assertEqual(report["containers"][0]["inferred_from"], "frames/0.json")
        self.assertEqual(report["containers"][0]["binding"], "inferred-not-authenticated")

    def test_c07_cross_stream_numbered_splice_refused(self):
        genesis = frame()
        child = frame(1, genesis, OTHER)
        self.assertEqual(R.verify_frame(child, head=genesis, stream_id_of_record=SID)[:2],
                         (False, "1a"))
        self.write("frames/0.json", genesis)
        self.write("frames/1.json", child)
        self.assert_refused(self.scan(), "frames/1.json", "1a")

    def test_cross_stream_jsonl_splice_refused(self):
        genesis = frame()
        self.write("events/activity.jsonl", octets(genesis) + b"\n"
                   + octets(frame(1, genesis, OTHER)) + b"\n")
        self.assert_refused(self.scan(), "events/activity.jsonl:2", "1a")

    def test_cross_stream_named_directory_splice_refused(self):
        genesis = frame()
        self.write("frames/start.json", genesis)
        self.write("frames/end.json", frame(1, genesis, OTHER))
        self.assert_refused(self.scan(), "frames/end.json", "1a")

    def test_separate_containers_do_not_share_inferred_stream_id(self):
        self.write("one/frames/0.json", frame())
        self.write("two/frames/0.json", frame(stream=OTHER))
        report = self.scan()
        self.assert_scoped_pass(report)
        self.assertEqual({c["stream_id"] for c in report["containers"]}, {SID, OTHER})
        self.assertEqual(len(report["chains"]), 2)

    def test_no_kind_family_or_registered_adoption_inferred_from_prefix(self):
        self.write("named.json", frame(kind="memory.custom"))
        report = self.scan()
        self.assert_scoped_pass(report)
        self.assertIn("kind-family", " ".join(report["scope"]["unmeasured"]))
        self.assertIn("registry", report["evidence"][0]["ok"])

    def test_c08_named_json_and_jsonl_invalid_frames_are_counted(self):
        invalid = frame()
        invalid["kind"] = "Body.Pulse"
        invalid["frame_hash"] = R.H("rapp/1:wave", {
            key: value for key, value in invalid.items() if key not in ("frame_hash", "sig")
        })
        self.write("named.json", invalid)
        self.write("frames/named.json", invalid)
        self.write("events/frames.jsonl", octets(invalid) + b"\n")
        report = self.scan()
        self.assertEqual(report["counts"]["frames"], 3)
        self.assertEqual(report["counts"]["unique_frames"], 1)
        self.assertEqual(report["counts"]["duplicate_frame_copies"], 2)
        for path in ("named.json", "frames/named.json", "events/frames.jsonl:1"):
            self.assert_refused(report, path, "1")

    def test_valid_named_json_and_generic_jsonl_are_discovered(self):
        genesis = frame()
        self.write("snapshot.json", genesis)
        self.write("activity.jsonl", octets(genesis) + b"\n" + octets(frame(1, genesis)) + b"\n")
        report = self.scan()
        self.assert_scoped_pass(report)
        self.assertEqual(report["counts"]["frames"], 3)
        self.assertEqual(report["counts"]["unique_frames"], 2)
        self.assertEqual(report["counts"]["jsonl_records"], 2)

    def test_duplicate_jsonl_bytes_report_precise_line_and_offset(self):
        first = octets(frame()) + b"\n"
        bad = octets(frame(1, frame())).replace(b'{"n":3}', b'{"n":1,"n":3}') + b"\n"
        self.write("events/frames.jsonl", first + bad)
        finding = self.assert_refused(self.scan(), "events/frames.jsonl:2", "parse")[0]
        self.assertEqual(finding["line"], 2)
        self.assertEqual(finding["byte_offset"], len(first))
        self.assertEqual(finding["size_bytes"], len(bad))
        self.assertEqual(finding["sha256"], hashlib.sha256(bad).hexdigest())

    def test_jsonl_valid_frame_does_not_hide_malformed_or_nonframe_record(self):
        self.write("events/frames.jsonl", octets(frame()) + b"\n" + b'{"unfinished":\n{}\n')
        report = self.scan()
        self.assert_refused(report, "events/frames.jsonl:2", "parse")
        self.assert_refused(report, "events/frames.jsonl:3", "1")

    def test_generic_frame_log_nonframe_records_are_not_silently_ignored(self):
        self.write("activity.jsonl", b'{"status":"ok"}\n' + octets(frame()) + b"\n")
        self.assert_refused(self.scan(), "activity.jsonl:1", "1")

    def test_malformed_generic_json_has_explicit_unclassified_refusal(self):
        self.write("settings.json", b'{"broken":')
        report = self.scan()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assert_refused(report, "settings.json", "parse")
        self.assertFalse(report["coverage"]["complete_within_supported_forms"])

    def test_empty_declared_stream_is_not_green(self):
        self.write("events/frames.jsonl", b"\n\n")
        report = self.scan()
        self.assert_refused(report, "events/frames.jsonl")
        self.assertEqual(report["counts"]["frames"], 0)

    def test_nonexistent_root_is_error(self):
        report = L.scan_repo(self.work / "absent")
        self.assertEqual(report["verdict"], "ERROR")
        self.assertEqual(report["exit_code"], 2)
        self.assert_refused(report)

    def test_file_root_is_error(self):
        path = self.write("file.json", frame())
        report = L.scan_repo(path)
        self.assertEqual(report["verdict"], "ERROR")
        self.assert_refused(report)

    def test_unreadable_root_is_error_even_if_account_could_bypass_mode_bits(self):
        with mock.patch.object(L.os, "scandir", side_effect=PermissionError(
                errno.EACCES, "test denied directory", str(self.work.absolute()))):
            report = self.scan()
        self.assertEqual(report["verdict"], "ERROR")
        self.assert_refused(report)
        self.assertIn("PermissionError", report["findings"][0]["detail"])

    def test_unreadable_candidate_not_silently_skipped(self):
        self.write("frames/named.json", frame())
        with mock.patch.object(L.os, "open", side_effect=PermissionError("test denied file")):
            report = self.scan()
        self.assert_refused(report, "frames/named.json")
        self.assertFalse(report["coverage"]["complete_within_supported_forms"])

    def test_unreadable_descendant_directory_makes_coverage_incomplete(self):
        denied = self.work / "blocked"
        denied.mkdir()
        original = L.os.scandir

        def scandir(path):
            if os.fspath(path) == str(denied.absolute()):
                raise PermissionError(errno.EACCES, "test denied subtree", str(denied.absolute()))
            return original(path)

        self.write("frame.json", frame())
        with mock.patch.object(L.os, "scandir", side_effect=scandir):
            report = self.scan()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assert_refused(report, "blocked")

    def test_empty_root_has_no_artifacts_not_protocol_success(self):
        report = self.scan()
        self.assertEqual(report["verdict"], "NO_ARTIFACTS")
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["gates"]["local_artifacts"], "unmeasured")
        self.assertEqual(report["evidence"], [])

    def test_configs_fixtures_and_source_strings_are_not_frames(self):
        self.write("config.json", {"name": "service", "port": 8080})
        self.write("fixtures.json", {"fixtures": [frame()]})
        self.write("array.json", [frame()])
        self.write("schema.json", {"properties": {"spec": {"const": "rapp/1"}}})
        self.write("orient.json", {"stream_id": SID, "spec": {"revision": "rev-15"}})
        self.write("source.json", R.canonical(frame()).encode("utf-8").decode())
        self.write("source.py", b'FRAME = ' + octets(frame()))
        report = self.scan()
        self.assertEqual(report["verdict"], "NO_ARTIFACTS")
        self.assertEqual(report["counts"]["frames"], 0)
        self.assertEqual(len(report["coverage"]["exclusions"]), 6)
        self.assertTrue(report["coverage"]["not_measured"])
        self.assertEqual(report["coverage"]["ignored_extensions"][".py"], 1)

    def test_declared_incomplete_or_nonobject_frames_all_refused(self):
        self.write("frames/array.json", [])
        self.write("frames/null.json", b"null")
        self.write("frames/empty.json", {})
        self.write("frames/typed-stream.json", {"spec": R.SPEC, "stream_id": 7})
        self.write("explicit.json", {"spec": R.SPEC})
        report = self.scan()
        for name in ("frames/array.json", "frames/null.json", "frames/empty.json",
                     "frames/typed-stream.json", "explicit.json"):
            self.assert_refused(report, name, "1")

    def test_duplicate_immutable_copies_do_not_advance_chain(self):
        genesis = frame()
        successor = frame(1, genesis)
        self.write("frames/000.json", genesis)
        self.write("frames/001.json", successor)
        self.write("snapshot.json", b" \n" + octets(genesis) + b"\n")
        self.write("archive.jsonl", octets(genesis) + b"\n" + octets(successor) + b"\n"
                   + octets(genesis) + b"\n")
        report = self.scan()
        self.assert_scoped_pass(report)
        self.assertEqual(report["counts"]["frames"], 6)
        self.assertEqual(report["counts"]["unique_frames"], 2)
        self.assertEqual(report["counts"]["duplicate_frame_copies"], 4)
        self.assertEqual(report["counts"]["verified_frames"], 2)
        self.assertEqual(report["chains"][0]["locally_verified_through_seq"], 1)

    def test_same_stream_forks_refuse_both_branches_and_descendants(self):
        genesis = frame()
        left, right = frame(1, genesis), frame(1, genesis, payload={"different": True})
        self.write("frames/start.json", genesis)
        self.write("left.json", left)
        self.write("right.json", right)
        self.write("descendant.json", frame(2, left))
        report = self.scan()
        for name in ("left.json", "right.json", "descendant.json"):
            findings = self.assert_refused(report, name)
            self.assertTrue(any(f["rule"] == "§7.6 fork" for f in findings))
        self.assertEqual(report["chains"][0]["fork_at_seq"], 1)
        self.assertEqual(report["chains"][0]["locally_verified_through_seq"], 0)

    def test_conflicting_genesis_is_not_an_authorized_head_reset(self):
        self.write("old.json", frame())
        self.write("new.json", frame(payload={"replacement": True}))
        report = self.scan()
        self.assert_refused(report, "old.json")
        self.assert_refused(report, "new.json")
        self.assertEqual(report["counts"]["verified_frames"], 0)
        self.assertIsNone(report["chains"][0]["locally_verified_through_seq"])

    def test_out_of_order_fork_does_not_leave_the_other_branch_verified(self):
        genesis = frame()
        left = frame(1, genesis)
        descendant = frame(2, left)
        right = frame(1, genesis, payload={"fork": True})
        self.write("events/frames.jsonl",
                   b"\n".join(map(octets, (genesis, left, descendant, right))) + b"\n")
        report = self.scan()
        for line in (2, 3, 4):
            findings = self.assert_refused(report, f"events/frames.jsonl:{line}")
            self.assertTrue(any(f["rule"] == "§7.6 fork" for f in findings))
        self.assertEqual(report["chains"][0]["fork_at_seq"], 1)
        self.assertEqual(report["counts"]["verified_frames"], 1)

    def test_partial_chain_only_hash_prefix_is_reported_and_gate_fails(self):
        unknown = frame()
        self.write("snapshot.json", frame(1, unknown))
        report = self.scan()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        finding = self.assert_refused(report, "snapshot.json", "4")[0]
        self.assertEqual(finding["rule"], "§7.5 missing chain context")
        self.assertEqual(report["chains"][0]["status"], "partial")
        self.assertEqual(report["counts"]["verified_frames"], 0)
        self.assertIsNone(report["chains"][0]["locally_verified_through_seq"])
        self.assertIn("steps 1-3", " ".join(report["artifacts"][0]["checks"]))

    def test_missing_middle_context_does_not_reparent_or_advance_head(self):
        genesis = frame()
        missing = frame(1, genesis)
        self.write("frames/0.json", genesis)
        self.write("frames/2.json", frame(2, missing))
        report = self.scan()
        self.assert_refused(report, "frames/2.json", "4")
        self.assertEqual(report["chains"][0]["locally_verified_through_seq"], 0)
        self.assertEqual(report["counts"]["verified_frames"], 1)

    def test_invalid_predecessor_does_not_become_chain_context(self):
        genesis = frame()
        invalid = frame(1, genesis)
        invalid["payload_hash"] = "f" * 64
        self.write("frames/0.json", genesis)
        self.write("frames/1.json", invalid)
        self.write("frames/2.json", frame(2, invalid))
        report = self.scan()
        self.assert_refused(report, "frames/1.json", "2")
        self.assert_refused(report, "frames/2.json", "4")
        self.assertEqual(report["chains"][0]["locally_verified_through_seq"], 0)

    def test_distinct_jsonl_history_is_not_silently_sorted(self):
        genesis = frame()
        one = frame(1, genesis)
        two = frame(2, one)
        self.write("events/frames.jsonl", b"\n".join(map(octets, (genesis, two, one))) + b"\n")
        findings = self.assert_refused(self.scan(), "events/frames.jsonl:3")
        self.assertTrue(any(f["rule"] == "§7.6 source order" for f in findings))

    def test_signature_variant_not_hidden_as_a_hash_duplicate(self):
        genesis = frame()
        signed = dict(genesis, sig="not-authenticated")
        self.assertEqual(genesis["frame_hash"], signed["frame_hash"])
        self.write("unsigned.json", genesis)
        self.write("signed.json", signed)
        report = self.scan()
        self.assert_refused(report, "signed.json")
        self.assertEqual(report["counts"]["duplicate_frame_copies"], 0)
        self.assertEqual(report["counts"]["unique_frames"], 2)
        self.assertFalse(report["scope"]["authenticated_acceptance"])

    def test_absent_required_swarm_signature_is_not_accepted(self):
        self.write("swarm.json", frame(stream="net:test", kind="swarm.pulse"))
        report = self.scan()
        self.assert_refused(report, "swarm.json", "6")
        self.assertEqual(report["verdict"], "DRIFT")

    def test_file_byte_limit_is_explicit_not_domain_normalization(self):
        self.write("frames/named.json", frame())
        with mock.patch.object(L, "MAX_JSON_BYTES", 16):
            report = self.scan()
        self.assert_refused(report, "frames/named.json")
        self.assertEqual(report["counts"]["bytes_read"], 0)
        self.assertEqual(report["coverage"]["limits"]["json_file_or_line_bytes"], 16)
        self.assertTrue(report["coverage"]["exclusions"][0]["affects_gate"])

    def test_total_read_budget_cannot_produce_partial_green(self):
        raw = octets(frame())
        self.write("frames/0.json", raw)
        self.write("frames/1.json", raw)
        with mock.patch.object(L, "MAX_TOTAL_BYTES", len(raw)):
            report = self.scan()
        self.assert_refused(report, "frames/1.json")
        self.assertEqual(report["counts"]["bytes_read"], len(raw))

    def test_document_and_jsonl_line_limits_disclose_unread_tail(self):
        self.write("events/frames.jsonl", (octets(frame()) + b"\n") * 3)
        for name in ("MAX_DOCUMENTS", "MAX_JSONL_LINES"):
            with self.subTest(limit=name), mock.patch.object(L, name, 1):
                report = self.scan()
                finding = self.assert_refused(report, "events/frames.jsonl:2")[0]
                self.assertGreater(finding["remaining_bytes"], 0)
                self.assertFalse(report["coverage"]["complete_within_supported_forms"])

    def test_jsonl_single_line_budget_disclosed(self):
        self.write("events/frames.jsonl", octets(frame()) + b"\n")
        with mock.patch.object(L, "MAX_JSON_BYTES", 16):
            report = self.scan()
        self.assert_refused(report, "events/frames.jsonl:1")

    def test_file_count_limit_disclosed(self):
        self.write("a.json", frame())
        self.write("b.json", frame())
        with mock.patch.object(L, "MAX_FILES", 1):
            report = self.scan()
        self.assert_refused(report, "b.json")

    def test_symlink_candidate_not_followed_or_silently_skipped(self):
        target = self.write("bytes.bin", octets({"schema": R.SPEC, "rappid": SID}))
        (self.work / "rappid.json").symlink_to(target.name)
        report = self.scan()
        self.assert_refused(report, "rappid.json")
        self.assertEqual(report["counts"]["bytes_read"], 0)

    def test_templates_are_scaffolding_not_measured_deployed_identities(self):
        self.write("rappid.json", {"schema": R.SPEC, "rappid": "rappid:@test/body:__RAPPID__"})
        report = self.scan()
        self.assertEqual(report["verdict"], "NO_ARTIFACTS")
        self.assertEqual(report["counts"]["verified_identities"], 0)
        self.assertEqual(report["evidence"][0]["scope"], "scaffolding-only")

    def test_identity_schema_parent_and_name_hash_checks_not_disabled(self):
        cases = {
            "schema": {"rappid": SID},
            "parent": {"schema": R.SPEC, "rappid": SID, "parent_rappid": "invalid"},
            "name-hash": {"schema": R.SPEC, "rappid":
                         "rappid:@test/body:" + hashlib.sha256(b"test/body").hexdigest()},
        }
        for name, identity in cases.items():
            self.write(name + "/rappid.json", identity)
        report = self.scan()
        for name in cases:
            self.assert_refused(report, name + "/rappid.json")

    def test_eggs_delegate_integrity_and_path_checks_without_extraction(self):
        files = {"rappid.json": octets({"schema": R.SPEC, "rappid": SID}), "soul.md": b"# test\n"}
        valid = R.pack_egg("organism", SID, UTC, files=files)
        invalid_files = dict(files, **{"../escape.txt": b"refuse, do not extract"})
        invalid = R.pack_egg("organism", SID, UTC, files=invalid_files)
        self.write("valid.egg", valid)
        self.write("unsafe.egg", invalid)
        report = self.scan()
        self.assert_refused(report, "unsafe.egg")
        self.assertEqual(report["counts"]["eggs"], 2)
        self.assertEqual(report["counts"]["verified_eggs"], 1)
        self.assertEqual(sorted(p.name for p in self.work.iterdir()), ["unsafe.egg", "valid.egg"])

    def test_json_egg_duplicate_members_are_not_repaired(self):
        raw = R.pack_egg("session", SID, UTC, payload={"runtime": "test", "transcript": []})
        raw = raw.replace(b'"runtime":"test"', b'"runtime":"other","runtime":"test"')
        self.write("bad.egg", raw)
        self.assert_refused(self.scan(), "bad.egg")

    def test_declared_egg_in_unsupported_jsonl_does_not_disappear(self):
        raw = R.pack_egg("session", SID, UTC, payload={"runtime": "test", "transcript": []})
        self.write("frame.json", frame())
        self.write("eggs.jsonl", raw + b"\n")
        report = self.scan()
        self.assert_refused(report, "eggs.jsonl:1")
        self.assertEqual(report["counts"]["eggs"], 1)

    def test_check_repo_tuple_and_json_cli_compatibility(self):
        self.write("frames/0.json", frame())
        verdict, findings, evidence = L.check_repo(self.work)
        self.assertEqual(verdict, "COMPLIANT")
        self.assertEqual(findings, [])
        self.assertTrue(evidence)
        command = [sys.executable, "-S", "-B", str(ROOT / "rapp_check.py")]
        for root, expected in ((self.work, 0), (self.work / "missing", 2)):
            process = subprocess.run(command + [str(root), "--json"], capture_output=True, text=True)
            self.assertEqual(process.returncode, expected, process.stderr)
            self.assertEqual(process.stderr, "")
            report = json.loads(process.stdout)
            self.assertEqual(report["exit_code"], expected)
            self.assertIn("counts", report)
            self.assertFalse(report["scope"]["authenticated_acceptance"])

    def test_actual_anchor_frames_are_counted_without_authentication_claim(self):
        lines = (ROOT / "anchor/chain.jsonl").read_bytes().splitlines()
        copies = list((ROOT / "anchor/frames").glob("*.json"))
        report = L.scan_repo(ROOT)
        self.assert_scoped_pass(report)
        self.assertEqual(len(lines), len(copies))
        self.assertEqual(report["counts"]["frames"], len(lines) + len(copies))
        self.assertEqual(report["counts"]["unique_frames"], len(lines))
        self.assertEqual(report["counts"]["duplicate_frame_copies"], len(copies))
        self.assertEqual(report["counts"]["verified_frames"], len(lines))
        self.assertEqual(report["counts"]["identities"], 1)
        self.assertEqual(report["counts"]["eggs"], 0)
        self.assertEqual(report["chains"][0]["genesis_registration"], "not-measured")


class RegistryBindingTests(unittest.TestCase):
    def registry(self, deprecated=False, family="body", kind="body.pulse"):
        return REG.Registry([
            {"type": "estate_owner", "rappid": SID},
            {"type": "kind", "kind": kind, "family": family, "deprecated": deprecated},
        ])

    def test_c09_retired_known_kind_preserves_unchanged_historical_frame(self):
        genesis = frame()
        raw = octets(genesis)
        before, after = self.registry(), self.registry(deprecated=True)
        self.assertEqual(before.check_frame_binding(genesis), (True, "ok"))
        self.assertEqual(after.check_frame_binding(genesis), (True, "ok"))
        self.assertEqual(after.family("body.pulse"), "body")
        self.assertEqual(octets(genesis), raw)
        self.assertEqual(R.verify_frame(genesis, stream_id_of_record=SID), (True, None, "ok"))

    def test_retirement_changes_only_producer_discovery_policy(self):
        before, after = self.registry(), self.registry(deprecated=True)
        self.assertEqual(before.producer_family("body.pulse"), "body")
        self.assertIsNone(after.producer_family("body.pulse"))
        self.assertEqual(before.family("body.pulse"), after.family("body.pulse"))

    def test_unknown_kind_remains_refused(self):
        for retired in (False, True):
            registry = self.registry(retired)
            self.assertFalse(registry.check_frame_binding(frame(kind="body.unknown"))[0])
            self.assertIsNone(registry.family("body.unknown"))
            self.assertIsNone(registry.producer_family("body.unknown"))

    def test_family_mismatch_refused_before_and_after_retirement(self):
        for retired in (False, True):
            ok, reason = self.registry(retired, family="memory").check_frame_binding(frame())
            self.assertFalse(ok)
            self.assertIn("incompatible", reason)

    def test_registered_family_not_kind_prefix_controls_binding(self):
        registry = self.registry(deprecated=True, family="memory", kind="body.pulse")
        self.assertEqual(registry.check_frame_binding(frame(stream=SID + ":session")),
                         (True, "ok"))
        self.assertFalse(registry.check_frame_binding(frame())[0])

    def test_structural_registry_is_not_a_signed_document(self):
        registry = self.registry()
        self.assertFalse(hasattr(registry, "sig"))
        before = copy.deepcopy(registry.entries)
        registry.check_frame_binding(frame())
        self.assertEqual(registry.entries, before)

    def test_invalid_kind_value_refused_without_lookup_exception(self):
        registry = self.registry()
        for kind in (None, [], {}):
            self.assertFalse(registry.check_frame_binding(dict(frame(), kind=kind))[0])
            self.assertIsNone(registry.family(kind))
            self.assertIsNone(registry.producer_family(kind))

    def test_nonobject_frame_binding_is_explicit_refusal(self):
        for value in (None, [], "frame"):
            self.assertEqual(self.registry().check_frame_binding(value),
                             (False, "frame MUST be an object"))


if __name__ == "__main__":
    unittest.main()
