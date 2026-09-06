"""Frozen SPEC §§4, 6.1.1, 7, 9: independent regression and extraction checks."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import math
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

import rapp as R


ROOT = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = load("protocol_test_sdk", "agents/rapp_sdk_builder_agent.py")
MODULES = (R, A)
SID = "rappid:@audit/artifact:" + "a" * 64
UTC = "2026-09-06T00:00:00.000Z"

# RFC 8785 Appendix B, not answers obtained from either implementation.
RFC8785_NUMBERS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]
PARSE_ACCEPT = [
    ("0.1", "0.1"),
    ("9007199254740992", "9007199254740992"),
    ("100000000000000000000000", "1e+23"),
    ("295147905179352830000", "295147905179352830000"),
    ("1.00", "1"),
    ("1e0", "1"),
    ("-0", "0"),
    ("-0.000e9999", "0"),
    ("1E+21", "1e+21"),
    ("1e20", "100000000000000000000"),
    ("1e-6", "0.000001"),
    ("1e-7", "1e-7"),
    ("5e-324", "5e-324"),
]
PARSE_REFUSE = [
    "9007199254740993",
    "0.10000000000000001",
    "1.0000000000000001",
    "295147905179352825856",
    "1000000000000000128",
    "1e999",
    "1e-999",
    "NaN",
    "Infinity",
    "-Infinity",
]


def frame(module=R, **changes):
    values = dict(kind="body.pulse", stream_id=SID, seq=0, utc=UTC,
                  payload={}, prev=None)
    values.update(changes)
    return module.build_frame(**values)


def rehash(module, value):
    value["payload_hash"] = module.H("rapp/1:particle", value["payload"])
    value["frame_hash"] = module.H("rapp/1:wave", {
        key: item for key, item in value.items() if key not in ("frame_hash", "sig")
    })
    return value


def nested(containers, leaf=0):
    for _ in range(containers):
        leaf = {"v": leaf}
    return leaf


def organism(files=None):
    contents = {"rappid.json": R.canonical({"rappid": SID}).encode(),
                "soul.md": b"# synthetic fixture\n"}
    contents.update(files or {})
    return R.pack_egg("organism", SID, UTC, files=contents)


def estate(files=None):
    group = "rappid:@audit/group:" + "b" * 64
    owner = "rappid:@audit/estate:" + "c" * 64
    neighborhood = R.pack_egg(
        "neighborhood", group, UTC,
        files={"audit--artifact.egg": organism(files)}, payload={"members": [SID]},
    )
    return R.pack_egg(
        "estate", owner, UTC, files={"audit--group.egg": neighborhood},
        payload={"neighborhoods": [group]},
    )


class NumberTests(unittest.TestCase):
    def test_rfc8785_binary64_known_answers(self):
        for module in MODULES:
            for bits, expected in RFC8785_NUMBERS:
                with self.subTest(module=module.__name__, bits=bits):
                    value = struct.unpack(">d", bytes.fromhex(bits))[0]
                    self.assertEqual(module.canonical(value), expected)

    def test_native_integer_profile_is_not_uint53(self):
        for module in MODULES:
            for value, expected in ((2**53, "9007199254740992"), (10**23, "1e+23")):
                with self.subTest(module=module.__name__, value=value):
                    self.assertEqual(module.canonical(value), expected)
            for value in (2**53 + 1, 2**68, 10**999):
                with self.subTest(module=module.__name__, refused=value.bit_length()):
                    with self.assertRaises(ValueError):
                        module.canonical(value)

    def test_raw_tokens_preserve_mathematical_value(self):
        for module in MODULES:
            for token, expected in PARSE_ACCEPT:
                with self.subTest(module=module.__name__, token=token):
                    self.assertEqual(module.canonical(module._strict_json(token)), expected)

    def test_lossy_and_nonfinite_raw_tokens_are_refused(self):
        for module in MODULES:
            for token in PARSE_REFUSE:
                with self.subTest(module=module.__name__, token=token):
                    with self.assertRaises(ValueError):
                        module._strict_json('{"n":' + token + "}")

    def test_nonfinite_native_numbers_are_refused(self):
        for module in MODULES:
            for value in (math.inf, -math.inf, math.nan):
                with self.subTest(module=module.__name__, value=value):
                    with self.assertRaises(ValueError):
                        module.canonical(value)

    def test_negative_zero_uses_the_zero_address(self):
        for module in MODULES:
            self.assertEqual(module.canonical(-0.0), "0")
            self.assertEqual(module.H("rapp/1:particle", -0.0),
                             module.H("rapp/1:particle", 0))

    def test_canonical_numbers_parse_back_to_their_known_bytes(self):
        for module in MODULES:
            for _bits, text in RFC8785_NUMBERS:
                with self.subTest(module=module.__name__, text=text):
                    self.assertEqual(module.canonical(module._strict_json(text)), text)

    def test_payload_numbers_do_not_relax_sequence_grammar(self):
        for module in MODULES:
            good = frame(module, payload={"n": 2**53, "fraction": 0.1})
            self.assertTrue(module.verify_frame(good, stream_id_of_record=SID)[0])
            for seq in (True, 0.0, 2**53, -1):
                with self.subTest(module=module.__name__, seq=seq):
                    candidate = rehash(module, {**good, "seq": seq})
                    self.assertEqual(module.verify_frame(candidate)[:2], (False, "1"))
            for token in ("0.0", "0e0"):
                raw = module.canonical(good).replace('"seq":0', '"seq":' + token)
                parsed = module._strict_json(raw)
                self.assertIsInstance(parsed["seq"], float)
                self.assertEqual(module.verify_frame(parsed)[:2], (False, "1"))


class ValueDomainTests(unittest.TestCase):
    def test_utf16_order_and_no_unicode_normalization(self):
        for module in MODULES:
            self.assertEqual(module.canonical({"\ue000": 2, "\U0001f600": 1}),
                             '{"\U0001f600":1,"\ue000":2}')
            value = {"e\u0301": 1, "\u00e9": 2}
            self.assertEqual(json.loads(module.canonical(value)), value)

    def test_duplicate_members_and_surrogates(self):
        for module in MODULES:
            for raw in ('{"x":1,"x":2}', '"\\ud800"', '{"\\udfff":1}'):
                with self.subTest(module=module.__name__, raw=raw):
                    with self.assertRaises(ValueError):
                        module._strict_json(raw)
            self.assertEqual(module._strict_json('"\\ud834\\udd1e"'), "\U0001d11e")
            for value in ({1: "x"}, "\ud800", {"\udfff": 1}):
                with self.assertRaises(ValueError):
                    module.canonical(value)

    def test_cycles_are_refused_but_shared_subtrees_are_valid(self):
        for module in MODULES:
            cyclic = {}
            cyclic["self"] = cyclic
            with self.assertRaises(ValueError):
                module.canonical(cyclic)
            shared = {"x": [1]}
            self.assertEqual(module.canonical([shared, shared]), '[{"x":[1]},{"x":[1]}]')

    def test_container_depth_counts_no_scalar_leaf(self):
        for module in MODULES:
            at_limit = nested(64)
            self.assertEqual(module._strict_json(module.canonical(at_limit)), at_limit)
            with self.assertRaises(ValueError):
                module.canonical(nested(65))
            with self.assertRaises(ValueError):
                module._strict_json('{"v":' * 65 + "0" + "}" * 65)

    def test_complete_frame_depth_not_only_payload_or_preimage(self):
        for module in MODULES:
            good = frame(module, payload=nested(63))
            self.assertTrue(module.verify_frame(good, stream_id_of_record=SID)[0])
            with self.assertRaises(ValueError):
                frame(module, payload=nested(64))
            bad = {**good, "payload": nested(64)}
            self.assertEqual(module.verify_frame(bad)[:2], (False, "1"))

    def test_complete_frame_exact_byte_boundary(self):
        for module in MODULES:
            base = frame(module, payload={"text": ""})
            count = 2**20 - len(module.canonical(base).encode("utf-8"))
            good = frame(module, payload={"text": "a" * count})
            self.assertEqual(len(module.canonical(good).encode("utf-8")), 2**20)
            self.assertTrue(module.verify_frame(good, stream_id_of_record=SID)[0])
            with self.assertRaises(ValueError):
                frame(module, payload={"text": "a" * (count + 1)})
            bad = {**good, "payload": {"text": "a" * (count + 1)}}
            self.assertEqual(module.verify_frame(bad)[:2], (False, "1"))
            bad_signature = {**base, "sig": "a" * 2**20}
            self.assertEqual(module.verify_frame(bad_signature)[:2], (False, "1"))

    def test_canonical_bytes_not_raw_whitespace_or_character_count(self):
        for module in MODULES:
            self.assertEqual(module._strict_json(" " * 2**20 + "1"), 1)
            good = "\u00e9" * ((2**20 - 2) // 2)
            self.assertEqual(len(module.canonical(good).encode()), 2**20)
            self.assertEqual(module._strict_json(module.canonical(good)), good)
            with self.assertRaises(ValueError):
                module.canonical(good + "\u00e9")

    def test_invalid_verifier_inputs_are_controlled(self):
        for module in MODULES:
            cyclic = {}
            cyclic["cycle"] = cyclic
            good = frame(module)
            inputs = [None, [], "{}", 1, {1: "x"}, {**good, "payload": cyclic},
                      {**good, "payload": {"n": math.nan}},
                      {**good, "payload": {"n": "\ud800"}}]
            for value in inputs:
                with self.subTest(module=module.__name__, type=type(value).__name__):
                    result = module.verify_frame(value)
                    self.assertFalse(result[0])
                    self.assertEqual(result[1], "1")
            child = frame(module, seq=1, prev=good["payload_hash"])
            for head in ([], 1, {}):
                self.assertFalse(module.verify_frame(child, head=head)[0])


class GrammarTests(unittest.TestCase):
    def test_stream_forms_and_kind_lengths(self):
        for module in MODULES:
            good = frame(module)
            invalid_streams = ["s-1", "net:", "net:A", "net:a--b",
                               SID + ":", SID + ":" + "x" * 65]
            invalid_kinds = ["a" * 65 + ".pulse", "body." + "a" * 65,
                             "Body.Pulse", "body.a--b", "not-a-kind"]
            for key, values in (("stream_id", invalid_streams), ("kind", invalid_kinds)):
                for value in values:
                    with self.subTest(module=module.__name__, key=key, value=value):
                        bad = rehash(module, {**good, key: value})
                        self.assertEqual(module.verify_frame(bad)[:2], (False, "1"))
                        arguments = {key: value}
                        with self.assertRaises(ValueError):
                            frame(module, **arguments)

    def test_no_invented_swarm_cap_or_kind_prefix_inference(self):
        for module in MODULES:
            for stream in (SID, SID + ":instance", "net:" + "a" * 4096):
                candidate = frame(module, stream_id=stream, kind="vendor.event",
                                  sig="test-only-verifier" if stream.startswith("net:") else None)
                # Test adapter isolates grammar; it is not a positive crypto claim.
                result = module.verify_frame(candidate, stream_id_of_record=stream,
                                             signature_verifier=lambda *_: True)
                self.assertTrue(result[0], result)

    def test_ascii_fixed_calendar_timestamp(self):
        for module in MODULES:
            good = frame(module)
            for utc in ("\uff12\uff10\uff12\uff16-09-06T00:00:00.000Z",
                        "2025-02-29T00:00:00.000Z", "2026-13-01T00:00:00.000Z",
                        "2026-09-06T00:00:60.000Z", "2026-09-06T00:00:00Z"):
                with self.subTest(module=module.__name__, utc=utc):
                    self.assertFalse(module.utc_valid(utc))
                    self.assertEqual(module.verify_frame(rehash(module, {**good, "utc": utc}))[:2],
                                     (False, "1"))
            self.assertTrue(module.utc_valid("2024-02-29T23:59:59.999Z"))


class SignatureIsolationTests(unittest.TestCase):
    def test_sdk_does_not_coerce_malformed_frame_arguments(self):
        agent = A.RappSdkBuilderAgent()
        for changes in ({"seq": True}, {"seq": 0.0}, {"seq": "0"}, {"seq": 2**53},
                        {"payload": None}, {"kind": ""}, {"utc": ""}):
            with self.subTest(changes=changes):
                result = json.loads(agent.perform(action="frame", id=SID, **changes))
                self.assertEqual(result["status"], "error")
                self.assertNotIn("frame", result)

    def test_sdk_sync_checks_transitive_helpers_and_limit_constants(self):
        agent = A.RappSdkBuilderAgent()
        reference = (ROOT / "rapp.py").read_bytes()
        with mock.patch.object(A, "_fetch", return_value=reference):
            result = json.loads(agent.perform(action="sync"))
        self.assertTrue(result["embedded_matches_public_reference"])
        self.assertIn("_canonical_number", result["per_primitive"])
        self.assertIn("_strict_json", result["per_primitive"])
        changed = reference.replace(b"MAX_JSON_DEPTH = 64", b"MAX_JSON_DEPTH = 63")
        with mock.patch.object(A, "_fetch", return_value=changed):
            result = json.loads(agent.perform(action="sync"))
        self.assertFalse(result["embedded_matches_public_reference"])
        self.assertFalse(result["per_primitive"]["MAX_JSON_DEPTH"])

    def test_callback_cannot_mutate_a_verified_frame(self):
        for module in MODULES:
            candidate = frame(module, payload={"nested": ["unchanged"]}, sig="test-only")
            before = copy.deepcopy(candidate)
            expected = module.canonical({k: v for k, v in before.items() if k != "sig"})
            seen = []

            def verifier(unsigned, _signature):
                seen.append(module.canonical(unsigned))
                unsigned["payload"]["nested"].append("changed")
                return True, "test-only verifier"

            self.assertTrue(module.verify_frame(candidate, signature_verifier=verifier)[0])
            self.assertEqual(candidate, before)
            self.assertEqual(seen, [expected])
            self.assertEqual(candidate["payload_hash"], module.H("rapp/1:particle", candidate["payload"]))

    def test_refusing_or_throwing_callback_also_leaves_input_intact(self):
        for module in MODULES:
            candidate = frame(module, payload={"nested": []}, sig="test-only")
            before = copy.deepcopy(candidate)

            def verifier(unsigned, _signature):
                unsigned["payload"]["nested"].append("changed")
                raise ValueError("test refusal")

            result = module.verify_frame(candidate, signature_verifier=verifier)
            self.assertEqual(result[:2], (False, "6"))
            self.assertEqual(candidate, before)
            self.assertEqual(module.verify_frame(candidate)[:2], (False, "6"))

    def test_missing_optional_cryptography_fails_closed(self):
        original_import = __import__

        def without_cryptography(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise ImportError("deliberately absent")
            return original_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=without_cryptography):
            ok, why = R.verify_detached_jws({}, "not-a-signature", b"not-a-key")
        self.assertFalse(ok)
        self.assertIn("cryptography", why)


class SdkObservationTests(unittest.TestCase):
    def check(self, response=None, error=None):
        with mock.patch.object(A, "_fetch", return_value=response, side_effect=error):
            return json.loads(A.RappSdkBuilderAgent().perform(action="check", repo="owner/repo"))

    def test_transport_failure_is_incomplete_not_clean(self):
        result = self.check(error=OSError("controlled network failure"))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertEqual(result["identity_records_parsed"], 0)

    def test_real_404_has_no_identity_evidence_not_repository_cleanliness(self):
        error = urllib.error.HTTPError("https://example.invalid", 404, "missing", None, None)
        result = self.check(error=error)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["verdict"], "NO_ARTIFACTS")
        self.assertFalse(result["repository_artifacts_checked"])

    def test_original_duplicate_or_malformed_identity_json_refuses(self):
        bad = [
            b"{", b"[]",
            ('{"schema":"rapp/1","rappid":"invalid","rappid":"' + SID + '"}').encode(),
            ('{"schema":"rapp/1","rappid":"' + SID + '","value":1.0000000000000001}').encode(),
        ]
        for raw in bad:
            with self.subTest(raw=raw):
                result = self.check(response=raw)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["verdict"], "DRIFT")
                self.assertEqual(result["identity_records_parsed"], 0)

    def test_success_is_only_the_observed_identity_scope(self):
        result = self.check(response=R.canonical({"schema": "rapp/1", "rappid": SID}).encode())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["verdict"], "COMPLIANT")
        self.assertEqual(result["identity_records_parsed"], 1)
        self.assertFalse(result["repository_artifacts_checked"])
        self.assertFalse(result["authenticated_acceptance"])
        self.assertIn("identity", result["scope"])

    def test_invalid_identity_shapes_are_explicit_findings(self):
        for changes in ({"rappid": {}}, {"parent_rappid": False}, {"schema": "other"}):
            with self.subTest(changes=changes):
                record = {"schema": "rapp/1", "rappid": SID, **changes}
                result = self.check(response=R.canonical(record).encode())
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["verdict"], "DRIFT")
                self.assertTrue(result["findings"])


class GeneratedVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = R._strict_json(
            (ROOT / "conformance" / "vectors.json").read_bytes()
        )["sections"]

    def test_numeric_fixtures_match_independent_standard_answers(self):
        self.assertEqual(
            [(row["binary64_hex"], row["canonical"]) for row in self.vectors["4_numbers"]],
            RFC8785_NUMBERS,
        )
        self.assertEqual(
            [(row["json_text"], row["canonical"]) for row in self.vectors["4_parse_accept"]],
            PARSE_ACCEPT,
        )
        for row in self.vectors["4_refuse"]:
            for module in MODULES:
                with self.subTest(module=module.__name__, row=row):
                    with self.assertRaises(ValueError):
                        module._strict_json(row["json_text"])

    def test_all_committed_canonical_and_hash_vectors(self):
        for module in MODULES:
            for row in self.vectors["4_canonical"]:
                self.assertEqual(module.canonical(row["value"]), row["canonical"])
            hashes = self.vectors["5_hash"]
            for space, expected in hashes["H"].items():
                self.assertEqual(module.H(space, hashes["value"]), expected)
            for space, octets in (("rapp/1:egg", b"raw octets\x00\xff"),
                                  ("rapp/1:rappid", b"\x30\x2a fake-spki")):
                self.assertEqual(module.Hb(space, octets), hashes["Hb"][space])

    def test_all_committed_identity_and_frame_vectors(self):
        identities = self.vectors["6_rappid"]
        chain = self.vectors["7_frame"]
        for module in MODULES:
            for value in identities["valid"]:
                self.assertTrue(module.rappid_valid(value))
            for value in identities["invalid"]:
                self.assertFalse(module.rappid_valid(value))
            keyed = identities["keyed_mint"]
            self.assertEqual(module.mint_rappid("kody", "twin", bytes.fromhex(keyed["spki_der_hex"])),
                             keyed["rappid"])
            self.assertTrue(module.verify_frame(chain["genesis"], stream_id_of_record=chain["stream_id"])[0])
            self.assertTrue(module.verify_frame(
                chain["child"], head=chain["genesis"], stream_id_of_record=chain["stream_id"]
            )[0])
            for row in chain["tampers"]:
                with self.subTest(module=module.__name__, label=row["label"]):
                    self.assertEqual(module.verify_frame(
                        row["frame"], head=row["head"], stream_id_of_record=row["stream_id_of_record"]
                    )[:2], (False, row["expect_step"]))

    def test_late_refusal_vectors_reach_all_steps_with_valid_hashes(self):
        tampers = self.vectors["7_frame"]["tampers"]
        self.assertEqual({row["expect_step"] for row in tampers}, {"1", "1a", "2", "3", "4", "5", "6"})
        for row in tampers:
            if row["expect_step"] in {"4", "5", "6"}:
                original = copy.deepcopy(row["frame"])
                self.assertEqual(rehash(R, copy.deepcopy(original)), original)

    def test_committed_session_egg_bytes_and_address(self):
        egg = self.vectors["9_egg"]
        manifest = egg["manifest"]
        packed = R.pack_egg(
            manifest["variant"], manifest["rappid"], manifest["created_utc"],
            payload=manifest["payload"], sig=manifest["sig"],
        )
        self.assertEqual(packed.hex(), egg["egg_octets_hex"])
        self.assertEqual(R.egg_address(manifest), egg["egg_address"])
        self.assertTrue(R.verify_egg(packed)[0])


class EggAndExtractionTests(unittest.TestCase):
    def test_tree_variants_require_zip_even_when_empty(self):
        for variant, payload in (("estate", {"neighborhoods": []}),
                                 ("neighborhood", {"members": []})):
            with self.subTest(variant=variant):
                blob = R.pack_egg(variant, SID, UTC, payload=payload)
                self.assertTrue(R.verify_egg(blob)[0])
                manifest, _ = R.read_egg(blob)
                self.assertEqual(R.verify_egg(R.canonical(manifest).encode())[:2],
                                 (False, "§9.1"))

    def test_json_variant_cannot_be_wrapped_in_a_zip(self):
        blob = R.pack_egg("session", SID, UTC, payload={"runtime": "test", "transcript": []})
        class Utf8Info(zipfile.ZipInfo):
            def _encodeFilenameFlags(self):
                return self.filename.encode("utf-8"), self.flag_bits | 0x800
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr(Utf8Info("manifest.json", (1980, 1, 1, 0, 0, 0)), blob)
        self.assertEqual(R.verify_egg(out.getvalue())[:2], (False, "§9.1"))

    def test_session_scalar_leaf_at_container_depth64(self):
        blob = R.pack_egg("session", SID, UTC,
                          payload={"runtime": "test", "transcript": [nested(61)]})
        self.assertTrue(R.verify_egg(blob)[0])

    def test_protocol_paths_are_exact_but_extraction_policy_is_conservative(self):
        for paths in (("A.txt", "a.txt"), ("\u0130.txt", "i\u0307.txt"),
                      ("a", "a/b"), ("MANIFEST.JSON",)):
            with self.subTest(paths=paths):
                blob = organism({path: path.encode() for path in paths})
                self.assertTrue(R.verify_egg(blob)[0], R.verify_egg(blob))
                _, files = R.read_egg(blob)
                self.assertFalse(R._path_set_valid(["manifest.json", *files]))
                for path in paths:
                    self.assertEqual(files[path], path.encode())

    def test_unsafe_wire_path_grammar_remains_refused(self):
        for path in ("../escape", "/absolute", "a\\b", "a.", "a ", "CON", "a:b",
                     "cafe\u0301.txt", "a\nb"):
            with self.subTest(path=path):
                self.assertFalse(R.verify_egg(organism({path: b"x"}))[0])

    def test_hatch_refuses_collisions_before_allocating_or_writing(self):
        hatch = load("protocol_test_hatch", "hatch_and_prove.py")
        for files in ({"A.txt": b"a", "a.txt": b"b"}, {"a": b"a", "a/b": b"b"}):
            blob = estate(files)
            self.assertTrue(R.verify_egg(blob)[0])
            manifest, _ = R.read_egg(blob)
            with mock.patch.object(hatch, "_read_pinned_gzip", return_value=blob), \
                 mock.patch.object(hatch.tempfile, "mkdtemp") as allocate, \
                 mock.patch.object(Path, "write_bytes") as write:
                with self.assertRaisesRegex(ValueError, "extraction|filesystem|collid"):
                    hatch.hatch("unused", R.egg_address(manifest), "unused")
                allocate.assert_not_called()
                write.assert_not_called()

    def test_hatch_materializes_safe_files_without_running_them(self):
        hatch = load("protocol_test_safe_hatch", "hatch_and_prove.py")
        blob = estate({"state/value.txt": b"unchanged"})
        manifest, _ = R.read_egg(blob)
        with tempfile.TemporaryDirectory() as work:
            destination = str(Path(work) / "hatch")
            with mock.patch.object(hatch, "_read_pinned_gzip", return_value=blob), \
                 mock.patch.object(hatch.tempfile, "mkdtemp", return_value=destination):
                home, returned = hatch.hatch("unused", R.egg_address(manifest), "unused")
            self.assertEqual(returned, blob)
            self.assertEqual((Path(home) / "audit--artifact/state/value.txt").read_bytes(),
                             b"unchanged")

    def test_repack_keeps_distinct_wire_members_without_extraction(self):
        repacker = load("protocol_test_repack", "egg_repack.py")
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            archive.writestr("manifest.json", json.dumps({
                "schema": "brainstem-egg/2.2-organism", "rappid": SID,
            }))
            archive.writestr("A.txt", b"uppercase")
            archive.writestr("a.txt", b"lowercase")
        repacked = repacker.repack(out.getvalue())
        self.assertTrue(R.verify_egg(repacked)[0])
        _, files = R.read_egg(repacked)
        self.assertEqual(files["A.txt"], b"uppercase")
        self.assertEqual(files["a.txt"], b"lowercase")


class HatchObservationTests(unittest.TestCase):
    def setUp(self):
        self.hatch = load("protocol_observation_hatch", "hatch_and_prove.py")
        import rapp_check
        self.checker = rapp_check
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.valid = self.root / "valid"
        self.valid.mkdir()
        (self.valid / "frame.json").write_bytes(R.canonical(frame(R)).encode())

    def test_only_nonempty_measured_compliant_scope_passes(self):
        result = self.hatch.check_bundled_repositories(self.checker, [self.valid])
        self.assertTrue(result["passed"])
        self.assertFalse(result["authenticated_acceptance"])
        self.assertGreater(result["observations"][0]["measured_artifacts"], 0)

    def test_empty_missing_incomplete_and_drift_scope_cannot_turn_green(self):
        empty = self.root / "empty"
        empty.mkdir()
        incomplete = self.root / "incomplete"
        incomplete.mkdir()
        (incomplete / "frame.json").write_bytes(R.canonical(frame(R)).encode())
        (incomplete / "settings.json").write_bytes(b"{")
        drift = self.root / "drift"
        drift.mkdir()
        bad = frame(R)
        bad["frame_hash"] = "0" * 64
        (drift / "frame.json").write_bytes(R.canonical(bad).encode())
        for scope in ([], [empty], [self.root / "missing"], [incomplete], [drift],
                      [self.valid, empty], [self.valid, self.valid]):
            with self.subTest(scope=scope):
                result = self.hatch.check_bundled_repositories(self.checker, scope)
                self.assertFalse(result["passed"])

    def test_missing_counted_checker_or_fabricated_zero_evidence_refuses(self):
        self.assertFalse(self.hatch.check_bundled_repositories(object(), [self.valid])["passed"])
        class IncompleteChecker:
            @staticmethod
            def scan_repo(path):
                return {"verdict": "COMPLIANT", "exit_code": 0, "findings": [],
                        "counts": {"verified_frames": 0, "verified_eggs": 0, "verified_identities": 0},
                        "gates": {"discovery": "pass", "local_artifacts": "pass"},
                        "coverage": {"complete_within_supported_forms": True}, "evidence": []}
        self.assertFalse(self.hatch.check_bundled_repositories(IncompleteChecker, [self.valid])["passed"])


class PlaybookIngressTests(unittest.TestCase):
    def run_recipe(self, raw):
        text = (ROOT / "STANDING-GUARD-PLAYBOOK.md").read_text().replace("\r\n", "\n")
        blocks = re.findall(r"```python\n(.*?)\n```", text, re.S)
        block = next(value for value in blocks if "raw_read_budget" in value)
        tree = ast.parse(block)
        selected = [node for node in tree.body if (
            isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "raw_read_budget" for target in node.targets)
        ) or isinstance(node, ast.For)]
        self.assertEqual(len(selected), 2)
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "0.json"
            path.write_bytes(raw)
            namespace = {"files": [str(path)], "rapp": R, "head": None, "expected_stream": SID}
            with contextlib.redirect_stdout(io.StringIO()):
                exec(compile(ast.Module(body=selected, type_ignores=[]), "published-playbook", "exec"), namespace)
            return namespace

    def test_malformed_tail_after_old_prefix_limit_is_not_ignored(self):
        valid = R.canonical(frame(R)).encode()
        raw = valid + b" " * (R.MAX_CANONICAL_BYTES + 1 - len(valid)) + b"\nnot-json"
        with self.assertRaises(ValueError):
            self.run_recipe(raw)

    def test_local_budget_overflow_refuses_instead_of_parsing_a_prefix(self):
        valid = R.canonical(frame(R)).encode()
        raw = valid + b" " * (8 * 1024 * 1024 + 1 - len(valid)) + b"\nnot-json"
        with self.assertRaisesRegex(ValueError, "local budget"):
            self.run_recipe(raw)

    def test_raw_whitespace_below_local_budget_is_not_canonical_size_drift(self):
        valid = frame(R)
        raw = R.canonical(valid).encode() + b" " * R.MAX_CANONICAL_BYTES
        result = self.run_recipe(raw)
        self.assertEqual(result["head"], valid)


if __name__ == "__main__":
    unittest.main()
