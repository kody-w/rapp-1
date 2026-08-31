#!/usr/bin/env python3
"""Focused conformance tests for the RAPP/1 DOGG specification chain."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import unittest
import uuid


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rapp as R
from anchor import materialize_spec as M
from anchor import update_anchor as U


CHAIN = ROOT / "anchor" / "chain.jsonl"
ORIENT = ROOT / "anchor" / "orient.json"
INDEX = ROOT / "anchor" / "index.json"
SPEC = ROOT / "SPEC.md"
REPLACED_DRAFT_FRAME_HASH = (
    "aa9af1c34eefab67d08c6fe814206d635d6a20f48a3ebbe30d0724b218d0afd9"
)
HISTORICAL_LINE_SHA256 = (
    "dd11f0775259cb92a2d1f02034c8dc076510b4470a9e9720cb5225802fa8dd4b",
    "a3fdef2b31d2168396ddf534ff87b7578842354e5232a2b95a77cef5cbd23ced",
    "da9e14d90e7ad909f5c876262d1c19f18f0a25a253babd00519e43c96f2fe0b3",
    "c4791aca601cdb0b1adeea68019fb5f6369c5ab43b81934d2092720e4b05bbf1",
    "c8abf05c4323a0a967fdd4dffe73acd3b7b33dbcb1225e35d72aeb44b3c42deb",
    "c5b03b1d9e3fd97a07832e3583c2a784aee579dfc419dbc5ffb6052dd029af9e",
    "25a7103366583eaf416477551631b331bd9d273991c3510d2f7a890246955e9f",
    "495dfe6c9551ea392a3bc4df4f98e28ed2be096ea1305f649bb589905bea7536",
    "7f6997d018cae005600f2e9d84fd0808bc1360627423d3ebe742071407856b5d",
    "aa59998bbdffaf7525d6db5cec2053b30c0e8f91560cad7f2cac4802331269f3",
    "d8b62080efc76f8bbe5d165ddc55491488fe4e05f0d2584f23cc237499c99577",
    "9a6f3773b1206e1e72dcb9cd67ade6a5d6d442c5af868c7b4d248f010c4d774f",
    "e9877cd1f1fe9e9c657065e7c06fc5a5cac1befa6d1ef903de4e7c0dfa1bbe88",
    "329390a26d0f270afb3357420d919c6046c8d47ace80c590ccac5371eec061e7",
    "f168e0e37d845c63f2a12f842b486f20c5abfc9236263c8cf2aad53928f72acb",
)


class SpecChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bootstrap_profile, cls.bootstrap_index = M.load_bootstrap()
        cls.chain_octets = CHAIN.read_bytes()
        cls.lines = cls.chain_octets.splitlines(keepends=True)
        cls.frames = M.verify_chain(
            cls.chain_octets,
            bootstrap_profile=cls.bootstrap_profile,
        )
        cls.index_octets = INDEX.read_bytes()
        cls.index = M.verify_revision_index(
            cls.index_octets,
            cls.frames,
            bootstrap_index=cls.bootstrap_index,
            bootstrap_profile=cls.bootstrap_profile,
        )
        cls.orient = M.verify_orient(
            ORIENT.read_bytes(),
            cls.frames,
            index_octets=cls.index_octets,
            bootstrap_index=cls.bootstrap_index,
        )
        cls.head = cls.frames[-1]
        cls.scratch_root = ROOT / ".anchor-test-work"
        cls.scratch_root.mkdir(exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.scratch_root, ignore_errors=True)

    def scratch(self) -> pathlib.Path:
        path = self.scratch_root / uuid.uuid4().hex
        path.mkdir()
        self.addCleanup(shutil.rmtree, path, True)
        return path

    def appended(self, frame: dict, prefix: bytes | None = None) -> bytes:
        return (
            self.chain_octets if prefix is None else prefix
        ) + json.dumps(frame, ensure_ascii=False).encode("utf-8") + b"\n"

    def rebuild_last(self, payload: dict) -> bytes:
        predecessor = self.frames[-2]
        frame = R.build_frame(
            self.head["kind"],
            self.head["stream_id"],
            self.head["seq"],
            self.head["utc"],
            payload,
            predecessor["payload_hash"],
        )
        return b"".join(self.lines[:-1]) + json.dumps(
            frame, ensure_ascii=False
        ).encode("utf-8") + b"\n"

    def assert_chain_refused(self, chain_octets: bytes, contains: str) -> None:
        with self.assertRaisesRegex(M.ChainError, contains):
            M.verify_chain(chain_octets)

    def assert_rev15_head(self) -> None:
        self.assertEqual(
            (self.head["seq"], self.head["payload"]["revision"]),
            (15, "rev-15"),
            "rev-15 anchor generation has not run",
        )

    def test_historical_lines_are_byte_exact(self) -> None:
        self.assertEqual(len(self.lines), 16)
        actual = tuple(hashlib.sha256(line).hexdigest() for line in self.lines[:15])
        self.assertEqual(actual, HISTORICAL_LINE_SHA256)
        for line, frame in zip(self.lines, self.frames):
            object_path = (
                ROOT / "anchor" / "frames" / f"{frame['frame_hash']}.json"
            )
            self.assertEqual(object_path.read_bytes(), line[:-1])
        self.assertNotIn(
            REPLACED_DRAFT_FRAME_HASH,
            {frame["frame_hash"] for frame in self.frames},
        )
        self.assertFalse(
            (
                ROOT
                / "anchor"
                / "frames"
                / f"{REPLACED_DRAFT_FRAME_HASH}.json"
            ).exists()
        )

    def test_full_chain_head_and_beacon_verify(self) -> None:
        self.assert_rev15_head()
        self.assertEqual(self.head["seq"], 15)
        self.assertEqual(self.head["kind"], "body.pulse")
        self.assertEqual(set(self.head), R.FRAME_KEYS)
        self.assertEqual(self.head["payload"]["schema"], M.REVISION_SCHEMA)
        self.assertEqual(self.head["payload"]["revision"], "rev-15")
        self.assertEqual(self.orient["head"]["frame_hash"], self.head["frame_hash"])
        self.assertEqual(self.index["head"]["frame_hash"], self.head["frame_hash"])
        self.assertLessEqual(
            len(R.canonical(self.head).encode("utf-8")),
            R.MAX_CANONICAL_BYTES,
        )

    def test_spec_roundtrip_is_byte_exact_and_atomic(self) -> None:
        self.assert_rev15_head()
        materialized = M.resolve_spec_bytes(self.head, offline=True)
        self.assertEqual(materialized, SPEC.read_bytes())
        target = self.scratch() / "SPEC.md"
        target.write_bytes(b"old")
        M.atomic_write(target, materialized)
        self.assertEqual(target.read_bytes(), SPEC.read_bytes())
        self.assertFalse(any(target.parent.glob(".SPEC.md.*.tmp")))

    def test_resolution_by_every_identifier(self) -> None:
        self.assert_rev15_head()
        selectors = [
            {},
            {"revision": "rev-15"},
            {"seq": 15},
            {"frame_hash": self.head["frame_hash"]},
            {"payload_hash": self.head["payload_hash"]},
        ]
        resolved = [
            M.resolve_frame_object(
                self.frames,
                self.index,
                bootstrap_profile=self.bootstrap_profile,
                **selector,
            )
            for selector in selectors
        ]
        self.assertTrue(all(frame == self.head for frame in resolved))
        self.assertEqual(M.resolve_frame(self.frames, revision="rev-5")["seq"], 5)

    def test_bootstrap_profile_and_verifier_are_content_addressed(self) -> None:
        profile_path = ROOT / self.bootstrap_index["profile_path"]
        profile_octets = profile_path.read_bytes()
        verifier_octets = (ROOT / self.bootstrap_index["verifier_path"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(profile_octets).hexdigest(),
            self.bootstrap_index["profile_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(verifier_octets).hexdigest(),
            self.bootstrap_index["verifier_sha256"],
        )
        self.assertEqual(
            profile_path.name,
            f"sha256-{self.bootstrap_index['profile_sha256']}.json",
        )
        with self.assertRaisesRegex(M.ChainError, "verifier SHA-256 mismatch"):
            M.load_bootstrap(verifier_octets=verifier_octets + b"\n")
        with self.assertRaisesRegex(M.ChainError, "profile SHA-256 mismatch"):
            M.load_bootstrap(profile_octets=profile_octets + b"\n")

    def test_accepted_bootstrap_v1_cannot_be_deleted_or_replaced(self) -> None:
        profile_path = self.bootstrap_index["profile_path"]
        verifier_path = self.bootstrap_index["verifier_path"]
        accepted_index = (ROOT / "anchor" / "bootstrap" / "index.json").read_bytes()
        accepted_profile = (ROOT / profile_path).read_bytes()
        accepted_verifier = (ROOT / verifier_path).read_bytes()
        accepted_v2_verifier_path = "anchor/bootstrap_verify_v2.py"
        accepted_v2_verifier = b"# accepted bootstrap v2 verifier\n"
        accepted_v2 = json.loads(accepted_profile)
        accepted_v2["schema"] = "rapp-anchor-bootstrap/2"
        accepted_v2["version"] = 2
        accepted_v2["verifier"] = {
            "path": accepted_v2_verifier_path,
            "sha256": hashlib.sha256(accepted_v2_verifier).hexdigest(),
            "bytes": len(accepted_v2_verifier),
        }
        accepted_v2_profile = U.json_octets(accepted_v2)
        accepted_v2_path = (
            "anchor/bootstrap/sha256-"
            + hashlib.sha256(accepted_v2_profile).hexdigest()
            + ".json"
        )
        accepted_files = {
            "anchor/bootstrap/index.json": accepted_index,
            profile_path: accepted_profile,
            verifier_path: accepted_verifier,
            accepted_v2_path: accepted_v2_profile,
            accepted_v2_verifier_path: accepted_v2_verifier,
        }
        snapshot = U.accepted_bootstrap_snapshot(
            blob_reader=lambda _ref, path: accepted_files.get(path),
            tree_paths=[
                "anchor/bootstrap/index.json",
                profile_path,
                accepted_v2_path,
            ],
        )
        self.assertIsNotNone(snapshot)
        files = {
            **accepted_files,
        }

        def reader(path: str) -> bytes:
            if path not in files:
                raise FileNotFoundError(path)
            return files[path]

        U.preserve_accepted_bootstraps(
            snapshot,
            local_reader=reader,
            candidate_index_octets=accepted_index,
        )
        mutations = (
            ("anchor/bootstrap/index.json", None, "index was deleted"),
            ("anchor/bootstrap/index.json", b"changed", "index was changed"),
            (profile_path, None, "profile was deleted"),
            (profile_path, b"changed", "profile was changed"),
            (verifier_path, None, "verifier was deleted"),
            (verifier_path, b"changed", "verifier was changed"),
            (accepted_v2_path, None, "profile was deleted"),
            (accepted_v2_verifier_path, None, "verifier was deleted"),
        )
        for path, replacement, message in mutations:
            with self.subTest(path=path, replacement=replacement):
                original = files.get(path)
                if replacement is None:
                    files.pop(path, None)
                else:
                    files[path] = replacement
                try:
                    with self.assertRaisesRegex(M.ChainError, message):
                        U.preserve_accepted_bootstraps(
                            snapshot,
                            local_reader=reader,
                            candidate_index_octets=accepted_index,
                        )
                finally:
                    files[path] = original

    def test_v2_requires_explicit_external_transition_without_reselection(self) -> None:
        profile_path = ROOT / self.bootstrap_index["profile_path"]
        accepted_octets = profile_path.read_bytes()
        candidate = json.loads(accepted_octets)
        candidate["schema"] = "rapp-anchor-bootstrap/2"
        candidate["version"] = 2
        candidate["verifier"] = {
            "path": "anchor/bootstrap_verify_v2.py",
            "sha256": "0" * 64,
            "bytes": 1,
        }
        candidate_octets = U.json_octets(candidate)
        transition = U.build_bootstrap_transition(
            accepted_octets,
            candidate_octets,
        )
        self.assertEqual(
            transition["schema"],
            "rapp-anchor-bootstrap-transition/1",
        )
        self.assertEqual(
            transition["status"],
            "draft-external-ratification-required",
        )
        self.assertFalse(transition["selection_changed"])
        self.assertIsNone(transition["external_ratification"])

        snapshot = {
            "ref": "accepted-commit",
            "index": (ROOT / "anchor" / "bootstrap" / "index.json").read_bytes(),
            "profiles": {str(profile_path.relative_to(ROOT)): accepted_octets},
            "verifiers": {
                self.bootstrap_index["verifier_path"]: (
                    ROOT / self.bootstrap_index["verifier_path"]
                ).read_bytes()
            },
        }
        files = {
            "anchor/bootstrap/index.json": snapshot["index"],
            **snapshot["profiles"],
            **snapshot["verifiers"],
        }
        with self.assertRaisesRegex(M.ChainError, "silently replace"):
            U.preserve_accepted_bootstraps(
                snapshot,
                local_reader=lambda path: files[path],
                candidate_index_octets=b"candidate-v2-index",
            )

        mutated_v1 = json.loads(accepted_octets)
        mutated_v1["limits"]["json_nesting_depth"] -= 1
        with self.assertRaisesRegex(M.ChainError, "advance exactly one version"):
            U.build_bootstrap_transition(
                accepted_octets,
                U.json_octets(mutated_v1),
            )

    def test_wrong_content_at_hash_path_is_refused(self) -> None:
        wrong = (
            ROOT
            / "anchor"
            / "frames"
            / f"{self.frames[0]['frame_hash']}.json"
        ).read_bytes()
        with self.assertRaisesRegex(
            M.ResolutionError,
            "content does not match requested hash",
        ):
            M.resolve_frame_object(
                self.frames,
                self.index,
                frame_hash=self.head["frame_hash"],
                object_loader=lambda _path: wrong,
                bootstrap_profile=self.bootstrap_profile,
            )

    def test_publication_metadata_separates_integrity_and_authority(self) -> None:
        publication = self.head["payload"]["publication"]
        self.assertEqual(publication, M.AUTHORITY_POLICY)
        self.assertEqual(self.index["authority"], M.AUTHORITY_POLICY)
        self.assertEqual(self.orient["authority"], M.AUTHORITY_POLICY)
        self.assertEqual(publication["protected_ref"], "refs/heads/main")
        self.assertIn("owner-ratified acceptance", publication["selection"])
        self.assertEqual(publication["history_replacement"], "prohibited")
        self.assertIsNone(publication["authenticated_registry_checkpoint"])

    def test_beacon_keeps_legacy_path_alias_and_all_head_mirrors(self) -> None:
        self.assert_rev15_head()
        self.assertEqual(
            self.orient["spec"]["normative_path"],
            self.orient["spec"]["materialized_path"],
        )
        self.assertEqual(
            self.orient["registered_kinds"],
            self.head["payload"]["registered_kinds"],
        )
        expected_kinds = {
            "body.lens",
            "body.tile",
            "memory.tile",
            "swarm.tile",
        }
        self.assertTrue(
            expected_kinds <= set(self.head["payload"]["registered_kinds"])
        )
        self.assertEqual(
            self.head["payload"]["registered_kinds"],
            sorted(self.head["payload"]["registered_kinds"]),
        )
        expected_vocabulary = {
            "lens",
            "tile",
            "crack",
            "clean-frame",
            "worn-frame",
            "generation",
            "fan-out",
            "fan-in",
            "dream-caught",
            "facet",
            "marble",
            "environment",
            "facet-claim",
            "registered-genesis",
            "signature-isolation",
            "container-depth",
            "acyclic-json",
        }
        self.assertTrue(
            expected_vocabulary <= set(self.head["payload"]["vocabulary"])
        )
        self.assertEqual(
            self.orient["vocabulary"],
            self.head["payload"]["vocabulary"],
        )
        drift = copy.deepcopy(self.orient)
        drift["registered_kinds"] = drift["registered_kinds"][:-1]
        with self.assertRaisesRegex(M.ChainError, "registered_kinds mirror"):
            M.verify_orient(
                (json.dumps(drift) + "\n").encode("utf-8"),
                self.frames,
                index_octets=self.index_octets,
                bootstrap_index=self.bootstrap_index,
            )

        vocabulary_drift = copy.deepcopy(self.orient)
        del vocabulary_drift["vocabulary"]["generation"]
        with self.assertRaisesRegex(M.ChainError, "vocabulary mirror"):
            M.verify_orient(
                (json.dumps(vocabulary_drift) + "\n").encode("utf-8"),
                self.frames,
                index_octets=self.index_octets,
                bootstrap_index=self.bootstrap_index,
            )

    def test_legacy_frames_retain_immutable_pointer_contract(self) -> None:
        for frame in self.frames[:14]:
            metadata = M._legacy_metadata(frame["payload"])
            self.assertEqual(
                metadata["canonical_repo"], "https://github.com/kody-w/rapp-1"
            )
            self.assertRegex(metadata["commit"], r"^[0-9a-f]{40}$")
            self.assertEqual(metadata["normative_path"], "SPEC.md")
            self.assertRegex(metadata["normative_sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(metadata["normative_bytes"], 0)
            self.assertIn(f"/{metadata['commit']}/SPEC.md", M.legacy_url(frame["payload"]))

    def test_legacy_resolution_uses_injected_source_and_verified_cache(self) -> None:
        legacy_octets = "# legacy specification\n".encode("utf-8")
        payload = {
            "revision": "rev-1",
            "canonical_repo": "https://github.com/example/spec",
            "commit": "a" * 40,
            "normative_path": "SPEC.md",
            "normative_sha256": hashlib.sha256(legacy_octets).hexdigest(),
            "normative_bytes": str(len(legacy_octets)),
        }
        frame = {"payload": payload}
        fetched = []

        def local_source(url: str) -> bytes:
            fetched.append(url)
            return legacy_octets

        cache = self.scratch()
        self.assertEqual(
            M.resolve_spec_bytes(frame, fetcher=local_source, cache_dir=cache),
            legacy_octets,
        )
        self.assertEqual(
            fetched,
            [
                "https://raw.githubusercontent.com/example/spec/"
                + "a" * 40
                + "/SPEC.md"
            ],
        )
        self.assertEqual(
            M.resolve_spec_bytes(frame, cache_dir=cache, offline=True),
            legacy_octets,
        )
        cache_file = cache / f"{payload['normative_sha256']}.md"
        cache_file.write_bytes(b"x" * len(legacy_octets))
        with self.assertRaisesRegex(M.ResolutionError, "SHA-256 mismatch"):
            M.resolve_spec_bytes(
                frame,
                fetcher=lambda _url: self.fail("corrupt cache must not be bypassed"),
                cache_dir=cache,
            )

    def test_offline_inline_and_legacy_behavior(self) -> None:
        self.assert_rev15_head()
        self.assertEqual(M.resolve_spec_bytes(self.head, offline=True), SPEC.read_bytes())
        with self.assertRaisesRegex(M.ResolutionError, "offline mode"):
            M.resolve_spec_bytes(self.frames[13], offline=True)

    def test_mutable_legacy_pointer_is_refused(self) -> None:
        payload = copy.deepcopy(self.frames[13]["payload"])
        payload["commit"] = "main"
        with self.assertRaisesRegex(M.ChainError, "40 lowercase hex"):
            M.legacy_url(payload)

    def test_legacy_path_is_validated_before_normalization(self) -> None:
        invalid = (
            "",
            "/SPEC.md",
            "./SPEC.md",
            "SPEC.md/",
            "a//b",
            "a/./b",
            "a/../b",
            "a\\b",
            "%2e%2e/SPEC.md",
            "a/%2F/b",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(M.ChainError):
                    M._safe_normative_path(value)
        self.assertEqual(M._safe_normative_path("docs/SPEC.md"), "docs/SPEC.md")

    def test_corrupt_frame_payload_wave_and_prev_are_refused(self) -> None:
        malformed = copy.deepcopy(self.head)
        malformed["extra"] = None
        malformed_chain = b"".join(self.lines[:-1]) + json.dumps(
            malformed, ensure_ascii=False
        ).encode("utf-8") + b"\n"
        self.assert_chain_refused(malformed_chain, "eleven-key envelope")

        payload = copy.deepcopy(self.head)
        payload["payload"]["revision"] = "rev-999"
        payload_chain = b"".join(self.lines[:-1]) + json.dumps(
            payload, ensure_ascii=False
        ).encode("utf-8") + b"\n"
        self.assert_chain_refused(payload_chain, "particle mismatch")

        wave = copy.deepcopy(self.head)
        wave["frame_hash"] = "0" * 64
        wave_chain = b"".join(self.lines[:-1]) + json.dumps(
            wave, ensure_ascii=False
        ).encode("utf-8") + b"\n"
        self.assert_chain_refused(wave_chain, "wave mismatch")

        prev = copy.deepcopy(self.head)
        prev["prev"] = "0" * 64
        preimage = {
            key: value
            for key, value in prev.items()
            if key not in ("frame_hash", "sig")
        }
        prev["frame_hash"] = R.H("rapp/1:wave", preimage)
        prev_chain = b"".join(self.lines[:-1]) + json.dumps(
            prev, ensure_ascii=False
        ).encode("utf-8") + b"\n"
        self.assert_chain_refused(prev_chain, "prev does not match")

    def test_corrupt_inline_text_hash_and_length_are_refused(self) -> None:
        text = copy.deepcopy(self.head["payload"])
        text["normative"]["text"] += "x"
        self.assert_chain_refused(self.rebuild_last(text), "byte length mismatch")

        digest = copy.deepcopy(self.head["payload"])
        digest["normative"]["sha256"] = "0" * 64
        digest["normative_sha256"] = "0" * 64
        self.assert_chain_refused(self.rebuild_last(digest), "SHA-256 mismatch")

        length = copy.deepcopy(self.head["payload"])
        length["normative"]["bytes"] += 1
        length["normative_bytes"] = str(length["normative"]["bytes"])
        self.assert_chain_refused(self.rebuild_last(length), "byte length mismatch")

    def test_malformed_utf8_and_unsupported_schema_are_refused(self) -> None:
        self.assert_chain_refused(self.chain_octets[:-1] + b"\xff\n", "valid UTF-8")
        payload = copy.deepcopy(self.head["payload"])
        payload["schema"] = "rapp-spec-revision/2"
        self.assert_chain_refused(self.rebuild_last(payload), "unsupported")

    def test_malformed_scalar_fields_are_controlled_refusals(self) -> None:
        cases = (
            ("seq", []),
            ("seq", True),
            ("frame_hash", {}),
            ("payload_hash", []),
            ("prev", {}),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                frame = copy.deepcopy(self.head)
                frame[field] = value
                chain = b"".join(self.lines[:-1]) + json.dumps(
                    frame, ensure_ascii=False
                ).encode("utf-8") + b"\n"
                with self.assertRaises(M.ChainError):
                    M.verify_chain(chain)

    def test_duplicate_revision_seq_and_fork_are_refused(self) -> None:
        self.assert_rev15_head()
        legacy_predecessor = self.frames[6]
        legacy_payload = copy.deepcopy(legacy_predecessor["payload"])
        legacy_payload["test_marker"] = True
        duplicate_legacy = R.build_frame(
            "body.pulse",
            legacy_predecessor["stream_id"],
            7,
            legacy_predecessor["utc"],
            legacy_payload,
            legacy_predecessor["payload_hash"],
        )
        self.assert_chain_refused(
            self.appended(duplicate_legacy, b"".join(self.lines[:7])),
            "duplicate specification revision",
        )

        duplicate_revision_payload = copy.deepcopy(self.head["payload"])
        duplicate_revision_payload["previous_revision"] = "rev-15"
        duplicate_revision_payload["previous_normative_sha256"] = self.head[
            "payload"
        ]["normative_sha256"]
        duplicate_revision = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            16,
            self.head["utc"],
            duplicate_revision_payload,
            self.head["payload_hash"],
        )
        self.assert_chain_refused(
            self.appended(duplicate_revision),
            "duplicate specification revision",
        )

        fork_payload = copy.deepcopy(self.head["payload"])
        fork_payload["revision"] = "rev-16"
        fork_payload["previous_revision"] = "rev-14"
        fork_payload["previous_normative_sha256"] = self.frames[-2]["payload"][
            "normative_sha256"
        ]
        fork = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            15,
            self.head["utc"],
            fork_payload,
            self.frames[-2]["payload_hash"],
        )
        self.assert_chain_refused(self.appended(fork), "duplicate seq/fork")

    def test_legacy_revision_emission_after_inline_profile_is_refused(self) -> None:
        self.assert_rev15_head()
        payload = copy.deepcopy(self.frames[13]["payload"])
        payload["test_marker"] = "new-legacy-emission"
        frame = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            16,
            self.head["utc"],
            payload,
            self.head["payload_hash"],
        )
        self.assert_chain_refused(
            self.appended(frame),
            "legacy pointer frame cannot follow",
        )

    def test_stale_competing_append_must_rebase(self) -> None:
        self.assert_rev15_head()
        payload = copy.deepcopy(self.head["payload"])
        payload["revision"] = "rev-16"
        payload["previous_revision"] = "rev-15"
        payload["previous_normative_sha256"] = self.head["payload"][
            "normative_sha256"
        ]
        competing = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            16,
            self.head["utc"],
            payload,
            self.head["payload_hash"],
        )
        competing_chain = self.appended(competing)
        canonical_rev14 = b"".join(self.lines[:15])
        with self.assertRaisesRegex(SystemExit, "stale or competing"):
            U.select_chain_base(
                competing_chain,
                canonical_rev14,
                self.bootstrap_profile,
            )

    def test_rev15_lens_tile_terminology_and_lineage_are_published(self) -> None:
        self.assert_rev15_head()
        spec = SPEC.read_text(encoding="utf-8")
        phrases = (
            "### 7.7 Lens cracking and tile lineage",
            '"schema": "rapp-lens/1"',
            '"facets": ["<lclabel>", "..."]',
            '"schema": "rapp-tile/1"',
            '"crack": {"crack_id": "<64hex>", "facet": "<lclabel>", "tile_index": 0, "tile_count": 1}',
            "Rev-15 registers exactly `body.lens`→`body`",
            "**tile / worn frame**",
            "1 + max(parent contribution)",
            "The tile schema contains no `provenance_class`",
            "#### 7.7.4 Fan-out, sibling tiles, and Dream-Catcher fan-in",
            "(crack.crack_id, tile_index)",
            "The fresh frame is the marble",
            "Stateless tile verification",
            "atomic compare-and-set claim",
            "Lineage depth is not limited by the host language's call stack",
            "Scalar leaves do not add a depth level",
            "frame from era genesis through target",
            "immutable canonical bytes or a deep",
            "An in-memory cyclic object/list graph is not a JSON tree",
            "frame.prev",
            "same invocation",
            "byte-identical canonical payload",
        )
        normalized_spec = " ".join(spec.split())
        normalized_payload = " ".join(
            self.head["payload"]["normative"]["text"].split()
        )
        for phrase in phrases:
            normalized_phrase = " ".join(phrase.split())
            self.assertIn(normalized_phrase, normalized_spec)
            self.assertIn(normalized_phrase, normalized_payload)

    def test_rev14_transition_wording_is_published(self) -> None:
        constitution = (ROOT / "CONSTITUTION.md").read_text(encoding="utf-8")
        spec = SPEC.read_text(encoding="utf-8")
        anchor_readme = (ROOT / "anchor" / "README.md").read_text(encoding="utf-8")
        wording = (
            "Rev-14 is ratified under rev-13 Article 14",
            "chain-append process",
            "rev-15",
        )
        for text in (constitution, spec, anchor_readme):
            text = " ".join(text.split())
            for phrase in wording:
                self.assertIn(phrase, text)

    def test_beacon_drift_is_refused(self) -> None:
        orient = copy.deepcopy(self.orient)
        orient["head"]["frame_hash"] = "0" * 64
        with self.assertRaisesRegex(M.ChainError, "verified chain head"):
            M.verify_orient(
                (json.dumps(orient) + "\n").encode("utf-8"),
                self.frames,
            )

    def test_generator_rerun_is_deterministic_and_idempotent(self) -> None:
        self.assert_rev15_head()
        before_chain = CHAIN.read_bytes()
        before_orient = ORIENT.read_bytes()
        result = subprocess.run(
            [sys.executable, str(ROOT / "anchor" / "update_anchor.py")],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), self.head["frame_hash"])
        self.assertEqual(CHAIN.read_bytes(), before_chain)
        self.assertEqual(ORIENT.read_bytes(), before_orient)

    def test_exclusive_lock_serializes_concurrent_writers(self) -> None:
        lock = self.scratch() / "update.lock"
        script = (
            "import pathlib,sys,time;"
            "from anchor import update_anchor as U;"
            "p=pathlib.Path(sys.argv[1]);"
            "\nwith U.exclusive_lock(p):"
            "\n print('locked',flush=True);"
            "\n time.sleep(float(sys.argv[2]))"
        )
        first = subprocess.Popen(
            [sys.executable, "-c", script, str(lock), "0.7"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(first.stdout.readline().strip(), "locked")
            started = time.monotonic()
            second = subprocess.run(
                [sys.executable, "-c", script, str(lock), "0"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(second.stdout.strip(), "locked")
            self.assertGreaterEqual(elapsed, 0.45)
        finally:
            first.wait(timeout=5)
            if first.stdout is not None:
                first.stdout.close()

    def test_stale_writer_compare_and_swap_is_refused(self) -> None:
        scratch = self.scratch()
        chain = scratch / "chain.jsonl"
        orient = scratch / "orient.json"
        chain.write_bytes(b"newer")
        orient.write_bytes(b"old beacon")
        with self.assertRaisesRegex(M.ResolutionError, "stale writer"):
            U.publish_chain_and_beacon(
                chain,
                orient,
                expected_chain=b"older",
                candidate_chain=b"candidate",
                candidate_orient=b"new beacon",
            )
        self.assertEqual(chain.read_bytes(), b"newer")
        self.assertEqual(orient.read_bytes(), b"old beacon")

    def test_beacon_recovers_after_interrupted_chain_publication(self) -> None:
        scratch = self.scratch()
        chain = scratch / "chain.jsonl"
        orient = scratch / "orient.json"
        chain.write_bytes(b"old chain")
        orient.write_bytes(b"stale beacon")

        def interrupt() -> None:
            raise RuntimeError("simulated crash after chain replacement")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            U.publish_chain_and_beacon(
                chain,
                orient,
                expected_chain=b"old chain",
                candidate_chain=b"new chain",
                candidate_orient=b"new beacon",
                after_chain=interrupt,
            )
        self.assertEqual(chain.read_bytes(), b"new chain")
        self.assertEqual(orient.read_bytes(), b"stale beacon")

        M.safe_unlink(orient)
        U.publish_chain_and_beacon(
            chain,
            orient,
            expected_chain=b"new chain",
            candidate_chain=b"new chain",
            candidate_orient=b"new beacon",
        )
        self.assertEqual(chain.read_bytes(), b"new chain")
        self.assertEqual(orient.read_bytes(), b"new beacon")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_atomic_write_refuses_symlink_leaf_and_parent(self) -> None:
        scratch = self.scratch()
        victim = scratch / "victim"
        victim.write_bytes(b"victim")
        leaf = scratch / "leaf"
        try:
            os.symlink(victim.name, leaf)
        except OSError as error:
            self.skipTest(f"cannot create symlink: {error}")
        with self.assertRaisesRegex(M.ResolutionError, "symlink leaf"):
            M.atomic_write(leaf, b"replacement")
        self.assertTrue(leaf.is_symlink())
        self.assertEqual(victim.read_bytes(), b"victim")

        real_directory = scratch / "real"
        real_directory.mkdir()
        linked_directory = scratch / "linked"
        os.symlink(real_directory.name, linked_directory)
        with self.assertRaisesRegex(M.ResolutionError, "path component"):
            M.atomic_write(linked_directory / "file", b"replacement")
        self.assertFalse((real_directory / "file").exists())

    def test_atomic_compare_and_swap_race_is_refused(self) -> None:
        target = self.scratch() / "target"
        target.write_bytes(b"raced")
        with self.assertRaisesRegex(
            M.ResolutionError,
            "compare-and-swap destination changed",
        ):
            M.atomic_write(target, b"replacement", expected=b"old")
        self.assertEqual(target.read_bytes(), b"raced")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_cache_refuses_symlink_and_oversized_entries(self) -> None:
        octets = b"legacy"
        payload = {
            "revision": "rev-1",
            "canonical_repo": "https://github.com/example/spec",
            "commit": "a" * 40,
            "normative_path": "SPEC.md",
            "normative_sha256": hashlib.sha256(octets).hexdigest(),
            "normative_bytes": str(len(octets)),
        }
        frame = {"payload": payload}
        cache = self.scratch()
        cache_file = cache / f"{payload['normative_sha256']}.md"
        cache_file.write_bytes(octets + b"x")
        with self.assertRaisesRegex(M.ResolutionError, "expected size"):
            M.resolve_spec_bytes(frame, cache_dir=cache, offline=True)

        cache_file.unlink()
        victim = cache / "victim"
        victim.write_bytes(octets)
        try:
            os.symlink(victim.name, cache_file)
        except OSError as error:
            self.skipTest(f"cannot create symlink: {error}")
        with self.assertRaisesRegex(M.ResolutionError, "symlink leaf"):
            M.resolve_spec_bytes(frame, cache_dir=cache, offline=True)


if __name__ == "__main__":
    unittest.main()
