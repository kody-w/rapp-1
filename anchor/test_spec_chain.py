#!/usr/bin/env python3
"""Focused conformance tests for the RAPP/1 DOGG specification chain."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
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

    def test_historical_lines_are_byte_exact(self) -> None:
        self.assertEqual(len(self.lines), 15)
        actual = tuple(hashlib.sha256(line).hexdigest() for line in self.lines[:14])
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
        self.assertEqual(self.head["seq"], 14)
        self.assertEqual(self.head["kind"], "body.pulse")
        self.assertEqual(set(self.head), R.FRAME_KEYS)
        self.assertEqual(self.head["payload"]["schema"], M.REVISION_SCHEMA)
        self.assertEqual(self.orient["head"]["frame_hash"], self.head["frame_hash"])
        self.assertEqual(self.index["head"]["frame_hash"], self.head["frame_hash"])
        self.assertLessEqual(
            len(R.canonical(self.head).encode("utf-8")),
            R.MAX_CANONICAL_BYTES,
        )

    def test_spec_roundtrip_is_byte_exact_and_atomic(self) -> None:
        materialized = M.resolve_spec_bytes(self.head, offline=True)
        self.assertEqual(materialized, SPEC.read_bytes())
        target = self.scratch() / "SPEC.md"
        target.write_bytes(b"old")
        M.atomic_write(target, materialized)
        self.assertEqual(target.read_bytes(), SPEC.read_bytes())
        self.assertFalse(any(target.parent.glob(".SPEC.md.*.tmp")))

    def test_resolution_by_every_identifier(self) -> None:
        selectors = [
            {},
            {"revision": "rev-14"},
            {"seq": 14},
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
        self.assertEqual(M.resolve_spec_bytes(self.head, offline=True), SPEC.read_bytes())
        with self.assertRaisesRegex(M.ResolutionError, "offline mode"):
            M.resolve_spec_bytes(self.frames[13], offline=True)

    def test_mutable_legacy_pointer_is_refused(self) -> None:
        payload = copy.deepcopy(self.frames[13]["payload"])
        payload["commit"] = "main"
        with self.assertRaisesRegex(M.ChainError, "40 lowercase hex"):
            M.legacy_url(payload)

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

    def test_duplicate_revision_seq_and_fork_are_refused(self) -> None:
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
        duplicate_revision_payload["previous_revision"] = "rev-14"
        duplicate_revision_payload["previous_normative_sha256"] = self.head[
            "payload"
        ]["normative_sha256"]
        duplicate_revision = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            15,
            self.head["utc"],
            duplicate_revision_payload,
            self.head["payload_hash"],
        )
        self.assert_chain_refused(
            self.appended(duplicate_revision),
            "duplicate specification revision",
        )

        fork_payload = copy.deepcopy(self.head["payload"])
        fork_payload["revision"] = "rev-15"
        fork_payload["previous_revision"] = "rev-13"
        fork_payload["previous_normative_sha256"] = self.frames[-2]["payload"][
            "normative_sha256"
        ]
        fork = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            14,
            self.head["utc"],
            fork_payload,
            self.frames[-2]["payload_hash"],
        )
        self.assert_chain_refused(self.appended(fork), "duplicate seq/fork")

    def test_legacy_revision_emission_after_inline_profile_is_refused(self) -> None:
        payload = copy.deepcopy(self.frames[13]["payload"])
        payload["test_marker"] = "new-legacy-emission"
        frame = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            15,
            self.head["utc"],
            payload,
            self.head["payload_hash"],
        )
        self.assert_chain_refused(
            self.appended(frame),
            "legacy pointer frame cannot follow",
        )

    def test_stale_competing_append_must_rebase(self) -> None:
        payload = copy.deepcopy(self.head["payload"])
        payload["revision"] = "rev-15"
        payload["previous_revision"] = "rev-14"
        payload["previous_normative_sha256"] = self.head["payload"][
            "normative_sha256"
        ]
        competing = R.build_frame(
            "body.pulse",
            self.head["stream_id"],
            15,
            self.head["utc"],
            payload,
            self.head["payload_hash"],
        )
        competing_chain = self.appended(competing)
        canonical_rev13 = b"".join(self.lines[:14])
        with self.assertRaisesRegex(SystemExit, "stale or competing"):
            U.select_chain_base(
                competing_chain,
                canonical_rev13,
                self.bootstrap_profile,
            )

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


if __name__ == "__main__":
    unittest.main()
