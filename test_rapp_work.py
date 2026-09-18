"""Unit and adversarial vectors for rapp-work/1."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import rapp as R
import rapp_registry as REG
import rapp_work as W
from rapp_profile import particle_hash

ROOT = Path(__file__).resolve().parent
EXAMPLES = ROOT / "protocols" / "examples"
SIGNATURE = "fixture-signature"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def fixed_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class RappWorkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.release = load_json("release.json")
        self.rollback_release = load_json("rollback-release.json")
        self.deployment = load_json("deployment.json")
        bundle = load_json("work-lifecycle.json")
        self.organization = bundle["organization"]
        self.catalog = bundle["catalog"]
        self.vector = bundle["vector"]
        self.rollback = bundle["rollback"]
        self.migration = bundle["migration"]
        self.receipt = bundle["receipt"]
        self.observation = bundle["observation"]

    @staticmethod
    def signature_verifier(_unsigned: dict, signature: str):
        return signature == SIGNATURE, "bad fixture signature"

    @staticmethod
    def authorization_verifier(_frame: dict, _purpose: str) -> bool:
        return True

    def frames(self, receipt: Optional[dict] = None) -> dict:
        payloads = [
            ("work.organization", self.organization),
            ("work.catalog", self.catalog),
            ("work.vector", self.vector),
            ("work.rollback", self.rollback),
            ("work.migration", self.migration),
            ("work.receipt", receipt or self.receipt),
            ("work.observation", self.observation),
        ]
        frames = {}
        head = None
        for sequence, (kind, payload) in enumerate(payloads):
            frame = R.build_frame(
                kind,
                self.organization["organization_rappid"],
                sequence,
                payload.get("created_utc")
                or payload.get("observed_utc")
                or payload.get("issued_utc"),
                payload,
                None if head is None else head["payload_hash"],
                sig=SIGNATURE,
            )
            frames[kind] = frame
            head = frame
        return frames

    def prepared_ledger(self) -> W.WorkLedger:
        ledger = W.WorkLedger(self.organization)
        ledger.accept_vector(
            self.vector,
            hive_verifier=lambda checkpoint, head: (
                checkpoint["mother_head_frame_hash"] == head["frame_hash"]
            ),
        )
        ledger.register_rollback(
            self.rollback,
            self.rollback_release,
            deployment=self.deployment,
            candidate_release=self.release,
        )
        ledger.register_migration(
            self.migration,
            self.catalog,
            self.vector,
            self.release,
            self.rollback,
        )
        return ledger

    def test_positive_lifecycle_and_exact_eleven_key_wire(self) -> None:
        self.assertEqual(
            W.validate_organization(self.organization),
            particle_hash(self.organization),
        )
        self.assertEqual(W.validate_catalog(self.catalog, self.organization), particle_hash(self.catalog))
        self.assertEqual(W.validate_vector(self.vector, self.organization), particle_hash(self.vector))
        self.assertEqual(
            W.validate_rollback(
                self.rollback,
                self.organization,
                self.rollback_release,
                deployment=self.deployment,
                candidate_release=self.release,
            ),
            particle_hash(self.rollback),
        )
        self.assertEqual(
            W.validate_migration(
                self.migration,
                self.organization,
                self.catalog,
                self.vector,
                self.release,
                self.rollback,
            ),
            particle_hash(self.migration),
        )
        self.assertEqual(
            W.validate_migration_receipt(
                self.receipt,
                self.migration,
                self.organization,
                custody_verifier=lambda _custody: True,
            ),
            particle_hash(self.receipt),
        )
        self.assertEqual(
            W.validate_observation(
                self.observation,
                self.organization,
                self.release,
                self.deployment,
                self.vector,
                health_verifier=lambda _observation: True,
            ),
            particle_hash(self.observation),
        )

        frames = self.frames()
        head = None
        for kind in (
            "work.organization",
            "work.catalog",
            "work.vector",
            "work.rollback",
            "work.migration",
            "work.receipt",
            "work.observation",
        ):
            frame = frames[kind]
            self.assertEqual(set(frame), R.FRAME_KEYS)
            payload = W.authorize_frame(
                frame,
                expected_kind=kind,
                head=head,
                stream_id=self.organization["organization_rappid"],
                registered_kinds=set(W.WORK_KINDS),
                signature_verifier=self.signature_verifier,
                authorization_verifier=self.authorization_verifier,
                organization=self.organization,
            )
            self.assertEqual(payload, frame["payload"])
            head = frame

        forged = dict(frames["work.organization"])
        forged["twelfth"] = "forbidden"
        ok, step, _why = R.verify_frame(
            forged,
            stream_id_of_record=self.organization["organization_rappid"],
            signature_verifier=self.signature_verifier,
        )
        self.assertFalse(ok)
        self.assertEqual(step, "1")

        ledger = self.prepared_ledger()
        mutations = []
        result = ledger.recover_completed_migration(
            migration=self.migration,
            catalog=self.catalog,
            vector=self.vector,
            target_release=self.release,
            rollback=self.rollback,
            receipt_frame=frames["work.receipt"],
            frame_head=frames["work.migration"],
            observed_source=copy.deepcopy(self.migration["source"]),
            registered_kinds=set(W.WORK_KINDS),
            signature_verifier=self.signature_verifier,
            authorization_verifier=self.authorization_verifier,
            evidence_verifier=lambda _address: True,
            custody_verifier=lambda _custody: True,
            mutate=lambda token: mutations.append(token) or {"status": "created"},
        )
        self.assertEqual(result, {"status": "created"})
        self.assertEqual(len(mutations), 1)
        replay = ledger.recover_completed_migration(
            migration=self.migration,
            catalog=self.catalog,
            vector=self.vector,
            target_release=self.release,
            rollback=self.rollback,
            receipt_frame=frames["work.receipt"],
            frame_head=frames["work.migration"],
            observed_source=copy.deepcopy(self.migration["source"]),
            registered_kinds=set(W.WORK_KINDS),
            signature_verifier=self.signature_verifier,
            authorization_verifier=self.authorization_verifier,
            evidence_verifier=lambda _address: True,
            custody_verifier=lambda _custody: True,
            mutate=lambda token: mutations.append(token),
        )
        self.assertEqual(replay["status"], "replayed")
        self.assertEqual(len(mutations), 1)

    def test_signed_hive_vector_rollback_is_refused(self) -> None:
        ledger = W.WorkLedger(self.organization)
        ledger.accept_vector(
            self.vector,
            hive_verifier=lambda _checkpoint, _head: True,
        )
        rollback = copy.deepcopy(self.vector)
        rollback["observed_utc"] = "2026-09-18T12:03:00.000Z"
        rollback["previous_vector_payload_hash"] = particle_hash(self.vector)
        rollback["mother_head"]["seq"] -= 1
        rollback["mother_head"]["frame_hash"] = digest("rolled-back-hive-head")
        rollback["hive_checkpoint"]["mother_head_frame_hash"] = rollback["mother_head"]["frame_hash"]
        with self.assertRaisesRegex(ValueError, "signed Hive head rollback"):
            ledger.accept_vector(
                rollback,
                hive_verifier=lambda _checkpoint, _head: True,
                ancestry_verifier=lambda _old, _new: True,
            )
        self.assertEqual(ledger.vector, self.vector)

    def test_signed_hive_vector_same_sequence_fork_is_refused(self) -> None:
        fork = copy.deepcopy(self.vector)
        fork["observed_utc"] = "2026-09-18T12:03:00.000Z"
        fork["previous_vector_payload_hash"] = particle_hash(self.vector)
        fork["mother_head"]["frame_hash"] = digest("same-sequence-fork")
        fork["mother_head"]["payload_hash"] = digest("same-sequence-fork-payload")
        fork["hive_checkpoint"]["mother_head_frame_hash"] = fork["mother_head"]["frame_hash"]
        with self.assertRaisesRegex(ValueError, "same-sequence fork"):
            W.advance_vector(
                self.vector,
                fork,
                self.organization,
                ancestry_verifier=lambda _old, _new: True,
            )

    def test_missing_completed_evidence_refuses_before_mutation(self) -> None:
        ledger = self.prepared_ledger()
        receipt = copy.deepcopy(self.receipt)
        receipt["evidence"] = []
        frames = self.frames(receipt)
        mutations = []
        with self.assertRaisesRegex(ValueError, "at least one address"):
            ledger.recover_completed_migration(
                migration=self.migration,
                catalog=self.catalog,
                vector=self.vector,
                target_release=self.release,
                rollback=self.rollback,
                receipt_frame=frames["work.receipt"],
                frame_head=frames["work.migration"],
                observed_source=copy.deepcopy(self.migration["source"]),
                registered_kinds=set(W.WORK_KINDS),
                signature_verifier=self.signature_verifier,
                authorization_verifier=self.authorization_verifier,
                evidence_verifier=lambda _address: True,
                custody_verifier=lambda _custody: True,
                mutate=lambda token: mutations.append(token),
            )
        self.assertEqual(mutations, [])
        self.assertEqual(ledger.completed, {})

    def test_changed_source_recovery_refuses_before_mutation(self) -> None:
        ledger = self.prepared_ledger()
        frames = self.frames()
        changed = copy.deepcopy(self.migration["source"])
        changed["snapshot"]["hash"] = digest("changed source snapshot")
        mutations = []
        with self.assertRaisesRegex(ValueError, "source changed"):
            ledger.recover_completed_migration(
                migration=self.migration,
                catalog=self.catalog,
                vector=self.vector,
                target_release=self.release,
                rollback=self.rollback,
                receipt_frame=frames["work.receipt"],
                frame_head=frames["work.migration"],
                observed_source=changed,
                registered_kinds=set(W.WORK_KINDS),
                signature_verifier=self.signature_verifier,
                authorization_verifier=self.authorization_verifier,
                evidence_verifier=lambda _address: True,
                custody_verifier=lambda _custody: True,
                mutate=lambda token: mutations.append(token),
            )
        self.assertEqual(mutations, [])
        self.assertEqual(ledger.completed, {})

    def test_missing_custody_refuses_before_mutation(self) -> None:
        ledger = self.prepared_ledger()
        frames = self.frames()
        mutations = []
        with self.assertRaisesRegex(ValueError, "custody is missing"):
            ledger.recover_completed_migration(
                migration=self.migration,
                catalog=self.catalog,
                vector=self.vector,
                target_release=self.release,
                rollback=self.rollback,
                receipt_frame=frames["work.receipt"],
                frame_head=frames["work.migration"],
                observed_source=copy.deepcopy(self.migration["source"]),
                registered_kinds=set(W.WORK_KINDS),
                signature_verifier=self.signature_verifier,
                authorization_verifier=self.authorization_verifier,
                evidence_verifier=lambda _address: True,
                custody_verifier=lambda _custody: False,
                mutate=lambda token: mutations.append(token),
            )
        self.assertEqual(mutations, [])
        self.assertEqual(ledger.completed, {})

    def test_mutable_rollback_locator_is_refused(self) -> None:
        rollback = copy.deepcopy(self.rollback)
        rollback["locator"]["commit"] = "main"
        with self.assertRaisesRegex(ValueError, "immutable commit object id"):
            W.validate_rollback(
                rollback,
                self.organization,
                self.rollback_release,
                deployment=self.deployment,
                candidate_release=self.release,
            )

    def test_unsigned_static_receipt_is_non_authoritative(self) -> None:
        receipt = {
            "schema": W.RECEIPT_SCHEMA,
            "organization_payload_hash": particle_hash(self.organization),
            "receipt_type": "catalog-verified",
            "subject": {
                "kind": "static-api",
                "address": {
                    "space": "rapp/1:particle",
                    "hash": digest("static api document"),
                },
            },
            "issued_utc": "2026-09-18T12:05:00.000Z",
            "result": "verified",
            "evidence": [
                {
                    "space": "rapp/1:particle",
                    "hash": digest("static api evidence"),
                }
            ],
            "migration": None,
            "custody": None,
        }
        self.assertEqual(W.validate_receipt(receipt, self.organization), particle_hash(receipt))
        frame = R.build_frame(
            "work.receipt",
            self.organization["organization_rappid"],
            0,
            receipt["issued_utc"],
            receipt,
            None,
            sig=None,
        )
        with self.assertRaisesRegex(ValueError, "must be signed"):
            W.authorize_frame(
                frame,
                expected_kind="work.receipt",
                head=None,
                stream_id=self.organization["organization_rappid"],
                registered_kinds=set(W.WORK_KINDS),
                signature_verifier=self.signature_verifier,
                authorization_verifier=self.authorization_verifier,
                organization=self.organization,
            )

    def test_incompatible_portable_neuron_is_refused(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        neuron = next(item for item in catalog["items"] if item["kind"] == "portable-neuron")
        neuron["compatibility"]["verdict"] = "incompatible"
        with self.assertRaisesRegex(ValueError, "incompatible Portable Neuron"):
            W.validate_catalog(catalog, self.organization)

    def test_duplicate_catalog_item_is_refused(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["items"].append(copy.deepcopy(catalog["items"][0]))
        catalog["items"].sort(key=lambda item: item["id"])
        with self.assertRaisesRegex(ValueError, "duplicate catalog item"):
            W.validate_catalog(catalog, self.organization)

    def test_create_only_migration_cannot_change_under_one_id(self) -> None:
        ledger = self.prepared_ledger()
        changed = copy.deepcopy(self.migration)
        changed["created_utc"] = "2026-09-18T12:04:01.000Z"
        with self.assertRaisesRegex(ValueError, "create-only migration changed"):
            ledger.register_migration(
                changed,
                self.catalog,
                self.vector,
                self.release,
                self.rollback,
            )
        self.assertEqual(
            ledger.migrations[self.migration["migration_id"]]["hash"],
            particle_hash(self.migration),
        )

    def test_release_observations_are_bounded_before_append(self) -> None:
        ledger = W.WorkLedger(self.organization)
        ledger.accept_vector(
            self.vector,
            hive_verifier=lambda _checkpoint, _head: True,
        )
        start = datetime(2026, 9, 18, 13, 0, tzinfo=timezone.utc)
        previous = None
        for index in range(W.MAX_RELEASE_OBSERVATIONS):
            observation = copy.deepcopy(self.observation)
            observation["observed_utc"] = fixed_utc(start + timedelta(seconds=index))
            observation["evidence"] = [
                {
                    "space": "rapp/1:particle",
                    "hash": digest(f"observation evidence {index}"),
                }
            ]
            observation["previous_observation_payload_hash"] = (
                particle_hash(previous) if previous is not None else None
            )
            ledger.record_observation(
                observation,
                self.release,
                self.deployment,
                self.vector,
                health_verifier=lambda _observation: True,
            )
            previous = observation
        overflow = copy.deepcopy(self.observation)
        overflow["observed_utc"] = fixed_utc(
            start + timedelta(seconds=W.MAX_RELEASE_OBSERVATIONS)
        )
        overflow["evidence"] = [
            {
                "space": "rapp/1:particle",
                "hash": digest("observation evidence overflow"),
            }
        ]
        overflow["previous_observation_payload_hash"] = particle_hash(previous)
        with self.assertRaisesRegex(ValueError, "exceed the bounded profile"):
            ledger.record_observation(
                overflow,
                self.release,
                self.deployment,
                self.vector,
                health_verifier=lambda _observation: True,
            )
        self.assertEqual(len(ledger.observations), W.MAX_RELEASE_OBSERVATIONS)

    def test_registry_adoption_uses_only_existing_entry_types(self) -> None:
        spec_hash = hashlib.sha256(
            (ROOT / W.SPEC_PATH).read_bytes()
        ).hexdigest()
        owner = "rappid:@example/owner:" + "a" * 64
        protocol_entries = [
            {
                "type": "protocol",
                "name": "rapp/1",
                "spec_repo": "https://github.com/kody-w/rapp-1",
                "spec_path": "SPEC.md",
                "spec_hash": digest("rapp/1 spec"),
                "deprecated": False,
            },
            {
                "type": "protocol",
                "name": "rapp-hive/1",
                "spec_repo": "https://github.com/kody-w/rapp-work",
                "spec_path": "protocols/rapp-hive/1/SPEC.md",
                "spec_hash": digest("rapp-hive/1 spec"),
                "deprecated": False,
            },
            {
                "type": "protocol",
                "name": "rapp-cicd/1",
                "spec_repo": W.CANONICAL_REPOSITORY,
                "spec_path": "protocols/rapp-cicd/1/SPEC.md",
                "spec_hash": digest("rapp-cicd/1 spec"),
                "deprecated": False,
            },
            {
                "type": "protocol",
                "name": "rapp-deploy/1",
                "spec_repo": W.CANONICAL_REPOSITORY,
                "spec_path": "protocols/rapp-deploy/1/SPEC.md",
                "spec_hash": digest("rapp-deploy/1 spec"),
                "deprecated": False,
            },
        ]
        entries = [
            {"type": "estate_owner", "rappid": owner},
            *protocol_entries,
            *W.required_registry_entries(spec_hash),
        ]
        registry = REG.Registry(entries)
        self.assertTrue(W.validate_registry_adoption(registry, spec_hash))
        self.assertEqual(
            {entry["kind"] for entry in W.required_registry_entries(spec_hash)[1:]},
            set(W.WORK_KINDS),
        )
        self.assertTrue(
            all(entry["type"] in REG.ENTRY_MEMBERS for entry in W.required_registry_entries(spec_hash))
        )
        conflicting = REG.Registry(
            [
                *entries,
                {
                    "type": "protocol",
                    "name": W.PROFILE,
                    "spec_repo": "https://github.com/kody-w/rapp-work",
                    "spec_path": "SPEC.md",
                    "spec_hash": digest("different active rapp-work/1"),
                    "deprecated": False,
                },
            ]
        )
        with self.assertRaisesRegex(ValueError, "canonical protocol pin"):
            W.validate_registry_adoption(conflicting, spec_hash)

    def test_sdk_builder_discovers_work_profile_without_claiming_authority(self) -> None:
        from agents.rapp_sdk_builder_agent import RappSdkBuilderAgent

        result = json.loads(
            RappSdkBuilderAgent().perform(action="discover", protocol=W.PROFILE)
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["profile"]["name"], W.PROFILE)
        self.assertEqual(set(result["profile"]["kinds"]), set(W.WORK_KINDS))
        self.assertEqual(
            result["profile"]["authority"],
            "discovery-only-until-signed-registry-adoption",
        )
        self.assertTrue(
            all(set(entry) == {"type", "kind", "family", "deprecated"}
                for entry in result["registry_entries"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
