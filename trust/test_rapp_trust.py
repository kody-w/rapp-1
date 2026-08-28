#!/usr/bin/env python3
"""Synthetic, ephemeral conformance vectors for the candidate trust profile."""
from __future__ import annotations

import base64
import copy
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "trust"))

import rapp as R
import rapp_trust as T


UTC_0 = "2026-08-28T00:00:00.000Z"
UTC_1 = "2026-08-28T00:01:00.000Z"
UTC_2 = "2026-08-28T00:02:00.000Z"


class TrustVectors(unittest.TestCase):
    def setUp(self):
        self.owner_private = Ed25519PrivateKey.generate()
        self.actor_private = Ed25519PrivateKey.generate()
        self.owner = T.keyed_rappid(
            "synthetic-test", "estate-owner", self.owner_private.public_key()
        )
        self.actor = T.keyed_rappid(
            "synthetic-test", "factory-producer", self.actor_private.public_key()
        )
        self.document = T.load_json(ROOT / "trust" / "registry-candidate.json")
        self.document["estate"] = "synthetic-test"
        self.document["issued_utc"] = UTC_1
        self.document["status"] = "owner-signed"
        self.document["registry_seq"] = 7
        self.document["rappids"] = [
            {
                "rappid": self.owner,
                "role": "estate_owner",
                "minted_utc": UTC_0,
                "grown_from": None,
            },
            {
                "rappid": self.actor,
                "role": "producer",
                "minted_utc": UTC_0,
                "grown_from": None,
            },
        ]
        self.document["owners"] = [
            {
                "rappid": self.owner,
                "valid_from_utc": UTC_0,
                "valid_until_utc": None,
            }
        ]
        self.document["keys"] = [
            self.key_record(self.owner, self.owner_private),
            self.key_record(self.actor, self.actor_private),
        ]
        self.resign()

    @staticmethod
    def key_record(kid, private, not_after=None, deprecated=False):
        spki = T.public_spki_der(private.public_key())
        return {
            "kid": kid,
            "alg": "EdDSA",
            "spki_der_b64": base64.b64encode(spki).decode("ascii"),
            "not_before_utc": UTC_0,
            "not_after_utc": not_after,
            "deprecated": deprecated,
        }

    def resign(self):
        self.document["sig"] = T.sign_value(
            self.document, self.owner_private, self.owner
        )

    def verified(self):
        return T.verify_candidate(self.document, trust_anchor=self.owner)

    def signed_swarm(self, private=None, kid=None, utc=UTC_2, stream="net:synthetic"):
        private = private or self.actor_private
        kid = kid or self.actor
        frame = R.build_frame(
            "ms-rapp.factory-output-wave",
            stream,
            0,
            utc,
            {"artifact": "synthetic"},
            prev=None,
        )
        frame["sig"] = T.sign_value(frame, private, kid)
        return frame

    def assert_refused(self, code, action):
        with self.assertRaises(T.TrustRefusal) as caught:
            action()
        self.assertEqual(code, caught.exception.code)

    def test_v1_candidate_is_deterministic_and_locally_pinned(self):
        first = T.candidate_digest(self.document)
        reordered = {key: self.document[key] for key in reversed(self.document)}
        self.assertEqual(first, T.candidate_digest(reordered))
        committed = T.load_json(ROOT / "trust" / "registry-candidate.json")
        expected = (ROOT / "trust" / "registry-candidate.digest").read_text().strip()
        self.assertEqual(expected, T.candidate_digest(committed))
        T.verify_local_pins(
            committed, ROOT
        )

    def test_v2_floats_are_refused(self):
        self.assert_refused("non-ijson", lambda: T.canonicalize({"x": 0.1}))

    def test_v3_signed_registry_and_frame_verify(self):
        registry = self.verified()
        T.verify_frame(
            self.signed_swarm(), registry, stream_id_of_record="net:synthetic"
        )

    def test_v4_tamper_is_refused_without_repair(self):
        tampered = copy.deepcopy(self.document)
        tampered["kinds"][0]["family"] = "memory"
        before = copy.deepcopy(tampered)
        self.assert_refused(
            "bad-signature",
            lambda: T.verify_candidate(tampered, trust_anchor=self.owner),
        )
        self.assertEqual(before, tampered)

    def test_v5_wrong_owner_and_cross_estate_replay_are_refused(self):
        other = Ed25519PrivateKey.generate()
        other_owner = T.keyed_rappid("other-estate", "owner", other.public_key())
        self.assert_refused(
            "cross-estate-replay",
            lambda: T.verify_candidate(self.document, trust_anchor=other_owner),
        )

    def test_v6_expired_key_is_refused(self):
        self.document["keys"][1]["not_after_utc"] = UTC_1
        self.resign()
        registry = self.verified()
        self.assert_refused(
            "key-expired",
            lambda: T.verify_frame(
                self.signed_swarm(), registry, stream_id_of_record="net:synthetic"
            ),
        )

    def test_v7_revoked_key_is_refused(self):
        tombstone = {"rappid": self.actor, "revoked_utc": UTC_1, "sig": None}
        tombstone["sig"] = T.sign_value(tombstone, self.owner_private, self.owner)
        self.document["tombstones"] = [tombstone]
        self.resign()
        registry = self.verified()
        self.assert_refused(
            "key-revoked",
            lambda: T.verify_frame(
                self.signed_swarm(), registry, stream_id_of_record="net:synthetic"
            ),
        )

    def test_v8_unsigned_swarm_is_refused(self):
        frame = self.signed_swarm()
        frame["sig"] = None
        self.assert_refused(
            "frame-step-6",
            lambda: T.verify_frame(
                frame, self.verified(), stream_id_of_record="net:synthetic"
            ),
        )

    def test_v9_registry_rollback_and_equivocation_are_refused(self):
        self.assert_refused(
            "registry-rollback",
            lambda: T.verify_candidate(
                self.document, trust_anchor=self.owner, highest_registry_seq=8
            ),
        )
        self.assert_refused(
            "registry-equivocation",
            lambda: T.verify_candidate(
                self.document,
                trust_anchor=self.owner,
                highest_registry_seq=7,
                highest_registry_digest="f" * 64,
            ),
        )

    def test_v10_cross_stream_replay_is_refused(self):
        frame = self.signed_swarm(stream="net:alpha")
        self.assert_refused(
            "frame-step-1a",
            lambda: T.verify_frame(
                frame, self.verified(), stream_id_of_record="net:beta"
            ),
        )

    def test_v11_unknown_authority_is_refused(self):
        stranger = Ed25519PrivateKey.generate()
        stranger_kid = T.keyed_rappid(
            "synthetic-test", "stranger", stranger.public_key()
        )
        frame = self.signed_swarm(stranger, stranger_kid)
        self.assert_refused(
            "unknown-authority",
            lambda: T.verify_frame(
                frame, self.verified(), stream_id_of_record="net:synthetic"
            ),
        )

    def test_v12_exact_eleven_and_unknown_kind_are_refused(self):
        extra = self.signed_swarm()
        extra["twelfth"] = True
        self.assert_refused(
            "frame-step-1",
            lambda: T.verify_frame(
                extra, self.verified(), stream_id_of_record="net:synthetic"
            ),
        )
        unknown = R.build_frame(
            "unknown.event", "net:synthetic", 0, UTC_2, {}, prev=None
        )
        unknown["sig"] = T.sign_value(unknown, self.actor_private, self.actor)
        self.assert_refused(
            "unknown-kind",
            lambda: T.verify_frame(
                unknown, self.verified(), stream_id_of_record="net:synthetic"
            ),
        )

    def test_v13_kind_family_is_registry_bound(self):
        frame = R.build_frame(
            "ms-rapp.factory-artifact", "net:synthetic", 0, UTC_2, {}, prev=None
        )
        frame["sig"] = T.sign_value(frame, self.actor_private, self.actor)
        self.assert_refused(
            "kind-family",
            lambda: T.verify_frame(
                frame, self.verified(), stream_id_of_record="net:synthetic"
            ),
        )

    def test_v14_mint_once_duplicate_is_refused(self):
        self.document["rappids"].append(copy.deepcopy(self.document["rappids"][1]))
        self.resign()
        self.assert_refused(
            "mint-once",
            lambda: T.verify_candidate(self.document, trust_anchor=self.owner),
        )

    def test_v15_rotation_requires_continuity_and_cuts_over_at_utc(self):
        new_private = Ed25519PrivateKey.generate()
        new_actor = T.keyed_rappid(
            "synthetic-test", "factory-producer-v2", new_private.public_key()
        )
        self.document["rappids"].append(
            {
                "rappid": new_actor,
                "role": "producer",
                "minted_utc": UTC_1,
                "grown_from": None,
            }
        )
        self.document["keys"][1]["deprecated"] = True
        self.document["keys"].append(
            self.key_record(new_actor, new_private, deprecated=False)
        )
        anchor = {
            "old_rappid": self.actor,
            "new_rappid": new_actor,
            "case": "rotation",
            "utc": UTC_1,
            "sig": None,
            "old_key_sig": None,
        }
        anchor["old_key_sig"] = T.sign_value(
            anchor,
            self.actor_private,
            self.actor,
            excluded=("sig", "old_key_sig"),
        )
        anchor["sig"] = T.sign_value(anchor, self.owner_private, self.owner)
        self.document["re_anchors"] = [anchor]
        self.resign()
        registry = self.verified()
        before = self.signed_swarm(
            self.actor_private,
            self.actor,
            utc="2026-08-28T00:00:30.000Z",
        )
        T.verify_frame(before, registry, stream_id_of_record="net:synthetic")
        after_old = self.signed_swarm(self.actor_private, self.actor, utc=UTC_2)
        self.assert_refused(
            "key-superseded",
            lambda: T.verify_frame(
                after_old, registry, stream_id_of_record="net:synthetic"
            ),
        )
        after_new = self.signed_swarm(new_private, new_actor, utc=UTC_2)
        T.verify_frame(after_new, registry, stream_id_of_record="net:synthetic")

    def test_v16_committed_candidate_is_explicitly_pre_trust(self):
        candidate = T.load_json(ROOT / "trust" / "registry-candidate.json")
        self.assertIsNone(T.verify_candidate(candidate, allow_unsigned=True))
        self.assert_refused(
            "unsigned-registry", lambda: T.verify_candidate(candidate)
        )
        self.assertEqual([], candidate["owners"])
        self.assertEqual([], candidate["keys"])
        self.assertIsNone(candidate["sig"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
