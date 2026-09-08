"""Registry authorization orchestration tests; the JWS boundary is mocked, not cryptography."""
import base64
import copy
import unittest
from unittest.mock import patch

import rapp as R
import rapp_registry as REG


class RegistryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.der = {}
        self.keys = {}
        self.signatures = {}
        self.issued_utc = "2026-07-01T00:00:00.000Z"
        for name in ("owner", "worker", "successor", "outsider"):
            der = ("synthetic-public-key-" + name).encode()
            kid = R.mint_rappid("test", name, spki_der=der)
            self.der[kid] = der
            self.keys[name] = kid

    def sign(self, value, kid):
        token = "test-signature-" + str(len(self.signatures))
        self.signatures[token] = (R.canonical(value), kid, self.der[kid])
        return token

    def verify(self, value, sig, der, expected_kid=None):
        expected = self.signatures.get(sig)
        actual = (R.canonical(value), expected_kid, der)
        return (True, "ok") if expected == actual else (False, "invalid test signature")

    def entries(self, owner="owner"):
        return [{"type": "estate_owner", "rappid": self.keys[owner]}] + [
            {"type": "spki", "rappid": kid, "deprecated": False,
             "spki_der_b64": base64.b64encode(der).decode()}
            for kid, der in self.der.items()
        ]

    def tombstone(self, target="worker", signer="owner"):
        value = {"type": "tombstone", "rappid": self.keys[target],
                 "revoked_utc": "2026-07-01T00:00:00.000Z"}
        value["sig"] = self.sign(value, self.keys[signer])
        return value

    def reanchor(self, old="worker", new="successor", signer="owner", case="rotation",
                 utc="2026-07-01T00:00:00.000Z"):
        value = {"type": "re-anchor", "old_rappid": self.keys[old],
                 "new_rappid": self.keys[new], "case": case,
                 "utc": utc}
        if case == "rotation":
            value["old_key_sig"] = self.sign(value, self.keys[old])
        value["sig"] = self.sign(value, self.keys[signer])
        return value

    def document(self, entries, owner="owner"):
        value = {"schema": "rapp/1-registry", "registry_seq": 2, "entries": entries}
        value["sig"] = self.sign(value, self.keys[owner])
        return value

    def load(self, document, owner="owner", **kwargs):
        # Fixture configuration stands in for authenticated issuance evidence.
        # It is independent of the revocation cutoff carried in the entry.
        kwargs.setdefault("tombstone_issued_at", lambda entry_hash: self.issued_utc)
        with patch.object(R, "verify_detached_jws", side_effect=self.verify):
            return REG.load_document(document, entries_member="entries",
                                     trust_anchor=self.keys[owner], **kwargs)

    def test_valid_tombstone_and_worker_rotation(self):
        for entry in (self.tombstone(), self.reanchor()):
            with self.subTest(entry=entry["type"]):
                self.assertEqual(self.load(self.document(self.entries() + [entry]))[0], "verified")

    def test_valid_enclosing_signature_does_not_bless_forged_tombstone(self):
        entry = self.tombstone()
        entry["sig"] = "forged"
        self.assertEqual(self.load(self.document(self.entries() + [entry]))[0], "refused")

    def test_valid_enclosing_signature_does_not_bless_forged_reanchor(self):
        entry = self.reanchor()
        entry["sig"] = "forged"
        self.assertEqual(self.load(self.document(self.entries() + [entry]))[0], "refused")

    def test_rotation_requires_valid_old_key_continuity(self):
        entry = self.reanchor()
        entry["old_key_sig"] = "forged"
        unsigned = {k: v for k, v in entry.items() if k != "sig"}
        entry["sig"] = self.sign(unsigned, self.keys["owner"])
        self.assertEqual(self.load(self.document(self.entries() + [entry]))[0], "refused")

    def test_non_owner_cannot_sign_lifecycle_entry(self):
        for entry in (self.tombstone(signer="outsider"), self.reanchor(signer="outsider")):
            with self.subTest(entry=entry["type"]):
                self.assertEqual(self.load(self.document(self.entries() + [entry]))[0], "refused")

    def test_owner_rotation_is_signed_by_outgoing_owner_at_the_boundary(self):
        entry = self.reanchor(old="owner", signer="owner")
        doc = self.document(self.entries(owner="successor") + [entry], owner="successor")
        self.assertEqual(self.load(doc, owner="successor")[0], "verified")

    def test_new_owner_cannot_fabricate_predecessors_consent(self):
        entry = self.reanchor(old="owner", signer="successor")
        doc = self.document(self.entries(owner="successor") + [entry], owner="successor")
        self.assertEqual(self.load(doc, owner="successor")[0], "refused")

    def test_compromise_requires_a_registered_signed_tombstone(self):
        entry = self.reanchor(case="compromise")
        doc = self.document(self.entries() + [entry])
        self.assertEqual(self.load(doc)[0], "refused")
        doc = self.document(self.entries() + [entry, self.tombstone()])
        self.assertEqual(self.load(doc)[0], "verified")

    def test_unknown_old_key_refuses_rotation(self):
        entry = self.reanchor()
        entries = [e for e in self.entries() if e.get("rappid") != self.keys["worker"]]
        self.assertEqual(self.load(self.document(entries + [entry]))[0], "refused")

    def test_tampered_entry_does_not_mutate_input_on_refusal(self):
        entry = self.tombstone()
        entry["revoked_utc"] = "2026-08-01T00:00:00.000Z"
        doc = self.document(self.entries() + [entry])
        before = copy.deepcopy(doc)
        self.assertEqual(self.load(doc)[0], "refused")
        self.assertEqual(doc, before)

    def test_unsigned_draft_stays_draft_not_verified_authority(self):
        doc = {"schema": "rapp/1-registry", "registry_seq": 1,
               "entries": self.entries() + [self.reanchor()], "sig": None}
        self.assertEqual(self.load(doc, allow_unsigned=True)[0], "draft")

    def test_historical_owner_signature_keeps_its_original_tenure(self):
        transition = self.reanchor(old="owner", signer="owner")
        retired = {"type": "tombstone", "rappid": self.keys["worker"],
                   "revoked_utc": "2026-06-01T00:00:00.000Z"}
        retired["sig"] = self.sign(retired, self.keys["owner"])
        self.issued_utc = "2026-06-15T00:00:00.000Z"
        doc = self.document(self.entries(owner="successor") + [transition, retired],
                            owner="successor")
        self.assertEqual(self.load(doc, owner="successor")[0], "verified")

    def test_stale_owner_cannot_sign_after_its_tenure(self):
        transition = self.reanchor(old="owner", signer="owner")
        retired = self.tombstone()
        doc = self.document(self.entries(owner="successor") + [transition, retired],
                            owner="successor")
        self.assertEqual(self.load(doc, owner="successor")[0], "refused")

    def test_reanchor_requires_one_unambiguous_fresh_successor(self):
        cases = (
            [self.reanchor(old="worker", new="worker")],
            [self.reanchor(), self.reanchor(old="outsider")],
            [self.reanchor(), self.reanchor(old="successor", new="worker")],
        )
        for records in cases:
            with self.subTest(records=len(records)):
                doc = self.document(self.entries() + records)
                self.assertEqual(self.load(doc)[0], "refused")

    def test_revocation_cutoff_is_not_the_tombstone_issuance_time(self):
        transition = self.reanchor(old="owner", signer="owner")
        retired = {"type": "tombstone", "rappid": self.keys["worker"],
                   "revoked_utc": "2026-06-01T00:00:00.000Z"}
        retired["sig"] = self.sign(retired, self.keys["successor"])
        self.issued_utc = "2026-08-01T00:00:00.000Z"
        doc = self.document(self.entries(owner="successor") + [transition, retired],
                            owner="successor")
        self.assertEqual(self.load(doc, owner="successor")[0], "verified")

    def test_tombstone_without_trusted_issuance_context_is_refused(self):
        doc = self.document(self.entries() + [self.tombstone()])
        status, _, why = self.load(doc, tombstone_issued_at=None)
        self.assertEqual(status, "refused")
        self.assertIn("issuance", why)

    def test_invalid_issuance_context_is_not_a_success_fallback(self):
        doc = self.document(self.entries() + [self.tombstone()])
        for invalid in (None, False, 1, "", "2026-99-01T00:00:00.000Z"):
            with self.subTest(invalid=invalid):
                self.assertEqual(self.load(
                    doc, tombstone_issued_at=lambda entry_hash: invalid,
                )[0], "refused")

    def test_issuance_resolver_receives_the_exact_signed_entry_commitment(self):
        entry = self.tombstone()
        seen = []
        def resolve(entry_hash):
            seen.append(entry_hash)
            return self.issued_utc
        self.assertEqual(self.load(self.document(self.entries() + [entry]),
                                  tombstone_issued_at=resolve)[0], "verified")
        self.assertEqual(seen, [R.H("rapp/1:particle", entry)])

    def test_revoked_key_cannot_supply_uncompromised_rotation_continuity(self):
        retired = {"type": "tombstone", "rappid": self.keys["worker"],
                   "revoked_utc": "2026-06-01T00:00:00.000Z"}
        retired["sig"] = self.sign(retired, self.keys["owner"])
        doc = self.document(self.entries() + [retired, self.reanchor()])
        self.assertEqual(self.load(doc)[0], "refused")

    def test_prior_supersession_cannot_be_ignored_for_a_second_rotation(self):
        earlier = self.reanchor(utc="2026-06-01T00:00:00.000Z")
        later = self.reanchor(new="outsider")
        doc = self.document(self.entries() + [earlier, later])
        self.assertEqual(self.load(doc)[0], "refused")

    def test_retirement_after_a_historical_rotation_does_not_invalidate_it(self):
        retired = {"type": "tombstone", "rappid": self.keys["worker"],
                   "revoked_utc": "2026-08-01T00:00:00.000Z"}
        retired["sig"] = self.sign(retired, self.keys["owner"])
        doc = self.document(self.entries() + [self.reanchor(), retired])
        self.assertEqual(self.load(doc)[0], "verified")

    def test_compromise_does_not_require_a_retired_keys_authority(self):
        retired = {"type": "tombstone", "rappid": self.keys["worker"],
                   "revoked_utc": "2026-06-01T00:00:00.000Z"}
        retired["sig"] = self.sign(retired, self.keys["owner"])
        entry = self.reanchor(case="compromise")
        continuity = {k: v for k, v in entry.items() if k != "sig"}
        entry["old_key_sig"] = self.sign(continuity, self.keys["worker"])
        entry["sig"] = self.sign({k: v for k, v in entry.items() if k != "sig"},
                                 self.keys["owner"])
        doc = self.document(self.entries() + [retired, entry])
        self.assertEqual(self.load(doc)[0], "verified")

    def test_owner_succession_cannot_run_backwards_or_have_empty_tenure(self):
        first = self.reanchor(old="owner", signer="owner",
                              utc="2026-08-01T00:00:00.000Z")
        for when in ("2026-07-01T00:00:00.000Z", "2026-08-01T00:00:00.000Z"):
            with self.subTest(when=when):
                second = self.reanchor(old="successor", new="outsider",
                                       signer="successor", utc=when)
                doc = self.document(self.entries(owner="outsider") + [first, second],
                                    owner="outsider")
                self.assertEqual(self.load(doc, owner="outsider")[0], "refused")

    def test_renaming_a_key_does_not_make_its_tail_fresh_in_its_lineage(self):
        alias = R.mint_rappid("test", "renamed-worker", spki_der=self.der[self.keys["worker"]])
        self.keys["alias"] = alias
        self.der[alias] = self.der[self.keys["worker"]]
        first = self.reanchor(utc="2026-06-01T00:00:00.000Z")
        second = self.reanchor(old="successor", new="alias")
        doc = self.document(self.entries() + [first, second])
        self.assertEqual(self.load(doc)[0], "refused")

    def worker_alias(self):
        alias = R.mint_rappid("test", "worker-alias", spki_der=self.der[self.keys["worker"]])
        self.keys["alias"] = alias
        self.der[alias] = self.der[self.keys["worker"]]
        return alias

    def test_revoked_old_key_cannot_rotate_through_a_source_alias(self):
        self.worker_alias()
        retired = {"type": "tombstone", "rappid": self.keys["worker"],
                   "revoked_utc": "2026-06-01T00:00:00.000Z"}
        retired["sig"] = self.sign(retired, self.keys["owner"])
        transition = self.reanchor(old="alias", new="outsider")
        status, _, why = self.load(self.document(self.entries() + [retired, transition]))
        self.assertEqual(status, "refused")
        self.assertIn("old-key authority", why)

    def test_superseded_old_key_cannot_rotate_through_a_source_alias(self):
        self.worker_alias()
        earlier = self.reanchor(utc="2026-06-01T00:00:00.000Z")
        later = self.reanchor(old="alias", new="outsider")
        status, _, why = self.load(self.document(self.entries() + [earlier, later]))
        self.assertEqual(status, "refused")
        self.assertIn("old-key authority", why)

    def test_unretired_source_alias_is_not_rejected_merely_for_its_name(self):
        self.worker_alias()
        transition = self.reanchor(old="alias", new="outsider")
        self.assertEqual(self.load(self.document(self.entries() + [transition]))[0], "verified")


if __name__ == "__main__":
    unittest.main()
