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

    def reanchor(self, old="worker", new="successor", signer="owner", case="rotation"):
        value = {"type": "re-anchor", "old_rappid": self.keys[old],
                 "new_rappid": self.keys[new], "case": case,
                 "utc": "2026-07-01T00:00:00.000Z"}
        if case == "rotation":
            value["old_key_sig"] = self.sign(value, self.keys[old])
        value["sig"] = self.sign(value, self.keys[signer])
        return value

    def document(self, entries, owner="owner"):
        value = {"schema": "rapp/1-registry", "registry_seq": 2, "entries": entries}
        value["sig"] = self.sign(value, self.keys[owner])
        return value

    def load(self, document, owner="owner", **kwargs):
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


if __name__ == "__main__":
    unittest.main()
