"""§13.1 registry container and §13.4 declared-entry tests (stdlib; JWS boundary mocked)."""
import base64
import copy
import json
import unittest

import rapp as R
import rapp_registry as REG
from registry_fixtures import MockEstate, SOURCE, T0, real_ed25519_signer

LATER = "2026-08-01T00:00:00.000Z"


class RegistryContainerTests(unittest.TestCase):
    def setUp(self):
        self.estate = MockEstate()

    def test_the_five_member_container_verifies(self):
        doc = self.estate.document(self.estate.base_entries())
        status, reg, why = self.estate.load(doc)
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(reg.canonical_source, SOURCE)

    def test_every_container_member_is_required(self):
        for member in REG.DOCUMENT_MEMBERS:
            with self.subTest(member=member):
                doc = self.estate.document(self.estate.base_entries())
                del doc[member]
                self.assertEqual(self.estate.load(doc)[0], "refused")

    def test_container_member_shapes_are_refused_not_repaired(self):
        cases = {
            "canonical_source": ["http://registry.example.test/r.json", "", 7, None],
            "entries": [{}, "entries", None],
            "registry_seq": [-1, True, "2"],
            "schema": ["rapp/1-registry-v2", None],
        }
        beyond = self.estate.document(self.estate.base_entries())
        beyond["registry_seq"] = 2**53  # not even canonicalizable, so it cannot be signed
        with self.assertRaisesRegex(REG.RegistryError, "uint53"):
            REG.validate_document(beyond)
        self.assertEqual(self.estate.load(beyond)[0], "refused")
        for member, values in cases.items():
            for value in values:
                with self.subTest(member=member, value=value):
                    # Signed AFTER the change, so only the container rule can refuse it.
                    doc = self.estate.document(self.estate.base_entries(), extra={member: value})
                    status, _, why = self.estate.load(doc)
                    self.assertEqual(status, "refused")
                    self.assertNotIn("signature", why)
                    with self.assertRaises(REG.RegistryError):
                        REG.validate_document(doc)
        for value in ("", 5, ["jws"]):
            with self.subTest(member="sig", value=value):
                doc = self.estate.document(self.estate.base_entries())
                doc["sig"] = value
                with self.assertRaisesRegex(REG.RegistryError, "sig must be"):
                    REG.validate_document(doc)
                self.assertEqual(self.estate.load(doc)[0], "refused")

    def test_other_top_level_members_are_signed_but_meaningless(self):
        extra = {"estate": "test", "anchor": {"revision": "rev-0"}, "published_utc": T0}
        doc = self.estate.document(self.estate.base_entries(), extra=extra)
        self.assertEqual(self.estate.load(doc)[0], "verified")
        doc["estate"] = "tampered"  # covered by the document signature
        self.assertEqual(self.estate.load(doc)[0], "refused")

    def test_entries_member_has_exactly_one_name(self):
        doc = self.estate.document(self.estate.base_entries())
        self.assertEqual(self.estate.load(doc, entries_member="items")[0], "refused")
        renamed = {k: v for k, v in doc.items() if k != "entries"}
        renamed["items"] = doc["entries"]
        self.assertEqual(self.estate.load(renamed, entries_member="items")[0], "refused")

    def test_out_of_band_canonical_source_must_match(self):
        doc = self.estate.document(self.estate.base_entries())
        self.assertEqual(self.estate.load(doc, canonical_source=SOURCE)[0], "verified")
        self.assertEqual(
            self.estate.load(doc, canonical_source="https://mirror.example.test/r.json")[0],
            "refused",
        )

    def test_unhashable_entry_type_is_a_refusal_not_a_crash(self):
        for bad in ([], {}, 7, None):
            with self.subTest(type=bad):
                with self.assertRaises(REG.RegistryError):
                    REG.validate_entry({"type": bad})
                doc = self.estate.document(self.estate.base_entries() + [{"type": bad}])
                self.assertEqual(self.estate.load(doc)[0], "refused")

    def test_unsigned_container_is_a_draft_only_when_allowed(self):
        doc = self.estate.document(self.estate.base_entries(), signed=False)
        self.assertEqual(self.estate.load(doc)[0], "refused")
        self.assertEqual(self.estate.load(doc, allow_unsigned=True)[0], "draft")

    def test_validate_document_checks_structure_only(self):
        doc = self.estate.document(self.estate.base_entries())
        self.assertIs(REG.validate_document(doc), doc)
        with self.assertRaises(REG.RegistryError):
            REG.validate_document({k: v for k, v in doc.items() if k != "canonical_source"})


class DocumentLimitTests(unittest.TestCase):
    """§4(d) and §3: a registry is one §4 value, and its URIs are absolute HTTPS URIs."""

    def setUp(self):
        self.estate = MockEstate()

    def draft(self, document):
        return REG.load_document(document, trust_anchor=self.estate.keys["owner"], allow_unsigned=True)

    def test_a_document_beyond_the_section_4_limits_is_refused(self):
        base = self.estate.base_entries()
        kinds = [{"type": "kind", "kind": f"body.k{n}", "family": "body", "deprecated": False}
                 for n in range(16000)]
        oversized = self.estate.document(base + kinds, signed=False)
        self.assertGreater(len(R.canonical(oversized).encode("utf-8")), R.MAX_CANONICAL_BYTES)
        with self.assertRaisesRegex(REG.RegistryError, "not a §4 value: .*1 MiB"):
            REG.validate_document(oversized)
        self.assertEqual(self.draft(oversized)[0], "refused")
        for depth, expect in ((70, "refused"), (10, "draft")):
            nested = "x"
            for _ in range(depth):
                nested = [nested]
            with self.subTest(depth=depth):
                document = self.estate.document(base, signed=False, extra={"note": nested})
                status, _, why = self.draft(document)
                self.assertEqual(status, expect, why)
                if expect == "refused":
                    self.assertIn("nesting depth exceeds 64", why)

    def test_absolute_https_uris_are_strict(self):
        base = self.estate.base_entries()
        for source in ("https:///rapp-registry.json", "https://?x", "https://user@registry.example.test/r.json",
                       "https://registry.example.test/r json", "https://registry.exämple.test/r.json",
                       "https://[::1/r.json", "http://registry.example.test/r.json", "https://",
                       "https://registry.example.test/<r>.json", "https://registry.example.test/%zz.json",
                       "https://registry.example.test:port/r.json", "https://@registry.example.test/r.json",
                       "https://:8443/r.json", "HTTPS://registry.example.test/r.json",
                       # Refused on every Python version: parsed by RFC 3986's grammar, never by urllib.
                       "https://registry.example.test:+443/r.json", "https://registry.example.test:4_43/r.json",
                       "https://registry.example.test:-0/r.json", "https://[zz]/r.json", "https://[::1]x/r.json",
                       "https://registry.example.test/a[b].json", "https://[::1%25eth0]/r.json",
                       "https://registry.example.test/r.json#top", "urn:x:registry", "URN:rapp:registry",
                       "urn:rapp:registry#top"):
            with self.subTest(source=source):
                with self.assertRaisesRegex(REG.RegistryError, "canonical_source"):
                    REG.validate_document(self.estate.document(base, signed=False, source=source))
        for source in ("https://registry.example.test:8443/r.json?v=1", "https://[::1]/r.json",
                       "https://registry.example.test/a%20b/r.json",
                       "urn:rapp:private-hive:" + "ab" * 32 + ":registry-history"):  # a private Hive's
            with self.subTest(source=source):
                self.assertEqual(self.draft(self.estate.document(base, signed=False, source=source))[0], "draft")


class UnknownEntryTypeTests(unittest.TestCase):
    """§13.3: an entry type this consumer does not implement is ignored unless it is marked critical."""

    def setUp(self):
        self.estate = MockEstate()

    def test_an_unknown_type_is_ignored_and_grants_nothing(self):
        base = self.estate.base_entries()
        future = {"type": "future-grant", "rappid": self.estate.keys["worker"], "power": "everything"}
        for entry in (future, dict(future, critical=False)):
            with self.subTest(critical=entry.get("critical", "absent")):
                registry = REG.Registry(base + [entry])
                self.assertEqual(registry.unknown_entries, [len(base)])
                self.assertEqual(REG.Registry(base).spki, registry.spki)  # it binds no key
                status, loaded, why = self.estate.load(self.estate.document(base + [entry]))
                self.assertEqual((status, why), ("verified", "ok"))  # still covered by the signature
                self.assertEqual(loaded.unknown_entries, [len(base)])

    def test_an_unknown_type_marked_critical_refuses_the_registry(self):
        base = self.estate.base_entries()
        for value in (True, "yes", 1, None, []):
            with self.subTest(critical=value):
                with self.assertRaisesRegex(REG.RegistryError, "marked critical"):
                    REG.Registry(base + [{"type": "future-revocation", "critical": value}])

    def test_known_types_and_malformed_types_are_still_exact(self):
        base = self.estate.base_entries()
        with self.assertRaisesRegex(REG.RegistryError, "member set"):
            REG.Registry(base + [dict(self.estate.spki("worker"), critical=False)])
        for entry in ({"type": 7}, {"type": ""}, {"type": None}, {"kind": "no type"}, ["type"]):
            with self.subTest(entry=entry):
                with self.assertRaisesRegex(REG.RegistryError, "unknown entry type|not an object"):
                    REG.Registry(base + [entry])


class ProtocolPinTests(unittest.TestCase):
    def pin(self, spec_hash, deprecated, name="rapp-work/1"):
        return {"type": "protocol", "name": name, "spec_repo": "https://github.com/kody-w/rapp-1",
                "spec_path": "protocols/rapp-work/1/SPEC.md", "spec_hash": spec_hash,
                "deprecated": deprecated}

    def test_current_pin_is_the_sole_non_deprecated_entry(self):
        estate = MockEstate()
        reg = REG.Registry(estate.base_entries() + [self.pin("a" * 64, True), self.pin("b" * 64, False)])
        self.assertEqual(reg.current_protocol("rapp-work/1")["spec_hash"], "b" * 64)
        self.assertEqual(reg.protocols["rapp-work/1"]["spec_hash"], "b" * 64)
        self.assertEqual([p["spec_hash"] for p in reg.protocol_history["rapp-work/1"]], ["a" * 64, "b" * 64])

    def test_two_current_pins_for_one_name_have_no_current_pin(self):
        estate = MockEstate()
        reg = REG.Registry(estate.base_entries() + [self.pin("a" * 64, False), self.pin("b" * 64, False)])
        self.assertIsNone(reg.current_protocol("rapp-work/1"))
        self.assertEqual(len(reg.protocol_history["rapp-work/1"]), 2)

    def test_a_fully_retired_protocol_has_no_current_pin(self):
        estate = MockEstate()
        reg = REG.Registry(estate.base_entries() + [self.pin("a" * 64, True)])
        self.assertIsNone(reg.current_protocol("rapp-work/1"))
        self.assertEqual(len(reg.protocol_history["rapp-work/1"]), 1)


class DeclaredEntryTests(unittest.TestCase):
    def setUp(self):
        self.estate = MockEstate()

    def load(self, extra_entries, owner="owner", entries=None, **kwargs):
        base = entries if entries is not None else self.estate.base_entries(owner)
        doc = self.estate.document(base + extra_entries, owner=owner)
        return self.estate.load(doc, owner=owner, **kwargs)

    def test_owner_declared_grail_kernel_verifies(self):
        self.assertEqual(self.load([self.estate.grail_kernel()])[0], "verified")

    def test_document_signature_never_blesses_a_forged_declaration(self):
        entry = self.estate.grail_kernel()
        entry["sig"] = "forged"
        self.assertEqual(self.load([entry])[0], "refused")

    def test_declaration_signed_by_another_registered_key_is_refused(self):
        forged_signer = self.estate.grail_kernel(declared="owner", signer="worker")
        self.assertEqual(self.load([forged_signer])[0], "refused")
        not_owner = self.estate.grail_kernel(declared="worker")
        self.assertEqual(self.load([not_owner])[0], "refused")

    def test_mutated_declaration_is_refused(self):
        entry = self.estate.grail_kernel()
        entry["size_bytes"] = 2048
        self.assertEqual(self.load([entry])[0], "refused")

    def test_owner_tenure_is_evaluated_at_activated_utc(self):
        rotation = self.estate.reanchor("owner", "successor", signer="owner", utc="2026-07-15T00:00:00.000Z")
        base = self.estate.base_entries(owner="successor")
        before = self.estate.grail_kernel(declared="owner", activated=T0)
        after_old = self.estate.grail_kernel(scope="https://releases.example.test/scope/b",
                                             declared="owner", activated=LATER)
        after_new = self.estate.grail_kernel(scope="https://releases.example.test/scope/c",
                                             declared="successor", activated=LATER)
        backdated = self.estate.grail_kernel(scope="https://releases.example.test/scope/d",
                                             declared="successor", activated=T0)
        self.assertEqual(self.load([rotation, before, after_new], owner="successor", entries=base)[0], "verified")
        self.assertEqual(self.load([rotation, after_old], owner="successor", entries=base)[0], "refused")
        self.assertEqual(self.load([rotation, backdated], owner="successor", entries=base)[0], "refused")

    def test_first_seen_skew_is_bounded_at_300_seconds(self):
        entry = self.estate.grail_kernel(activated="2026-07-01T00:05:00.000Z")
        self.assertEqual(self.load([entry], verification_utc=T0)[0], "verified")
        late = self.estate.grail_kernel(activated="2026-07-01T00:05:00.001Z")
        self.assertEqual(self.load([late], verification_utc=T0)[0], "refused")
        self.assertEqual(self.load([entry], verification_utc="not-a-time")[0], "refused")

    def test_first_seen_is_resolved_per_entry(self):
        early = self.estate.grail_kernel(activated=T0)
        later = self.estate.grail_kernel(scope="https://releases.example.test/scope/b",
                                         activated="2026-07-09T00:00:00.000Z")
        seen = {REG.entry_hash(early): T0, REG.entry_hash(later): "2026-07-09T00:00:00.000Z"}
        self.assertEqual(self.load([early, later], first_seen=seen.__getitem__)[0], "verified")
        # One scalar for both would wrongly refuse the entry appended later …
        self.assertEqual(self.load([early, later], verification_utc=T0)[0], "refused")
        # … and a resolver that remembers an early first sighting keeps refusing a late-dated one.
        seen[REG.entry_hash(later)] = T0
        self.assertEqual(self.load([early, later], first_seen=seen.__getitem__)[0], "refused")
        self.assertEqual(self.load([early], first_seen={}.__getitem__)[0], "refused")
        self.assertEqual(self.load([early], first_seen={}.get)[0], "refused")  # None is no time
        self.assertEqual(self.load([early], first_seen=lambda h: "yesterday")[0], "refused")
        self.assertEqual(
            self.load([early], first_seen=seen.__getitem__, verification_utc=T0)[0], "refused"
        )

    def test_a_declared_entry_without_first_seen_context_is_refused(self):
        doc = self.estate.document(self.estate.base_entries() + [self.estate.grail_kernel()])
        with self.estate.mocked():
            status, _, why = REG.load_document(doc, trust_anchor=self.estate.keys["owner"])
        self.assertEqual(status, "refused")
        self.assertIn("first-seen context", why)
        plain = self.estate.document(self.estate.base_entries())
        with self.estate.mocked():
            self.assertEqual(REG.load_document(plain, trust_anchor=self.estate.keys["owner"])[0],
                             "verified")

    def test_declaring_key_must_be_acceptable_at_activated_utc(self):
        cutoff = "2026-07-15T00:00:00.000Z"
        tombstone = {"type": "tombstone", "rappid": self.estate.keys["owner"], "revoked_utc": cutoff}
        tombstone["sig"] = self.estate.sign(tombstone, self.estate.keys["owner"])
        before = self.estate.grail_kernel(activated=T0)
        after = self.estate.grail_kernel(scope="https://releases.example.test/scope/b", activated=LATER)
        self.assertEqual(self.load([tombstone, before])[0], "verified")
        status, _, why = self.load([tombstone, after])
        self.assertEqual(status, "refused")
        self.assertIn("tombstoned", why)

    def test_an_exact_copy_verifies_apart_from_its_document(self):
        entry = self.estate.grail_kernel()
        status, reg, why = self.load([entry])
        self.assertEqual((status, why), ("verified", "ok"))
        with self.estate.mocked():
            self.assertEqual(reg.declared_entry_ok(copy.deepcopy(entry)), (True, "ok"))
            # A copy is compared by its canonical form (§4): the same value, however it is formatted.
            reformatted = json.loads(json.dumps(dict(reversed(list(entry.items()))), indent=2))
            self.assertEqual(reg.declared_entry_ok(reformatted), (True, "ok"))
            altered = copy.deepcopy(entry)
            altered["commit"] = "3" * 40
            self.assertFalse(reg.declared_entry_ok(altered)[0])
            self.assertFalse(reg.declared_entry_ok({"type": "spki"})[0])
            self.assertFalse(reg.declared_entry_ok({"type": ["grail-kernel"]})[0])
            self.assertFalse(reg.declared_entry_ok(self.estate.spki("worker"))[0])

    def test_only_an_accepted_registry_says_a_copy_is_a_declaration(self):
        entry = self.estate.grail_kernel()
        with self.estate.mocked():
            built = REG.Registry(self.estate.base_entries() + [entry])  # nothing verified it
            ok, why = built.declared_entry_ok(copy.deepcopy(entry))
            self.assertFalse(ok)
            self.assertIn("registry status is None", why)
            self.assertFalse(built.declared_entry_ok(entry, allow_draft=True)[0])
            document = self.estate.document(self.estate.base_entries() + [entry], signed=False)
            status, draft, _ = REG.load_document(document, trust_anchor=self.estate.keys["owner"],
                                                 allow_unsigned=True)
            self.assertEqual(status, "draft")
            self.assertIn("registry status is 'draft'", draft.declared_entry_ok(entry)[1])
            self.assertEqual(draft.declared_entry_ok(entry, allow_draft=True), (True, "ok"))

    def test_a_well_signed_copy_the_registry_does_not_carry_is_not_a_declaration(self):
        rotation = self.estate.reanchor("owner", "successor", signer="owner",
                                        utc="2026-07-15T00:00:00.000Z")
        carried = self.estate.grail_kernel(declared="successor", activated=LATER)
        base = self.estate.base_entries(owner="successor")
        status, reg, why = self.estate.load(self.estate.document(base + [rotation, carried], owner="successor"),
                                            owner="successor")
        self.assertEqual((status, why), ("verified", "ok"))
        with self.estate.mocked():
            self.assertEqual(reg.declared_entry_ok(carried), (True, "ok"))
            unregistered = self.estate.grail_kernel(scope="https://releases.example.test/scope/new",
                                                    declared="successor", activated=LATER)
            backdated_by_retired_key = self.estate.grail_kernel(
                scope="https://releases.example.test/scope/old", declared="owner", activated=T0)
            rebinding = self.estate.grail_kernel(declared="successor", activated=LATER, sha256="b" * 64)
            for label, forged in (("unregistered", unregistered),
                                  ("retired key, backdated", backdated_by_retired_key),
                                  ("rebinds a registered scope", rebinding)):
                with self.subTest(copy=label):
                    ok, why = reg.declared_entry_ok(forged)
                    self.assertFalse(ok)
                    self.assertIn("not an entry of this registry", why)

    def test_persisted_declarations_are_retained_byte_for_byte(self):
        entry = self.estate.grail_kernel()
        persisted = [R._strict_json(R.canonical(entry))]
        self.assertEqual(self.load([entry], persisted_entries=persisted)[0], "verified")
        self.assertEqual(self.load([], persisted_entries=persisted)[0], "refused")
        resigned = self.estate.grail_kernel()  # same members, a different signature
        self.assertNotEqual(resigned["sig"], entry["sig"])
        self.assertEqual(self.load([resigned], persisted_entries=persisted)[0], "refused")
        self.assertEqual(
            self.load([entry], persisted_entries=[self.estate.spki("worker")])[0], "refused"
        )

    def test_time_values_are_the_ascii_fixed_form(self):
        year = "\u0662\u0660\u0662\u0666-07-01T00:00:00.000Z"  # Arabic-Indic digits pass rapp.utc_valid
        self.assertTrue(R.utc_valid(year))
        worker = self.estate.keys["worker"]
        for member, entry in (
                ("activated_utc", dict(self.estate.grail_kernel(), activated_utc=year)),
                ("revoked_utc", {"type": "tombstone", "rappid": worker, "revoked_utc": year, "sig": "s"}),
                ("utc", dict(self.estate.reanchor("owner", "successor", signer="owner"), utc=year))):
            with self.subTest(member=member):
                with self.assertRaisesRegex(REG.RegistryError, f"`{member}` is not the fixed §7.4 UTC form"):
                    REG.validate_entry(entry)
        # The caller's first-seen and tombstone issuance contexts are time values too.
        entry = self.estate.grail_kernel()
        for context in ({"verification_utc": year}, {"first_seen": lambda entry_hash: year}):
            with self.subTest(context=sorted(context)):
                status, _, why = self.load([entry], **context)
                self.assertEqual(status, "refused")
                self.assertIn("first-seen context did not supply a valid UTC", why)
        tombstone = {"type": "tombstone", "rappid": worker, "revoked_utc": LATER}
        tombstone["sig"] = self.estate.sign(tombstone, self.estate.keys["owner"])
        self.assertEqual(self.load([tombstone])[0], "verified")
        status, _, why = self.load([tombstone], tombstone_issued_at=lambda entry_hash: year)
        self.assertEqual(status, "refused")
        self.assertIn("tombstone issuance context did not supply a valid UTC", why)
        status, reg, _ = self.load([entry])
        with self.estate.mocked():
            ok, why = reg.declared_entry_ok(entry, verification_utc=year)
        self.assertFalse(ok)
        self.assertIn("first-seen time: not the fixed §7.4 UTC form", why)
        # Owner tenure and key acceptability compare times bytewise, so they refuse the form too.
        with self.assertRaisesRegex(REG.RegistryError, "not the fixed §7.4 UTC form"):
            reg.owner_at(year)
        self.assertEqual(reg.signer_acceptable(self.estate.keys["owner"], year),
                         (False, "the artifact's time is not the fixed §7.4 UTC form"))


class LinearChainTests(unittest.TestCase):
    def chains(self, items):
        return REG.linear_chains(items, key=lambda e: e["k"], ident=lambda e: e["id"],
                                 link=lambda e: e["prev"], where="test chain")

    def test_chain_order_follows_links(self):
        items = [{"k": "a", "id": 1, "prev": None}, {"k": "b", "id": 1, "prev": None},
                 {"k": "a", "id": 2, "prev": 1}, {"k": "a", "id": 3, "prev": 2}]
        result = self.chains(items)
        self.assertEqual([e["id"] for e in result["a"]], [1, 2, 3])
        self.assertEqual([e["id"] for e in result["b"]], [1])

    def test_fork_forward_link_duplicate_and_root_count_are_refused(self):
        bad = {
            "fork": [{"k": "a", "id": 1, "prev": None}, {"k": "a", "id": 2, "prev": 1},
                     {"k": "a", "id": 3, "prev": 1}],
            "forward": [{"k": "a", "id": 2, "prev": 1}, {"k": "a", "id": 1, "prev": None}],
            "self": [{"k": "a", "id": 1, "prev": 1}],
            "duplicate": [{"k": "a", "id": 1, "prev": None}, {"k": "a", "id": 1, "prev": None}],
            "duplicate that would loop": [{"k": "a", "id": 1, "prev": None}, {"k": "a", "id": 2, "prev": 1},
                                          {"k": "a", "id": 1, "prev": 2}],
            "two roots": [{"k": "a", "id": 1, "prev": None}, {"k": "a", "id": 2, "prev": None}],
            "cross-chain link": [{"k": "a", "id": 1, "prev": None}, {"k": "b", "id": 2, "prev": 1}],
        }
        for label, items in bad.items():
            with self.subTest(label=label):
                with self.assertRaises(REG.RegistryError):
                    self.chains(items)

    def test_entry_hash_names_the_exact_signed_entry(self):
        estate = MockEstate()
        entry = estate.grail_kernel()
        self.assertEqual(REG.entry_hash(entry), R.H("rapp/1:particle", entry))
        altered = dict(entry, sig="other")
        self.assertNotEqual(REG.entry_hash(entry), REG.entry_hash(altered))


@unittest.skipUnless(real_ed25519_signer(), "optional cryptography import is absent")
class RealSignatureTests(unittest.TestCase):
    """The same rules through the real detached-JWS boundary (§10), no mocks."""

    def test_real_owner_signatures_on_document_and_declared_entry(self):
        spki_der, sign = real_ed25519_signer()
        owner = R.mint_rappid("test", "estate-owner", spki_der=spki_der)
        kernel = {
            "type": "grail-kernel", "release_scope": "https://releases.example.test/scope/lts",
            "grail_id": "grail:" + R.Hb("rapp/1:grail", b"kernel"),
            "repository": "https://git.example.test/estate/kernel",
            "immutable_ref": "refs/tags/kernel-v1", "object_format": "sha1",
            "commit": "1" * 40, "path": "kernel/brainstem.py", "mode": "100644",
            "blob": "2" * 40, "sha256": "a" * 64, "size_bytes": 6,
            "activated_utc": T0, "predecessor": None, "declared_by": owner,
        }
        kernel["sig"] = sign(kernel, owner)
        entries = [{"type": "estate_owner", "rappid": owner},
                   {"type": "spki", "rappid": owner, "deprecated": False,
                    "spki_der_b64": base64.b64encode(spki_der).decode("ascii")},
                   kernel]
        doc = {"schema": "rapp/1-registry", "registry_seq": 1, "canonical_source": SOURCE,
               "entries": entries}
        doc["sig"] = sign(doc, owner)
        self.assertEqual(REG.load_document(doc, trust_anchor=owner, verification_utc=T0)[0], "verified")
        tampered = copy.deepcopy(doc)
        tampered["entries"][2]["size_bytes"] = 7
        tampered.pop("sig")
        tampered["sig"] = sign(tampered, owner)  # a valid document signature cannot bless it
        self.assertEqual(REG.load_document(tampered, trust_anchor=owner, verification_utc=T0)[0], "refused")


if __name__ == "__main__":
    unittest.main()
