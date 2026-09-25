"""§13.7 stream-signer grants and the authority check above §7.5 (stdlib; JWS boundary mocked).

Frames are real `rapp.build_frame` frames. Their `sig` is shaped like a detached JWS, so the
registry can read the protected `kid` (`rapp.parse_detached_jws`), while the mocked
`rapp.verify_detached_jws` accepts only the token recorded over canonical(frame \\ {sig}) —
exactly the value `Registry.signature_verifier()` receives from `rapp.verify_frame` step 6.
`RealSignatureTests` runs the same path with real Ed25519 keys when `cryptography` is present.
"""
import base64
import copy
import unittest

import rapp as R
import rapp_profile as P
import rapp_registry as REG
from registry_fixtures import MockEstate, SOURCE, T0, real_ed25519_signer

BEFORE = "2026-07-09T23:59:59.999Z"
SINCE = "2026-07-10T00:00:00.000Z"
INSIDE = "2026-07-20T00:00:00.000Z"
ROTATED = "2026-07-25T00:00:00.000Z"
LAST = "2026-08-09T23:59:59.999Z"
UNTIL = "2026-08-10T00:00:00.000Z"
LATER = "2026-09-01T00:00:00.000Z"
FAR = "2099-12-31T23:59:59.999Z"

KINDS = {  # kind -> family, registered in every test registry
    "body.pulse": "body", "body.notice": "body", "body.twin-pulse": "body", "body-x.pulse": "body",
    "memory.save": "memory", "swarm.echo": "swarm",
    "body.re-genesis": "body", "memory.re-genesis": "memory", "swarm.re-genesis": "swarm",
}
STEPS = ("1", "1a", "2", "3", "4", "5", "6")


def b64url(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def jws_shaped(kid, token):
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid}
    return b64url(R.canonical(header).encode("utf-8")) + ".." + b64url(token.encode("utf-8"))


class SignerEstate(MockEstate):
    """A MockEstate whose frame signatures carry a parseable protected header."""

    def sign_frame(self, frame, name):
        kid = self.keys[name]
        sig = jws_shaped(kid, "test-signature-" + str(len(self.signatures)))
        unsigned = {k: v for k, v in frame.items() if k != "sig"}
        self.signatures[sig] = (R.canonical(unsigned), kid, self.der[kid])
        return dict(frame, sig=sig)


class Base(unittest.TestCase):
    def setUp(self):
        self.estate = SignerEstate(names=("owner", "heir", "signer", "signer-next", "crawler"))
        self.keys = self.estate.keys
        self.station = R.mint_rappid("test", "station")  # keyless: its tail hashes a UUIDv4, no key

    def kind_entries(self, deprecated=()):
        return [{"type": "kind", "kind": kind, "family": family, "deprecated": kind in deprecated}
                for kind, family in KINDS.items()]

    def base(self, owner="owner"):
        return self.estate.base_entries(owner) + self.kind_entries()

    def grant(self, declared="owner", sign_as=None, **members):
        entry = {"type": "stream-signer", "stream_id": self.station, "signer": self.keys["signer"],
                 "kinds": ["body.pulse"], "since_utc": SINCE, "until_utc": UNTIL,
                 "activated_utc": T0, "declared_by": self.keys[declared]}
        entry.update(members)
        return self.estate.declare(entry, sign_as or declared)

    def registry(self, extra=(), entries=None):
        return REG.Registry((self.base() if entries is None else entries) + list(extra))

    def load(self, extra=(), owner="owner", entries=None, **kwargs):
        base = self.base(owner) if entries is None else entries
        return self.estate.load(self.estate.document(base + list(extra), owner=owner), owner=owner, **kwargs)

    def pulse(self, utc, *, stream_id=None, kind="body.pulse", head=None, signer="signer", payload=None):
        stream_id = self.station if stream_id is None else stream_id
        seq = 0 if head is None else head["seq"] + 1
        prev = None if head is None else head["payload_hash"]
        frame = R.build_frame(kind, stream_id, seq, utc, {"pulse": seq} if payload is None else payload, prev)
        return frame if signer is None else self.estate.sign_frame(frame, signer)

    def verify(self, reg, frame, head=None, stream_id_of_record=None):
        with self.estate.mocked():
            return reg.verify_authorized_frame(
                frame, head=head,
                stream_id_of_record=self.station if stream_id_of_record is None else stream_id_of_record,
            )

    def refused(self, extra, entries=None):
        with self.assertRaises(REG.RegistryError):
            self.registry(extra, entries=entries)


class GrantStructureTests(Base):
    def test_the_member_set_is_exactly_the_schema(self):
        self.assertEqual(REG.ENTRY_MEMBERS["stream-signer"], (
            {"type", "stream_id", "signer", "kinds", "since_utc", "until_utc", "activated_utc",
             "declared_by", "sig"}, set()))
        grant = self.grant()
        self.assertEqual(REG.validate_entry(grant), "stream-signer")
        for member in grant:
            with self.subTest(missing=member):
                self.refused([{k: v for k, v in grant.items() if k != member}])
        for extra in ("deprecated", "note"):
            with self.subTest(extra=extra):
                self.refused([dict(grant, **{extra: False})])

    def test_a_well_formed_grant_is_indexed_by_its_stream(self):
        grant = self.grant()
        reg = self.registry([grant])
        self.assertEqual(reg.stream_signers, {self.station: [grant]})
        self.assertEqual(reg.stream_grants(self.station), [grant])
        self.assertIsNone(reg.registered_genesis(self.station))  # a grant needs no genesis entry

    def test_stream_id_must_have_a_stream_form(self):
        for value in ("", "net:", "net:Wire", "rappid:@test/station", self.station + ":", "body", 7, None):
            with self.subTest(value=value):
                with self.assertRaises(REG.RegistryError):
                    REG.validate_entry(self.grant(stream_id=value))

    def test_signer_must_be_a_rappid(self):
        for value in ("", "rappid:signer", "rappid:@Test/signer:" + "0" * 64, None, 5, [self.keys["signer"]]):
            with self.subTest(value=value):
                with self.assertRaises(REG.RegistryError):
                    REG.validate_entry(self.grant(signer=value))

    def test_kinds_is_a_non_empty_array_of_kinds(self):
        for value in ("body.pulse", [], None, [7], ["body"], ["Body.pulse"], ["body.pulse", None],
                      {"body.pulse": True}):
            with self.subTest(value=value):
                with self.assertRaises(REG.RegistryError):
                    REG.validate_entry(self.grant(kinds=value))

    def test_kinds_ascend_bytewise_without_duplicates(self):
        for value in (["body.pulse", "body.notice"], ["body.pulse", "body.pulse"],
                      ["body.notice", "body.pulse", "body.notice"], ["body.pulse", "body-x.pulse"]):
            with self.subTest(value=value):
                with self.assertRaises(REG.RegistryError):
                    REG.validate_entry(self.grant(kinds=value))
        # "-" (0x2D) sorts before "." (0x2E): bytewise order, not a collation that skips punctuation.
        for value in (["body-x.pulse", "body.pulse"], ["body.notice", "body.pulse", "body.twin-pulse"]):
            with self.subTest(value=value):
                self.assertEqual(len(self.registry([self.grant(kinds=value)]).stream_grants(self.station)), 1)

    def test_re_genesis_kinds_are_reserved_for_the_owner(self):
        cases = (([("body.re-genesis")], self.station), (["memory.re-genesis"], self.station + ":main"),
                 (["swarm.re-genesis"], "net:wire"), (["body.pulse", "body.re-genesis"], self.station))
        for kinds, stream_id in cases:
            with self.subTest(kinds=kinds):
                with self.assertRaises(REG.RegistryError):  # structural: family and registration fit
                    REG.validate_entry(self.grant(stream_id=stream_id, kinds=kinds))

    def test_since_and_until_bound_a_non_empty_window(self):
        bad = (("since_utc", "2026-07-10T00:00:00Z"), ("since_utc", None),
               ("until_utc", "2026-13-01T00:00:00.000Z"), ("until_utc", ""), ("until_utc", 0),
               ("until_utc", False), ("until_utc", SINCE), ("until_utc", BEFORE))
        for member, value in bad:
            with self.subTest(member=member, value=value):
                with self.assertRaises(REG.RegistryError):
                    REG.validate_entry(self.grant(**{member: value}))
        for value in ("2026-07-10T00:00:00.001Z", None):
            with self.subTest(until_utc=value):
                self.registry([self.grant(until_utc=value)])

    def test_the_declared_members_keep_their_shapes(self):
        cases = {"activated_utc": ("yesterday", None), "declared_by": ("owner", None), "sig": ("", None, 5)}
        for member, values in cases.items():
            for value in values:
                with self.subTest(member=member, value=value):
                    grant = self.grant()
                    grant[member] = value
                    with self.assertRaises(REG.RegistryError):
                        REG.validate_entry(grant)


class GrantCrossEntryTests(Base):
    def test_the_signer_needs_an_spki_entry_in_this_registry(self):
        entries = [e for e in self.base() if e.get("rappid") != self.keys["signer"]]
        self.refused([self.grant()], entries=entries)

    def test_a_keyless_rappid_is_never_a_signer(self):
        self.refused([self.grant(signer=self.station)])
        claimed = {"type": "spki", "rappid": self.station, "deprecated": False,
                   "spki_der_b64": base64.b64encode(b"any key at all").decode("ascii")}
        self.refused([claimed])  # no SPKI hashes to a UUIDv4 tail (§10 key discovery)

    def test_every_kind_must_be_registered_here(self):
        self.refused([self.grant(kinds=["body.heartbeat"])])
        self.refused([self.grant(kinds=["body.heartbeat", "body.pulse"])])

    def test_every_kind_family_must_fit_the_stream_form(self):
        memory = self.station + ":main"
        for stream_id, kinds in ((self.station, ["memory.save"]), (self.station, ["swarm.echo"]),
                                 (memory, ["body.pulse"]), ("net:wire", ["body.pulse"]),
                                 (self.station, ["body.pulse", "memory.save"])):
            with self.subTest(stream_id=stream_id, kinds=kinds):
                self.refused([self.grant(stream_id=stream_id, kinds=kinds)])
        for stream_id, kinds in ((memory, ["memory.save"]), ("net:wire", ["swarm.echo"])):
            with self.subTest(stream_id=stream_id, kinds=kinds):
                self.assertEqual(len(self.registry([self.grant(stream_id=stream_id, kinds=kinds)])
                                     .stream_grants(stream_id)), 1)

    def test_retired_keys_and_kinds_never_invalidate_a_grant(self):
        entries = [dict(e, deprecated=True) if e.get("rappid") == self.keys["signer"] and e["type"] == "spki"
                   else e for e in self.estate.base_entries()] + self.kind_entries(deprecated={"body.pulse"})
        reg = self.registry([self.grant()], entries=entries)
        self.assertEqual(len(reg.stream_grants(self.station)), 1)
        # Retirement still bites where it should: a retired kind is not live (§7.5 step 1) and a
        # key whose spki entry is deprecated without a re-anchor is refused (§10).
        self.assertEqual(self.verify(reg, self.pulse(INSIDE))[:2], (False, "1"))
        ok, why = reg.frame_authorized(self.pulse(INSIDE))
        self.assertFalse(ok)
        self.assertIn("deprecated", why)


class AuthorityTests(Base):
    def test_an_owner_signed_frame_speaks_for_the_estate_without_a_grant(self):
        reg = self.registry()
        self.assertEqual(reg.stream_grants(self.station), [])
        self.assertEqual(reg.frame_authorized(self.pulse(INSIDE, signer="owner")), (True, "estate owner"))
        memory = self.pulse(INSIDE, stream_id=self.station + ":main", kind="memory.save", signer="owner")
        self.assertEqual(reg.frame_authorized(memory), (True, "estate owner"))

    def test_a_granted_signer_inside_its_window_speaks_for_the_estate(self):
        reg = self.registry([self.grant()])
        self.assertEqual(reg.frame_authorized(self.pulse(INSIDE)), (True, "stream-signer grant"))

    def test_the_window_includes_since_and_excludes_until(self):
        reg = self.registry([self.grant()])
        for utc, expected in ((SINCE, True), (LAST, True), (BEFORE, False), (UNTIL, False), (LATER, False)):
            with self.subTest(utc=utc):
                ok, why = reg.frame_authorized(self.pulse(utc))
                self.assertEqual(ok, expected, why)
                if not expected:
                    self.assertIn("window", why)

    def test_an_open_ended_grant_never_ends_and_any_covering_grant_suffices(self):
        reg = self.registry([self.grant(until_utc=None)])
        self.assertTrue(reg.frame_authorized(self.pulse(FAR))[0])
        self.assertFalse(reg.frame_authorized(self.pulse(BEFORE))[0])
        split = self.registry([self.grant(until_utc=INSIDE), self.grant(since_utc=ROTATED, until_utc=None)])
        verdicts = [split.frame_authorized(self.pulse(utc))[0] for utc in (SINCE, INSIDE, ROTATED, FAR)]
        self.assertEqual(verdicts, [True, False, True, True])

    def test_a_backdated_grant_adopts_frames_already_published_in_its_window(self):
        first = self.pulse(SINCE)  # signed and published while no grant exists
        second = self.pulse(LAST, head=first)
        self.assertEqual(self.verify(self.registry(), first)[:2], (False, "authority"))
        grant = self.grant(activated_utc=LATER)  # declared after the whole window has passed
        self.assertTrue(grant["since_utc"] < grant["until_utc"] < grant["activated_utc"])
        status, reg, why = self.load([grant], verification_utc=LATER)
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(self.verify(reg, first), (True, None, "stream-signer grant"))
        self.assertEqual(self.verify(reg, second, head=first), (True, None, "stream-signer grant"))
        ok, why = reg.frame_authorized(self.pulse(LATER, head=second))
        self.assertFalse(ok)  # the window bounds what it adopts, not activated_utc
        self.assertIn("window", why)
        straddling = self.registry([self.grant(activated_utc=INSIDE, until_utc=None)])
        self.assertEqual([straddling.frame_authorized(self.pulse(utc))[0] for utc in (BEFORE, SINCE, INSIDE, FAR)],
                         [False, True, True, True])

    def test_a_kind_the_grant_does_not_list_is_refused(self):
        reg = self.registry([self.grant(kinds=["body.notice", "body.pulse"])])
        self.assertTrue(reg.frame_authorized(self.pulse(INSIDE, kind="body.notice"))[0])
        ok, why = reg.frame_authorized(self.pulse(INSIDE, kind="body.twin-pulse"))
        self.assertFalse(ok)
        self.assertIn("lists kind", why)

    def test_a_grant_covers_only_its_own_stream(self):
        reg = self.registry([self.grant()])
        other = R.mint_rappid("test", "other-station")
        for stream_id, kind in ((other, "body.pulse"), (self.station + ":main", "memory.save"),
                                ("net:wire", "swarm.echo")):
            with self.subTest(stream_id=stream_id):
                ok, why = reg.frame_authorized(self.pulse(INSIDE, stream_id=stream_id, kind=kind))
                self.assertFalse(ok)
                self.assertIn("neither", why)
        memory_only = self.registry([self.grant(stream_id=self.station + ":main", kinds=["memory.save"])])
        self.assertFalse(memory_only.frame_authorized(self.pulse(INSIDE))[0])

    def test_a_registered_key_without_a_grant_is_valid_yet_not_the_estates_statement(self):
        reg = self.registry([self.grant()])
        frame = self.pulse(INSIDE, signer="crawler")
        with self.estate.mocked():
            self.assertEqual(R.verify_frame(frame, head=None, stream_id_of_record=self.station,
                                            signature_verifier=reg.signature_verifier()), (True, None, "ok"))
        ok, why = reg.frame_authorized(frame)
        self.assertFalse(ok)
        self.assertIn("neither", why)

    def test_an_unsigned_frame_is_valid_yet_never_the_estates_statement(self):
        reg = self.registry([self.grant()])
        frame = self.pulse(INSIDE, signer=None)
        self.assertEqual(R.verify_frame(frame, head=None, stream_id_of_record=self.station), (True, None, "ok"))
        self.assertEqual(reg.check_frame_binding(frame), (True, "ok"))
        ok, why = reg.frame_authorized(frame)
        self.assertFalse(ok)
        self.assertIn("unsigned", why)
        self.assertEqual(self.verify(reg, frame)[:2], (False, "authority"))

    def test_a_stream_runs_unsigned_then_signed_as_one_chain(self):
        reg = self.registry([self.grant(until_utc=None)])
        first = self.pulse("2026-07-01T00:00:00.000Z", signer=None)
        second = self.pulse("2026-07-05T00:00:00.000Z", head=first, signer=None)
        third = self.pulse(SINCE, head=second)
        fourth = self.pulse(INSIDE, head=third)
        head, verdicts = None, []
        for frame in (first, second, third, fourth):
            with self.estate.mocked():
                self.assertEqual(R.verify_frame(frame, head=head, stream_id_of_record=self.station,
                                                signature_verifier=reg.signature_verifier()), (True, None, "ok"))
            verdicts.append(self.verify(reg, frame, head=head))
            head = frame
        self.assertEqual([verdict[:2] for verdict in verdicts],
                         [(False, "authority"), (False, "authority"), (True, None), (True, None)])
        self.assertEqual(third["prev"], second["payload_hash"])
        self.assertEqual(verdicts[2][2], "stream-signer grant")

    def test_a_tombstoned_signer_is_refused_from_revoked_utc(self):
        tombstone = {"type": "tombstone", "rappid": self.keys["signer"], "revoked_utc": ROTATED}
        tombstone["sig"] = self.estate.sign(tombstone, self.keys["owner"])
        reg = self.registry([self.grant(), tombstone])
        self.assertTrue(reg.frame_authorized(self.pulse(INSIDE))[0])
        for utc in (ROTATED, LAST):
            with self.subTest(utc=utc):
                ok, why = reg.frame_authorized(self.pulse(utc))
                self.assertFalse(ok)
                self.assertIn("tombstoned", why)
                self.assertTrue(reg.grant_covers(self.station, self.keys["signer"], "body.pulse", utc))
        # §7.5 step 6 refuses the same frame first: an invalid frame, not merely an unauthorized one.
        self.assertEqual(self.verify(reg, self.pulse(ROTATED))[:2], (False, "6"))
        self.assertEqual(self.load([self.grant(), tombstone])[0], "verified")

    def test_a_rotated_signer_needs_a_new_grant_for_its_successor(self):
        rotation = self.estate.reanchor("signer", "signer-next", signer="owner", utc=ROTATED)
        entries = [dict(e, deprecated=True) if e.get("rappid") == self.keys["signer"] and e["type"] == "spki"
                   else e for e in self.base()]
        old_grant = self.grant(until_utc=None)
        reg = self.registry([old_grant, rotation], entries=entries)
        self.assertTrue(reg.frame_authorized(self.pulse(INSIDE))[0])
        ok, why = reg.frame_authorized(self.pulse(ROTATED))
        self.assertFalse(ok)
        self.assertIn("superseded", why)
        ok, why = reg.frame_authorized(self.pulse(ROTATED, signer="signer-next"))
        self.assertFalse(ok)  # never inherited through the re-anchor
        self.assertIn("neither", why)
        new_grant = self.grant(signer=self.keys["signer-next"], since_utc=ROTATED, until_utc=None,
                               activated_utc=ROTATED)
        reg = self.registry([old_grant, rotation, new_grant], entries=entries)
        self.assertEqual(reg.frame_authorized(self.pulse(ROTATED, signer="signer-next")),
                         (True, "stream-signer grant"))
        self.assertFalse(reg.frame_authorized(self.pulse(ROTATED))[0])
        self.assertEqual(self.load([old_grant, rotation, new_grant], entries=entries)[0], "verified")

    def test_owner_authority_follows_the_owners_tenure(self):
        handover = self.estate.reanchor("owner", "heir", signer="owner", utc=ROTATED)
        reg = self.registry([handover], entries=self.base(owner="heir"))
        self.assertEqual(reg.frame_authorized(self.pulse(INSIDE, signer="owner")), (True, "estate owner"))
        self.assertFalse(reg.frame_authorized(self.pulse(ROTATED, signer="owner"))[0])
        self.assertEqual(reg.frame_authorized(self.pulse(ROTATED, signer="heir")), (True, "estate owner"))
        self.assertFalse(reg.frame_authorized(self.pulse(INSIDE, signer="heir"))[0])

    def test_an_owner_key_refused_by_section_10_does_not_speak_for_the_estate(self):
        tombstone = {"type": "tombstone", "rappid": self.keys["owner"], "revoked_utc": ROTATED}
        tombstone["sig"] = self.estate.sign(tombstone, self.keys["owner"])
        reg = self.registry([tombstone])
        self.assertEqual(reg.frame_authorized(self.pulse(INSIDE, signer="owner")), (True, "estate owner"))
        ok, why = reg.frame_authorized(self.pulse(ROTATED, signer="owner"))
        self.assertFalse(ok)
        self.assertIn("tombstoned", why)

    def test_a_keyless_organism_speaks_through_a_granted_keyed_signer(self):
        self.assertEqual(REG.stream_form(self.station), "body-stream")
        self.assertNotIn(self.station, self.estate.der)
        reg = self.registry([self.grant()])
        self.assertEqual(self.verify(reg, self.pulse(INSIDE)), (True, None, "stream-signer grant"))
        ok, _ = reg.authority_decision(self.station, self.station, "body.pulse", INSIDE)
        self.assertFalse(ok)  # the organism's own rappid is no key, so it is never a kid

    def test_a_grant_on_a_swarm_stream(self):
        reg = self.registry([self.grant(stream_id="net:wire", kinds=["swarm.echo"])])
        frame = self.pulse(INSIDE, stream_id="net:wire", kind="swarm.echo")
        self.assertEqual(self.verify(reg, frame, stream_id_of_record="net:wire"), (True, None, "stream-signer grant"))
        unsigned = self.pulse(INSIDE, stream_id="net:wire", kind="swarm.echo", signer=None)
        self.assertEqual(self.verify(reg, unsigned, stream_id_of_record="net:wire")[:2], (False, "6"))

    def test_a_sig_whose_protected_header_does_not_parse_is_refused(self):
        reg = self.registry([self.grant()])
        frame = self.pulse(INSIDE)
        ok, why = reg.frame_authorized(dict(frame, sig="not-a-jws"))
        self.assertFalse(ok)
        self.assertIn("JWS", why)
        header = {"alg": ["EdDSA"], "b64": False, "crit": ["b64"], "kid": self.keys["signer"]}
        unhashable = b64url(R.canonical(header).encode("utf-8")) + ".." + b64url(b"x")
        self.assertFalse(reg.frame_authorized(dict(frame, sig=unhashable))[0])
        self.assertEqual(reg.frame_authorized([]), (False, "frame is not a JSON object"))

    def test_the_pure_helpers_decide_over_a_frame_summary(self):
        reg = self.registry([self.grant()])
        signer, owner = self.keys["signer"], self.keys["owner"]
        self.assertTrue(reg.grant_covers(self.station, signer, "body.pulse", INSIDE))
        for args in ((self.station, signer, "body.pulse", UNTIL), (self.station, signer, "body.notice", INSIDE),
                     (self.station, self.keys["crawler"], "body.pulse", INSIDE),
                     (self.station, signer, "body.pulse", "2026-07-20"), (None, signer, "body.pulse", INSIDE)):
            with self.subTest(args=args):
                self.assertFalse(reg.grant_covers(*args))
        self.assertEqual(reg.authority_decision(self.station, signer, "body.pulse", INSIDE),
                         (True, "stream-signer grant"))
        self.assertEqual(reg.authority_decision(self.station, owner, "body.notice", T0), (True, "estate owner"))
        for kid, utc in ((None, INSIDE), ("not-a-rappid", INSIDE), (signer, "2026-07-20")):
            with self.subTest(kid=kid, utc=utc):
                self.assertFalse(reg.authority_decision(self.station, kid, "body.pulse", utc)[0])

    def test_stream_grants_are_append_ordered_copies(self):
        first = self.grant()
        second = self.grant(signer=self.keys["crawler"], kinds=["body.notice"])
        reg = self.registry([first, second])
        grants = reg.stream_grants(self.station)
        self.assertEqual(grants, [first, second])
        grants.clear()
        self.assertEqual(len(reg.stream_grants(self.station)), 2)
        for stream_id in ("net:wire", None, ["unhashable"]):
            with self.subTest(stream_id=stream_id):
                self.assertEqual(reg.stream_grants(stream_id), [])


class VerifyAuthorizedFrameTests(Base):
    def test_a_valid_frame_without_authority_fails_at_authority_not_at_a_725_step(self):
        reg = self.registry([self.grant()])
        ok, step, why = self.verify(reg, self.pulse(INSIDE, signer="crawler"))
        self.assertEqual((ok, step), (False, "authority"))
        self.assertNotIn(step, STEPS)
        self.assertIn("neither", why)

    def test_an_invalid_frame_fails_at_its_725_step(self):
        entries = self.estate.base_entries() + self.kind_entries(deprecated={"body.twin-pulse"})
        reg = self.registry([self.grant(kinds=["body.pulse", "body.twin-pulse"])], entries=entries)
        good = self.pulse(INSIDE)
        forged = dict(good, sig=jws_shaped(self.keys["signer"], "never-recorded"))
        transplanted = dict(self.pulse(INSIDE, payload={"pulse": 7}, signer=None), sig=good["sig"])
        memory = self.station + ":main"
        cases = (
            ("payload changed after hashing", dict(good, payload={"pulse": 99}), None, self.station, "2"),
            ("frame_hash changed", dict(good, frame_hash="0" * 64), None, self.station, "3"),
            ("read as another stream", good, None, R.mint_rappid("test", "elsewhere"), "1a"),
            ("forged signature", forged, None, self.station, "6"),
            ("a valid signature moved onto another frame", transplanted, None, self.station, "6"),
            ("genesis presented as a successor", good, self.pulse(SINCE), self.station, "4"),
            ("unregistered kind", self.pulse(INSIDE, kind="body.heartbeat"), None, self.station, "1"),
            ("retired kind", self.pulse(INSIDE, kind="body.twin-pulse"), None, self.station, "1"),
            ("family does not fit the stream", self.pulse(INSIDE, stream_id=memory), None, memory, "1"),
            ("unregistered kind outranks a forged signature",
             dict(self.pulse(INSIDE, kind="body.heartbeat"), sig=forged["sig"]), None, self.station, "1"),
            ("twelfth key", dict(good, extra=1), None, self.station, "1"),
            ("not an object", [], None, self.station, "1"),
        )
        for label, frame, head, stream_id, step in cases:
            with self.subTest(label):
                self.assertEqual(self.verify(reg, frame, head=head, stream_id_of_record=stream_id)[:2],
                                 (False, step))

    def test_the_stream_of_record_is_required(self):
        reg = self.registry([self.grant()])
        with self.estate.mocked():
            self.assertEqual(reg.verify_authorized_frame(self.pulse(INSIDE), head=None, stream_id_of_record=None)[:2],
                             (False, "1a"))
        with self.assertRaises(TypeError):
            reg.verify_authorized_frame(self.pulse(INSIDE))  # head and stream are keyword-only, required

    def test_success_names_the_authority(self):
        reg = self.registry([self.grant()])
        self.assertEqual(self.verify(reg, self.pulse(INSIDE)), (True, None, "stream-signer grant"))
        self.assertEqual(self.verify(reg, self.pulse(INSIDE, signer="owner")), (True, None, "estate owner"))

    def test_advancing_the_head_past_until_utc_ends_backdated_speech(self):
        reg = self.registry([self.grant()])
        first = self.pulse(INSIDE)
        # utc is producer-controlled: after until_utc has passed, the signer can still stamp just below it
        self.assertEqual(self.verify(reg, self.pulse(LAST, head=first), head=first),
                         (True, None, "stream-signer grant"))
        # until the owner advances the head past until_utc (§14): a successor then either precedes
        # the head (§7.5 step 4) or falls outside the window (authority).
        closing = self.pulse(UNTIL, head=first, signer="owner")
        self.assertEqual(self.verify(reg, closing, head=first), (True, None, "estate owner"))
        self.assertEqual(self.verify(reg, self.pulse(LAST, head=closing), head=closing)[:2], (False, "4"))
        self.assertEqual(self.verify(reg, self.pulse(UNTIL, head=closing), head=closing)[:2],
                         (False, "authority"))


class ProfileAuthorizationTests(Base):
    def test_authorization_verifier_plugs_into_authoritative_frame_payload(self):
        reg = self.registry([self.grant()])
        payload = {"schema": "test-pulse/1", "crawl": 1}

        def accept(frame):
            with self.estate.mocked():
                return P.authoritative_frame_payload(
                    frame, expected_schema="test-pulse/1", purpose="test-pulse", head=None,
                    stream_id=self.station, registered_kinds=set(reg.kinds),
                    signature_verifier=reg.signature_verifier(),
                    authorization_verifier=reg.authorization_verifier(),
                )

        self.assertEqual(accept(self.pulse(INSIDE, payload=payload)), payload)
        self.assertEqual(accept(self.pulse(INSIDE, payload=payload, signer="owner")), payload)
        with self.assertRaisesRegex(ValueError, "signer is not authorized"):
            accept(self.pulse(INSIDE, payload=payload, signer="crawler"))
        with self.assertRaisesRegex(ValueError, "signer is not authorized"):
            accept(self.pulse(UNTIL, payload=payload))
        with self.assertRaisesRegex(ValueError, "must be signed"):
            accept(self.pulse(INSIDE, payload=payload, signer=None))
        verifier = reg.authorization_verifier()
        self.assertIs(verifier(self.pulse(INSIDE)), True)
        self.assertIs(verifier(self.pulse(INSIDE), "any purpose"), True)
        self.assertIs(verifier(self.pulse(INSIDE, signer="crawler"), "test-pulse"), False)

    def test_a_profile_defined_signer_rule_is_kept(self):
        # §13.7 binds only a consumer with no profile-defined signer rule; a profile's own rule (here
        # a stage-approver set) keeps governing its payload, with or without a grant.
        reg = self.registry([self.grant()])
        payload = {"schema": "test-pulse/1", "crawl": 1}
        approvers = {self.keys["crawler"]}

        def approver(frame, purpose=None):
            return R.parse_detached_jws(frame["sig"])[0]["kid"] in approvers

        def accept(frame, rule):
            with self.estate.mocked():
                return P.authoritative_frame_payload(
                    frame, expected_schema="test-pulse/1", purpose="test-pulse", head=None,
                    stream_id=self.station, registered_kinds=set(reg.kinds),
                    signature_verifier=reg.signature_verifier(), authorization_verifier=rule,
                )

        by_approver = self.pulse(INSIDE, payload=payload, signer="crawler")
        by_grantee = self.pulse(INSIDE, payload=payload)
        self.assertFalse(reg.frame_authorized(by_approver)[0])
        self.assertEqual(accept(by_approver, approver), payload)
        with self.assertRaisesRegex(ValueError, "signer is not authorized"):
            accept(by_grantee, approver)  # a grant is not the profile's approval
        approvers.add(self.keys["signer"])
        grant_check = reg.authorization_verifier()

        def approver_and_grant(frame, purpose=None):  # a profile MAY also require the §13.7 check
            return approver(frame, purpose) and grant_check(frame, purpose)

        self.assertEqual(accept(by_grantee, approver_and_grant), payload)
        with self.assertRaisesRegex(ValueError, "signer is not authorized"):
            accept(by_approver, approver_and_grant)


class GrantDeclarationTests(Base):
    def test_an_owner_declared_grant_verifies(self):
        status, reg, why = self.load([self.grant()])
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(len(reg.stream_grants(self.station)), 1)

    def test_a_forged_grant_refuses_the_whole_registry(self):
        entry = self.grant()
        entry["sig"] = "forged"
        self.assertEqual(self.load([entry])[0], "refused")

    def test_a_signer_cannot_grant_itself(self):
        status, _, why = self.load([self.grant(declared="signer")])
        self.assertEqual(status, "refused")
        self.assertIn("declared_by is not the estate owner", why)

    def test_a_grant_signed_by_another_registered_key_is_refused(self):
        self.assertEqual(self.load([self.grant(sign_as="signer")])[0], "refused")

    def test_widening_a_signed_grant_is_refused(self):
        for member, value in (("until_utc", None), ("kinds", ["body.notice", "body.pulse"]),
                              ("stream_id", R.mint_rappid("test", "elsewhere")), ("since_utc", T0)):
            with self.subTest(member=member):
                entry = self.grant()
                entry[member] = value
                self.assertEqual(self.load([entry])[0], "refused")

    def test_the_grant_is_authenticated_at_its_activated_utc(self):
        handover = self.estate.reanchor("owner", "heir", signer="owner", utc=ROTATED)
        before = self.grant(declared="owner", activated_utc=INSIDE)
        current = self.grant(declared="heir", activated_utc=LATER)
        stale = self.grant(declared="owner", activated_utc=LATER)
        backdated = self.grant(declared="heir", activated_utc=INSIDE)

        def load(*grants):
            return self.load([handover] + list(grants), owner="heir", entries=self.base(owner="heir"))[0]

        self.assertEqual(load(before, current), "verified")
        self.assertEqual(load(stale), "refused")
        self.assertEqual(load(backdated), "refused")

    def test_first_seen_skew_bounds_activated_utc(self):
        self.assertEqual(self.load([self.grant(activated_utc="2026-07-01T00:05:00.000Z")],
                                   verification_utc=T0)[0], "verified")
        self.assertEqual(self.load([self.grant(activated_utc="2026-07-01T00:05:00.001Z")],
                                   verification_utc=T0)[0], "refused")

    def test_an_accepted_grant_is_retained_byte_for_byte(self):
        self.assertIn("stream-signer", REG.DECLARED_TYPES)
        self.assertIn("stream-signer", REG.PERSISTED_TYPES)
        grant = self.grant()
        self.assertEqual(self.load([grant])[0], "verified")
        persisted = [R._strict_json(R.canonical(grant))]  # what the consumer stored on acceptance

        def later(extra):
            document = self.estate.document(self.base() + list(extra), seq=3)
            return self.estate.load(document, persisted_seq=2, persisted_entries=persisted)

        self.assertEqual(later([grant])[0], "verified")
        self.assertEqual(later([grant, self.grant(kinds=["body.notice"])])[0], "verified")  # growth
        status, _, why = later([])  # dropped, though registry_seq increased
        self.assertEqual(status, "refused")
        self.assertIn("removed or mutated", why)
        # An owner-signed variant in its place is refused too, narrowed as much as widened: a grant
        # ends early only by the until_utc it was declared with, or by §10 refusing its signer.
        variants = {"narrowed until_utc": {"until_utc": INSIDE}, "open-ended": {"until_utc": None},
                    "widened kinds": {"kinds": ["body.notice", "body.pulse"]},
                    "later since_utc": {"since_utc": ROTATED}, "re-signed, same members": {}}
        for label, members in variants.items():
            with self.subTest(label):
                variant = self.grant(**members)
                self.assertNotEqual(R.canonical(variant), R.canonical(grant))
                self.assertEqual(self.load([variant])[0], "verified")  # a valid declaration on its own
                status, _, why = later([variant])
                self.assertEqual(status, "refused")
                self.assertIn("removed or mutated", why)

    def test_an_exact_copy_verifies_apart_from_its_document(self):
        entry = self.grant()
        with self.estate.mocked():
            reg = self.registry([entry])
            self.assertEqual(reg.declared_entry_ok(copy.deepcopy(entry)), (True, "ok"))
            self.assertFalse(reg.declared_entry_ok(dict(entry, until_utc=None))[0])


@unittest.skipUnless(real_ed25519_signer(), "optional cryptography import is absent")
class RealSignatureTests(unittest.TestCase):
    """A keyless station's body.pulse stream signed by a granted key, through the real §10 boundary."""

    def test_a_real_signed_pulse_on_a_keyless_station(self):
        owner_der, owner_sign = real_ed25519_signer()
        signer_der, signer_sign = real_ed25519_signer()
        crawler_der, crawler_sign = real_ed25519_signer()
        owner = R.mint_rappid("test", "estate-owner", spki_der=owner_der)
        signer = R.mint_rappid("test", "pulse-signer", spki_der=signer_der)
        crawler = R.mint_rappid("test", "crawler", spki_der=crawler_der)
        station = R.mint_rappid("test", "station")

        def spki(rappid, der):
            return {"type": "spki", "rappid": rappid, "deprecated": False,
                    "spki_der_b64": base64.b64encode(der).decode("ascii")}

        def declared(entry, sign, kid):
            return dict(entry, sig=sign(entry, kid))

        def document(entries):
            doc = {"schema": "rapp/1-registry", "registry_seq": 1, "canonical_source": SOURCE, "entries": entries}
            return dict(doc, sig=owner_sign(doc, owner))

        grant = {"type": "stream-signer", "stream_id": station, "signer": signer, "kinds": ["body.pulse"],
                 "since_utc": SINCE, "until_utc": None, "activated_utc": T0, "declared_by": owner}
        base = [{"type": "estate_owner", "rappid": owner}, spki(owner, owner_der), spki(signer, signer_der),
                spki(crawler, crawler_der), {"type": "kind", "kind": "body.pulse", "family": "body",
                                             "deprecated": False}]
        status, reg, why = REG.load_document(document(base + [declared(grant, owner_sign, owner)]),
                                             trust_anchor=owner, verification_utc=T0)
        self.assertEqual((status, why), ("verified", "ok"))
        self_grant = declared(dict(grant, declared_by=signer), signer_sign, signer)
        status, _, why = REG.load_document(document(base + [self_grant]), trust_anchor=owner,
                                           verification_utc=T0)
        self.assertEqual(status, "refused")
        self.assertIn("declared_by is not the estate owner in effect", why)

        def signed(frame, sign, kid):
            return dict(frame, sig=sign({k: v for k, v in frame.items() if k != "sig"}, kid))

        pulse = R.build_frame("body.pulse", station, 0, INSIDE, {"schema": "test-pulse/1", "crawl": 1}, None)
        granted = signed(pulse, signer_sign, signer)
        self.assertEqual(reg.verify_authorized_frame(granted, head=None, stream_id_of_record=station),
                         (True, None, "stream-signer grant"))
        self.assertEqual(reg.verify_authorized_frame(signed(pulse, owner_sign, owner), head=None,
                                                     stream_id_of_record=station), (True, None, "estate owner"))
        self.assertEqual(reg.verify_authorized_frame(signed(pulse, crawler_sign, crawler), head=None,
                                                     stream_id_of_record=station)[:2], (False, "authority"))
        impostor = signed(pulse, crawler_sign, signer)  # the crawler's key under the signer's kid
        self.assertEqual(reg.verify_authorized_frame(impostor, head=None, stream_id_of_record=station)[:2],
                         (False, "6"))
        successor = signed(R.build_frame("body.pulse", station, 1, LATER, {"schema": "test-pulse/1", "crawl": 2},
                                         pulse["payload_hash"]), signer_sign, signer)
        self.assertEqual(reg.verify_authorized_frame(successor, head=granted, stream_id_of_record=station),
                         (True, None, "stream-signer grant"))
        payload = P.authoritative_frame_payload(
            granted, expected_schema="test-pulse/1", purpose="test-pulse", head=None, stream_id=station,
            registered_kinds={"body.pulse"}, signature_verifier=reg.signature_verifier(),
            authorization_verifier=reg.authorization_verifier(),
        )
        self.assertEqual(payload, pulse["payload"])


if __name__ == "__main__":
    unittest.main()
