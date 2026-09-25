"""§13.6 lifecycle notice tests (stdlib; the detached-JWS boundary is mocked as in
test_registry_lifecycle.py, plus an optional class that signs with a real Ed25519 key)."""
import base64
import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

import rapp as R
import rapp_check as C
import rapp_registry as REG
from registry_fixtures import MockEstate, SOURCE, T0, real_ed25519_signer

ROOT = Path(__file__).resolve().parent
EARLIER = "2026-06-01T00:00:00.000Z"
ROTATION = "2026-07-15T00:00:00.000Z"
T1 = "2026-08-01T00:00:00.000Z"
T2 = "2026-09-01T00:00:00.000Z"
T3 = "2026-10-01T00:00:00.000Z"
FUTURE = "2027-01-01T00:00:00.000Z"


def organism(slug, n):
    """A reproducible keyless §6.2 rappid (the mint over a fixed UUIDv4); synthetic."""
    return f"rappid:@acme/{slug}:" + R.Hb("rapp/1:rappid", bytes.fromhex("00000000000040008000%012x" % n))


ALPHA, BETA, GAMMA, DELTA = (organism(slug, n) for n, slug in enumerate(("alpha", "beta", "gamma", "delta"), 1))
BODY_PULSE = {"type": "kind", "kind": "body.pulse", "family": "body", "deprecated": False}


def b64url(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def mock_jws(estate, value, name):
    """A detached-JWS-shaped token that the mocked boundary accepts for exactly `value` signed by
    `name`, so `Registry.signature_verifier()` can read its protected `kid`."""
    kid = estate.keys[name]
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid}
    token = b64url(R.canonical(header).encode("utf-8")) + ".." + b64url(b"synthetic-%d" % len(estate.signatures))
    estate.signatures[token] = (R.canonical(value), kid, estate.der[kid])
    return token


class LifecycleCase(unittest.TestCase):
    def setUp(self):
        self.estate = MockEstate()

    def notice(self, rappid, state, since=T0, previous=None, superseded_by=None,
               activated=T0, declared="owner", signer=None):
        """One owner-declared §13.3 `lifecycle` entry; `previous` may be the entry it follows."""
        if isinstance(previous, dict):
            previous = REG.entry_hash(previous)
        entry = {"type": "lifecycle", "rappid": rappid, "state": state, "superseded_by": superseded_by,
                 "since_utc": since, "previous": previous, "activated_utc": activated,
                 "declared_by": self.estate.keys[declared]}
        return self.estate.declare(entry, signer or declared)

    def registry(self, *entries):
        return REG.Registry(self.estate.base_entries() + list(entries))

    def assertRefused(self, *entries, reason=None):
        with self.assertRaises(REG.RegistryError) as caught:
            self.registry(*entries)
        if reason is not None:
            self.assertRegex(str(caught.exception), reason)

    def load(self, entries, owner="owner", base=None, **kwargs):
        base = self.estate.base_entries(owner) if base is None else base
        document = self.estate.document(base + list(entries), owner=owner)
        return self.estate.load(document, owner=owner, **kwargs)


class LifecycleEntryTests(LifecycleCase):
    def test_a_notice_is_a_declared_entry_with_exactly_its_members(self):
        good = self.notice(ALPHA, "active")
        self.assertEqual(REG.validate_entry(good), "lifecycle")
        self.assertEqual(set(good), {"type", "rappid", "state", "superseded_by", "since_utc", "previous",
                                     "activated_utc", "declared_by", "sig"})
        self.assertEqual(REG.ENTRY_MEMBERS["lifecycle"], (set(good), set()))
        self.assertIn("lifecycle", REG.DECLARED_TYPES)
        self.assertIn("lifecycle", REG.PERSISTED_TYPES)  # every declared entry is persisted (§13.4)
        self.assertEqual(REG.LIFECYCLE_STATES, ("active", "deprecated", "superseded", "archived"))
        for member in sorted(set(good) - {"type"}):
            with self.subTest(missing=member):
                self.assertRefused({k: v for k, v in good.items() if k != member}, reason="member set")
        for extra in ({"deprecated": False}, {"until_utc": T1}, {"reason": "renamed"}):
            with self.subTest(extra=extra):
                self.assertRefused(dict(good, **extra), reason="member set")

    def test_each_member_has_its_grammar(self):
        bad = {
            "rappid": [None, ALPHA.upper(), ALPHA.rsplit(":", 1)[0] + ":" + "a" * 32, "@acme/alpha", 7],
            "state": [None, "", "Active", "retired", "deleted", ["active"]],
            "superseded_by": ["", "https://git.example.test/acme/beta", BETA[:-1] + "A", BETA.replace("@", "")],
            "since_utc": [None, "2026-07-01T00:00:00Z", "2026-07-01T00:00:00.000+00:00",
                          "2026-02-30T00:00:00.000Z", "2026-07-01t00:00:00.000z", 1783000000],
            "previous": ["", "A" * 64, "a" * 63, "a" * 65, 7],
            "activated_utc": [None, "2026-07-01", "2026-13-01T00:00:00.000Z"],
            "declared_by": [None, "", "owner", self.estate.keys["owner"].rsplit(":", 1)[0]],
            "sig": [None, "", 7],
        }
        for member, values in bad.items():
            # `deprecated` may name a successor, so a bad `superseded_by` is refused for its grammar.
            good = self.notice(ALPHA, "deprecated")
            for value in values:
                with self.subTest(member=member, value=value):
                    self.assertRefused(dict(good, **{member: value}), reason=re.escape(f"`{member}`"))
        previous = self.notice(ALPHA, "active")
        self.assertEqual(REG.validate_entry(self.notice(ALPHA, "archived", previous=previous)), "lifecycle")

    def test_state_decides_whether_a_successor_is_named(self):
        accepted = [("active", None), ("deprecated", None), ("deprecated", BETA),
                    ("superseded", BETA), ("archived", None), ("archived", BETA)]
        for state, successor in accepted:
            with self.subTest(state=state, superseded_by=successor):
                registry = self.registry(self.notice(ALPHA, state, superseded_by=successor))
                self.assertEqual(registry.lifecycle_head(ALPHA)["state"], state)
                self.assertEqual(registry.successor_at(ALPHA, T0), successor)
                self.assertIsNone(registry.successor_at(ALPHA, EARLIER))
        self.assertRefused(self.notice(ALPHA, "active", superseded_by=BETA), reason="must be null")
        self.assertRefused(self.notice(ALPHA, "superseded"), reason="names its successor")
        for state in ("deprecated", "superseded", "archived"):
            with self.subTest(state=state, superseded_by="itself"):
                self.assertRefused(self.notice(ALPHA, state, superseded_by=ALPHA), reason="never equals")


class LifecycleChainTests(LifecycleCase):
    def test_a_chain_follows_previous_links_and_its_last_entry_is_current(self):
        a1 = self.notice(ALPHA, "active")
        b1 = self.notice(BETA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, superseded_by=BETA, activated=T1)
        a3 = self.notice(ALPHA, "superseded", since=T2, previous=a2, superseded_by=BETA, activated=T2)
        registry = self.registry(a1, b1, a2, a3)
        self.assertEqual(registry.lifecycle_chain(ALPHA), [a1, a2, a3])
        self.assertEqual(registry.lifecycle_chain(BETA), [b1])
        self.assertEqual(registry.lifecycle_head(ALPHA), a3)
        self.assertEqual(registry.successor_at(ALPHA, T2), BETA)
        self.assertIsNone(registry.successor_at(BETA, T2))
        for absent in (GAMMA, None, 7):
            with self.subTest(rappid=absent):
                self.assertEqual(registry.lifecycle_chain(absent), [])
                self.assertIsNone(registry.lifecycle_head(absent))
                self.assertIsNone(registry.successor_at(absent, T2))
        registry.lifecycle_chain(ALPHA).clear()  # a caller's copy, never the index
        self.assertEqual(len(registry.lifecycle_chain(ALPHA)), 3)

    def test_a_fork_is_refused(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, activated=T1)
        rival = self.notice(ALPHA, "archived", since=T1, previous=a1, activated=T1)
        self.assertRefused(a1, a2, rival, reason="fork")

    def test_two_first_entries_are_refused(self):
        a1 = self.notice(ALPHA, "active")
        second = self.notice(ALPHA, "deprecated", since=T1, activated=T1)
        self.assertRefused(a1, second, reason="exactly one first entry")

    def test_a_link_to_a_later_entry_is_refused(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, activated=T1)
        self.assertEqual(self.registry(a1, a2).lifecycle_chain(ALPHA), [a1, a2])
        self.assertRefused(a2, a1, reason="does not precede")

    def test_a_link_to_another_organisms_entry_is_refused(self):
        a1 = self.notice(ALPHA, "active")
        b1 = self.notice(BETA, "active")
        crossed = self.notice(BETA, "deprecated", since=T1, previous=a1, activated=T1)
        self.assertRefused(a1, b1, crossed, reason="does not precede")
        self.assertRefused(a1, crossed, reason="does not precede")

    def test_a_link_must_name_an_earlier_lifecycle_entry(self):
        spki = self.estate.spki("worker")  # carried by the registry, but no lifecycle entry
        for named in (REG.entry_hash(spki), "0" * 64):
            with self.subTest(previous=named):
                a1 = self.notice(ALPHA, "active")
                self.assertRefused(a1, dict(self.notice(ALPHA, "archived", since=T1, activated=T1), previous=named),
                                   reason="does not precede")
                self.assertRefused(dict(a1, previous=named), reason="exactly one first entry|does not precede")

    def test_previous_names_the_exact_signed_entry(self):
        a1 = self.notice(ALPHA, "active")
        unsigned = R.H("rapp/1:particle", {k: v for k, v in a1.items() if k != "sig"})
        resigned = self.notice(ALPHA, "active")  # the same members under another signature
        self.assertNotEqual(REG.entry_hash(resigned), REG.entry_hash(a1))
        for named in (unsigned, REG.entry_hash(resigned)):
            with self.subTest(previous=named):
                follower = self.notice(ALPHA, "archived", since=T1, previous=named, activated=T1)
                self.assertRefused(a1, follower, reason="does not precede")

    def test_a_repeated_notice_is_refused(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, activated=T1)
        self.assertRefused(a1, copy.deepcopy(a1), reason="duplicate")
        self.assertRefused(a1, a2, copy.deepcopy(a2), reason="duplicate")

    def test_since_utc_never_decreases_along_a_chain(self):
        a1 = self.notice(ALPHA, "deprecated", since=T1, activated=T1)
        earlier = self.notice(ALPHA, "archived", since=T0, previous=a1, activated=T1)
        self.assertRefused(a1, earlier, reason="`since_utc` decreases")
        same = self.notice(ALPHA, "archived", since=T1, previous=a1, activated=T1)
        self.assertEqual(self.registry(a1, same).lifecycle_head(ALPHA), same)

    def test_activated_utc_never_decreases_along_a_chain(self):
        a1 = self.notice(ALPHA, "active", activated=T1)
        backdated = self.notice(ALPHA, "archived", since=T1, previous=a1, activated=T0)
        self.assertRefused(a1, backdated, reason="`activated_utc` decreases")
        millisecond = self.notice(ALPHA, "archived", since=T1, previous=a1, activated="2026-07-31T23:59:59.999Z")
        self.assertRefused(a1, millisecond, reason="`activated_utc` decreases")
        same = self.notice(ALPHA, "archived", since=T1, previous=a1, activated=T1)
        self.assertEqual(self.registry(a1, same).lifecycle_head(ALPHA), same)


class LifecycleStateAtTests(LifecycleCase):
    def test_the_state_in_effect_follows_since_utc(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, superseded_by=BETA, activated=T1)
        a3 = self.notice(ALPHA, "superseded", since=T2, previous=a2, superseded_by=BETA, activated=T2)
        registry = self.registry(a1, a2, a3)
        expected = [
            (EARLIER, None), ("2026-06-30T23:59:59.999Z", None), (T0, "active"),
            ("2026-07-31T23:59:59.999Z", "active"), (T1, "deprecated"), ("2026-08-15T12:00:00.000Z", "deprecated"),
            (T2, "superseded"), (FUTURE, "superseded"),
        ]
        for utc, state in expected:
            with self.subTest(utc=utc):
                self.assertEqual(registry.lifecycle_state_at(ALPHA, utc), state)
        self.assertEqual(registry.lifecycle_at(ALPHA, T0), a1)
        self.assertEqual(registry.lifecycle_at(ALPHA, "2026-08-15T12:00:00.000Z"), a2)
        self.assertEqual(registry.lifecycle_at(ALPHA, T3), a3)
        self.assertIsNone(registry.lifecycle_at(ALPHA, EARLIER))

    def test_the_successor_named_follows_since_utc(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, superseded_by=BETA, activated=T1)
        a3 = self.notice(ALPHA, "superseded", since=T2, previous=a2, superseded_by=GAMMA, activated=T2)
        a4 = self.notice(ALPHA, "archived", since=T3, previous=a3, activated=T3)
        registry = self.registry(a1, a2, a3, a4)
        expected = [
            (EARLIER, None), (T0, None), ("2026-07-31T23:59:59.999Z", None), (T1, BETA),
            ("2026-08-31T23:59:59.999Z", BETA), (T2, GAMMA), ("2026-09-30T23:59:59.999Z", GAMMA),
            (T3, None), (FUTURE, None),
        ]
        for utc, successor in expected:
            with self.subTest(utc=utc):
                self.assertEqual(registry.successor_at(ALPHA, utc), successor)
                in_effect = registry.lifecycle_at(ALPHA, utc)
                self.assertEqual(successor, None if in_effect is None else in_effect["superseded_by"])
        for named in (BETA, GAMMA):
            with self.subTest(successor=named):  # being named declares nothing for the successor
                self.assertIsNone(registry.successor_at(named, T3))
                self.assertIsNone(registry.lifecycle_state_at(named, T3))

    def test_absence_is_no_declared_lifecycle_never_deprecation(self):
        registry = self.registry(self.notice(ALPHA, "active", since=T1, activated=T1))
        self.assertIsNone(registry.lifecycle_state_at(ALPHA, T0))  # before its first since_utc
        for rappid in (BETA, GAMMA):
            with self.subTest(rappid=rappid):
                self.assertIsNone(registry.lifecycle_at(rappid, T2))
                self.assertIsNone(registry.lifecycle_state_at(rappid, T2))

    def test_a_retroactive_notice_governs_from_its_since_utc(self):
        g1 = self.notice(GAMMA, "active")
        g2 = self.notice(GAMMA, "archived", since=T1, previous=g1, activated=T3)  # declared later
        self.assertEqual(self.registry(g1).lifecycle_state_at(GAMMA, T2), "active")  # an older registry
        registry = self.registry(g1, g2)
        self.assertEqual(registry.lifecycle_state_at(GAMMA, "2026-07-31T23:59:59.999Z"), "active")
        self.assertEqual(registry.lifecycle_state_at(GAMMA, T1), "archived")
        self.assertEqual(registry.lifecycle_state_at(GAMMA, T2), "archived")

    def test_a_scheduled_notice_is_current_before_it_is_in_effect(self):
        g1 = self.notice(GAMMA, "active")
        g2 = self.notice(GAMMA, "superseded", since=FUTURE, previous=g1, superseded_by=DELTA, activated=T1)
        registry = self.registry(g1, g2)
        self.assertEqual(registry.lifecycle_head(GAMMA), g2)
        self.assertEqual(registry.lifecycle_head(GAMMA)["superseded_by"], DELTA)
        # A scheduled notice names no successor before its since_utc arrives.
        for utc in (T2, "2026-12-31T23:59:59.999Z"):
            with self.subTest(utc=utc):
                self.assertIsNone(registry.successor_at(GAMMA, utc))
        self.assertEqual(registry.successor_at(GAMMA, FUTURE), DELTA)
        self.assertEqual(registry.lifecycle_state_at(GAMMA, T2), "active")
        self.assertEqual(registry.lifecycle_state_at(GAMMA, "2026-12-31T23:59:59.999Z"), "active")
        self.assertEqual(registry.lifecycle_state_at(GAMMA, FUTURE), "superseded")
        first = self.notice(DELTA, "deprecated", since=FUTURE, activated=T1)
        registry = self.registry(first)
        self.assertEqual(registry.lifecycle_head(DELTA), first)
        self.assertIsNone(registry.lifecycle_state_at(DELTA, T2))
        self.assertEqual(registry.lifecycle_state_at(DELTA, FUTURE), "deprecated")

    def test_a_later_notice_with_the_same_since_utc_corrects_it(self):
        mistaken = self.notice(ALPHA, "deprecated", since=T1, activated=T1)
        corrected = self.notice(ALPHA, "active", since=T1, previous=mistaken, activated=T2)
        registry = self.registry(mistaken, corrected)
        self.assertEqual(registry.lifecycle_state_at(ALPHA, T1), "active")
        self.assertEqual(registry.lifecycle_at(ALPHA, T3), corrected)
        self.assertIsNone(registry.lifecycle_state_at(ALPHA, T0))

    def test_the_query_time_has_the_fixed_utc_form(self):
        registry = self.registry(self.notice(ALPHA, "active"))
        for utc in (None, "2026-07-01", "2026-07-01T00:00:00Z", "2026-02-30T00:00:00.000Z", 1783000000):
            with self.subTest(utc=utc):
                with self.assertRaises(REG.RegistryError):
                    registry.lifecycle_at(ALPHA, utc)
                with self.assertRaises(ValueError):
                    registry.lifecycle_state_at(BETA, utc)
                with self.assertRaises(REG.RegistryError):
                    registry.successor_at(ALPHA, utc)


class LifecycleCycleTests(LifecycleCase):
    def test_organisms_superseding_each_other_are_refused(self):
        self.assertRefused(self.notice(ALPHA, "superseded", superseded_by=BETA),
                           self.notice(BETA, "superseded", superseded_by=ALPHA), reason="cycle")

    def test_a_line_of_successors_is_accepted(self):
        registry = self.registry(self.notice(ALPHA, "superseded", superseded_by=BETA),
                                 self.notice(BETA, "superseded", superseded_by=GAMMA),
                                 self.notice(GAMMA, "active"))
        self.assertEqual([registry.successor_at(r, T0) for r in (ALPHA, BETA, GAMMA, DELTA)],
                         [BETA, GAMMA, None, None])
        registry = self.registry(self.notice(ALPHA, "superseded", superseded_by=BETA),
                                 self.notice(BETA, "archived", superseded_by=GAMMA))  # GAMMA declares nothing
        self.assertEqual(registry.successor_at(BETA, T0), GAMMA)
        self.assertIsNone(registry.lifecycle_head(GAMMA))

    def test_longer_cycles_are_refused_wherever_the_walk_starts(self):
        self.assertRefused(self.notice(ALPHA, "superseded", superseded_by=BETA),
                           self.notice(BETA, "archived", superseded_by=GAMMA),
                           self.notice(GAMMA, "deprecated", superseded_by=ALPHA), reason="cycle")
        self.assertRefused(self.notice(DELTA, "superseded", superseded_by=ALPHA),  # leads into the cycle
                           self.notice(ALPHA, "superseded", superseded_by=BETA),
                           self.notice(BETA, "superseded", superseded_by=ALPHA), reason="cycle")

    def test_a_recommended_successor_counts(self):
        self.assertRefused(self.notice(ALPHA, "deprecated", superseded_by=BETA),
                           self.notice(BETA, "superseded", superseded_by=ALPHA), reason="cycle")

    def test_the_notices_in_effect_at_any_one_time_must_not_loop(self):
        a1 = self.notice(ALPHA, "superseded", superseded_by=BETA)
        a2 = self.notice(ALPHA, "active", since=T1, previous=a1, activated=T1)  # reinstated
        # BETA naming ALPHA from T0 loops with a1 until a2 takes effect, though the current notices
        # (a2 and BETA's) do not loop.
        self.assertRefused(a1, a2, self.notice(BETA, "superseded", superseded_by=ALPHA),
                           reason=f"in effect at {re.escape(T0)} form a cycle")
        # BETA naming ALPHA only from T1, when a2 withdraws a1: the two never loop at one time.
        b1 = self.notice(BETA, "superseded", since=T1, superseded_by=ALPHA, activated=T1)
        registry = self.registry(a1, a2, b1)
        self.assertEqual((registry.successor_at(ALPHA, T0), registry.successor_at(BETA, T0)), (BETA, None))
        self.assertEqual((registry.successor_at(ALPHA, T1), registry.successor_at(BETA, T1)), (None, ALPHA))
        scheduled = self.notice(ALPHA, "superseded", since=FUTURE, previous=a2, superseded_by=BETA, activated=T2)
        self.assertRefused(a1, a2, b1, scheduled, reason=f"in effect at {re.escape(FUTURE)} form a cycle")

    def test_a_scheduled_reinstatement_that_leaves_a_loop_in_effect_is_refused(self):
        a1 = self.notice(ALPHA, "superseded", superseded_by=BETA)
        reinstatement = self.notice(ALPHA, "active", since=FUTURE, previous=a1, activated=T1)  # scheduled
        # The current notices do not loop, but a1 and BETA's notice are both in effect until FUTURE.
        self.assertRefused(a1, reinstatement, self.notice(BETA, "superseded", superseded_by=ALPHA),
                           reason="cycle")
        # Scheduled to take effect as a1 is withdrawn, BETA's notice never loops with it.
        b1 = self.notice(BETA, "superseded", since=FUTURE, superseded_by=ALPHA, activated=T1)
        registry = self.registry(a1, reinstatement, b1)
        for utc, named in ((T2, (BETA, None)), (FUTURE, (None, ALPHA))):
            with self.subTest(utc=utc):
                self.assertEqual((registry.successor_at(ALPHA, utc), registry.successor_at(BETA, utc)), named)
                walk, organism = [], ALPHA  # a walk along the successors in effect at one time ends
                while organism is not None:
                    self.assertNotIn(organism, walk)
                    walk.append(organism)
                    organism = registry.successor_at(organism, utc)

    def test_a_retroactive_notice_cannot_close_a_loop_in_the_past(self):
        a1 = self.notice(ALPHA, "superseded", superseded_by=BETA)
        a2 = self.notice(ALPHA, "active", since=T2, previous=a1, activated=T2)
        late = self.notice(BETA, "superseded", since=T1, superseded_by=ALPHA, activated=T3)  # declared later
        self.assertEqual(self.registry(a1, a2).successor_at(ALPHA, T1), BETA)
        self.assertRefused(a1, a2, late, reason=f"in effect at {re.escape(T1)} form a cycle")

    def test_every_since_utc_is_checked_not_only_the_first_and_current_notices(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "superseded", since=T1, previous=a1, superseded_by=BETA, activated=T1)
        a3 = self.notice(ALPHA, "active", since=T2, previous=a2, activated=T2)
        b1 = self.notice(BETA, "superseded", superseded_by=ALPHA)
        b2 = self.notice(BETA, "active", since=T3, previous=b1, activated=T3)
        # Neither the first notices (a1, b1) nor the current ones (a3, b2) loop; a2 and b1 do, from T1 to T2.
        self.assertRefused(a1, a2, a3, b1, b2, reason=f"in effect at {re.escape(T1)} form a cycle")
        undone = self.notice(ALPHA, "active", since=T2, previous=a1, activated=T2)
        self.assertIsNone(self.registry(a1, undone, b1, b2).successor_at(ALPHA, T1))

    def test_a_later_notice_can_close_a_cycle_its_first_notice_did_not(self):
        g1 = self.notice(GAMMA, "active")
        g2 = self.notice(GAMMA, "superseded", since=T1, previous=g1, superseded_by=DELTA, activated=T1)
        d1 = self.notice(DELTA, "deprecated", superseded_by=GAMMA)
        self.assertEqual(self.registry(g1, d1).successor_at(DELTA, T0), GAMMA)
        self.assertRefused(g1, d1, g2, reason="cycle")


class LifecycleSignatureTests(LifecycleCase):
    def test_owner_declared_notices_verify_in_a_signed_document(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "superseded", since=T1, previous=a1, superseded_by=BETA, activated=T1)
        status, registry, why = self.load([a1, a2])
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(registry.lifecycle_state_at(ALPHA, T2), "superseded")
        self.assertIsNone(registry.successor_at(ALPHA, T0))
        self.assertEqual(registry.successor_at(ALPHA, T2), BETA)

    def test_a_forged_or_mutated_notice_is_refused(self):
        forged = self.notice(ALPHA, "active")
        forged["sig"] = "forged"
        self.assertEqual(self.load([forged])[0], "refused")
        mutated = self.notice(ALPHA, "deprecated", superseded_by=BETA)
        for member, value in (("state", "archived"), ("since_utc", T1), ("superseded_by", GAMMA)):
            with self.subTest(member=member):
                self.assertEqual(self.load([dict(mutated, **{member: value})])[0], "refused")
        self.assertEqual(self.load([mutated])[0], "verified")

    def test_only_the_estate_owner_declares(self):
        other_signer = self.notice(ALPHA, "active", declared="owner", signer="worker")
        self.assertEqual(self.load([other_signer])[0], "refused")
        not_owner = self.notice(ALPHA, "active", declared="worker")
        self.assertEqual(self.load([not_owner])[0], "refused")
        self.assertEqual(self.load([self.notice(ALPHA, "active")])[0], "verified")

    def test_the_declarer_is_the_owner_in_effect_at_activated_utc(self):
        rotation = self.estate.reanchor("owner", "successor", signer="owner", utc=ROTATION)
        base = self.estate.base_entries(owner="successor")
        before = self.notice(ALPHA, "active", declared="owner", activated=T0)
        after = self.notice(ALPHA, "deprecated", since=T1, previous=before, declared="successor", activated=T1)
        status, registry, why = self.load([rotation, before, after], owner="successor", base=base)
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(registry.lifecycle_chain(ALPHA), [before, after])
        retired_key = self.notice(BETA, "active", declared="owner", activated=T1)
        self.assertEqual(self.load([rotation, retired_key], owner="successor", base=base)[0], "refused")
        backdated = self.notice(GAMMA, "active", declared="successor", activated=T0)
        self.assertEqual(self.load([rotation, backdated], owner="successor", base=base)[0], "refused")

    def test_a_tombstoned_owner_key_declares_nothing_after_revocation(self):
        tombstone = {"type": "tombstone", "rappid": self.estate.keys["owner"], "revoked_utc": T1}
        tombstone["sig"] = self.estate.sign(tombstone, self.estate.keys["owner"])
        before = self.notice(ALPHA, "active", activated=T0)
        self.assertEqual(self.load([tombstone, before])[0], "verified")
        after = self.notice(BETA, "active", since=T2, activated=T2)
        self.assertEqual(self.load([tombstone, after])[0], "refused")

    def test_first_seen_bounds_activated_utc_not_since_utc(self):
        on_time = self.notice(ALPHA, "active", activated="2026-07-01T00:05:00.000Z", since=FUTURE)
        self.assertEqual(self.load([on_time], verification_utc=T0)[0], "verified")
        late = self.notice(ALPHA, "active", activated="2026-07-01T00:05:00.001Z")
        self.assertEqual(self.load([late], verification_utc=T0)[0], "refused")

    def test_first_seen_is_resolved_per_notice(self):
        a1 = self.notice(ALPHA, "active", activated=T0)
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, activated=T1)  # appended later
        seen = {REG.entry_hash(a1): T0, REG.entry_hash(a2): T1}
        self.assertEqual(self.load([a1, a2], first_seen=seen.__getitem__)[0], "verified")
        self.assertEqual(self.load([a1, a2], verification_utc=T0)[0], "refused")  # one time for both
        seen[REG.entry_hash(a2)] = T0  # first seen a month before it says it was declared
        self.assertEqual(self.load([a1, a2], first_seen=seen.__getitem__)[0], "refused")

    def test_a_copy_counts_only_when_the_registry_carries_it(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, superseded_by=BETA, activated=T1)
        with self.estate.mocked():
            registry = self.registry(a1, a2)
            member_file_copy = json.loads(json.dumps(a2, indent=2))  # a Hive notice or member file
            self.assertEqual(registry.declared_entry_ok(member_file_copy), (True, "ok"))
            unregistered = self.notice(ALPHA, "archived", since=T2, previous=a2, activated=T2)  # owner-signed
            resigned = self.notice(ALPHA, "deprecated", since=T1, previous=a1, superseded_by=BETA, activated=T1)
            claims = [("unregistered successor notice", unregistered), ("same members, another sig", resigned)]
            claims += [(f"altered {member}", dict(a2, **{member: value})) for member, value in (
                ("state", "archived"), ("since_utc", T2), ("superseded_by", GAMMA), ("previous", None))]
            for label, claim in claims:
                with self.subTest(claim=label):
                    ok, why = registry.declared_entry_ok(claim)
                    self.assertFalse(ok)
                    self.assertIn("not an entry of this registry", why)
            # A claim no verified entry supports is unverified: the state stays the chain's.
            self.assertEqual(registry.lifecycle_state_at(ALPHA, T3), "deprecated")
            # An authentic copy of an earlier notice verifies, but it is history: the chain decides.
            self.assertEqual(registry.declared_entry_ok(copy.deepcopy(a1)), (True, "ok"))
            self.assertEqual(registry.lifecycle_head(ALPHA), a2)
            self.assertEqual(registry.lifecycle_state_at(ALPHA, T2), "deprecated")
            self.assertEqual(registry.lifecycle_at(ALPHA, T2), a2)

    def test_an_unsigned_document_is_a_draft_and_still_refuses_a_broken_chain(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "deprecated", since=T1, previous=a1, activated=T1)
        draft = self.estate.document(self.estate.base_entries() + [a1, a2], signed=False)
        status, registry, _ = self.estate.load(draft, allow_unsigned=True)
        self.assertEqual(status, "draft")
        self.assertEqual(registry.lifecycle_state_at(ALPHA, T1), "deprecated")
        broken = self.estate.document(self.estate.base_entries() + [a2, a1], signed=False)
        self.assertEqual(self.estate.load(broken, allow_unsigned=True)[0], "refused")


class LifecycleRetentionTests(LifecycleCase):
    """§13.4: every declared entry is persisted, so an accepted notice is retained byte for byte."""

    def setUp(self):
        super().setUp()
        self.a1 = self.notice(ALPHA, "active")
        self.a2 = self.notice(ALPHA, "superseded", since=T1, previous=self.a1, superseded_by=BETA, activated=T1)
        status, accepted, why = self.load([self.a1, self.a2])
        self.assertEqual((status, why), ("verified", "ok"))
        # What the consumer keeps once it has accepted that registry: the canonical notices.
        self.persisted = [R._strict_json(R.canonical(e)) for e in accepted.entries if e["type"] == "lifecycle"]
        self.assertEqual(self.persisted, [self.a1, self.a2])

    def later(self, notices, *, retained=True):
        """A later, higher-sequence registry of the same estate, loaded with or without retention."""
        document = self.estate.document(self.estate.base_entries() + list(notices), seq=3)
        kwargs = {"persisted_entries": self.persisted} if retained else {}
        return self.estate.load(document, persisted_seq=2, **kwargs)

    def resigned(self, **changes):
        """The owner re-signs the accepted `a2` with some members changed."""
        fields = {"state": "superseded", "since": T1, "previous": self.a1, "superseded_by": BETA, "activated": T1}
        fields.update(changes)
        return self.notice(ALPHA, fields.pop("state"), **fields)

    def test_a_later_registry_that_keeps_the_chain_may_extend_it(self):
        a3 = self.notice(ALPHA, "active", since=T2, previous=self.a2, activated=T2)  # reinstated by a new notice
        status, registry, why = self.later([self.a1, self.a2, a3])
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(registry.check_retained(self.persisted), (True, "ok"))
        self.assertEqual(registry.lifecycle_chain(ALPHA), [self.a1, self.a2, a3])
        self.assertEqual(registry.lifecycle_state_at(ALPHA, T1), "superseded")  # history stays on record
        self.assertEqual(registry.lifecycle_state_at(ALPHA, T3), "active")
        reordered = [json.loads(json.dumps(e, indent=2, sort_keys=False)) for e in reversed(self.persisted)]
        self.assertEqual(registry.check_retained(reordered), (True, "ok"))  # canonical bytes, any order

    def test_a_later_registry_that_drops_or_rewrites_a_notice_is_refused(self):
        attacks = {
            "drops the current notice": [self.a1],
            "drops the whole chain": [],
            "rewrites the state": [self.a1, self.resigned(state="deprecated")],
            "rewrites the successor": [self.a1, self.resigned(superseded_by=GAMMA)],
            "moves since_utc later": [self.a1, self.resigned(since=T3)],
            "re-signs the same members": [self.a1, self.resigned()],
            "forks a rival notice in its place": [self.a1, self.notice(ALPHA, "active", since=T1,
                                                                       previous=self.a1, activated=T1)],
        }
        for label, notices in attacks.items():
            with self.subTest(attack=label):
                # By itself the later registry verifies: nothing but retention can refuse it …
                self.assertEqual(self.later(notices, retained=False)[:1], ("verified",))
                # … and retention does, however much registry_seq increased.
                status, registry, why = self.later(notices)
                self.assertEqual((status, registry), ("refused", None))
                self.assertIn("persisted lifecycle entry was removed or mutated", why)

    def test_the_state_cannot_silently_revert(self):
        status, forgetful, _ = self.later([self.a1], retained=False)
        self.assertEqual(status, "verified")
        self.assertEqual(forgetful.lifecycle_state_at(ALPHA, T2), "active")  # what dropping a2 would show
        self.assertIsNone(forgetful.successor_at(ALPHA, T2))
        self.assertEqual(self.later([self.a1])[0], "refused")
        # With the chain retained, a state changes only by a new notice on the record, and never
        # before the current notice's since_utc.
        backdated = self.notice(ALPHA, "archived", since=T0, previous=self.a2, activated=T2)
        status, _, why = self.later([self.a1, self.a2, backdated])
        self.assertEqual(status, "refused")
        self.assertIn("`since_utc` decreases", why)
        corrected = self.notice(ALPHA, "active", since=T1, previous=self.a2, activated=T2)
        status, registry, why = self.later([self.a1, self.a2, corrected])
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(registry.lifecycle_chain(ALPHA), [self.a1, self.a2, corrected])
        self.assertEqual(registry.lifecycle_state_at(ALPHA, T2), "active")
        for utc in (T0, "2026-07-31T23:59:59.999Z"):
            with self.subTest(utc=utc):
                self.assertEqual(registry.lifecycle_state_at(ALPHA, utc), "active")  # unchanged before T1
                self.assertIsNone(registry.successor_at(ALPHA, utc))


class LifecycleIsNotTrustTests(LifecycleCase):
    """§13.6: a notice revokes no key, re-anchors no identity, and changes no §7.5 result."""

    def setUp(self):
        super().setUp()
        self.worker, self.successor = self.estate.keys["worker"], self.estate.keys["successor"]
        self.notices = [self.notice(self.worker, "superseded", since=T1, superseded_by=self.successor),
                        self.notice(ALPHA, "archived", since=T1)]

    def test_a_notice_leaves_signer_acceptability_alone(self):
        plain = self.registry()
        noticed = self.registry(*self.notices)
        self.assertEqual(noticed.lifecycle_state_at(self.worker, T2), "superseded")
        for kid in (self.worker, self.successor, self.estate.keys["owner"]):
            for utc in (T0, T1, T2, FUTURE):
                with self.subTest(kid=kid, utc=utc):
                    self.assertEqual(noticed.signer_acceptable(kid, utc), plain.signer_acceptable(kid, utc))
                    self.assertEqual(noticed.signer_acceptable(kid, utc), (True, "ok"))
        self.assertEqual(noticed.owner_at(T2), plain.owner_at(T2))
        self.assertEqual(noticed.successor_at(self.worker, T2), self.successor)
        self.assertIsNone(noticed.successor_at(self.successor, T2))  # naming a successor grants it nothing

    def test_frames_on_a_superseded_organisms_stream_still_verify(self):
        noticed = self.registry(BODY_PULSE, *self.notices)
        plain = self.registry(BODY_PULSE)
        genesis = R.build_frame("body.pulse", self.worker, 0, T2, {"pulse": 1}, None)
        signed = R.build_frame("body.pulse", self.worker, 1, T3, {"pulse": 2}, genesis["payload_hash"])
        signed["sig"] = mock_jws(self.estate, {k: v for k, v in signed.items() if k != "sig"}, "worker")
        keyless = R.build_frame("body.pulse", ALPHA, 0, T2, {"pulse": 1}, None)
        with self.estate.mocked():
            for registry in (noticed, plain):
                with self.subTest(notices=registry is noticed):
                    verifier = registry.signature_verifier()
                    self.assertEqual(R.verify_frame(genesis, stream_id_of_record=self.worker,
                                                    signature_verifier=verifier), (True, None, "ok"))
                    self.assertEqual(R.verify_frame(signed, head=genesis, stream_id_of_record=self.worker,
                                                    signature_verifier=verifier), (True, None, "ok"))
                    self.assertEqual(R.verify_frame(keyless, stream_id_of_record=ALPHA), (True, None, "ok"))
                    for frame in (genesis, signed, keyless):
                        self.assertEqual(registry.check_frame_binding(frame), (True, "ok"))
            forged = dict(signed, sig=mock_jws(self.estate, {"other": "bytes"}, "worker"))
            self.assertEqual(R.verify_frame(forged, head=genesis, stream_id_of_record=self.worker,
                                            signature_verifier=noticed.signature_verifier())[:2], (False, "6"))


class LifecycleLintTests(LifecycleCase):
    """rapp_check lints a registry that carries lifecycle notices through the same Registry."""

    def repository(self):
        temporary = tempfile.TemporaryDirectory(prefix=".rapp-check-test-", dir=ROOT)
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=1) + "\n", encoding="utf-8")

    def test_rapp_check_accepts_a_chain_and_refuses_a_broken_one(self):
        a1 = self.notice(ALPHA, "active")
        a2 = self.notice(ALPHA, "superseded", since=T1, previous=a1, superseded_by=BETA, activated=T1)
        repository = self.repository()
        self.write(repository / "estate" / "registry.json",
                   self.estate.document(self.estate.base_entries() + [a1, a2], signed=False))
        verdict, findings, evidence = C.check_repo(repository)
        self.assertEqual((verdict, findings), ("COMPLIANT", []))
        self.assertEqual([item["status"] for item in evidence], ["unverified"])
        self.assertIn("§13.1 registry structure OK", evidence[0]["ok"])

        broken = self.repository()
        self.write(broken / "fork" / "registry.json", self.estate.document(
            self.estate.base_entries() + [a1, a2, self.notice(ALPHA, "archived", since=T1, previous=a1,
                                                              activated=T1)]))
        self.write(broken / "cycle" / "registry.json", self.estate.document(
            self.estate.base_entries() + [self.notice(ALPHA, "superseded", superseded_by=BETA),
                                          self.notice(BETA, "superseded", superseded_by=ALPHA)]))
        verdict, findings, _ = C.check_repo(broken)
        self.assertEqual(verdict, "DRIFT")
        self.assertEqual({(item["artifact"], item["rule"]) for item in findings},
                         {("fork/registry.json", "§13 registry document"),
                          ("cycle/registry.json", "§13 registry document")})
        details = {item["artifact"]: item["detail"] for item in findings}
        self.assertIn("fork", details["fork/registry.json"])
        self.assertIn("cycle", details["cycle/registry.json"])


@unittest.skipUnless(real_ed25519_signer(), "optional cryptography import is absent")
class RealSignatureLifecycleTests(unittest.TestCase):
    """The same rules through the real detached-JWS boundary (§10), no mocks."""

    def test_real_notices_copies_and_frames(self):
        owner_der, owner_sign = real_ed25519_signer()
        worker_der, worker_sign = real_ed25519_signer()
        owner = R.mint_rappid("test", "estate-owner", spki_der=owner_der)
        worker = R.mint_rappid("test", "worker", spki_der=worker_der)

        def notice(state, since, previous, superseded_by):
            entry = {"type": "lifecycle", "rappid": worker, "state": state, "superseded_by": superseded_by,
                     "since_utc": since, "previous": previous, "activated_utc": since, "declared_by": owner}
            entry["sig"] = owner_sign(entry, owner)
            return entry

        a1 = notice("active", T0, None, None)
        a2 = notice("superseded", T1, REG.entry_hash(a1), BETA)
        entries = [{"type": "estate_owner", "rappid": owner}, BODY_PULSE]
        entries += [{"type": "spki", "rappid": kid, "deprecated": False,
                     "spki_der_b64": base64.b64encode(der).decode("ascii")}
                    for kid, der in ((owner, owner_der), (worker, worker_der))]
        doc = {"schema": "rapp/1-registry", "registry_seq": 1, "canonical_source": SOURCE,
               "entries": entries + [a1, a2]}
        doc["sig"] = owner_sign(doc, owner)
        status, registry, why = REG.load_document(doc, trust_anchor=owner, verification_utc=T1)
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(registry.lifecycle_state_at(worker, T2), "superseded")
        self.assertIsNone(registry.successor_at(worker, T0))
        self.assertEqual(registry.successor_at(worker, T2), BETA)

        self.assertEqual(registry.declared_entry_ok(json.loads(json.dumps(a2))), (True, "ok"))
        self.assertFalse(registry.declared_entry_ok(dict(a2, state="archived"))[0])
        unregistered = notice("archived", T2, REG.entry_hash(a2), None)  # really owner-signed, never carried
        worker_signed = dict(a2, sig=worker_sign({k: v for k, v in a2.items() if k != "sig"}, worker))
        for claim in (unregistered, worker_signed):
            ok, why = registry.declared_entry_ok(claim)
            self.assertFalse(ok)
            self.assertIn("not an entry of this registry", why)

        def signed_document(notices, seq=1):
            value = {"schema": "rapp/1-registry", "registry_seq": seq, "canonical_source": SOURCE,
                     "entries": entries + notices}
            value["sig"] = owner_sign(value, owner)
            return value

        # Carried by a registry the owner signs, the worker-signed notice fails its own signature.
        status, _, why = REG.load_document(signed_document([a1, worker_signed]), trust_anchor=owner,
                                           verification_utc=T1)
        self.assertEqual(status, "refused")
        self.assertIn("lifecycle entry signature refused", why)
        # A later registry cannot drop the accepted notice, even when the owner signs it.
        persisted = [R._strict_json(R.canonical(e)) for e in (a1, a2)]
        def reload(notices, **history):
            return REG.load_document(signed_document(notices, seq=2), trust_anchor=owner,
                                     verification_utc=T1, **history)[0]

        self.assertEqual(reload([a1]), "verified")
        self.assertEqual(reload([a1], persisted_seq=1, persisted_entries=persisted), "refused")
        self.assertEqual(reload([a1, a2], persisted_seq=1, persisted_entries=persisted), "verified")

        tampered = copy.deepcopy(doc)
        tampered["entries"][-1]["state"] = "archived"
        tampered.pop("sig")
        tampered["sig"] = owner_sign(tampered, owner)  # a valid document signature cannot bless it
        status, _, why = REG.load_document(tampered, trust_anchor=owner, verification_utc=T1)
        self.assertEqual(status, "refused")
        self.assertIn("lifecycle entry signature refused", why)

        frame = R.build_frame("body.pulse", worker, 0, T2, {"pulse": 1}, None)
        frame["sig"] = worker_sign({k: v for k, v in frame.items() if k != "sig"}, worker)
        self.assertEqual(R.verify_frame(frame, stream_id_of_record=worker,
                                        signature_verifier=registry.signature_verifier()), (True, None, "ok"))


if __name__ == "__main__":
    unittest.main()
