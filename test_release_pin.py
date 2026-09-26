"""§13.3 release-pin entries and §13.5 release families, pinned releases, manifests, and snapshots.

Stdlib only; the detached-JWS boundary is mocked by `registry_fixtures.MockEstate`, and one
optional class repeats the core path through real Ed25519 when `cryptography` is present.
Every name, key, repository, and file here is synthetic.
"""
import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import rapp as R
import rapp_check as C
import rapp_registry as REG
from registry_fixtures import MockEstate, SOURCE, T0, real_ed25519_signer

LATER = "2026-08-01T00:00:00.000Z"
LATEST = "2026-09-01T00:00:00.000Z"
# Release scopes name release families (§11.1); each binds at most one kernel, forever.
LTS = "https://releases.example.test/acme/1.0"    # kernel 1.0.0; channel lts appends its corrections
NEW_2 = "https://releases.example.test/acme/2.0"  # kernel 2.0.0; channel newest's first family
NEW_3 = "https://releases.example.test/acme/3.0"  # kernel 3.0.0; the family channel newest moves on to
RELEASES = "https://git.example.test/acme/releases"
KERNEL = "https://git.example.test/acme/brainstem"
PROTOCOL = "https://git.example.test/acme/protocol"
ALPHA = "https://git.example.test/acme/alpha"
BETA = "https://git.example.test/acme/beta"
MIRROR = "https://git.example.test/acme/monorepo"
KERNEL_PATH = "kernel/brainstem.py"


def digest(octets):
    return hashlib.sha256(octets).hexdigest()


def file_list(mapping):
    return [{"path": path, "sha256": digest(octets), "size_bytes": len(octets)}
            for path, octets in sorted(mapping.items(), key=lambda item: item[0].encode("utf-8"))]


def kernel_files(version):
    return {
        KERNEL_PATH: f'"""Synthetic kernel entry point {version}."""\n'.encode(),
        "kernel/agents/basic_agent.py": b"class BasicAgent:\n    pass\n",
        "kernel/VERSION": f"{version}\n".encode(),
    }


def persisted(*entries):
    """What a consumer keeps once it accepts entries of a persisted type (§13.4): canonical copies."""
    return [R._strict_json(R.canonical(entry)) for entry in entries]


class World:
    """A synthetic estate, its repositories (an in-memory store), and its releases."""

    def __init__(self):
        self.estate = MockEstate()
        self.store, self.calls = {}, []
        self.alpha = R.mint_rappid("acme", "organism-alpha")
        self.beta = R.mint_rappid("acme", "organism-beta")

    def publish(self, repository, commit, path, octets):
        self.store[(repository, commit, path)] = octets

    def fetch(self, repository, object_format, commit, path):
        self.calls.append((repository, object_format, commit, path))
        return self.store[(repository, commit, path)]

    def component(self, cid, kind, repository, commit, mapping, *, rappid=None, identity_path=None,
                  immutable_ref=None, object_format="sha1"):
        for path, octets in mapping.items():
            self.publish(repository, commit, path, octets)
        return {"id": cid, "kind": kind, "rappid": rappid, "identity_path": identity_path,
                "repository": repository, "object_format": object_format, "commit": commit,
                "immutable_ref": immutable_ref, "files": file_list(mapping)}

    @staticmethod
    def identity(rappid, **extra):
        return R.canonical({"schema": "rapp/1", "rappid": rappid, **extra}).encode("utf-8")

    def kernel(self, version="1.0.0", commit="1" * 40):
        return self.component("brainstem", "kernel", KERNEL, commit, kernel_files(version),
                              immutable_ref=f"refs/tags/brainstem-v{version}")

    def manifest(self, scope=LTS, *, kernel="1.0.0", kernel_commit="1" * 40, fix=0, release=None):
        """One release's manifest, named `release` — by default the family and correction number
        (acme-1.0.0, acme-1.0.1, …). A correction (`fix` > 0) moves organism-alpha and nothing else."""
        alpha_commit = "a" * 40 if not fix else ("a%x" % fix) * 20
        soul = b"# alpha\n" if not fix else f"# alpha, correction {fix}\n".encode()
        components = [
            self.component("organism-alpha", "organism", ALPHA, alpha_commit,
                           {"rappid.json": self.identity(self.alpha), "soul.md": soul},
                           rappid=self.alpha, identity_path="rappid.json"),
            self.component("organism-beta", "organism", BETA, "b" * 64,
                           {"rappid.json": self.identity(self.beta), "agents/beta_agent.py": b"# beta\n"},
                           rappid=self.beta, identity_path="rappid.json", object_format="sha256"),
            self.component("rapp-1", "protocol", PROTOCOL, "c" * 40, {"SPEC.md": b"# synthetic spec\n"}),
        ]
        if kernel is not None:
            components.insert(0, self.kernel(kernel, kernel_commit))
        name = release or "acme-%s.%d" % (scope.rsplit("/", 1)[1], fix)
        return {"schema": REG.MANIFEST_SCHEMA, "release_scope": scope, "release": name,
                "components": components}

    def grail(self, scope=LTS, version="1.0.0", commit="1" * 40, declared="owner"):
        octets = kernel_files(version)[KERNEL_PATH]
        return self.estate.declare({
            "type": "grail-kernel", "release_scope": scope,
            "grail_id": "grail:" + R.Hb("rapp/1:grail", octets), "repository": KERNEL,
            "immutable_ref": f"refs/tags/brainstem-v{version}", "object_format": "sha1",
            "commit": commit, "path": KERNEL_PATH, "mode": "100644", "blob": "2" * 40,
            "sha256": digest(octets), "size_bytes": len(octets), "activated_utc": T0,
            "predecessor": None, "declared_by": self.estate.keys[declared],
        }, declared)

    def pin(self, manifest, *, channel="lts", predecessor=None, activated=T0, declared="owner",
            signer=None, scope=None, commit="3" * 40):
        """Publish `manifest`'s canonical octets and declare the release-pin for them.
        `predecessor` is None, the release-pin this release follows, or a raw member value."""
        if isinstance(predecessor, dict):
            predecessor = predecessor["manifest_hash"]
        manifest_hash = R.H("rapp/1:particle", manifest)
        path = f"releases/{manifest_hash}.json"
        self.publish(RELEASES, commit, path, R.canonical(manifest).encode("utf-8"))
        return self.estate.declare({
            "type": "release-pin", "release_scope": scope or manifest["release_scope"],
            "channel": channel, "predecessor": predecessor, "manifest_hash": manifest_hash,
            "repository": RELEASES, "object_format": "sha1", "commit": commit, "path": path,
            "activated_utc": activated, "declared_by": self.estate.keys[declared],
        }, signer or declared)

    def load(self, extra, owner="owner", entries=None, seq=2, **kwargs):
        base = entries if entries is not None else self.estate.base_entries(owner)
        document = self.estate.document(base + extra, owner=owner, seq=seq,
                                        signed=kwargs.pop("signed", True))
        return self.estate.load(document, owner=owner, **kwargs)

    def registry(self, extra):
        """(manifest, registry): a verified LTS release with its family's grail-kernel."""
        manifest = self.manifest()
        status, reg, why = self.load([self.grail(), self.pin(manifest)] + extra)
        assert status == "verified", why
        return manifest, reg


def release_hash(n):
    """The placeholder manifest_hash of synthetic release `n`; these pins name no real manifest."""
    return hashlib.sha256(f"synthetic release {n}".encode()).hexdigest()


def unsigned_pin(n=1, *, after=None, **changes):
    """A structurally valid release-pin of placeholder release `n` in the LTS family and channel,
    following placeholder release `after` when given; `changes` override any member."""
    entry = {"type": "release-pin", "release_scope": LTS, "channel": "lts",
             "predecessor": None if after is None else release_hash(after),
             "manifest_hash": release_hash(n), "repository": RELEASES, "object_format": "sha1",
             "commit": "3" * 40, "path": f"releases/{n}.json", "activated_utc": T0,
             "declared_by": R.mint_rappid("acme", "estate-owner", spki_der=b"synthetic"), "sig": "<sig>"}
    entry.update(changes)
    return entry


def hashes(entries):
    return [entry["manifest_hash"] for entry in entries]


class ReleasePinEntryTests(unittest.TestCase):
    """§13.3: exactly the twelve members, each with its grammar."""

    def test_a_complete_release_pin_validates(self):
        self.assertEqual(REG.validate_entry(unsigned_pin()), "release-pin")
        self.assertEqual(set(REG.ENTRY_MEMBERS["release-pin"][0]), set(unsigned_pin()))
        self.assertEqual(REG.ENTRY_MEMBERS["release-pin"][1], set())

    def test_the_member_set_is_exact(self):
        for member in unsigned_pin():
            if member == "type":
                continue
            with self.subTest(missing=member):
                entry = unsigned_pin()
                del entry[member]
                self.assertRaises(REG.RegistryError, REG.validate_entry, entry)
        with self.assertRaises(REG.RegistryError):
            REG.validate_entry(unsigned_pin(deprecated=False))

    def test_every_member_is_refused_when_malformed(self):
        bad = {
            "release_scope": ["http://releases.example.test/acme/1.0", "https://", "https://a b", "", 7, None],
            "channel": ["", "LTS", "-lts", "lts-", "l_ts", "a" * 65, 5, None],
            # A predecessor names a release by its manifest_hash; a release_scope names a family.
            "predecessor": ["", "lts", LTS, "D" * 64, "d" * 63, "d" * 65, 7, ["d" * 64]],
            "manifest_hash": ["D" * 64, "d" * 63, 64, None],
            "repository": ["git@git.example.test:acme/releases.git", "http://git.example.test/r", None],
            "object_format": ["sha512", "SHA1", None],
            "commit": ["3" * 39, "3" * 64, "G" * 40, "A" * 40, "main", None],
            "path": ["", "/releases/lts-1.json", "releases//lts-1.json", "./releases/lts-1.json",
                     "releases/../lts-1.json", "releases/lts-1.json/", "releases\\lts-1.json",
                     "C:/releases/lts-1.json", "releases/CON.json", "releases/lts:1.json",
                     "releases/lts-1.json.", "releases/lts-1 ", "releases/e\u0301.json",
                     "releases/\x01.json", 5, None],
            "activated_utc": ["2026-07-01T00:00:00Z", "2026-13-01T00:00:00.000Z", None],
            "declared_by": ["rappid:@acme/x:" + "A" * 64, "owner", None],
            "sig": ["", None, 5],
        }
        for member, values in bad.items():
            for value in values:
                with self.subTest(member=member, value=value):
                    self.assertRaises(REG.RegistryError, REG.validate_entry, unsigned_pin(**{member: value}))

    def test_valid_member_variants_are_accepted(self):
        good = [
            {"object_format": "sha256", "commit": "3" * 64},
            {"predecessor": "e" * 64},
            {"channel": "a" * 64}, {"channel": "lts-2026"},
            {"path": "releases/\u00fcnic\u00f6de.json"},
        ]
        for changes in good:
            with self.subTest(changes=changes):
                self.assertEqual(REG.validate_entry(unsigned_pin(**changes)), "release-pin")

    def test_release_pin_is_a_declared_persisted_type(self):
        self.assertIn("release-pin", REG.DECLARED_TYPES)
        self.assertIs(REG.PERSISTED_TYPES, REG.DECLARED_TYPES)  # every declared entry is persisted (§13.4)


class ReleaseChannelTests(unittest.TestCase):
    """§13.3 uniqueness and §13.5 families, channels, and kernel order, decided by Registry(...) alone."""

    def setUp(self):
        self.estate = MockEstate()

    def registry(self, *entries):
        return REG.Registry(self.estate.base_entries() + list(entries))

    def test_a_family_appends_its_corrections_to_its_channel(self):
        reg = self.registry(
            unsigned_pin(1),
            unsigned_pin(4, release_scope=NEW_2, channel="newest"),
            unsigned_pin(2, after=1, activated_utc=LATER),
            unsigned_pin(3, after=2, activated_utc=LATER),
        )
        lts = [release_hash(n) for n in (1, 2, 3)]
        self.assertEqual(hashes(reg.release_channels["lts"]), lts)
        self.assertEqual(hashes(reg.scope_releases(LTS)), lts)
        self.assertEqual(hashes(reg.release_families[LTS]), lts)
        self.assertEqual(reg.scope_head(LTS)["manifest_hash"], release_hash(3))
        self.assertEqual(reg.channel_head("lts")["manifest_hash"], release_hash(3))
        self.assertEqual(reg.channel_head("newest")["manifest_hash"], release_hash(4))
        self.assertEqual(reg.scope_head(NEW_2)["manifest_hash"], release_hash(4))
        self.assertEqual(reg.release_pin(release_hash(2))["predecessor"], release_hash(1))
        self.assertEqual(list(reg.release_pins), [release_hash(n) for n in (1, 4, 2, 3)])  # append order

    def test_unknown_or_malformed_selections_name_nothing(self):
        reg = self.registry(unsigned_pin(1), unsigned_pin(2, after=1))
        for value in (release_hash(9), LTS, None, 7, ["x"]):
            with self.subTest(manifest_hash=value):
                self.assertIsNone(reg.release_pin(value))
        for value in (NEW_3, release_hash(1), None, 7, ["x"]):
            with self.subTest(release_scope=value):
                self.assertEqual(reg.scope_releases(value), [])
                self.assertIsNone(reg.scope_head(value))
        for value in ("newest", LTS, None, 7, ["lts"]):
            with self.subTest(channel=value):
                self.assertIsNone(reg.channel_head(value))
        releases = reg.scope_releases(LTS)
        releases.clear()  # a copy: the registry's own order is unchanged
        self.assertEqual(hashes(reg.scope_releases(LTS)), [release_hash(1), release_hash(2)])
        empty = self.registry()
        self.assertEqual((empty.release_pins, empty.release_channels, empty.release_families), ({}, {}, {}))

    def test_a_channel_moves_on_from_one_family_to_the_next(self):
        reg = self.registry(
            unsigned_pin(1),
            unsigned_pin(4, release_scope=NEW_2, channel="newest"),
            unsigned_pin(5, release_scope=NEW_2, channel="newest", after=4),
            unsigned_pin(6, release_scope=NEW_3, channel="newest", after=5, activated_utc=LATER),
        )
        self.assertEqual(hashes(reg.release_channels["newest"]), [release_hash(n) for n in (4, 5, 6)])
        self.assertEqual(reg.channel_head("newest")["release_scope"], NEW_3)
        self.assertEqual(reg.scope_head(NEW_2)["manifest_hash"], release_hash(5))  # current, no longer the head
        self.assertEqual(hashes(reg.scope_releases(NEW_2)), [release_hash(4), release_hash(5)])
        self.assertEqual(hashes(reg.scope_releases(NEW_3)), [release_hash(6)])
        self.assertEqual(reg.channel_head("lts")["manifest_hash"], release_hash(1))

    def test_a_channel_may_return_to_an_earlier_family(self):
        reg = self.registry(
            unsigned_pin(4, release_scope=NEW_2, channel="newest"),
            unsigned_pin(6, release_scope=NEW_3, channel="newest", after=4, activated_utc=LATER),
            unsigned_pin(5, release_scope=NEW_2, channel="newest", after=6, activated_utc=LATEST),
        )
        self.assertEqual(hashes(reg.release_channels["newest"]), [release_hash(n) for n in (4, 6, 5)])
        self.assertEqual(reg.channel_head("newest")["manifest_hash"], release_hash(5))
        # The family it returned to: its current release is its last release in entries order.
        self.assertEqual(hashes(reg.scope_releases(NEW_2)), [release_hash(4), release_hash(5)])
        self.assertEqual(reg.scope_head(NEW_2)["manifest_hash"], release_hash(5))
        self.assertEqual(reg.scope_head(NEW_3)["manifest_hash"], release_hash(6))  # the family it left

    def test_a_release_is_pinned_once(self):
        cases = {
            "as its own correction": [unsigned_pin(1), unsigned_pin(1, after=1, path="releases/again.json")],
            "at another locator": [unsigned_pin(1), unsigned_pin(1, commit="4" * 40)],
            "in another family and channel": [unsigned_pin(1), unsigned_pin(1, release_scope=NEW_2,
                                                                            channel="newest")],
        }
        for label, entries in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(REG.RegistryError, "second release-pin for manifest_hash"):
                    self.registry(*entries)

    def test_a_newest_family_graduates_to_an_lts_line(self):
        # The 2.0 family ships on newest, then the lts channel moves on from the 1.x family to a release
        # of it: one family, one kernel binding (§11.1), releases in two channels.
        reg = self.registry(
            unsigned_pin(1),
            unsigned_pin(4, release_scope=NEW_2, channel="newest"),
            unsigned_pin(5, release_scope=NEW_2, channel="newest", after=4, activated_utc=LATER),
            unsigned_pin(7, release_scope=NEW_2, after=1, activated_utc=LATER),
            unsigned_pin(6, release_scope=NEW_3, channel="newest", after=5, activated_utc=LATEST),
        )
        self.assertEqual(hashes(reg.release_channels["lts"]), [release_hash(1), release_hash(7)])
        self.assertEqual(hashes(reg.release_channels["newest"]), [release_hash(n) for n in (4, 5, 6)])
        self.assertEqual(hashes(reg.scope_releases(NEW_2)), [release_hash(n) for n in (4, 5, 7)])
        self.assertEqual(reg.scope_head(NEW_2)["manifest_hash"], release_hash(7))  # last in entries order
        self.assertEqual(reg.channel_head("lts")["release_scope"], NEW_2)
        self.assertEqual(reg.channel_head("newest")["release_scope"], NEW_3)
        # A later lts correction of the graduated family follows the lts head, as any correction does.
        correction = unsigned_pin(8, release_scope=NEW_2, after=7, activated_utc=LATEST)
        self.assertEqual(self.registry(
            unsigned_pin(1), unsigned_pin(4, release_scope=NEW_2, channel="newest"),
            unsigned_pin(7, release_scope=NEW_2, after=1, activated_utc=LATER), correction,
        ).scope_head(NEW_2)["manifest_hash"], release_hash(8))

    def test_equal_activation_is_not_a_regression(self):
        reg = self.registry(unsigned_pin(1), unsigned_pin(2, after=1))
        self.assertEqual(reg.channel_head("lts")["manifest_hash"], release_hash(2))

    def test_channel_structure_violations_refuse_the_registry(self):
        newest = {"channel": "newest"}
        cases = {
            "fork": ([unsigned_pin(1), unsigned_pin(2, after=1), unsigned_pin(3, after=1)], "fork"),
            "two roots": ([unsigned_pin(1), unsigned_pin(2)], "exactly one first entry"),
            "forward link": ([unsigned_pin(2, after=1), unsigned_pin(1)], "does not precede"),
            "self link": ([unsigned_pin(1, after=1)], "does not precede"),
            "cycle": ([unsigned_pin(1, after=2), unsigned_pin(2, after=1)], "does not precede"),
            "unknown predecessor": ([unsigned_pin(1), unsigned_pin(2, after=3)],
                                    "not the manifest_hash of any release-pin"),
            "a predecessor in another channel": (
                [unsigned_pin(1), unsigned_pin(4, release_scope=NEW_2, after=1, **newest)],
                "is a release-pin of channel 'lts'"),
            "activation regression": ([unsigned_pin(1, activated_utc=LATER), unsigned_pin(2, after=1)],
                                      "activated before its predecessor"),
            "activation regression across families": (
                [unsigned_pin(4, release_scope=NEW_2, activated_utc=LATER, **newest),
                 unsigned_pin(6, release_scope=NEW_3, after=4, **newest)],
                "activated before its predecessor"),
        }
        for label, (entries, message) in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(REG.RegistryError, message):
                    self.registry(*entries)

    def test_a_familys_grail_kernel_precedes_its_first_release(self):
        grail = self.estate.grail_kernel(scope=LTS)
        other = self.estate.grail_kernel(scope=NEW_2)
        accepted = {
            "declared before the family's first release": [grail, unsigned_pin(1), unsigned_pin(2, after=1)],
            "a family without releases yet": [unsigned_pin(1), other],
            "one family's kernel after another family's release":
                [unsigned_pin(1), other, unsigned_pin(4, release_scope=NEW_2, channel="newest")],
        }
        for label, entries in accepted.items():
            with self.subTest(label=label):
                self.registry(*entries)
        refused = {
            "after the family's only release": [unsigned_pin(1), grail],
            "between two releases of the family": [unsigned_pin(1), grail, unsigned_pin(2, after=1)],
            "after the first release of a family in another channel": [
                unsigned_pin(4, release_scope=NEW_2, channel="newest"), other],
        }
        for label, entries in refused.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(REG.RegistryError, "follows that family's first release-pin"):
                    self.registry(*entries)

    def test_a_refused_channel_refuses_the_whole_document(self):
        world = World()
        first = world.pin(world.manifest(kernel=None))
        second = world.pin(world.manifest(kernel=None, fix=1), predecessor=first)
        fork = world.pin(world.manifest(kernel=None, fix=2), predecessor=first)
        self.assertEqual(world.load([first, second])[0], "verified")
        self.assertEqual(world.load([first, second, fork])[0], "refused")
        self.assertEqual(world.load([first, second, world.grail()])[0], "refused")


class ReleasePinDeclarationTests(unittest.TestCase):
    """§13.4 for release-pin: the entry's own owner signature at its activated_utc."""

    def setUp(self):
        self.world = World()
        self.manifest = self.world.manifest(kernel=None)

    def test_an_owner_declared_release_pin_verifies(self):
        status, reg, why = self.world.load([self.world.pin(self.manifest)])
        self.assertEqual((status, why, reg.status), ("verified", "ok", "verified"))
        self.assertEqual(reg.channel_head("lts")["manifest_hash"], R.H("rapp/1:particle", self.manifest))

    def test_forged_or_foreign_declarations_are_refused(self):
        forged = self.world.pin(self.manifest)
        forged["sig"] = "forged"
        not_owner_signed = self.world.pin(self.manifest, declared="owner", signer="worker")
        not_owner = self.world.pin(self.manifest, declared="worker")
        for label, entry in (("forged", forged), ("signed by another key", not_owner_signed),
                             ("declared by a non-owner", not_owner)):
            with self.subTest(label=label):
                self.assertEqual(self.world.load([entry])[0], "refused")

    def test_a_mutated_declaration_is_refused(self):
        for member, value in (("manifest_hash", "e" * 64), ("commit", "4" * 40), ("channel", "newest"),
                              ("path", "releases/other.json"), ("release_scope", NEW_2),
                              ("activated_utc", LATER)):
            with self.subTest(member=member):
                entry = self.world.pin(self.manifest)
                entry[member] = value  # the document signature below is fresh; the entry's is not
                self.assertEqual(self.world.load([entry])[0], "refused")

    def test_owner_in_effect_at_activated_utc_across_rotation(self):
        estate = self.world.estate
        rotation = estate.reanchor("owner", "successor", signer="owner", utc="2026-07-15T00:00:00.000Z")
        base = estate.base_entries(owner="successor")
        before = self.world.pin(self.manifest, declared="owner", activated=T0)
        correction = self.world.manifest(kernel=None, fix=1)
        after_new = self.world.pin(correction, predecessor=before, declared="successor", activated=LATER)
        after_old = self.world.pin(correction, predecessor=before, declared="owner", activated=LATER)
        backdated = self.world.pin(correction, predecessor=before, declared="successor", activated=T0)

        def load(*entries):
            return self.world.load([rotation, *entries], owner="successor", entries=base)

        status, _, why = load(before, after_new)
        self.assertEqual((status, why), ("verified", "ok"))
        for label, correction_pin in (("old owner after the rotation", after_old),
                                      ("new owner before the rotation", backdated)):
            with self.subTest(label=label):
                status, _, why = load(before, correction_pin)
                self.assertEqual(status, "refused")
                self.assertIn("not the estate owner in effect at activated_utc", why)

    def test_first_seen_skew_is_bounded_at_300_seconds(self):
        edge = self.world.pin(self.manifest, activated="2026-07-01T00:05:00.000Z")
        late = self.world.pin(self.manifest, activated="2026-07-01T00:05:00.001Z")
        self.assertEqual(self.world.load([edge], verification_utc=T0)[0], "verified")
        self.assertEqual(self.world.load([late], verification_utc=T0)[0], "refused")

    def test_first_seen_is_resolved_per_release_pin(self):
        # A channel gathers corrections over time, so each release-pin is judged against the time the
        # consumer first saw it, never one time for the whole registry.
        first = self.world.pin(self.manifest)
        correction = self.world.pin(self.world.manifest(kernel=None, fix=1), predecessor=first, activated=LATER)
        seen = {REG.entry_hash(first): T0, REG.entry_hash(correction): LATER}
        self.assertEqual(self.world.load([first, correction], first_seen=seen.__getitem__)[0], "verified")
        self.assertEqual(self.world.load([first, correction], verification_utc=T0)[0], "refused")
        seen[REG.entry_hash(correction)] = T0  # first seen a month before its activated_utc
        status, _, why = self.world.load([first, correction], first_seen=seen.__getitem__)
        self.assertEqual(status, "refused")
        self.assertIn("300 s after first-seen", why)

    def test_persisted_release_pins_are_retained_byte_for_byte(self):
        pin = self.world.pin(self.manifest)
        kept = persisted(pin)
        correction = self.world.pin(self.world.manifest(kernel=None, fix=1), predecessor=pin, activated=LATER)
        self.assertEqual(self.world.load([pin, correction], persisted_entries=kept)[0], "verified")
        replaced = self.world.pin(self.world.manifest(kernel=None, fix=1))  # the family's first release swapped
        relocated = self.world.pin(self.manifest, commit="4" * 40)  # the same release at another locator
        resigned = self.world.pin(self.manifest)  # identical members, a different signature
        self.assertNotEqual(resigned["sig"], pin["sig"])
        for label, entries in (("dropped", []), ("replaced", [replaced]), ("relocated", [relocated]),
                               ("re-signed", [resigned])):
            with self.subTest(label=label):
                status, _, why = self.world.load(entries, persisted_entries=kept)
                self.assertEqual(status, "refused")
                self.assertIn("removed or mutated", why)

    def test_an_exact_copy_verifies_apart_from_its_document(self):
        pin = self.world.pin(self.manifest)
        status, reg, why = self.world.load([pin])
        self.assertEqual((status, why), ("verified", "ok"))
        with self.world.estate.mocked():
            self.assertEqual(reg.declared_entry_ok(copy.deepcopy(pin)), (True, "ok"))
            altered = dict(pin, manifest_hash="e" * 64)
            self.assertFalse(reg.declared_entry_ok(altered)[0])


def mutated(manifest, change):
    value = copy.deepcopy(manifest)
    change(value)
    return value


class ReleaseManifestTests(unittest.TestCase):
    """§13.5 manifest structure — every rule refuses on its own."""

    def setUp(self):
        self.world = World()
        self.manifest = self.world.manifest()

    def refuses(self, change, message=None):
        value = mutated(self.manifest, change)
        if message is None:
            self.assertRaises(REG.RegistryError, REG.validate_release_manifest, value)
        else:
            self.assertRaisesRegex(REG.RegistryError, message, REG.validate_release_manifest, value)

    def test_the_example_manifest_validates(self):
        self.assertIs(REG.validate_release_manifest(self.manifest), self.manifest)
        self.assertEqual([c["id"] for c in self.manifest["components"]],
                         ["brainstem", "organism-alpha", "organism-beta", "rapp-1"])
        self.assertEqual(REG.MANIFEST_SCHEMA, "rapp/1-release-manifest")

    def test_manifest_members_and_schema(self):
        for value in ([], "manifest", None):
            with self.subTest(value=value):
                self.assertRaises(REG.RegistryError, REG.validate_release_manifest, value)
        self.refuses(lambda m: m.update(note="extra"), "exactly the members")
        self.refuses(lambda m: m.pop("components"), "exactly the members")
        self.refuses(lambda m: m.pop("release"), "exactly the members")
        self.refuses(lambda m: m.update(schema="rapp/1-release-manifest-v2"), "schema")
        self.refuses(lambda m: m.update(schema="rapp/1"), "schema")
        self.refuses(lambda m: m.update(release_scope="http://releases.example.test/acme/1.0"), "release_scope")
        self.refuses(lambda m: m.update(release_scope=None), "release_scope")
        self.refuses(lambda m: m.update(components=[]), "non-empty")
        self.refuses(lambda m: m.update(components={}), "non-empty")

    def test_the_release_name_is_for_people(self):
        self.assertEqual(self.manifest["release"], "acme-1.0.0")
        for name in ("lts-2026.09", "brainstem-v0.6.16", "A", "7", "a" * 64, "LTS_2026.09-rc.1", "v1.", "1..2"):
            with self.subTest(release=name):
                value = mutated(self.manifest, lambda m: m.update(release=name))
                self.assertIs(REG.validate_release_manifest(value), value)
        for name in ("", "a" * 65, "-lts", ".lts", "_lts", "lts 2026.09", "lts/2026.09", "lts:1", "lts+1",
                     "l\u00e9ts", "\u0661", "lts\n", "\uff41", None, 7, True, ["lts"], {"name": "lts"}):
            with self.subTest(release=name):
                self.refuses(lambda m: m.update(release=name), "`release` must be 1-64 characters")

    def test_the_release_name_changes_the_manifest_hash_and_nothing_else(self):
        renamed = mutated(self.manifest, lambda m: m.update(release="acme-1.0.0-again"))
        self.assertNotEqual(R.H("rapp/1:particle", renamed), R.H("rapp/1:particle", self.manifest))
        self.assertEqual(renamed["components"], self.manifest["components"])

    def test_component_rules(self):
        def component(index, **changes):
            return lambda m: m["components"][index].update(changes)
        cases = [
            (lambda m: m["components"].__setitem__(0, "brainstem"), "exactly the members"),
            (component(0, extra=1), "exactly the members"),
            (lambda m: m["components"][0].pop("immutable_ref"), "exactly the members"),
            (component(0, id="Brainstem"), "`id`"), (component(0, id="-brainstem"), "`id`"),
            (component(0, id=""), "`id`"), (component(0, id="a_b"), "`id`"), (component(0, id=7), "`id`"),
            (component(3, id="z" * 101), "`id`"),
            (component(0, kind="Kernel"), "`kind`"), (component(0, kind="k" * 65), "`kind`"),
            (component(0, kind=""), "`kind`"), (component(0, kind=None), "`kind`"),
            (component(0, repository="http://git.example.test/acme/brainstem"), "`repository`"),
            (component(0, repository=""), "`repository`"),
            (component(0, object_format="md5"), "`object_format`"),
            (component(0, commit="1" * 64), "`commit`"),
            (component(2, commit="b" * 40), "`commit`"),
            (component(0, commit="A" * 40), "`commit`"), (component(0, commit="main"), "`commit`"),
            (component(0, immutable_ref="brainstem-v1.0.0"), "`immutable_ref`"),
            (component(0, immutable_ref="refs/tags/"), "`immutable_ref`"),
            (component(0, immutable_ref="refs/heads/main"), "`immutable_ref`"),
            (component(0, immutable_ref=""), "`immutable_ref`"), (component(0, immutable_ref=7), "`immutable_ref`"),
            (component(0, files={}), "`files`"), (component(0, files=None), "`files`"),
            (lambda m: m["components"].reverse(), "sorted ascending by `id`"),
            (lambda m: m["components"].insert(3, copy.deepcopy(m["components"][3])), "sorted ascending by `id`"),
        ]
        for index, (change, message) in enumerate(cases):
            with self.subTest(case=index, message=message):
                self.refuses(change, message)

    def test_component_variants_are_accepted(self):
        accepted = [
            lambda m: m["components"][3].update(files=[]),
            lambda m: m["components"][3].update(immutable_ref=None),
            lambda m: m["components"][3].update(immutable_ref="refs/tags/protocol/v1"),
            lambda m: m["components"][3].update(kind="document"),
            lambda m: m["components"][3].update(id="z" * 100),
            lambda m: m["components"][3].update(object_format="sha256", commit="c" * 64),
            lambda m: m["components"][3]["files"][0].update(size_bytes=0),
        ]
        for index, change in enumerate(accepted):
            with self.subTest(case=index):
                value = mutated(self.manifest, change)
                self.assertIs(REG.validate_release_manifest(value), value)

    def test_file_rules(self):
        def file(index, **changes):
            return lambda m: m["components"][0]["files"][index].update(changes)
        cases = [
            (lambda m: m["components"][0]["files"].__setitem__(0, "kernel/VERSION"), "exactly the members"),
            (file(0, mode="100644"), "exactly the members"),
            (lambda m: m["components"][0]["files"][0].pop("size_bytes"), "exactly the members"),
            (file(0, sha256="A" * 64), "`sha256`"), (file(0, sha256="a" * 63), "`sha256`"),
            (file(0, sha256=None), "`sha256`"),
            (file(0, size_bytes=-1), "`size_bytes`"), (file(0, size_bytes=2**53), "`size_bytes`"),
            (file(0, size_bytes=True), "`size_bytes`"), (file(0, size_bytes=1.5), "`size_bytes`"),
            (file(0, size_bytes="5"), "`size_bytes`"), (file(0, size_bytes=None), "`size_bytes`"),
            (lambda m: m["components"][0]["files"].reverse(), "ascend"),
            (lambda m: m["components"][0]["files"].insert(1, dict(m["components"][0]["files"][0])), "ascend"),
        ]
        for path in ("", "/kernel/VERSION", "kernel//VERSION", "./VERSION", "../VERSION", "kernel\\VERSION",
                     "C:/VERSION", "kernel/CON", "kernel/nul.txt", "kernel/VERSION.", "kernel/VERSION ",
                     "kernel/a:b", "kernel/e\u0301", "kernel/\x1f", 7, None):
            cases.append((file(0, path=path), "§9.1 path grammar"))
        for index, (change, message) in enumerate(cases):
            with self.subTest(case=index, message=message):
                self.refuses(change, message)

    def test_paths_collide_case_insensitively_and_across_directories(self):
        def with_paths(*paths):
            return lambda m: m["components"][3].update(files=[
                {"path": p, "sha256": "e" * 64, "size_bytes": 1} for p in paths])
        for paths in (("A.txt", "a.txt"), ("SS.md", "\u00df.md"), ("docs", "docs/index.md"),
                      ("DOCS", "docs/index.md"), ("\u00c5.md", "\u00e5.md")):
            with self.subTest(paths=paths):
                self.refuses(with_paths(*paths), "case-insensitively")
        self.refuses(with_paths("docs/a.md", "docs/b.md", "docs.md"), "ascend")  # "docs.md" sorts first
        value = mutated(self.manifest, with_paths("docs.md", "docs/a.md", "docs/b.md"))
        self.assertIs(REG.validate_release_manifest(value), value)

    def test_door_of_record_pairing_and_uniqueness(self):
        alpha = self.world.alpha
        cases = [
            (lambda m: m["components"][1].update(identity_path=None), "both be null or both be set"),
            (lambda m: m["components"][3].update(identity_path="SPEC.md"), "both be null or both be set"),
            (lambda m: m["components"][3].update(rappid=alpha, identity_path="SPEC.md"), "already bound"),
            (lambda m: m["components"][1].update(identity_path="other.json"), "one of the component's files"),
            (lambda m: m["components"][1].update(identity_path=7), "one of the component's files"),
            (lambda m: m["components"][1].update(rappid="rappid:@acme/organism-alpha:" + "a" * 32), "§6.1 rappid"),
            (lambda m: m["components"][1].update(rappid="acme/organism-alpha"), "§6.1 rappid"),
            (lambda m: m["components"][2].update(rappid=alpha), "already bound"),
        ]
        for index, (change, message) in enumerate(cases):
            with self.subTest(case=index, message=message):
                self.refuses(change, message)

    def test_the_canonical_form_is_bounded_at_one_mebibyte(self):
        big = [{"path": "p" * (R.MAX_CANONICAL_BYTES + 1), "sha256": "e" * 64, "size_bytes": 1}]
        self.refuses(lambda m: m["components"][3].update(files=big), "1 MiB")
        self.refuses(lambda m: m["components"][3]["files"][0].update(path="kernel/\ud800"), "UTF-8")


class ManifestOctetsTests(unittest.TestCase):
    """§13.5 step 2: the pinned octets are exactly canonical(manifest) and hash to the pin."""

    def setUp(self):
        self.world = World()
        self.manifest, self.reg = self.world.registry([])
        self.pin = self.reg.scope_head(LTS)
        self.octets = R.canonical(self.manifest).encode("utf-8")

    def verify(self, octets, pin=None):
        return REG.verify_release_manifest(self.reg, self.pin if pin is None else pin, octets)

    def test_exact_canonical_octets_verify(self):
        result = self.verify(self.octets)
        self.assertEqual(result, self.manifest)
        self.assertEqual(R.H("rapp/1:particle", result), self.pin["manifest_hash"])

    def test_only_a_verified_registry_says_what_a_release_pins(self):
        built = REG.Registry(self.reg.entries)  # the same entries, but nothing verified them
        with self.assertRaisesRegex(REG.RegistryError, "registry status is None"):
            REG.verify_release_manifest(built, self.pin, self.octets)
        with self.assertRaisesRegex(REG.RegistryError, "registry status is None"):
            REG.verify_release_manifest(built, self.pin, self.octets, allow_draft=True)
        status, draft, _ = self.world.load([self.world.grail(), self.pin], signed=False, allow_unsigned=True)
        self.assertEqual(status, "draft")
        with self.assertRaisesRegex(REG.RegistryError, "registry status is 'draft'"):
            REG.verify_release_manifest(draft, self.pin, self.octets)
        self.assertEqual(REG.verify_release_manifest(draft, self.pin, self.octets, allow_draft=True), self.manifest)

    def test_any_other_octets_are_refused(self):
        pretty = json.dumps(self.manifest, indent=2, sort_keys=True).encode("utf-8")
        compact_unsorted = json.dumps(self.manifest, separators=(",", ":")).encode("utf-8")
        cases = {
            "pretty-printed": pretty,
            "trailing newline": self.octets + b"\n",
            "trailing CRLF": self.octets + b"\r\n",
            "byte-order mark": b"\xef\xbb\xbf" + self.octets,
            "members out of canonical order": compact_unsorted,
            "UTF-16": R.canonical(self.manifest).encode("utf-16"),
            "not UTF-8": self.octets[:-2] + b"\xff}",
            "duplicate member": b'{"schema":"a","schema":"b"}',
            "not JSON": b"schema: rapp/1-release-manifest",
        }
        self.assertNotEqual(compact_unsorted, self.octets)
        for label, octets in cases.items():
            with self.subTest(label=label):
                self.assertRaises(REG.RegistryError, self.verify, octets)
        with self.assertRaisesRegex(REG.RegistryError, "bytes"):
            self.verify(R.canonical(self.manifest))

    def test_a_manifest_that_is_not_the_pinned_one_is_refused(self):
        other = mutated(self.manifest, lambda m: m["components"][3]["files"][0].update(size_bytes=18))
        with self.assertRaisesRegex(REG.RegistryError, "manifest_hash"):
            self.verify(R.canonical(other).encode("utf-8"))

    def test_a_manifest_naming_another_scope_is_refused_even_when_pinned(self):
        foreign = self.world.manifest(NEW_2, kernel=None)
        pin = self.world.pin(foreign, scope=LTS)  # an LTS release pinning NEW_2's manifest
        status, reg, why = self.world.load([pin])
        self.assertEqual(status, "verified", why)
        with self.assertRaisesRegex(REG.RegistryError, "release_scope other than its release-pin's"):
            REG.verify_release_manifest(reg, pin, R.canonical(foreign).encode("utf-8"))

    def test_only_the_registrys_own_release_pin_is_verified_against(self):
        cases = {
            "a relocated copy": dict(self.pin, commit="4" * 40),
            "a re-signed copy": dict(self.pin, sig="another signature"),
            "a copy with an extra member": dict(self.pin, note="x"),
            "a copy that is not I-JSON": dict(self.pin, note=1.5),
            "a release-pin of no registry": self.world.pin(self.world.manifest(NEW_2, kernel=None),
                                                           channel="newest"),
            "an unhashable manifest_hash": dict(self.pin, manifest_hash=["x"]),
            "not an object": "release-pin",
        }
        for label, pin in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(REG.RegistryError, "not an entry of this registry"):
                    self.verify(self.octets, pin)
        self.assertEqual(self.verify(self.octets, copy.deepcopy(self.pin)), self.manifest)

    def test_a_pinned_but_malformed_manifest_is_refused(self):
        broken = mutated(self.manifest, lambda m: m["components"].reverse())
        pin = self.world.pin(broken, scope=LTS)
        status, reg, _ = self.world.load([pin])
        self.assertEqual(status, "verified")
        with self.assertRaisesRegex(REG.RegistryError, "sorted ascending"):
            REG.verify_release_manifest(reg, pin, R.canonical(broken).encode("utf-8"))


class KernelCoherenceTests(unittest.TestCase):
    """§13.5 kernel coherence, both directions and every field."""

    def setUp(self):
        self.world = World()
        self.manifest = self.world.manifest()
        self.with_grail = REG.Registry(self.world.estate.base_entries() + [self.world.grail()])
        self.without_grail = REG.Registry(self.world.estate.base_entries())

    def coherent(self, manifest, registry=None):
        return REG.check_kernel_coherence(registry or self.with_grail, manifest)

    def test_the_kernel_component_matches_the_familys_grail(self):
        self.assertEqual(self.coherent(self.manifest), (True, "ok"))
        self.assertEqual(self.coherent(self.world.manifest(fix=1)), (True, "ok"))  # a correction keeps it

    def test_a_declared_grail_needs_exactly_one_kernel_component(self):
        no_kernel = self.world.manifest(kernel=None)
        second = mutated(self.manifest, lambda m: m["components"].insert(
            1, dict(copy.deepcopy(m["components"][0]), id="brainstem-copy")))
        self.assertFalse(self.coherent(no_kernel)[0])
        ok, why = self.coherent(second)
        self.assertFalse(ok)
        self.assertIn("not 2", why)

    def test_every_kernel_field_must_equal_the_grail_entry(self):
        def kernel(**changes):
            return mutated(self.manifest, lambda m: m["components"][0].update(changes))
        def kernel_file(**changes):
            return mutated(self.manifest, lambda m: m["components"][0]["files"][2].update(changes))
        self.assertEqual(self.manifest["components"][0]["files"][2]["path"], KERNEL_PATH)
        cases = {
            "repository": kernel(repository=MIRROR),
            "repository spelled another way": kernel(repository=KERNEL + ".git"),
            "object_format": kernel(object_format="sha256", commit="1" * 64),
            "commit": kernel(commit="9" * 40),
            "immutable_ref": kernel(immutable_ref="refs/tags/brainstem-v1.0.1"),
            "immutable_ref null": kernel(immutable_ref=None),
            "path": kernel_file(path="kernel/brainstem2.py"),
            "sha256": kernel_file(sha256="e" * 64),
            "size_bytes": kernel_file(size_bytes=1),
        }
        for label, manifest in cases.items():
            with self.subTest(field=label):
                REG.validate_release_manifest(manifest)
                self.assertFalse(self.coherent(manifest)[0])

    def test_without_a_grail_no_component_may_be_a_kernel(self):
        self.assertFalse(self.coherent(self.manifest, self.without_grail)[0])
        renamed = mutated(self.manifest, lambda m: m["components"][0].update(kind="runtime"))
        self.assertEqual(self.coherent(renamed, self.without_grail), (True, "ok"))
        self.assertEqual(self.coherent(self.world.manifest(kernel=None), self.without_grail), (True, "ok"))

    def test_another_familys_grail_does_not_count(self):
        other_family = REG.Registry(self.world.estate.base_entries() + [self.world.grail(scope=NEW_2)])
        self.assertFalse(self.coherent(self.manifest, other_family)[0])

    def test_an_invalid_manifest_is_not_coherent(self):
        ok, why = self.coherent(mutated(self.manifest, lambda m: m.update(schema="other")))
        self.assertFalse(ok)
        self.assertIn("schema", why)

    def test_verification_enforces_coherence(self):
        world = World()
        manifest = world.manifest()
        pin = world.pin(manifest)
        status, reg, _ = world.load([pin])  # no grail-kernel for LTS
        self.assertEqual(status, "verified")
        with self.assertRaisesRegex(REG.RegistryError, "needs a grail-kernel"):
            REG.verify_release_manifest(reg, pin, R.canonical(manifest).encode("utf-8"))


class VerifiedSnapshotTests(unittest.TestCase):
    """§13.5 verified snapshots: exactly the pinned files, all or nothing."""

    def setUp(self):
        self.world = World()
        self.manifest, self.reg = self.world.registry([])
        self.world.calls.clear()

    def snapshot(self, fetch=None, registry=None, **kwargs):
        if not {"release_scope", "channel", "manifest_hash"} & set(kwargs):
            kwargs["release_scope"] = LTS
        return REG.verify_snapshot(registry or self.reg, fetch or self.world.fetch, **kwargs)

    def test_the_snapshot_is_exactly_the_pinned_files(self):
        snapshot = self.snapshot()
        pin = self.reg.scope_head(LTS)
        expected = {(c["id"], f["path"]): self.world.store[(c["repository"], c["commit"], f["path"])]
                    for c in self.manifest["components"] for f in c["files"]}
        self.assertEqual(snapshot, expected)
        self.assertEqual(len(snapshot), 8)
        self.assertEqual(self.world.calls[0], (RELEASES, "sha1", "3" * 40, pin["path"]))
        self.assertEqual(self.world.calls[1:], [(c["repository"], c["object_format"], c["commit"], f["path"])
                                                for c in self.manifest["components"] for f in c["files"]])

    def test_each_snapshot_is_a_fresh_dict(self):
        first, second = self.snapshot(), self.snapshot()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first.clear()
        self.assertEqual(len(self.snapshot()), 8)

    def test_exactly_one_selector_names_the_release(self):
        manifest_hash = self.reg.scope_head(LTS)["manifest_hash"]
        several = [{}, {"release_scope": LTS, "channel": "lts"},
                   {"channel": "lts", "manifest_hash": manifest_hash},
                   {"release_scope": LTS, "manifest_hash": manifest_hash},
                   {"release_scope": LTS, "channel": "lts", "manifest_hash": manifest_hash}]
        for selectors in several:
            with self.subTest(selectors=sorted(selectors)):
                with self.assertRaisesRegex(REG.RegistryError, "select exactly one pinned release"):
                    REG.verify_snapshot(self.reg, self.world.fetch, **selectors)
        self.assertEqual(self.world.calls, [])  # refused before any transport is asked
        with self.assertRaises(TypeError):  # the selector is a keyword, never a position
            REG.verify_snapshot(self.reg, LTS, self.world.fetch)
        expected = self.snapshot()
        for selectors in ({"release_scope": LTS}, {"channel": "lts"}, {"manifest_hash": manifest_hash}):
            with self.subTest(selectors=selectors):
                self.assertEqual(REG.verify_snapshot(self.reg, self.world.fetch, **selectors), expected)
        unknown = [({"release_scope": NEW_2}, "release_scope"), ({"release_scope": ["x"]}, "release_scope"),
                   ({"channel": "newest"}, "channel"), ({"channel": LTS}, "channel"),
                   ({"manifest_hash": "e" * 64}, "manifest_hash"), ({"manifest_hash": LTS}, "manifest_hash")]
        for selectors, named in unknown:
            with self.subTest(selectors=selectors):
                with self.assertRaisesRegex(REG.RegistryError, f"no release-pin entry for {named}"):
                    REG.verify_snapshot(self.reg, self.world.fetch, **selectors)

    def tampering(self, target, replace):
        def fetch(repository, object_format, commit, path):
            octets = self.world.fetch(repository, object_format, commit, path)
            return replace(octets) if (repository, path) == target else octets
        return fetch

    def test_a_tampered_file_refuses_the_whole_snapshot(self):
        cases = {
            "one byte appended": ((ALPHA, "soul.md"), lambda o: o + b"!", "pinned"),
            "same length, other bytes": ((ALPHA, "soul.md"), lambda o: o.upper(), "SHA-256"),
            "kernel companion swapped": ((KERNEL, "kernel/VERSION"), lambda o: b"9.9.9\n", "SHA-256"),
            "empty": ((PROTOCOL, "SPEC.md"), lambda o: b"", "pinned"),
        }
        for label, (target, replace, message) in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(REG.RegistryError, message):
                    self.snapshot(self.tampering(target, replace))

    def test_transport_failures_refuse_the_whole_snapshot(self):
        del self.world.store[(BETA, "b" * 64, "agents/beta_agent.py")]
        with self.assertRaisesRegex(REG.RegistryError, "fetch failed"):
            self.snapshot()

        def offline(*locator):
            raise OSError("network unreachable")
        with self.assertRaisesRegex(REG.RegistryError, "fetch failed"):
            self.snapshot(offline)
        for returned in ("text", bytearray(b"x"), None):
            with self.subTest(returned=returned):
                with self.assertRaisesRegex(REG.RegistryError, "must return bytes"):
                    self.snapshot(lambda *locator, r=returned: r)

    def test_a_manifest_changed_at_its_locator_is_refused(self):
        newer = mutated(self.manifest, lambda m: m["components"][3]["files"][0].update(sha256="e" * 64))
        pin = self.reg.scope_head(LTS)
        self.world.publish(RELEASES, pin["commit"], pin["path"], R.canonical(newer).encode("utf-8"))
        with self.assertRaisesRegex(REG.RegistryError, "manifest_hash"):
            self.snapshot()

    def test_only_a_verified_registry_yields_a_snapshot(self):
        direct = REG.Registry(self.reg.entries)
        self.assertIsNone(direct.status)
        for allow_draft in (False, True):
            with self.subTest(direct=True, allow_draft=allow_draft):
                with self.assertRaisesRegex(REG.RegistryError, "status is None"):
                    self.snapshot(registry=direct, allow_draft=allow_draft)
        status, draft, _ = self.world.load(self.reg.entries[len(self.world.estate.base_entries()):],
                                           signed=False, allow_unsigned=True)
        self.assertEqual((status, draft.status), ("draft", "draft"))
        with self.assertRaisesRegex(REG.RegistryError, "status is 'draft'"):
            self.snapshot(registry=draft)
        self.assertEqual(len(self.snapshot(registry=draft, allow_draft=True)), 8)
        self.assertEqual(len(self.snapshot(allow_draft=True)), 8)

    def rebind_identity(self, octets):
        """Re-pin the LTS release with organism-alpha's identity file replaced by `octets`."""
        world = World()
        world.alpha = self.world.alpha
        manifest = world.manifest()
        alpha = manifest["components"][1]
        world.publish(ALPHA, alpha["commit"], "rappid.json", octets)
        alpha["files"] = file_list({"rappid.json": octets, "soul.md": b"# alpha\n"})
        status, reg, why = world.load([world.grail(), world.pin(manifest)])
        self.assertEqual(status, "verified", why)
        return lambda: REG.verify_snapshot(reg, world.fetch, release_scope=LTS)

    def test_every_door_of_record_binding_is_checked(self):
        alpha = self.world.alpha
        cases = {
            "another rappid": (World.identity(self.world.beta), "rappid differs"),
            "a legacy schema": (R.canonical({"schema": "rapp/0", "rappid": alpha}).encode(), "schema"),
            "not an object": (R.canonical([alpha]).encode(), "JSON object"),
            "not JSON": (b"rappid = " + alpha.encode(), "§4 value"),
            "duplicate member": (b'{"rappid":"x","rappid":"' + alpha.encode() + b'"}', "§4 value"),
            # json.loads would detect these encodings; the identity file is UTF-8 without a BOM.
            "UTF-8 with a byte-order mark": (b"\xef\xbb\xbf" + World.identity(alpha), "byte-order mark"),
            "UTF-16": (World.identity(alpha).decode("utf-8").encode("utf-16"), "must be UTF-8"),
            "UTF-32": (World.identity(alpha).decode("utf-8").encode("utf-32-le"), "never holds a NUL byte"),
            "UTF-16 without a mark": (World.identity(alpha).decode("utf-8").encode("utf-16-le"), "NUL byte"),
        }
        for label, (octets, message) in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(REG.RegistryError, message):
                    self.rebind_identity(octets)()
        without_schema = R.canonical({"rappid": alpha, "name": "alpha"}).encode()
        self.assertEqual(len(self.rebind_identity(without_schema)()), 8)

    def test_a_mirror_copy_is_not_the_door_of_record(self):
        beta = self.manifest["components"][2]
        identity = self.world.store[(BETA, beta["commit"], "rappid.json")]
        self.world.publish(MIRROR, "d" * 40, "organisms/beta/rappid.json", identity)  # a byte-identical copy
        snapshot = self.snapshot()
        self.assertEqual(snapshot[("organism-beta", "rappid.json")], identity)
        self.assertNotIn(MIRROR, {call[0] for call in self.world.calls})
        # A mirror that serves a manifest naming itself as beta's door of record is not the pin.
        mirrored = mutated(self.manifest, lambda m: m["components"][2].update(
            repository=MIRROR, object_format="sha1", commit="d" * 40, identity_path="organisms/beta/rappid.json",
            files=file_list({"organisms/beta/rappid.json": identity})))
        REG.validate_release_manifest(mirrored)
        pin = self.reg.scope_head(LTS)

        def hostile(repository, object_format, commit, path):
            if (repository, path) == (RELEASES, pin["path"]):
                return R.canonical(mirrored).encode("utf-8")
            return self.world.fetch(repository, object_format, commit, path)
        with self.assertRaisesRegex(REG.RegistryError, "manifest_hash"):
            self.snapshot(hostile)

    def test_an_incoherent_kernel_refuses_the_snapshot(self):
        world = World()
        manifest = world.manifest(kernel="1.0.1")  # the grail-kernel below pins 1.0.0
        status, reg, _ = world.load([world.grail(), world.pin(manifest)])
        self.assertEqual(status, "verified")
        with self.assertRaisesRegex(REG.RegistryError, "kernel component"):
            REG.verify_snapshot(reg, world.fetch, release_scope=LTS)
        self.assertEqual(len(world.calls), 1)  # refused at the manifest, before any member file

    def test_a_component_without_files_contributes_nothing(self):
        world = World()
        manifest = world.manifest()
        manifest["components"][3]["files"] = []
        status, reg, _ = world.load([world.grail(), world.pin(manifest)])
        self.assertEqual(status, "verified")
        snapshot = REG.verify_snapshot(reg, world.fetch, release_scope=LTS)
        self.assertEqual(len(snapshot), 7)
        self.assertNotIn("rapp-1", {cid for cid, _ in snapshot})
        self.assertNotIn(PROTOCOL, {call[0] for call in world.calls})


class ReleaseFamilyTests(unittest.TestCase):
    """§13.5 end to end: a family keeps its one kernel across corrections, a channel moves on to
    the next family, a late kernel is refused, and every pinned release stays verifiable."""

    def setUp(self):
        self.world = World()

    def test_an_lts_correction_keeps_the_familys_kernel(self):
        world = self.world
        original, correction = world.manifest(), world.manifest(fix=1)
        first = world.pin(original)
        second = world.pin(correction, predecessor=first, activated=LATER)
        status, reg, why = world.load([world.grail(), first, second])
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(reg.scope_releases(LTS), [first, second])
        self.assertEqual(reg.scope_head(LTS), second)
        self.assertEqual(reg.channel_head("lts"), second)
        self.assertEqual(original["components"][0], correction["components"][0])  # one kernel, byte for byte
        old = REG.verify_snapshot(reg, world.fetch, manifest_hash=first["manifest_hash"])
        new = REG.verify_snapshot(reg, world.fetch, manifest_hash=second["manifest_hash"])
        self.assertEqual(REG.verify_snapshot(reg, world.fetch, release_scope=LTS), new)
        self.assertEqual(REG.verify_snapshot(reg, world.fetch, channel="lts"), new)

        def kernel(snapshot):
            return {key: octets for key, octets in snapshot.items() if key[0] == "brainstem"}
        self.assertEqual(kernel(old), kernel(new))
        self.assertEqual(len(kernel(new)), 3)
        self.assertEqual(old[("organism-alpha", "soul.md")], b"# alpha\n")
        self.assertEqual(new[("organism-alpha", "soul.md")], b"# alpha, correction 1\n")

    def test_a_correction_cannot_change_the_familys_kernel(self):
        world = self.world
        first = world.pin(world.manifest())
        drifted = world.pin(world.manifest(kernel="1.0.1", kernel_commit="4" * 40, fix=1),
                            predecessor=first, activated=LATER)
        status, reg, why = world.load([world.grail(), first, drifted])
        self.assertEqual((status, why), ("verified", "ok"))  # the registry never sees manifest bytes
        with self.assertRaisesRegex(REG.RegistryError, "kernel component"):
            REG.verify_snapshot(reg, world.fetch, release_scope=LTS)
        self.assertEqual(len(REG.verify_snapshot(reg, world.fetch, manifest_hash=first["manifest_hash"])), 8)

    def test_the_newest_channel_moves_on_to_the_next_family(self):
        world = self.world
        first = world.pin(world.manifest(NEW_2, kernel="2.0.0", kernel_commit="5" * 40), channel="newest")
        second = world.pin(world.manifest(NEW_3, kernel="3.0.0", kernel_commit="6" * 40), channel="newest",
                           predecessor=first, activated=LATER)
        kernels = [world.grail(NEW_2, "2.0.0", "5" * 40), world.grail(NEW_3, "3.0.0", "6" * 40)]
        status, reg, why = world.load(kernels + [first, second])
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(reg.release_channels["newest"], [first, second])
        self.assertEqual((reg.channel_head("newest"), reg.scope_head(NEW_3)), (second, second))
        self.assertEqual(reg.scope_head(NEW_2), first)  # the family it left keeps its current release
        head = REG.verify_snapshot(reg, world.fetch, channel="newest")
        self.assertEqual(head, REG.verify_snapshot(reg, world.fetch, release_scope=NEW_3))
        self.assertEqual(head[("brainstem", KERNEL_PATH)], kernel_files("3.0.0")[KERNEL_PATH])
        left = REG.verify_snapshot(reg, world.fetch, release_scope=NEW_2)
        self.assertEqual(left[("brainstem", KERNEL_PATH)], kernel_files("2.0.0")[KERNEL_PATH])
        swapped = world.manifest(NEW_3, kernel="2.0.0", kernel_commit="5" * 40)  # NEW_3 carrying NEW_2's kernel
        self.assertFalse(REG.check_kernel_coherence(reg, swapped)[0])

    def test_a_kernel_declared_after_its_familys_first_release_is_refused_whole(self):
        world = self.world
        release = world.pin(world.manifest(kernel=None))
        self.assertEqual(world.load([release])[0], "verified")
        status, _, why = world.load([release, world.grail()], seq=3, persisted_entries=persisted(release))
        self.assertEqual(status, "refused")
        self.assertIn("follows that family's first release-pin", why)
        # Declared before the family's first release, the same kernel binds every release of it.
        status, reg, why = world.load([world.grail(), world.pin(world.manifest())])
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(len(REG.verify_snapshot(reg, world.fetch, release_scope=LTS)), 8)

    def test_every_pinned_release_stays_verifiable_and_heads_only_advance(self):
        world = self.world
        grail, first = world.grail(), world.pin(world.manifest())
        status, before, why = world.load([grail, first])
        self.assertEqual((status, why), ("verified", "ok"))
        original = REG.verify_snapshot(before, world.fetch, channel="lts")
        second = world.pin(world.manifest(fix=1), predecessor=first, activated=LATER)
        third = world.pin(world.manifest(fix=2), predecessor=second, activated=LATEST)
        status, after, why = world.load([grail, first, second, third], seq=3,
                                        persisted_entries=persisted(grail, first))
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(after.channel_head("lts"), third)
        self.assertEqual(REG.verify_snapshot(after, world.fetch, manifest_hash=first["manifest_hash"]), original)
        self.assertEqual(after.scope_releases(LTS), [first, second, third])
        kept = persisted(grail, first, second, third)
        rewind = world.pin(world.manifest(fix=3), predecessor=first, activated=LATEST)
        for label, entries in (("dropping the later releases", [grail, first]),
                               ("forking back to the first release", [grail, first, second, third, rewind])):
            with self.subTest(label=label):
                self.assertEqual(world.load(entries, seq=4, persisted_entries=kept)[0], "refused")

    def test_returning_to_earlier_content_is_a_new_release_with_a_new_name(self):
        world = self.world
        grail, first = world.grail(), world.pin(world.manifest())
        second = world.pin(world.manifest(fix=1), predecessor=first, activated=LATER)
        kept = persisted(grail, first, second)
        # The first release's exact manifest cannot be pinned again: it is that release, already pinned.
        again = world.pin(world.manifest(), predecessor=second, activated=LATEST)
        self.assertEqual(again["manifest_hash"], first["manifest_hash"])
        status, _, why = world.load([grail, first, second, again], seq=3, persisted_entries=kept)
        self.assertEqual(status, "refused")
        self.assertIn("second release-pin for manifest_hash", why)
        # The same files under a new release name are a new release, appended as the family's current one.
        back = world.manifest(release="acme-1.0.2")
        self.assertEqual(back["components"], world.manifest()["components"])
        returned = world.pin(back, predecessor=second, activated=LATEST)
        status, reg, why = world.load([grail, first, second, returned], seq=3, persisted_entries=kept)
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(reg.scope_releases(LTS), [first, second, returned])
        self.assertEqual(reg.channel_head("lts"), returned)
        self.assertEqual(REG.verify_snapshot(reg, world.fetch, channel="lts"),
                         REG.verify_snapshot(reg, world.fetch, manifest_hash=first["manifest_hash"]))
        self.assertNotEqual(REG.verify_snapshot(reg, world.fetch, manifest_hash=second["manifest_hash"]),
                            REG.verify_snapshot(reg, world.fetch, channel="lts"))


class ReleaseHistoryTests(unittest.TestCase):
    """§13.5: a consumer that accepted a release of a family refuses a later registry that adds a
    grail-kernel for that family. §13.4 retention of what it accepted makes the insertion visible;
    without that history only the kernel's place in `entries` can be judged."""

    def setUp(self):
        self.world = World()
        self.release = self.world.pin(self.world.manifest(kernel=None))  # the family's first release, no kernel
        status, _, why = self.world.load([self.release])
        self.assertEqual((status, why), ("verified", "ok"))
        self.kept = persisted(self.release)  # every declared entry the consumer accepted (§13.4)
        self.grail = self.world.grail()

    def test_a_kernel_inserted_ahead_of_an_accepted_release_is_refused(self):
        status, _, why = self.world.load([self.grail, self.release], seq=3, persisted_entries=self.kept)
        self.assertEqual(status, "refused")
        self.assertIn("was added after a release of that family was accepted", why)

    def test_a_kernel_appended_after_the_familys_first_release_is_refused_with_or_without_history(self):
        for kept in (self.kept, None):
            with self.subTest(persisted=kept is not None):
                status, _, why = self.world.load([self.release, self.grail], seq=3, persisted_entries=kept)
                self.assertEqual(status, "refused")
                self.assertIn("follows that family's first release-pin", why)

    def test_loaded_fresh_the_same_insertion_leaves_the_release_unverifiable(self):
        # With no history, a kernel placed ahead of every release of its family satisfies the in-document
        # ordering rule, so the registry verifies; but the release pinned without a kernel component is
        # then incoherent with its family's kernel, so it never yields a snapshot under that kernel.
        status, fresh, why = self.world.load([self.grail, self.release], seq=3)
        self.assertEqual((status, why), ("verified", "ok"))
        with self.assertRaisesRegex(REG.RegistryError, "exactly one kernel component, not 0"):
            REG.verify_snapshot(fresh, self.world.fetch, manifest_hash=self.release["manifest_hash"])
        # The same registry judged with the consumer's history is refused outright.
        ok, why = fresh.check_retained(self.kept)
        self.assertFalse(ok)
        self.assertIn("was added after a release of that family was accepted", why)

    def test_other_families_and_already_accepted_kernels_are_not_insertions(self):
        world = self.world
        other = world.grail(NEW_2, "2.0.0", "5" * 40)
        newest = world.pin(world.manifest(NEW_2, kernel="2.0.0", kernel_commit="5" * 40), channel="newest")
        status, _, why = world.load([other, self.release, newest], seq=3, persisted_entries=self.kept)
        self.assertEqual((status, why), ("verified", "ok"))
        correction = world.pin(world.manifest(kernel=None, fix=1), predecessor=self.release, activated=LATER)
        entries = [other, self.release, newest, correction]
        status, reg, why = world.load(entries, seq=4, persisted_entries=persisted(other, self.release, newest))
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(len(REG.verify_snapshot(reg, world.fetch, release_scope=LTS)), 5)

    def test_history_is_every_declared_entry_the_consumer_accepted(self):
        world = self.world
        grail, first = world.grail(), world.pin(world.manifest())
        second = world.pin(world.manifest(fix=1), predecessor=first, activated=LATER)
        entries = [grail, first, second]
        self.assertEqual(world.load(entries, seq=3, persisted_entries=persisted(grail, first))[0], "verified")
        # A consumer that kept the release but not its family's kernel breaks §13.4 and cannot tell that
        # kernel from an insertion, so the registry is refused rather than guessed at.
        status, _, why = world.load(entries, seq=3, persisted_entries=persisted(first))
        self.assertEqual(status, "refused")
        self.assertIn("was added after a release of that family was accepted", why)
        # The history is read in full even when it arrives as a one-pass iterable.
        status, _, why = world.load([grail, self.release], seq=3, persisted_entries=iter(self.kept))
        self.assertEqual(status, "refused")
        self.assertIn("was added after a release of that family was accepted", why)


class GithubRawUrlTests(unittest.TestCase):
    def test_a_commit_pinned_raw_url(self):
        self.assertEqual(
            REG.github_raw_url("https://github.com/kody-w/rapp-1", "a" * 40, "anchor/frames/x.json"),
            "https://raw.githubusercontent.com/kody-w/rapp-1/" + "a" * 40 + "/anchor/frames/x.json",
        )
        self.assertTrue(REG.github_raw_url("https://github.com/Kody-W/RAPP", "b" * 64, "SPEC.md")
                        .startswith("https://raw.githubusercontent.com/Kody-W/RAPP/" + "b" * 64 + "/"))

    def test_path_segments_are_percent_encoded(self):
        self.assertEqual(
            REG.github_raw_url("https://github.com/kody-w/rapp-1", "a" * 40, "docs/a b#c?d%e/\u00e9.md"),
            "https://raw.githubusercontent.com/kody-w/rapp-1/" + "a" * 40 + "/docs/a%20b%23c%3Fd%25e/%C3%A9.md",
        )

    def test_anything_else_has_no_github_raw_url(self):
        commit = "a" * 40
        repositories = ["https://git.example.test/acme/releases", "http://github.com/kody-w/rapp-1",
                        "https://github.com/kody-w/rapp-1/", "https://github.com/kody-w/rapp-1.git",
                        "https://github.com/kody-w/rapp-1/tree/main", "https://github.com/kody-w",
                        "https://github.com/kody-w/rapp-1?ref=main", "https://github.com/kody-w/rapp-1#x",
                        "https://www.github.com/kody-w/rapp-1", "https://github.com/-kody/rapp-1",
                        "https://github.com/kody-w/..", "https://github.com/kody w/rapp-1", None]
        for repository in repositories:
            with self.subTest(repository=repository):
                self.assertIsNone(REG.github_raw_url(repository, commit, "SPEC.md"))
        for bad_commit in ("main", "HEAD", "A" * 40, "a" * 39, "refs/tags/v1", None):
            with self.subTest(commit=bad_commit):
                self.assertIsNone(REG.github_raw_url("https://github.com/kody-w/rapp-1", bad_commit, "SPEC.md"))
        for bad_path in ("", "/SPEC.md", "../SPEC.md", "a//b", "a\\b", "CON", "e\u0301", "x\ud800", None):
            with self.subTest(path=bad_path):
                self.assertIsNone(REG.github_raw_url("https://github.com/kody-w/rapp-1", commit, bad_path))


class RappCheckReleaseManifestTests(unittest.TestCase):
    """rapp_check.py lints release manifests and release-pins as structure, never authority."""

    def repository(self, files):
        temporary = tempfile.TemporaryDirectory(prefix="rapp-check-release-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, octets in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_bytes(octets)
        return root

    def test_a_canonical_manifest_is_structural_evidence_never_authority(self):
        manifest = World().manifest()
        verdict, findings, evidence = C.check_repo(self.repository(
            {"releases/lts-1.json": R.canonical(manifest).encode("utf-8")}))
        self.assertEqual((verdict, findings), ("COMPLIANT", []))
        self.assertEqual(evidence, [{
            "artifact": "releases/lts-1.json",
            "ok": ("§13.5 release manifest structure OK (release name acme-1.0.0; 4 components; manifest_hash "
                   f"{R.H('rapp/1:particle', manifest)[:16]}…; authority requires a verified release-pin)"),
            "status": "unverified",
        }])

    def test_noncanonical_or_malformed_manifests_are_findings(self):
        manifest = World().manifest()
        unsorted = mutated(manifest, lambda m: m["components"].reverse())
        unnamed = mutated(manifest, lambda m: m.pop("release"))
        text = R.canonical(manifest)
        verdict, findings, evidence = C.check_repo(self.repository({
            "a/pretty.json": json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8"),
            "b/newline.json": R.canonical(manifest).encode("utf-8") + b"\n",
            "c/unsorted.json": R.canonical(unsorted).encode("utf-8"),
            "d/unnamed.json": R.canonical(unnamed).encode("utf-8"),
            # Not strict I-JSON at all: a duplicate member, and a float.
            "e/duplicate.json": (text[:-1] + ',"release":"acme-9.9.9"}').encode("utf-8"),
            "f/float.json": text.replace('"size_bytes":', '"size_bytes":1.5,"x":', 1).encode("utf-8"),
        }))
        self.assertEqual(verdict, "DRIFT")
        self.assertEqual(evidence, [])
        self.assertEqual({(f["artifact"], f["rule"]) for f in findings}, {
            ("a/pretty.json", "§13.5 release manifest"),
            ("b/newline.json", "§13.5 release manifest"),
            ("c/unsorted.json", "§13.5 release manifest"),
            ("d/unnamed.json", "§13.5 release manifest"),
            ("e/duplicate.json", "§13.5 release manifest"),
            ("f/float.json", "§13.5 release manifest"),
        })
        self.assertEqual(sum("not strict I-JSON" in f["detail"] for f in findings), 2)

    def test_a_manifest_nested_inside_another_document_is_not_linted(self):
        nested = {"schema": "example-vectors/1",
                  "cases": [{"manifest": dict(World().manifest(), release="-not a name-")}]}
        self.assertEqual(C.check_repo(self.repository({"vectors.json": json.dumps(nested).encode("utf-8")})),
                         ("CLEAN", [], []))

    def test_a_registry_document_whose_release_pins_break_the_rules_is_a_finding(self):
        estate = MockEstate()
        documents = {
            "a/registry.json": [unsigned_pin(1), unsigned_pin(2, after=1), unsigned_pin(3, after=1)],
            "b/registry.json": [unsigned_pin(1), estate.grail_kernel(scope=LTS)],
            "c/registry.json": [unsigned_pin(1), unsigned_pin(2, after=1)],
        }
        files = {path: R.canonical(estate.document(estate.base_entries() + pins, signed=False)).encode("utf-8")
                 for path, pins in documents.items()}
        verdict, findings, evidence = C.check_repo(self.repository(files))
        self.assertEqual(verdict, "DRIFT")
        self.assertEqual(sorted((f["artifact"], f["rule"]) for f in findings),
                         [("a/registry.json", "§13 registry document"),
                          ("b/registry.json", "§13 registry document")])
        self.assertIn("fork", findings[0]["detail"] + findings[1]["detail"])
        self.assertEqual([item["artifact"] for item in evidence], ["c/registry.json"])


@unittest.skipUnless(real_ed25519_signer(), "optional cryptography import is absent")
class RealSignatureReleasePinTests(unittest.TestCase):
    """The release-pin path through the real detached-JWS boundary (§10), no mocks."""

    def test_real_owner_signatures_bind_each_release_and_its_snapshot(self):
        spki_der, sign = real_ed25519_signer()
        owner = R.mint_rappid("test", "estate-owner", spki_der=spki_der)
        world = World()

        def declared(pin):
            value = {k: v for k, v in pin.items() if k != "sig"}
            value["declared_by"] = owner
            value["sig"] = sign({k: v for k, v in value.items() if k != "sig"}, owner)
            return value

        first = declared(world.pin(world.manifest(kernel=None)))
        second = declared(world.pin(world.manifest(kernel=None, fix=1), predecessor=first, activated=LATER))
        entries = [{"type": "estate_owner", "rappid": owner},
                   {"type": "spki", "rappid": owner, "deprecated": False,
                    "spki_der_b64": base64.b64encode(spki_der).decode("ascii")},
                   first, second]

        def signed(members):
            doc = {"schema": "rapp/1-registry", "registry_seq": 1, "canonical_source": SOURCE,
                   "entries": members}
            doc["sig"] = sign(doc, owner)
            return doc

        status, reg, why = REG.load_document(signed(entries), trust_anchor=owner, verification_utc=LATER)
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(reg.channel_head("lts"), second)
        self.assertEqual(len(REG.verify_snapshot(reg, world.fetch, release_scope=LTS)), 5)
        self.assertEqual(len(REG.verify_snapshot(reg, world.fetch, manifest_hash=first["manifest_hash"])), 5)
        repointed = copy.deepcopy(entries)
        repointed[3]["manifest_hash"] = "e" * 64  # a valid document signature cannot bless it
        status, _, why = REG.load_document(signed(repointed), trust_anchor=owner, verification_utc=LATER)
        self.assertEqual(status, "refused")
        self.assertIn("release-pin entry signature refused", why)


if __name__ == "__main__":
    unittest.main()
