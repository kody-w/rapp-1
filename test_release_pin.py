"""§13.3 release-pin entries and §13.5 release manifests and verified snapshots.

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
LTS_1 = "https://releases.example.test/acme/lts/1"
LTS_2 = "https://releases.example.test/acme/lts/2"
LTS_3 = "https://releases.example.test/acme/lts/3"
NEWEST_1 = "https://releases.example.test/acme/newest/1"
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

    def manifest(self, scope=LTS_1, *, kernel="1.0.0", kernel_commit="1" * 40):
        components = [
            self.component("organism-alpha", "organism", ALPHA, "a" * 40,
                           {"rappid.json": self.identity(self.alpha), "soul.md": b"# alpha\n"},
                           rappid=self.alpha, identity_path="rappid.json"),
            self.component("organism-beta", "organism", BETA, "b" * 64,
                           {"rappid.json": self.identity(self.beta), "agents/beta_agent.py": b"# beta\n"},
                           rappid=self.beta, identity_path="rappid.json", object_format="sha256"),
            self.component("rapp-1", "protocol", PROTOCOL, "c" * 40, {"SPEC.md": b"# synthetic spec\n"}),
        ]
        if kernel is not None:
            components.insert(0, self.kernel(kernel, kernel_commit))
        return {"schema": REG.MANIFEST_SCHEMA, "release_scope": scope, "components": components}

    def grail(self, scope=LTS_1, version="1.0.0", commit="1" * 40, declared="owner"):
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
        scope = scope or manifest["release_scope"]
        path = "releases/" + scope.rsplit("/acme/", 1)[1].replace("/", "-") + ".json"
        self.publish(RELEASES, commit, path, R.canonical(manifest).encode("utf-8"))
        return self.estate.declare({
            "type": "release-pin", "release_scope": scope, "channel": channel,
            "predecessor": predecessor, "manifest_hash": R.H("rapp/1:particle", manifest),
            "repository": RELEASES, "object_format": "sha1", "commit": commit, "path": path,
            "activated_utc": activated, "declared_by": self.estate.keys[declared],
        }, signer or declared)

    def load(self, extra, owner="owner", entries=None, **kwargs):
        base = entries if entries is not None else self.estate.base_entries(owner)
        document = self.estate.document(base + extra, owner=owner, signed=kwargs.pop("signed", True))
        return self.estate.load(document, owner=owner, **kwargs)

    def registry(self, extra):
        """(manifest, registry): a verified LTS_1 release with its grail-kernel."""
        manifest = self.manifest()
        status, reg, why = self.load([self.grail(), self.pin(manifest)] + extra)
        assert status == "verified", why
        return manifest, reg


def unsigned_pin(**changes):
    entry = {"type": "release-pin", "release_scope": LTS_1, "channel": "lts", "predecessor": None,
             "manifest_hash": "d" * 64, "repository": RELEASES, "object_format": "sha1",
             "commit": "3" * 40, "path": "releases/lts-1.json", "activated_utc": T0,
             "declared_by": R.mint_rappid("acme", "estate-owner", spki_der=b"synthetic"), "sig": "<sig>"}
    entry.update(changes)
    return entry


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
            "release_scope": ["http://releases.example.test/acme/lts/1", "https://", "https://a b", "", 7, None],
            "channel": ["", "LTS", "-lts", "lts-", "l_ts", "a" * 65, 5, None],
            "predecessor": ["", "lts", "http://releases.example.test/acme/lts/0", 7],
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
            {"predecessor": "https://releases.example.test/acme/lts/0"},
            {"channel": "a" * 64}, {"channel": "lts-2026"},
            {"path": "releases/\u00fcnic\u00f6de.json"},
        ]
        for changes in good:
            with self.subTest(changes=changes):
                self.assertEqual(REG.validate_entry(unsigned_pin(**changes)), "release-pin")

    def test_release_pin_is_a_declared_persisted_type(self):
        self.assertIn("release-pin", REG.DECLARED_TYPES)
        self.assertIn("release-pin", REG.PERSISTED_TYPES)
        self.assertEqual(REG.DECLARED_TYPES[0], "grail-kernel")


class ReleaseChannelTests(unittest.TestCase):
    """§13.3 scope uniqueness and §13.5 channels, decided by Registry(...) alone."""

    def setUp(self):
        self.estate = MockEstate()

    def registry(self, *pins):
        return REG.Registry(self.estate.base_entries() + list(pins))

    def test_a_linear_channel_has_one_head(self):
        reg = self.registry(
            unsigned_pin(),
            unsigned_pin(release_scope=NEWEST_1, channel="newest"),
            unsigned_pin(release_scope=LTS_2, predecessor=LTS_1, activated_utc=LATER),
            unsigned_pin(release_scope=LTS_3, predecessor=LTS_2, activated_utc=LATER),
        )
        self.assertEqual([e["release_scope"] for e in reg.release_channels["lts"]], [LTS_1, LTS_2, LTS_3])
        self.assertEqual(reg.channel_head("lts")["release_scope"], LTS_3)
        self.assertEqual(reg.channel_head("newest")["release_scope"], NEWEST_1)
        self.assertIsNone(reg.channel_head("unknown"))
        self.assertIsNone(reg.channel_head(["lts"]))
        self.assertEqual(reg.release_pin(LTS_2)["predecessor"], LTS_1)
        self.assertIsNone(reg.release_pin("https://releases.example.test/acme/none"))
        self.assertIsNone(reg.release_pin(None))
        self.assertEqual(REG.Registry(self.estate.base_entries()).release_channels, {})

    def test_release_scopes_are_never_rebound(self):
        with self.assertRaisesRegex(REG.RegistryError, "rebound"):
            self.registry(unsigned_pin(), unsigned_pin(channel="newest", manifest_hash="e" * 64))

    def test_a_grail_kernel_and_a_release_pin_share_their_scope(self):
        grail = self.estate.grail_kernel(scope=LTS_1)
        reg = REG.Registry(self.estate.base_entries() + [grail, unsigned_pin()])
        self.assertEqual(reg.release_pin(LTS_1)["release_scope"], grail["release_scope"])

    def test_equal_activation_is_not_a_regression(self):
        reg = self.registry(unsigned_pin(), unsigned_pin(release_scope=LTS_2, predecessor=LTS_1))
        self.assertEqual(reg.channel_head("lts")["release_scope"], LTS_2)

    def test_channel_structure_violations_refuse_the_registry(self):
        cases = {
            "fork": ([unsigned_pin(), unsigned_pin(release_scope=LTS_2, predecessor=LTS_1),
                      unsigned_pin(release_scope=LTS_3, predecessor=LTS_1)], "fork"),
            "two roots": ([unsigned_pin(), unsigned_pin(release_scope=LTS_2)], "exactly one first entry"),
            "forward link": ([unsigned_pin(release_scope=LTS_2, predecessor=LTS_1), unsigned_pin()],
                             "does not precede"),
            "self link": ([unsigned_pin(predecessor=LTS_1)], "does not precede"),
            "cycle": ([unsigned_pin(predecessor=LTS_2), unsigned_pin(release_scope=LTS_2, predecessor=LTS_1)],
                      "does not precede"),
            "unknown predecessor": ([unsigned_pin(), unsigned_pin(release_scope=LTS_2, predecessor=LTS_3)],
                                    "not the release_scope of any release-pin"),
            "cross-channel predecessor": ([unsigned_pin(), unsigned_pin(release_scope=NEWEST_1, channel="newest",
                                                                        predecessor=LTS_1)],
                                          "belongs to channel 'lts'"),
            "activation regression": ([unsigned_pin(activated_utc=LATER),
                                       unsigned_pin(release_scope=LTS_2, predecessor=LTS_1)],
                                      "activated before its predecessor"),
        }
        for label, (pins, message) in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(REG.RegistryError, message):
                    self.registry(*pins)

    def test_a_refused_channel_refuses_the_whole_document(self):
        world = World()
        manifest = world.manifest(kernel=None)
        fork = [world.pin(manifest), world.pin(world.manifest(LTS_2, kernel=None), predecessor=LTS_1),
                world.pin(world.manifest(LTS_3, kernel=None), predecessor=LTS_1)]
        self.assertEqual(world.load(fork)[0], "refused")
        self.assertEqual(world.load(fork[:2])[0], "verified")


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
                              ("path", "releases/other.json")):
            with self.subTest(member=member):
                entry = self.world.pin(self.manifest)
                entry[member] = value  # the document signature below is fresh; the entry's is not
                self.assertEqual(self.world.load([entry])[0], "refused")

    def test_owner_in_effect_at_activated_utc_across_rotation(self):
        estate = self.world.estate
        rotation = estate.reanchor("owner", "successor", signer="owner", utc="2026-07-15T00:00:00.000Z")
        base = estate.base_entries(owner="successor")
        before = self.world.pin(self.manifest, declared="owner", activated=T0)
        after_new = self.world.pin(self.world.manifest(NEWEST_1, kernel=None), channel="newest",
                                   declared="successor", activated=LATER)
        after_old = self.world.pin(self.world.manifest(NEWEST_1, kernel=None), channel="newest",
                                   declared="owner", activated=LATER)
        backdated = self.world.pin(self.world.manifest(NEWEST_1, kernel=None), channel="newest",
                                   declared="successor", activated=T0)

        def load(*entries):
            return self.world.load([rotation, *entries], owner="successor", entries=base)[0]

        self.assertEqual(load(before, after_new), "verified")
        self.assertEqual(load(after_old), "refused")
        self.assertEqual(load(backdated), "refused")

    def test_first_seen_skew_is_bounded_at_300_seconds(self):
        edge = self.world.pin(self.manifest, activated="2026-07-01T00:05:00.000Z")
        late = self.world.pin(self.manifest, activated="2026-07-01T00:05:00.001Z")
        self.assertEqual(self.world.load([edge], verification_utc=T0)[0], "verified")
        self.assertEqual(self.world.load([late], verification_utc=T0)[0], "refused")

    def test_persisted_release_pins_are_retained_byte_for_byte(self):
        pin = self.world.pin(self.manifest)
        persisted = [R._strict_json(R.canonical(pin))]
        successor = self.world.pin(self.world.manifest(LTS_2, kernel=None), predecessor=LTS_1, activated=LATER)
        self.assertEqual(self.world.load([pin, successor], persisted_entries=persisted)[0], "verified")
        self.assertEqual(self.world.load([], persisted_entries=persisted)[0], "refused")
        repointed = self.world.pin(self.world.manifest(LTS_1, kernel="1.0.1"))  # same scope, new manifest
        self.assertEqual(self.world.load([repointed], persisted_entries=persisted)[0], "refused")
        resigned = self.world.pin(self.manifest)  # identical members, a different signature
        self.assertNotEqual(resigned["sig"], pin["sig"])
        self.assertEqual(self.world.load([resigned], persisted_entries=persisted)[0], "refused")

    def test_an_exact_copy_verifies_apart_from_its_document(self):
        pin = self.world.pin(self.manifest)
        with self.world.estate.mocked():
            reg = REG.Registry(self.world.estate.base_entries() + [pin])
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
        self.refuses(lambda m: m.update(schema="rapp/1-release-manifest-v2"), "schema")
        self.refuses(lambda m: m.update(schema="rapp/1"), "schema")
        self.refuses(lambda m: m.update(release_scope="http://releases.example.test/acme/lts/1"), "release_scope")
        self.refuses(lambda m: m.update(release_scope=None), "release_scope")
        self.refuses(lambda m: m.update(components=[]), "non-empty")
        self.refuses(lambda m: m.update(components={}), "non-empty")

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
        self.octets = R.canonical(self.manifest).encode("utf-8")

    def test_exact_canonical_octets_verify(self):
        result = REG.verify_release_manifest(self.reg, LTS_1, self.octets)
        self.assertEqual(result, self.manifest)
        self.assertEqual(R.H("rapp/1:particle", result), self.reg.release_pin(LTS_1)["manifest_hash"])

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
                self.assertRaises(REG.RegistryError, REG.verify_release_manifest, self.reg, LTS_1, octets)
        with self.assertRaisesRegex(REG.RegistryError, "bytes"):
            REG.verify_release_manifest(self.reg, LTS_1, R.canonical(self.manifest))

    def test_a_manifest_that_is_not_the_pinned_one_is_refused(self):
        other = mutated(self.manifest, lambda m: m["components"][3]["files"][0].update(size_bytes=18))
        with self.assertRaisesRegex(REG.RegistryError, "manifest_hash"):
            REG.verify_release_manifest(self.reg, LTS_1, R.canonical(other).encode("utf-8"))

    def test_a_manifest_naming_another_scope_is_refused_even_when_pinned(self):
        foreign = self.world.manifest(LTS_2, kernel=None)
        pin = self.world.pin(foreign, scope=LTS_1)  # an entry for LTS_1 pinning LTS_2's manifest
        status, reg, why = self.world.load([pin])
        self.assertEqual(status, "verified", why)
        with self.assertRaisesRegex(REG.RegistryError, "different release_scope"):
            REG.verify_release_manifest(reg, LTS_1, R.canonical(foreign).encode("utf-8"))

    def test_an_unknown_scope_is_refused(self):
        with self.assertRaisesRegex(REG.RegistryError, "no release-pin"):
            REG.verify_release_manifest(self.reg, NEWEST_1, self.octets)

    def test_a_pinned_but_malformed_manifest_is_refused(self):
        broken = mutated(self.manifest, lambda m: m["components"].reverse())
        pin = self.world.pin(broken, scope=LTS_1)
        status, reg, _ = self.world.load([pin])
        self.assertEqual(status, "verified")
        with self.assertRaisesRegex(REG.RegistryError, "sorted ascending"):
            REG.verify_release_manifest(reg, LTS_1, R.canonical(broken).encode("utf-8"))


class KernelCoherenceTests(unittest.TestCase):
    """§13.5 kernel coherence, both directions and every field."""

    def setUp(self):
        self.world = World()
        self.manifest = self.world.manifest()
        self.with_grail = REG.Registry(self.world.estate.base_entries() + [self.world.grail()])
        self.without_grail = REG.Registry(self.world.estate.base_entries())

    def coherent(self, manifest, registry=None):
        return REG.check_kernel_coherence(registry or self.with_grail, manifest)

    def test_the_kernel_component_matches_the_scopes_grail(self):
        self.assertEqual(self.coherent(self.manifest), (True, "ok"))

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

    def test_another_scopes_grail_does_not_count(self):
        other_scope = REG.Registry(self.world.estate.base_entries() + [self.world.grail(scope=NEWEST_1)])
        self.assertFalse(self.coherent(self.manifest, other_scope)[0])

    def test_an_invalid_manifest_is_not_coherent(self):
        ok, why = self.coherent(mutated(self.manifest, lambda m: m.update(schema="other")))
        self.assertFalse(ok)
        self.assertIn("schema", why)

    def test_verification_enforces_coherence(self):
        world = World()
        manifest = world.manifest()
        status, reg, _ = world.load([world.pin(manifest)])  # no grail-kernel for LTS_1
        self.assertEqual(status, "verified")
        with self.assertRaisesRegex(REG.RegistryError, "needs a grail-kernel"):
            REG.verify_release_manifest(reg, LTS_1, R.canonical(manifest).encode("utf-8"))


class VerifiedSnapshotTests(unittest.TestCase):
    """§13.5 verified snapshots: exactly the pinned files, all or nothing."""

    def setUp(self):
        self.world = World()
        self.manifest, self.reg = self.world.registry([])
        self.world.calls.clear()

    def snapshot(self, fetch=None, registry=None, **kwargs):
        return REG.verify_snapshot(registry or self.reg, LTS_1, fetch or self.world.fetch, **kwargs)

    def test_the_snapshot_is_exactly_the_pinned_files(self):
        snapshot = self.snapshot()
        pin = self.reg.release_pin(LTS_1)
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
        pin = self.reg.release_pin(LTS_1)
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
        with self.assertRaisesRegex(REG.RegistryError, "no release-pin"):
            REG.verify_snapshot(self.reg, NEWEST_1, self.world.fetch)

    def rebind_identity(self, octets):
        """Re-pin LTS_1 with organism-alpha's identity file replaced by `octets`."""
        world = World()
        world.alpha = self.world.alpha
        manifest = world.manifest()
        alpha = manifest["components"][1]
        world.publish(ALPHA, alpha["commit"], "rappid.json", octets)
        alpha["files"] = file_list({"rappid.json": octets, "soul.md": b"# alpha\n"})
        status, reg, why = world.load([world.grail(), world.pin(manifest)])
        self.assertEqual(status, "verified", why)
        return lambda: REG.verify_snapshot(reg, LTS_1, world.fetch)

    def test_every_door_of_record_binding_is_checked(self):
        alpha = self.world.alpha
        cases = {
            "another rappid": (World.identity(self.world.beta), "rappid differs"),
            "a legacy schema": (R.canonical({"schema": "rapp/0", "rappid": alpha}).encode(), "schema"),
            "not an object": (R.canonical([alpha]).encode(), "JSON object"),
            "not JSON": (b"rappid = " + alpha.encode(), "§4 value"),
            "duplicate member": (b'{"rappid":"x","rappid":"' + alpha.encode() + b'"}', "§4 value"),
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
        pin = self.reg.release_pin(LTS_1)

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
            REG.verify_snapshot(reg, LTS_1, world.fetch)
        self.assertEqual(len(world.calls), 1)  # refused at the manifest, before any member file

    def test_a_component_without_files_contributes_nothing(self):
        world = World()
        manifest = world.manifest()
        manifest["components"][3]["files"] = []
        status, reg, _ = world.load([world.grail(), world.pin(manifest)])
        self.assertEqual(status, "verified")
        snapshot = REG.verify_snapshot(reg, LTS_1, world.fetch)
        self.assertEqual(len(snapshot), 7)
        self.assertNotIn("rapp-1", {cid for cid, _ in snapshot})
        self.assertNotIn(PROTOCOL, {call[0] for call in world.calls})


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
    """rapp_check.py lints a release manifest as structure and canonical bytes, never authority."""

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
            "ok": ("§13.5 release manifest structure OK (4 components; manifest_hash "
                   f"{R.H('rapp/1:particle', manifest)[:16]}…; authority requires a verified release-pin)"),
            "status": "unverified",
        }])

    def test_noncanonical_or_malformed_manifests_are_findings(self):
        manifest = World().manifest()
        unsorted = mutated(manifest, lambda m: m["components"].reverse())
        verdict, findings, evidence = C.check_repo(self.repository({
            "a/pretty.json": json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8"),
            "b/newline.json": R.canonical(manifest).encode("utf-8") + b"\n",
            "c/unsorted.json": R.canonical(unsorted).encode("utf-8"),
        }))
        self.assertEqual(verdict, "DRIFT")
        self.assertEqual(evidence, [])
        self.assertEqual({(f["artifact"], f["rule"]) for f in findings}, {
            ("a/pretty.json", "§13.5 release manifest"),
            ("b/newline.json", "§13.5 release manifest"),
            ("c/unsorted.json", "§13.5 release manifest"),
        })


@unittest.skipUnless(real_ed25519_signer(), "optional cryptography import is absent")
class RealSignatureReleasePinTests(unittest.TestCase):
    """The release-pin path through the real detached-JWS boundary (§10), no mocks."""

    def test_real_owner_signatures_bind_the_release_pin_and_its_snapshot(self):
        spki_der, sign = real_ed25519_signer()
        owner = R.mint_rappid("test", "estate-owner", spki_der=spki_der)
        world = World()
        manifest = world.manifest(kernel=None)
        pin = world.pin(manifest)
        pin = {k: v for k, v in pin.items() if k != "sig"}
        pin["declared_by"] = owner
        pin["sig"] = sign({k: v for k, v in pin.items() if k != "sig"}, owner)
        entries = [{"type": "estate_owner", "rappid": owner},
                   {"type": "spki", "rappid": owner, "deprecated": False,
                    "spki_der_b64": base64.b64encode(spki_der).decode("ascii")},
                   pin]

        def signed(members):
            doc = {"schema": "rapp/1-registry", "registry_seq": 1, "canonical_source": SOURCE,
                   "entries": members}
            doc["sig"] = sign(doc, owner)
            return doc

        status, reg, why = REG.load_document(signed(entries), trust_anchor=owner)
        self.assertEqual((status, why), ("verified", "ok"))
        self.assertEqual(len(REG.verify_snapshot(reg, LTS_1, world.fetch)), 5)
        repointed = copy.deepcopy(entries)
        repointed[2]["manifest_hash"] = "e" * 64  # a valid document signature cannot bless it
        self.assertEqual(REG.load_document(signed(repointed), trust_anchor=owner)[0], "refused")


if __name__ == "__main__":
    unittest.main()
