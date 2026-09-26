#!/usr/bin/env python3
"""make_vectors.py — emit conformance/vectors.json, the language-neutral known-answer vectors
an implementer in any language runs to claim rapp/1 conformance, and
conformance/registry-vectors.json, the §13 registry vectors. Every answer is derived from
rapp.py (and, for the registry file, rapp_registry.py); CI re-derives and diffs, so neither
file can drift from the reference.

  python3 conformance/make_vectors.py            # write both files
  python3 conformance/make_vectors.py --check    # exit 1 if a committed file differs
"""
import base64, copy, hashlib, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import rapp as R
import rapp_registry as REG

def vectors():
    v = {"schema": "rapp/1-conformance-vectors", "derived_from": "rapp.py", "sections": {}}
    # §4 canonical form — the bytes every implementation must produce
    canon_cases = [
        {"b": 1, "a": [3, 2], "c": {"y": 1, "x": 2}},
        {"z": None, "t": True, "f": False, "n": 0},
        {"unicode": "héllo — 日本 🐍", "escapes": "line\nbreak \"quoted\" \\ back /"},
        {"num": [0, 1, -1, 9007199254740991, -9007199254740991, 4294967296]},
        {"nested": {"deep": {"deeper": [[], {}, [{}]]}}},
        {"é": 1, "é": 2, "a": 3, "B": 4, "b": 5, "aa": 6, "a-b": 7},
        [],
        {},
        "just a string",
        42,
    ]
    v["sections"]["4_canonical"] = [{"value": c, "canonical": R.canonical(c)} for c in canon_cases]
    # §4 input-domain refusals: these MUST be refused, never repaired
    v["sections"]["4_refuse"] = [
        {"json_text": '{"a":1,"a":2}', "why": "duplicate member name"},
        {"json_text": '{"n": 9007199254740993}', "why": "integer does not survive binary64 round-trip"},
        {"json_text": '{"n": 1e999}', "why": "non-finite after parse"},
        {"json_text": '"\\ud800"', "why": "unpaired UTF-16 surrogate"},
    ]
    # §5 domain-separated hashing
    val = {"x": 1}
    v["sections"]["5_hash"] = {
        "value": val,
        "H": {space: R.H(space, val) for space in ["rapp/1:particle", "rapp/1:wave", "rapp/1:egg-manifest"]},
        "Hb": {"rapp/1:egg": R.Hb("rapp/1:egg", b"raw octets\x00\xff"), "rapp/1:rappid": R.Hb("rapp/1:rappid", b"\x30\x2a fake-spki")},
        "rule": "H(space,v) = hex(sha256(utf8(space) || 0x0A || canonical(v))); Hb likewise over raw octets",
    }
    # §6.1 rappid grammar
    good = "rappid:@kody-w/rapp-1-anchor:a4298c417789ecff68b7be3df4d8b90d397c43f972eaf839977db16dbe02acc6"
    bad = [
        "rappid:@Kody/x:" + "a" * 64, "rappid:@kody/x:" + "A" * 64, "rappid:@kody/x:" + "a" * 63,
        "rappid:@kody//x:" + "a" * 64, "rappid:@-kody/x:" + "a" * 64, "rappid:@kody--w/x:" + "a" * 64,
        "rappid:@" + "a" * 40 + "/x:" + "a" * 64, "rappid:@kody/" + "a" * 101 + ":" + "a" * 64,
        "rappid:v2:kody/x:" + "a" * 64, "rappid:x:" + "a" * 64, "a" * 64,
    ]
    v["sections"]["6_rappid"] = {"valid": [good], "invalid": bad,
                                 "keyed_mint": {"spki_der_hex": b"\x30\x2a fake-spki".hex(),
                                                "rappid": R.mint_rappid("kody", "twin", spki_der=b"\x30\x2a fake-spki")}}
    # §7 frames: a verified chain, then every single-field tamper with the step that must catch it
    sid = "rappid:@kody/twin:" + "a" * 64
    g = R.build_frame("body.pulse", sid, 0, "2026-07-15T00:00:00.000Z", {"hello": "world"}, prev=None)
    c = R.build_frame("body.pulse", sid, 1, "2026-07-15T00:00:01.000Z", {"n": 2}, prev=g["payload_hash"])
    tampers = []
    def tamper(label, frame, head, sid_of_record, mutate):
        t = json.loads(json.dumps(frame)); mutate(t)
        ok, step, why = R.verify_frame(t, head=head, stream_id_of_record=sid_of_record)
        assert not ok, label
        tampers.append({"label": label, "frame": t, "head": head, "stream_id_of_record": sid_of_record, "expect_step": step})
    tamper("payload changed", g, None, sid, lambda t: t.update(payload={"hello": "evil"}))
    tamper("utc changed", g, None, sid, lambda t: t.update(utc="2099-01-01T00:00:00.000Z"))
    tamper("kind grammar", g, None, sid, lambda t: t.update(kind="Body.Pulse"))
    tamper("twelfth key", g, None, sid, lambda t: t.update(extra=1))
    tamper("spec token", g, None, sid, lambda t: t.update(spec="rapp/2"))
    tamper("cross-stream replay", g, None, "rappid:@kody/other:" + "b" * 64, lambda t: None)
    tamper("genesis with prev", g, None, sid, lambda t: t.update(prev="f" * 64))
    tamper("child prev broken", c, g, sid, lambda t: t.update(prev="f" * 64))
    tamper("child seq skipped", c, g, sid, lambda t: t.update(seq=2))
    tamper("child utc before head", c, g, sid, lambda t: t.update(utc="2026-07-14T00:00:00.000Z"))
    tamper("prev_wave off swarm", c, g, sid, lambda t: t.update(prev_wave=g["frame_hash"]))
    v["sections"]["7_frame"] = {"stream_id": sid, "genesis": g, "child": c, "tampers": tampers,
                                "note": "tampered frames keep their original hashes on purpose; the verifier must recompute"}
    # §9 egg address known answer (JSON variant, no packed files)
    egg = R.pack_egg("session", sid, "2026-07-15T00:00:00.000Z", payload={"runtime": "test", "transcript": []})
    read = R.read_egg(egg)
    manifest = read[0] if isinstance(read, tuple) else read
    v["sections"]["9_egg"] = {"variant": "session", "egg_octets_hex": egg.hex(), "manifest": manifest,
                              "egg_address": R.egg_address(manifest),
                              "note": "a session egg is a JSON object; two conformant packers emit these exact octets"}
    v["reference_limits"] = [
        "rapp.py refuses non-integer JSON numbers rather than implementing full JCS number serialization; "
        "an implementation that does implement RFC 8785 numbers is more complete, not less conformant. "
        "Vectors therefore use integers only."
    ]
    return v

# ---------------------------------------------------------------------------------------
# §13 registry vectors. Signatures are opaque placeholders: these vectors fix the exact
# structural, uniqueness, and chain rules and the bytes that get signed; an implementation
# proves its §10/§13.4 signature checks with its own keys (the reference's are in
# test_registry_*.py and registry_conformance.py).
SIG = "<detached-jws>"
T0 = "2026-07-01T00:00:00.000Z"
LATER = "2026-08-01T00:00:00.000Z"
SOURCE = "https://registry.example.test/rapp-registry.json"


def _estate():
    der = b"vector-only SPKI bytes: a fingerprint, not a key"
    owner = R.mint_rappid("vector", "estate-owner", spki_der=der)
    return owner, [
        {"type": "estate_owner", "rappid": owner},
        {"type": "spki", "rappid": owner, "deprecated": False,
         "spki_der_b64": base64.b64encode(der).decode("ascii")},
    ]


def _registry_accepts(document):
    try:
        REG.validate_document(document)
        R.canonical(document)
        REG.Registry(document["entries"])
        return "accept"
    except (REG.RegistryError, ValueError):
        return "refuse"


def _grail(owner, scope="https://releases.example.test/scope/lts"):
    return {"type": "grail-kernel", "release_scope": scope,
            "grail_id": "grail:" + R.Hb("rapp/1:grail", b"vector kernel bytes"),
            "repository": "https://git.example.test/estate/kernel",
            "immutable_ref": "refs/tags/kernel-v1", "object_format": "sha1",
            "commit": "1" * 40, "path": "kernel/brainstem.py", "mode": "100644",
            "blob": "2" * 40, "sha256": "a" * 64, "size_bytes": 1024,
            "activated_utc": T0, "predecessor": None, "declared_by": owner, "sig": SIG}


# §13.5 release families: a release scope names one family, bound to at most one kernel forever, and
# each immutable release of a family is one release-pin naming its manifest by manifest_hash.
LTS = "https://releases.example.test/vector/1.0"    # the family of kernel 1.0.0-lts; channel lts
NEW_2 = "https://releases.example.test/vector/2.0"  # a family of channel newest
NEW_3 = "https://releases.example.test/vector/3.0"  # the family channel newest moves on to
GIT = "https://git.example.test/vector/"
KERNEL_FILES = {
    "kernel/VERSION": b"1.0.0-lts\n",
    "kernel/agents/basic_agent.py": b'class BasicAgent:\n    """Synthetic kernel companion."""\n',
    "kernel/brainstem.py": b'"""Synthetic kernel entry point."""\n',
}


def _keyless(slug, n):
    """A reproducible keyless rappid: the §6.2 mint over a fixed UUIDv4, for vectors only."""
    return f"rappid:@vector/{slug}:" + R.Hb("rapp/1:rappid", bytes.fromhex("00000000000040008000%012x" % n))


def _pins(files):
    return [{"path": path, "sha256": hashlib.sha256(octets).hexdigest(), "size_bytes": len(octets)}
            for path, octets in sorted(files.items(), key=lambda item: item[0].encode("utf-8"))]


def _component(cid, kind, repo, commit, files, rappid=None, identity_path=None, immutable_ref=None,
               object_format="sha1"):
    return {"id": cid, "kind": kind, "rappid": rappid, "identity_path": identity_path,
            "repository": GIT + repo, "object_format": object_format, "commit": commit,
            "immutable_ref": immutable_ref, "files": _pins(files)}


def _kernel_component():
    return _component("brainstem", "kernel", "brainstem", "1" * 40, KERNEL_FILES,
                      immutable_ref="refs/tags/brainstem-v1.0.0-lts")


def _release_files(fix=0):
    """The component files of one release; a correction (`fix` > 0) changes organism-alpha only."""
    alpha, beta = _keyless("organism-alpha", 1), _keyless("organism-beta", 2)
    soul = b"# organism alpha\n" if not fix else b"# organism alpha, correction %d\n" % fix
    return alpha, beta, {
        "brainstem": KERNEL_FILES,
        "organism-alpha": {"rappid.json": R.canonical({"rappid": alpha, "schema": "rapp/1"}).encode(),
                           "soul.md": soul},
        "organism-beta": {"agents/beta_agent.py": b"# organism beta agent\n",
                          "rappid.json": R.canonical({"rappid": beta, "schema": "rapp/1"}).encode()},
        "rapp-1": {"SPEC.md": b"# Synthetic protocol text\n"},
    }


def _release_manifest(scope=LTS, compact=False, fix=0):
    """One release of the family `scope`, named for people `vector-<family>.<fix>` (plus `-compact`
    for the three-component variant the manifest and octets cases mutate)."""
    alpha, beta, files = _release_files(fix)
    alpha_commit = "5" * 40 if not fix else ("5%x" % fix) * 20
    components = [
        _component("organism-alpha", "organism", "alpha", alpha_commit, files["organism-alpha"],
                   rappid=alpha, identity_path="rappid.json"),
        _component("rapp-1", "protocol", "protocol", "4" * 40, files["rapp-1"],
                   immutable_ref="refs/tags/rev-17"),
    ]
    if not compact:
        components[1:1] = [_component("organism-beta", "organism", "beta", "6" * 64, files["organism-beta"],
                                      rappid=beta, identity_path="rappid.json", object_format="sha256")]
        components.insert(0, _kernel_component())
    name = "vector-%s.%d%s" % (scope.rsplit("/", 1)[1], fix, "-compact" if compact else "")
    return {"schema": REG.MANIFEST_SCHEMA, "release_scope": scope, "release": name, "components": components}


def _release_grail(owner, scope=LTS):
    kernel = KERNEL_FILES["kernel/brainstem.py"]
    return {"type": "grail-kernel", "release_scope": scope,
            "grail_id": "grail:" + R.Hb("rapp/1:grail", kernel), "repository": GIT + "brainstem",
            "immutable_ref": "refs/tags/brainstem-v1.0.0-lts", "object_format": "sha1",
            "commit": "1" * 40, "path": "kernel/brainstem.py", "mode": "100644", "blob": "2" * 40,
            "sha256": hashlib.sha256(kernel).hexdigest(), "size_bytes": len(kernel),
            "activated_utc": T0, "predecessor": None, "declared_by": owner, "sig": SIG}


def _placeholder(n):
    """The manifest_hash of placeholder release `n`; entry cases pin no real manifest."""
    return hashlib.sha256(b"vector release %d" % n).hexdigest()


def _release_pin(owner, scope, manifest_hash, **changes):
    """One release-pin of the family `scope`; `changes` replace members, and `_DROP` removes one."""
    entry = {"type": "release-pin", "release_scope": scope, "channel": "lts", "predecessor": None,
             "manifest_hash": manifest_hash, "repository": GIT + "releases", "object_format": "sha1",
             "commit": "3" * 40, "path": f"releases/{manifest_hash}.json", "activated_utc": T0,
             "declared_by": owner, "sig": SIG}
    entry.update(changes)
    return {k: v for k, v in entry.items() if v is not _DROP}


def _changed(value, change):
    value = copy.deepcopy(value)
    change(value)
    return value


def _verdict(decide):
    try:
        return "accept" if decide() else "refuse"
    except (REG.RegistryError, ValueError):
        return "refuse"


def registry_sections():
    """Ordered (name, builder) pairs; each change to §13 appends its own section."""
    owner, base = _estate()

    def rehearsal(entries):
        """A registry of these entries as load_document returns an unsigned draft (vectors carry
        placeholder signatures); answers that need a verified registry are asked with allow_draft."""
        status, registry, why = REG.load_document(
            {"schema": "rapp/1-registry", "registry_seq": 1, "canonical_source": SOURCE, "entries": entries,
             "sig": None}, trust_anchor=owner, allow_unsigned=True)
        if status != "draft":
            raise REG.RegistryError(why)
        return registry

    def document(members, **changes):
        value = {"schema": "rapp/1-registry", "registry_seq": 1, "canonical_source": SOURCE,
                 "entries": members, "sig": SIG}
        value.update(changes)
        return {k: v for k, v in value.items() if v is not _DROP}

    def pin(spec_hash, deprecated):
        return {"type": "protocol", "name": "example-profile/1", "spec_repo": "https://git.example.test/spec",
                "spec_path": "SPEC.md", "spec_hash": spec_hash, "deprecated": deprecated}

    def document_cases():
        too_deep = "x"
        for _ in range(64):  # with the document and its member, 66 levels: §4 allows 64
            too_deep = [too_deep]
        cases = [
            ("the five-member container", document(base)),
            ("unsigned draft container (sig null)", document(base, sig=None)),
            ("other top-level members carry no meaning", document(base, estate="vector", published_utc=T0)),
            ("missing canonical_source", document(base, canonical_source=_DROP)),
            ("non-HTTPS canonical_source", document(base, canonical_source="http://registry.example.test/r.json")),
            ("canonical_source with an empty host", document(base, canonical_source="https:///rapp-registry.json")),
            ("canonical_source with user information",
             document(base, canonical_source="https://user@registry.example.test/r.json")),
            ("canonical_source with a port and a query",
             document(base, canonical_source="https://registry.example.test:8443/r.json?v=1")),
            ("canonical_source with a fragment (an absolute URI has none)",
             document(base, canonical_source="https://registry.example.test/r.json#top")),
            ("canonical_source a URN, as for a private Hive's registry history",
             document(base, canonical_source="urn:rapp:private-hive:" + "ab" * 32 + ":registry-history")),
            ("canonical_source a URN with a one-character namespace",
             document(base, canonical_source="urn:x:registry")),
            ("canonical_source with a signed port", document(base, canonical_source="https://registry.example.test:+443/r.json")),
            ("canonical_source with an IP literal that is not an IPv6 address",
             document(base, canonical_source="https://[zz]/r.json")),
            ("canonical_source with a bracket outside an IP literal",
             document(base, canonical_source="https://registry.example.test/a[b].json")),
            ("an entry of a type this reference does not implement is ignored",
             document(base + [{"type": "vector-future", "note": "grants nothing"}])),
            ("an unknown entry type with critical false is ignored",
             document(base + [{"type": "vector-future", "critical": False}])),
            ("an unknown entry type marked critical refuses the registry",
             document(base + [{"type": "vector-future", "critical": True}])),
            ("an unknown entry type whose critical is not false refuses the registry",
             document(base + [{"type": "vector-future", "critical": "no"}])),
            ("a known entry type may not carry critical",
             document([base[0], dict(base[1], critical=False)])),
            ("canonical_source with a character RFC 3986 does not allow",
             document(base, canonical_source="https://registry.example.test/<r>.json")),
            ("canonical_source with a port that is not a number",
             document(base, canonical_source="https://registry.example.test:port/r.json")),
            ("an extra member nested deeper than §4 allows", document(base, note=too_deep)),
            ("entries under another member name", {**document(base, entries=_DROP), "items": base}),
            ("entries is not an array", document(base, entries={})),
            ("missing sig member", document(base, sig=_DROP)),
            ("registry_seq beyond uint53", document(base, registry_seq=2**53)),
            ("a deprecated pin followed by the current one",
             document(base + [pin("b" * 64, True), pin("c" * 64, False)])),
        ]
        out = []
        for label, doc in cases:
            case = {"label": label, "expect": _registry_accepts(doc)}
            try:
                R._strict_json(R.canonical(doc))
                case["document"] = doc
            except ValueError:
                # Not I-JSON, or nested beyond §4's depth: carried as text, like 4_refuse, so this file
                # stays strict I-JSON within §4's limits.
                case["json_text"] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
            out.append(case)
        return out

    def declared_cases():
        entry = _grail(owner)
        unsigned = {k: v for k, v in entry.items() if k != "sig"}
        return {
            "declared_types": list(REG.DECLARED_TYPES),
            "persisted_types": list(REG.PERSISTED_TYPES),
            "first_seen_skew_seconds": REG.FIRST_SEEN_SKEW_SECONDS,
            "example": {
                "entry": entry,
                "signing_payload": R.canonical(unsigned),
                "entry_hash": REG.entry_hash(entry),
                "rule": "sig = detached JWS (kid == declared_by == owner in effect at activated_utc) "
                        "over canonical(entry \\ {sig}); entry_hash = H('rapp/1:particle', entry) with sig",
            },
        }

    def release_pin_cases():
        alpha, _, files = _release_files()
        manifest, compact = _release_manifest(), _release_manifest(compact=True)
        octets = R.canonical(manifest).encode("utf-8")
        grail = _release_grail(owner)
        pin = _release_pin(owner, LTS, R.H("rapp/1:particle", manifest))
        correction = _release_manifest(fix=1)
        correction_pin = _release_pin(owner, LTS, R.H("rapp/1:particle", correction),
                                      predecessor=pin["manifest_hash"], activated_utc=LATER)
        assert correction["components"][0] == manifest["components"][0]  # a correction keeps the kernel
        pinned_registry = rehearsal(base + [grail, pin, correction_pin])
        assert REG.verify_release_manifest(pinned_registry, pin, octets, allow_draft=True) == manifest
        assert REG.verify_release_manifest(
            pinned_registry, correction_pin, R.canonical(correction).encode("utf-8"), allow_draft=True) == correction

        def order(registry):
            """Each channel's and each family's releases in chain order; the last is current."""
            def hashes(chains):
                return {key: [e["manifest_hash"] for e in chain] for key, chain in sorted(chains.items())}
            return hashes(registry.release_channels), hashes(registry.release_families)

        def manifest_case(label, change, intended):
            value = _changed(compact, change)
            expect = _verdict(lambda: REG.validate_release_manifest(value))
            assert expect == intended, label
            try:
                R.canonical(value)
                return {"label": label, "manifest": value, "expect": expect}
            except ValueError:
                # Not a §4 value (an integer beyond 2^53-1): carried as text so this file stays I-JSON.
                return {"label": label, "json_text": json.dumps(value, sort_keys=True, separators=(",", ":")),
                        "expect": expect}

        def component(index, **changes):
            return lambda m: m["components"][index].update(changes)

        def first_file(**changes):
            return lambda m: m["components"][1]["files"][0].update(changes)

        def paths(*names):
            return component(1, files=[{"path": name, "sha256": "e" * 64, "size_bytes": 1} for name in names])

        manifest_cases = [
            manifest_case("a door-of-record organism and a protocol component", lambda m: None, "accept"),
            manifest_case("a component that pins only a commit (files [])", component(1, files=[]), "accept"),
            manifest_case("object_format sha256 with a 64-hex commit",
                          component(1, object_format="sha256", commit="4" * 64), "accept"),
            manifest_case("a release name of 64 characters with capitals, dots, dashes, and underscores",
                          lambda m: m.update(release="LTS-2026.09_" + "x" * 52), "accept"),
            manifest_case("an extra top-level member", lambda m: m.update(note="x"), "refuse"),
            manifest_case("no release member", lambda m: m.pop("release"), "refuse"),
            manifest_case("an empty release name", lambda m: m.update(release=""), "refuse"),
            manifest_case("a release name of 65 characters", lambda m: m.update(release="r" * 65), "refuse"),
            manifest_case("a release name beginning with a dot", lambda m: m.update(release=".lts-2026.09"),
                          "refuse"),
            manifest_case("a release name with a space", lambda m: m.update(release="lts 2026.09"), "refuse"),
            manifest_case("a release name outside ASCII", lambda m: m.update(release="lts-2026.09-\u00e9"),
                          "refuse"),
            manifest_case("a release name that is not a string", lambda m: m.update(release=202609), "refuse"),
            manifest_case("another schema", lambda m: m.update(schema="rapp/1-release-manifest-v2"), "refuse"),
            manifest_case("a release_scope that is not an absolute HTTPS URI",
                          lambda m: m.update(release_scope="http://releases.example.test/vector/1.0"), "refuse"),
            manifest_case("no components", lambda m: m.update(components=[]), "refuse"),
            manifest_case("components out of id order", lambda m: m["components"].reverse(), "refuse"),
            manifest_case("a duplicate component id",
                          lambda m: m["components"].append(copy.deepcopy(m["components"][1])), "refuse"),
            manifest_case("an id that is not an lclabel", component(1, id="Rapp_1"), "refuse"),
            manifest_case("an id of 101 characters", component(1, id="r" * 101), "refuse"),
            manifest_case("a kind of 65 characters", component(1, kind="k" * 65), "refuse"),
            manifest_case("a commit of the wrong length for its object_format", component(1, commit="4" * 64),
                          "refuse"),
            manifest_case("an immutable_ref that is not a full refs/tags/ name",
                          component(1, immutable_ref="rev-17"), "refuse"),
            manifest_case("a file with an extra member", first_file(mode="100644"), "refuse"),
            manifest_case("a path outside the §9.1 grammar (a reserved device name)", paths("docs/CON.md"),
                          "refuse"),
            manifest_case("files out of UTF-8 byte order", paths("b.md", "a.md"), "refuse"),
            manifest_case("two paths equal case-insensitively", paths("README.md", "readme.md"), "refuse"),
            manifest_case("a file that is also a directory above another", paths("docs", "docs/index.md"),
                          "refuse"),
            manifest_case("a size_bytes beyond uint53", first_file(size_bytes=2**53), "refuse"),
            manifest_case("a sha256 that is not 64 lowercase hex", first_file(sha256="E" * 64), "refuse"),
            manifest_case("a rappid without its identity_path", component(0, identity_path=None), "refuse"),
            manifest_case("an identity_path that is not one of the component's files",
                          component(0, identity_path="identity.json"), "refuse"),
            manifest_case("one rappid bound by two components", component(1, rappid=alpha, identity_path="SPEC.md"),
                          "refuse"),
        ]

        def octets_case(label, entries, manifest_hash, data, intended):
            def decide():
                registry = rehearsal(entries)
                return REG.verify_release_manifest(registry, registry.release_pin(manifest_hash), data,
                                                   allow_draft=True)
            expect = _verdict(decide)
            assert expect == intended, label
            return {"label": label, "entries": entries, "manifest_hash": manifest_hash, "octets_hex": data.hex(),
                    "expect": expect}

        compact_hash = R.H("rapp/1:particle", compact)
        compact_octets = R.canonical(compact).encode("utf-8")
        compact_fix = _release_manifest(compact=True, fix=1)
        pinned = base + [_release_pin(owner, LTS, compact_hash)]
        corrected = pinned + [_release_pin(owner, LTS, R.H("rapp/1:particle", compact_fix),
                                           predecessor=compact_hash, activated_utc=LATER)]
        foreign = _release_manifest(NEW_2, compact=True)
        other = _changed(compact, component(1, commit="7" * 40))
        octets_cases = [
            octets_case("exactly canonical(manifest)", pinned, compact_hash, compact_octets, "accept"),
            octets_case("pretty-printed", pinned, compact_hash,
                        json.dumps(compact, indent=2, sort_keys=True).encode("utf-8"), "refuse"),
            octets_case("a trailing line terminator", pinned, compact_hash, compact_octets + b"\n", "refuse"),
            octets_case("a UTF-8 byte-order mark", pinned, compact_hash, b"\xef\xbb\xbf" + compact_octets,
                        "refuse"),
            octets_case("the canonical bytes of a manifest other than the pinned one", pinned, compact_hash,
                        R.canonical(other).encode("utf-8"), "refuse"),
            octets_case("the pinned manifest names another release_scope",
                        base + [_release_pin(owner, LTS, R.H("rapp/1:particle", foreign))],
                        R.H("rapp/1:particle", foreign), R.canonical(foreign).encode("utf-8"), "refuse"),
            octets_case("no release-pin pins the manifest_hash", base, compact_hash, compact_octets, "refuse"),
            octets_case("an earlier release of the family, selected by its manifest_hash after a correction",
                        corrected, compact_hash, compact_octets, "accept"),
            octets_case("the correction's octets for the earlier release's manifest_hash", corrected, compact_hash,
                        R.canonical(compact_fix).encode("utf-8"), "refuse"),
        ]

        def entry_case(label, entries, intended):
            entries = base + entries
            expect = _verdict(lambda: REG.Registry(entries))
            assert expect == intended, label
            channels = families = None
            if expect == "accept":
                channels, families = order(REG.Registry(entries))
            return {"label": label, "entries": entries, "expect": expect, "channels": channels,
                    "families": families}

        def rp(n, scope=LTS, after=None, **changes):
            changes.setdefault("predecessor", None if after is None else _placeholder(after))
            return _release_pin(owner, scope, _placeholder(n), **changes)

        newest = {"channel": "newest"}
        entry_cases = [
            entry_case("an lts family with two corrections beside a newest channel",
                       [rp(1), rp(4, NEW_2, **newest), rp(2, after=1, activated_utc=LATER),
                        rp(3, after=2, activated_utc=LATER)], "accept"),
            entry_case("a newest channel moving on from one family to the next",
                       [rp(4, NEW_2, **newest), rp(5, NEW_2, after=4, **newest),
                        rp(6, NEW_3, after=5, activated_utc=LATER, **newest)], "accept"),
            entry_case("a newest channel returning to an earlier family",
                       [rp(4, NEW_2, **newest), rp(6, NEW_3, after=4, activated_utc=LATER, **newest),
                        rp(5, NEW_2, after=6, activated_utc=LATER, **newest)], "accept"),
            entry_case("equal activation times in one channel", [rp(1), rp(2, after=1)], "accept"),
            entry_case("a family's grail-kernel before its first release", [grail, rp(1), rp(2, after=1)],
                       "accept"),
            entry_case("a grail-kernel for a family that has no release yet", [rp(1), _grail(owner, NEW_2)],
                       "accept"),
            entry_case("one release pinned twice, as its own correction", [rp(1), rp(1, after=1)], "refuse"),
            entry_case("one manifest_hash pinned by two families", [rp(1), rp(1, NEW_2, **newest)], "refuse"),
            entry_case("one family in two channels", [rp(1), rp(2, **newest)], "refuse"),
            entry_case("a fork: two releases follow one release", [rp(1), rp(2, after=1), rp(3, after=1)],
                       "refuse"),
            entry_case("two first releases in one channel", [rp(1), rp(2)], "refuse"),
            entry_case("a predecessor appended after its successor", [rp(2, after=1), rp(1)], "refuse"),
            entry_case("a predecessor that is a release of another channel",
                       [rp(1), rp(4, NEW_2, after=1, **newest)], "refuse"),
            entry_case("a predecessor that no release-pin's manifest_hash names", [rp(1), rp(2, after=3)],
                       "refuse"),
            entry_case("a predecessor that names a release_scope, not a manifest_hash",
                       [rp(1), rp(2, predecessor=LTS)], "refuse"),
            entry_case("a successor activated before its predecessor",
                       [rp(1, activated_utc=LATER), rp(2, after=1)], "refuse"),
            entry_case("a grail-kernel after its family's first release", [rp(1), grail], "refuse"),
            entry_case("a grail-kernel between two releases of its family", [rp(1), grail, rp(2, after=1)],
                       "refuse"),
            entry_case("a channel that is not an lclabel", [rp(1, channel="LTS")], "refuse"),
            entry_case("a path outside the §9.1 grammar", [rp(1, path="releases/lts:1.json")], "refuse"),
            entry_case("a commit of the wrong length for object_format", [rp(1, object_format="sha256")],
                       "refuse"),
            entry_case("an extra member", [rp(1, deprecated=False)], "refuse"),
            entry_case("a missing member", [rp(1, predecessor=_DROP)], "refuse"),
        ]

        def history_case(label, persisted, entries, intended):
            """A later registry judged against what a consumer accepted before (§13.4, §13.5)."""
            entries = base + entries
            expect = _verdict(lambda: REG.Registry(entries).check_retained(persisted)[0])
            assert expect == intended, label
            return {"label": label, "persisted": persisted, "entries": entries, "expect": expect}

        other_kernel = _grail(owner, NEW_2)
        history_cases = [
            history_case("a correction appended after the accepted release", [rp(1)],
                         [rp(1), rp(2, after=1, activated_utc=LATER)], "accept"),
            history_case("the accepted kernel and release retained, and a correction appended", [grail, rp(1)],
                         [grail, rp(1), rp(2, after=1, activated_utc=LATER)], "accept"),
            history_case("a grail-kernel for a family with no accepted release", [rp(1)],
                         [rp(1), other_kernel, rp(4, NEW_2, **newest)], "accept"),
            history_case("a grail-kernel inserted ahead of an accepted release of its family", [rp(1)],
                         [grail, rp(1)], "refuse"),
            history_case("a grail-kernel appended after an accepted release of its family", [rp(1)],
                         [rp(1), grail], "refuse"),
            history_case("an accepted release dropped", [rp(1)], [], "refuse"),
            history_case("an accepted release moved to another locator", [rp(1)], [rp(1, commit="4" * 40)],
                         "refuse"),
            history_case("an accepted kernel dropped", [grail, rp(1)], [rp(1)], "refuse"),
        ]

        kernel_only = {"schema": REG.MANIFEST_SCHEMA, "release_scope": LTS, "release": "vector-1.0.0-kernel",
                       "components": [_kernel_component()]}
        assert kernel_only["components"][0]["files"][2]["path"] == grail["path"]

        def coherence_case(label, with_grail, value, intended):
            entries = base + ([grail] if with_grail else [])
            expect = _verdict(lambda: REG.check_kernel_coherence(REG.Registry(entries), value)[0])
            assert expect == intended, label
            return {"label": label, "grail_kernel": grail if with_grail else None, "manifest": value,
                    "expect": expect}

        def kernel(**changes):
            return _changed(kernel_only, lambda m: m["components"][0].update(changes))

        def entry_point(**changes):
            return _changed(kernel_only, lambda m: m["components"][0]["files"][2].update(changes))

        second_kernel = _changed(kernel_only, lambda m: m["components"].append(
            dict(copy.deepcopy(m["components"][0]), id="brainstem-copy")))
        coherence_cases = [
            coherence_case("the kernel component equals the family's grail-kernel", True, kernel_only, "accept"),
            coherence_case("neither a grail-kernel nor a kernel component", False, compact, "accept"),
            coherence_case("a grail-kernel but no kernel component", True, compact, "refuse"),
            coherence_case("two kernel components", True, second_kernel, "refuse"),
            coherence_case("another repository", True, kernel(repository=GIT + "mirror"), "refuse"),
            coherence_case("the same repository spelled another way", True,
                           kernel(repository=GIT + "brainstem.git"), "refuse"),
            coherence_case("another object_format", True, kernel(object_format="sha256", commit="1" * 64), "refuse"),
            coherence_case("another commit", True, kernel(commit="9" * 40), "refuse"),
            coherence_case("another immutable_ref", True, kernel(immutable_ref="refs/tags/brainstem-v1.0.1-lts"),
                           "refuse"),
            coherence_case("no immutable_ref", True, kernel(immutable_ref=None), "refuse"),
            coherence_case("the grail-kernel path is not pinned", True, entry_point(path="kernel/main.py"), "refuse"),
            coherence_case("the grail-kernel path pinned with other bytes", True, entry_point(sha256="e" * 64),
                           "refuse"),
            coherence_case("the grail-kernel path pinned with another length", True, entry_point(size_bytes=1),
                           "refuse"),
            coherence_case("a kernel component without a grail-kernel for its family", False, kernel_only,
                           "refuse"),
        ]

        unsigned_pin = {k: v for k, v in pin.items() if k != "sig"}
        channels, families = order(pinned_registry)
        return {
            "manifest_schema": REG.MANIFEST_SCHEMA,
            "example": {
                "manifest": manifest,
                "canonical": R.canonical(manifest),
                "manifest_hash": R.H("rapp/1:particle", manifest),
                "raw_sha256": hashlib.sha256(octets).hexdigest(),
                "files": [{"component": c["id"], "path": f["path"],
                           "octets_utf8": files[c["id"]][f["path"]].decode("utf-8")}
                          for c in manifest["components"] for f in c["files"]],
                "grail_kernel": grail,
                "release_pin": pin,
                "release_pin_signing_payload": R.canonical(unsigned_pin),
                "release_pin_entry_hash": REG.entry_hash(pin),
                "correction": {
                    "manifest": correction,
                    "manifest_hash": R.H("rapp/1:particle", correction),
                    "release_pin": correction_pin,
                },
                "channels": channels,
                "families": families,
                "rule": "the release-pin's manifest_hash = H('rapp/1:particle', manifest), whose `release` name "
                        "is part of those bytes but never selects a release; the stored manifest octets are "
                        "exactly canonical(manifest), so raw_sha256 is their SHA-256; each file's sha256 and "
                        "size_bytes are the raw SHA-256 and length of octets_utf8's UTF-8 bytes; the verified "
                        "snapshot is exactly these files, keyed by (component id, path). The correction is the "
                        "family's next release, with its own release name: its predecessor is the first "
                        "release's manifest_hash, its kernel component is the same, and it supersedes the first "
                        "release as the head of channel lts and the family's current release, while the first "
                        "release stays verifiable by its manifest_hash",
            },
            "manifest_cases": manifest_cases,
            "octets_cases": octets_cases,
            "entry_cases": entry_cases,
            "history_cases": history_cases,
            "kernel_coherence_cases": coherence_cases,
        }

    return [("13_1_document", document_cases), ("13_4_declared", declared_cases),
            ("13_release_pin", release_pin_cases)]


class _Drop:
    pass


_DROP = _Drop()


def registry_vectors():
    return {
        "schema": "rapp/1-registry-conformance-vectors",
        "derived_from": "rapp_registry.py",
        "signature_boundary": (
            "sig values are placeholders; accept/refuse covers structure, uniqueness, and chains. "
            "Verify §10/§13.4 signatures with real keys in your own tests."
        ),
        "sections": {name: build() for name, build in registry_sections()},
    }


OUTPUTS = (
    ("vectors.json", vectors, "rapp.py"),
    ("registry-vectors.json", registry_vectors, "rapp_registry.py"),
)


def main():
    stale = False
    for name, build, source in OUTPUTS:
        out = os.path.join(ROOT, "conformance", name)
        text = json.dumps(build(), indent=1, ensure_ascii=False, sort_keys=True) + "\n"
        if "--check" in sys.argv:
            current = open(out, encoding="utf-8").read() if os.path.exists(out) else ""
            if current != text:
                print(f"conformance/{name} is stale — run python3 conformance/make_vectors.py")
                stale = True
            else:
                print(f"{name} matches {source}")
            continue
        open(out, "w", encoding="utf-8").write(text); print("wrote", out)
    if stale:
        sys.exit(1)

if __name__ == "__main__":
    main()
