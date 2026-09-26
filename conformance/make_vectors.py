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
            ("an entry whose type is the empty string", document(base + [{"type": ""}])),
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

    def lifecycle_cases():
        """§13.6 lifecycle notices: entry rules, one chain per subject (a rappid or a repository URI),
        times, cycles, and the state and successor in effect."""
        earlier, just_before_t1 = "2026-06-01T00:00:00.000Z", "2026-07-31T23:59:59.999Z"
        t1, t2, t3 = "2026-08-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z", "2026-10-01T00:00:00.000Z"
        future = "2027-01-01T00:00:00.000Z"

        def organism(slug, n):
            """A reproducible keyless rappid: the §6.2 mint over a fixed UUIDv4, for vectors only."""
            return f"rappid:@vector/{slug}:" + R.Hb("rapp/1:rappid", bytes.fromhex("00000000000040008000%012x" % n))

        alpha, beta, gamma, delta, epsilon = (
            organism(slug, n) for n, slug in enumerate(("alpha", "beta", "gamma", "delta", "epsilon"), 1))
        # Repositories with no rappid of their own are subjects too, named by their HTTPS URI.
        handbook, docs = "https://git.example.test/vector/handbook", "https://git.example.test/vector/docs"

        def notice(subject, state, since=T0, previous=None, superseded_by=None, activated=T0, **changes):
            """A lifecycle entry with a placeholder sig; `previous` may be the entry it follows."""
            entry = {"type": "lifecycle", "subject": subject, "state": state, "superseded_by": superseded_by,
                     "since_utc": since,
                     "previous": REG.entry_hash(previous) if isinstance(previous, dict) else previous,
                     "activated_utc": activated, "declared_by": owner, "sig": SIG}
            entry.update(changes)
            return {k: v for k, v in entry.items() if v is not _DROP}

        def current(registry):
            """Each subject's current notice (its chain's last entry), scheduled or in effect."""
            heads = {subject: registry.lifecycle_head(subject) for subject in sorted(registry.lifecycle)}
            return {subject: {"state": head["state"], "superseded_by": head["superseded_by"]}
                    for subject, head in heads.items()}

        def case(label, notices, expect):
            """`expect` is "accept", or text the reference's refusal must contain, so every refusal
            vector is proven to fail for the rule its label names."""
            entries = base + notices
            try:
                registry = REG.Registry(entries)
            except REG.RegistryError as why:
                assert expect != "accept" and expect in str(why), (label, str(why))
                return {"label": label, "entries": entries, "expect": "refuse", "current": None}
            assert expect == "accept", label
            return {"label": label, "entries": entries, "expect": "accept", "current": current(registry)}

        a1 = notice(alpha, "active")
        a2 = notice(alpha, "deprecated", since=t1, previous=a1, superseded_by=beta, activated=t1)
        a3 = notice(alpha, "superseded", since=t2, previous=a2, superseded_by=beta, activated=t2)
        b1 = notice(beta, "active")
        b2 = notice(beta, "archived", since=t2, previous=b1, activated=t2)
        c1 = notice(alpha, "deprecated", since=t1, activated=t1)
        s1 = notice(alpha, "superseded", superseded_by=beta)
        a2_loop = notice(alpha, "superseded", since=t1, previous=a1, superseded_by=beta, activated=t1)
        b_loop = notice(beta, "superseded", superseded_by=alpha)
        cases = [
            case("one active notice", [a1], "accept"),
            case("a chain: active, then deprecated recommending beta, then superseded by beta", [a1, a2, a3],
                 "accept"),
            case("two organisms' chains interleaved in entries", [a1, b1, a2, b2], "accept"),
            case("deprecated and archived without a successor",
                 [notice(alpha, "deprecated"), notice(beta, "archived")], "accept"),
            case("archived naming a successor", [notice(alpha, "archived", superseded_by=beta)], "accept"),
            case("a correction: equal since_utc and activated_utc along a chain",
                 [c1, notice(alpha, "active", since=t1, previous=c1, activated=t1)], "accept"),
            case("a retroactive notice: since_utc before its activated_utc",
                 [a1, notice(alpha, "archived", since=t1, previous=a1, activated=t3)], "accept"),
            case("a scheduled notice: since_utc after its activated_utc",
                 [a1, notice(alpha, "archived", since=future, previous=a1, activated=t1)], "accept"),
            case("a line of successors: alpha to beta to gamma, gamma active",
                 [s1, notice(beta, "superseded", superseded_by=gamma), notice(gamma, "active")], "accept"),
            case("a successor that declares no lifecycle of its own",
                 [notice(alpha, "superseded", superseded_by=delta)], "accept"),
            case("a repository with no rappid: active, then superseded by the repository it moved to",
                 [notice(handbook, "active"),
                  notice(handbook, "superseded", since=t1, previous=notice(handbook, "active"),
                         superseded_by=docs, activated=t1)], "accept"),
            case("a repository superseded by an organism (the member minted an identity), and an organism "
                 "deprecated in favour of a repository",
                 [notice(handbook, "superseded", superseded_by=alpha),
                  notice(beta, "deprecated", superseded_by=docs)], "accept"),
            case("two spellings of one repository are two subjects, each with its own first notice",
                 [notice(docs, "active"), notice(docs.replace("/docs", "/Docs"), "archived")], "accept"),
            case("a supersession withdrawn as the reverse one takes effect: the two never loop at one time",
                 [s1, notice(alpha, "active", since=t1, previous=s1, activated=t1),
                  notice(beta, "superseded", since=t1, superseded_by=alpha, activated=t1)], "accept"),
            case("a scheduled reinstatement and a scheduled reverse supersession taking effect together",
                 [s1, notice(alpha, "active", since=future, previous=s1, activated=t1),
                  notice(beta, "superseded", since=future, superseded_by=alpha, activated=t1)], "accept"),
            case("a missing member (previous)", [notice(alpha, "active", previous=_DROP)], "member set"),
            case("an extra member (deprecated)", [notice(alpha, "active", deprecated=False)], "member set"),
            case("a subject rappid with a provisional 32-hex tail",
                 [notice(alpha.rsplit(":", 1)[0] + ":" + "a" * 32, "active")], "`subject`"),
            case("a subject that is an http (not https) URI",
                 [notice("http://git.example.test/vector/handbook", "active")], "`subject`"),
            case("a subject that is a bare owner/repository name", [notice("vector/handbook", "active")],
                 "`subject`"),
            case("a subject HTTPS URI with no host", [notice("https:///vector/handbook", "active")], "`subject`"),
            case("a subject HTTPS URI whose IP literal is not an IPv6 address",
                 [notice("https://[zz]/vector/handbook", "active")], "`subject`"),
            case("a state outside the four", [notice(alpha, "retired")], "`state`"),
            case("a superseded_by that is neither a rappid nor an HTTPS URI",
                 [notice(alpha, "deprecated", superseded_by="http://git.example.test/vector/beta")],
                 "`superseded_by`"),
            case("superseded_by equal to subject", [notice(alpha, "archived", superseded_by=alpha)], "never equals"),
            case("a repository superseded by itself", [notice(docs, "superseded", superseded_by=docs)],
                 "never equals"),
            case("active naming a successor", [notice(alpha, "active", superseded_by=beta)], "must be null"),
            case("superseded naming no successor", [notice(alpha, "superseded")], "names its successor"),
            case("a since_utc without milliseconds", [notice(alpha, "active", since="2026-07-01T00:00:00Z")],
                 "`since_utc`"),
            case("a since_utc that is not a calendar time",
                 [notice(alpha, "active", since="2026-02-30T00:00:00.000Z")], "`since_utc`"),
            case("an activated_utc with a numeric offset",
                 [notice(alpha, "active", activated="2026-07-01T00:00:00.000+00:00")], "`activated_utc`"),
            case("a previous that is not 64 lowercase hex",
                 [a1, notice(alpha, "archived", since=t1, previous=REG.entry_hash(a1).upper(), activated=t1)],
                 "`previous`"),
            case("a declared_by that is not a rappid", [notice(alpha, "active", declared_by="owner")],
                 "`declared_by`"),
            case("an empty sig", [notice(alpha, "active", sig="")], "`sig`"),
            case("two first notices for one subject", [a1, c1], "exactly one first entry"),
            case("a fork: two notices follow one",
                 [a1, a2, notice(alpha, "archived", since=t1, previous=a1, activated=t1)], "fork"),
            case("previous names a notice appended after it", [a2, a1], "does not precede"),
            case("previous names another subject's notice",
                 [a1, b1, notice(beta, "deprecated", since=t1, previous=a1, activated=t1)], "does not precede"),
            case("previous names an entry that is not a lifecycle notice (the owner's spki)",
                 [a1, notice(alpha, "archived", since=t1, previous=base[1], activated=t1)], "does not precede"),
            case("previous names no entry",
                 [a1, notice(alpha, "archived", since=t1, previous="0" * 64, activated=t1)], "does not precede"),
            case("the same notice twice", [a1, a1], "duplicate"),
            case("since_utc decreases along a chain",
                 [c1, notice(alpha, "archived", since=T0, previous=c1, activated=t1)], "`since_utc` decreases"),
            case("activated_utc decreases along a chain",
                 [c1, notice(alpha, "archived", since=t1, previous=c1, activated=T0)], "`activated_utc` decreases"),
            case("alpha and beta supersede each other", [s1, notice(beta, "superseded", superseded_by=alpha)],
                 "cycle"),
            case("a three-organism cycle through a deprecation's recommended successor",
                 [s1, notice(beta, "archived", superseded_by=gamma),
                  notice(gamma, "deprecated", superseded_by=alpha)], "cycle"),
            case("a cycle across forms: a repository superseded by an organism that names the repository",
                 [notice(handbook, "superseded", superseded_by=alpha), notice(alpha, "superseded", superseded_by=handbook)],
                 f"in effect at {T0} form a cycle"),
            case("delta leads into the alpha-beta cycle",
                 [notice(delta, "superseded", superseded_by=alpha), s1,
                  notice(beta, "superseded", superseded_by=alpha)], "cycle"),
            case("a scheduled notice closes a cycle",
                 [a1, notice(alpha, "superseded", since=future, previous=a1, superseded_by=beta, activated=t1),
                  notice(beta, "superseded", superseded_by=alpha)], f"in effect at {future} form a cycle"),
            case("a supersession withdrawn only after the reverse one took effect: they loop until then",
                 [s1, notice(alpha, "active", since=t1, previous=s1, activated=t1),
                  notice(beta, "superseded", superseded_by=alpha)], f"in effect at {T0} form a cycle"),
            case("a scheduled reinstatement leaves the loop in effect until its since_utc",
                 [s1, notice(alpha, "active", since=future, previous=s1, activated=t1),
                  notice(beta, "superseded", superseded_by=alpha)], f"in effect at {T0} form a cycle"),
            case("a retroactive notice closes a loop in the past",
                 [s1, notice(alpha, "active", since=t2, previous=s1, activated=t2),
                  notice(beta, "superseded", since=t1, superseded_by=alpha, activated=t3)],
                 f"in effect at {t1} form a cycle"),
            case("a loop in effect only between two later since_utc instants: neither the first nor the "
                 "current notices loop",
                 [a1, a2_loop, notice(alpha, "active", since=t2, previous=a2_loop, activated=t2),
                  b_loop, notice(beta, "active", since=t3, previous=b_loop, activated=t3)],
                 f"in effect at {t1} form a cycle"),
        ]

        g1 = notice(gamma, "active")
        d1 = notice(delta, "active", since=t1, activated=t1)
        e1 = notice(epsilon, "deprecated", since=t1, superseded_by=gamma, activated=t1)
        h1 = notice(handbook, "active")
        timeline = base + [
            a1, g1, a2, d1, e1, a3, h1,
            notice(gamma, "archived", since=t1, previous=g1, activated=t3),  # retroactive
            notice(delta, "superseded", since=future, previous=d1, superseded_by=beta, activated=t2),  # scheduled
            notice(epsilon, "active", since=t1, previous=e1, activated=t2),  # a correction withdraws gamma
            notice(handbook, "superseded", since=t2, previous=h1, superseded_by=docs, activated=t1),  # a move
        ]
        # The lifecycle in effect is an answer, given only by a loaded registry; these vectors are
        # unsigned, so the timeline loads as a draft and is asked as a rehearsal (allow_draft=True).
        status, registry, why = REG.load_document(document(timeline, sig=None), trust_anchor=owner,
                                                  allow_unsigned=True)
        assert status == "draft", why
        times = (earlier, T0, just_before_t1, t1, t2, t3, future)
        intended = {  # subject -> (state, superseded_by) in effect at each of `times`
            alpha: ((None, None), ("active", None), ("active", None), ("deprecated", beta),
                    ("superseded", beta), ("superseded", beta), ("superseded", beta)),
            beta: ((None, None),) * len(times),
            gamma: ((None, None), ("active", None), ("active", None), ("archived", None),
                    ("archived", None), ("archived", None), ("archived", None)),
            delta: ((None, None), (None, None), (None, None), ("active", None),
                    ("active", None), ("active", None), ("superseded", beta)),
            epsilon: ((None, None), (None, None), (None, None), ("active", None),
                      ("active", None), ("active", None), ("active", None)),
            handbook: ((None, None), ("active", None), ("active", None), ("active", None),
                       ("superseded", docs), ("superseded", docs), ("superseded", docs)),
            docs: ((None, None),) * len(times),
        }
        queries = []
        for subject, answers in intended.items():
            for utc, expected in zip(times, answers):
                answer = (registry.lifecycle_state_at(subject, utc, allow_draft=True),
                          registry.successor_at(subject, utc, allow_draft=True))
                assert answer == expected, (subject, utc, answer)
                queries.append({"subject": subject, "utc": utc, "state": answer[0], "superseded_by": answer[1]})

        return {
            "states": list(REG.LIFECYCLE_STATES),
            "example": {
                "first": a1,
                "first_entry_hash": REG.entry_hash(a1),
                "second": a2,
                "second_signing_payload": R.canonical({k: v for k, v in a2.items() if k != "sig"}),
                "rule": "second.previous = H('rapp/1:particle', first), over the complete entry with its sig; "
                        "each notice is a declared entry signed over canonical(entry \\ {sig})",
            },
            "cases": cases,
            "state_at": {
                "entries": timeline,
                "current": current(registry),
                "queries": queries,
                "rule": "the notice in effect at utc is the last chain entry whose since_utc <= utc (bytewise); "
                        "its state and superseded_by are those in effect at utc. A null state is no declared "
                        "lifecycle, never deprecation; a null superseded_by names no successor at utc, and a "
                        "scheduled notice names none before its since_utc",
            },
        }

    def stream_signer_cases():
        def keyless(slug, uuid4_hex):
            # §6.2 keyless mint over a fixed UUIDv4, so the vectors reproduce anywhere.
            return f"rappid:@vector/{slug}:" + R.Hb("rapp/1:rappid", bytes.fromhex(uuid4_hex))

        def keyed(slug, deprecated=False):
            der = f"vector-only SPKI bytes: {slug}".encode("ascii")
            rappid = R.mint_rappid("vector", slug, spki_der=der)
            return rappid, {"type": "spki", "rappid": rappid, "deprecated": deprecated,
                            "spki_der_b64": base64.b64encode(der).decode("ascii")}

        since, inside, revoked = "2026-07-10T00:00:00.000Z", "2026-07-20T00:00:00.000Z", "2026-07-25T00:00:00.000Z"
        rotated_at, until = "2026-07-28T00:00:00.000Z", "2026-08-10T00:00:00.000Z"
        adopted = "2026-09-01T00:00:00.000Z"  # a backdated grant's activated_utc, after its whole window
        station = keyless("station", "5e1f0c2a7b3d4e8f9a6b1c2d3e4f5a6b")
        other = keyless("other-station", "0a1b2c3d4e5f40718293a4b5c6d7e8f9")
        signer, signer_spki = keyed("pulse-signer")
        crawler, crawler_spki = keyed("crawler")
        retired, retired_spki = keyed("retired-signer")
        rotating, rotating_spki = keyed("rotating-signer", deprecated=True)  # §10: a re-anchor retires it
        successor, successor_spki = keyed("rotating-signer-next")
        backfill, backfill_spki = keyed("backfill-signer")
        unregistered = keyed("unregistered-signer")[0]
        members = base + [signer_spki, crawler_spki, retired_spki, rotating_spki, successor_spki,
                          backfill_spki] + [
            {"type": "kind", "kind": kind, "family": family, "deprecated": deprecated}
            for kind, family, deprecated in (
                ("body.pulse", "body", False), ("body.notice", "body", False),
                ("body.twin-pulse", "body", False), ("body.legacy-pulse", "body", True),
                ("body-sensor.pulse", "body", False), ("body.re-genesis", "body", False),
                ("memory.save", "memory", False), ("swarm.echo", "swarm", False))]

        def grant(**changes):
            entry = {"type": "stream-signer", "stream_id": station, "signer": signer,
                     "kinds": ["body.notice", "body.pulse"], "since_utc": since, "until_utc": until,
                     "activated_utc": T0, "declared_by": owner, "sig": SIG}
            entry.update(changes)
            return {k: v for k, v in entry.items() if v is not _DROP}

        def grant_case(label, entries, intended):
            expect = _registry_accepts(document(members + entries))
            assert expect == intended, label
            return {"label": label, "entries": entries, "expect": expect}

        grant_cases = [
            grant_case("a grant on a keyless station's body stream", [grant()], "accept"),
            grant_case("an open-ended grant (until_utc null)", [grant(until_utc=None)], "accept"),
            grant_case("kinds ascend bytewise: '-' (0x2D) sorts before '.' (0x2E)",
                       [grant(kinds=["body-sensor.pulse", "body.pulse"])], "accept"),
            grant_case("a listed kind whose kind entry is deprecated",
                       [grant(kinds=["body.legacy-pulse", "body.pulse"])], "accept"),
            grant_case("a signer whose spki entry is deprecated", [grant(signer=rotating)], "accept"),
            grant_case("a memory stream with a memory kind",
                       [grant(stream_id=station + ":main", kinds=["memory.save"])], "accept"),
            grant_case("a swarm stream with a swarm kind",
                       [grant(stream_id="net:wire", kinds=["swarm.echo"])], "accept"),
            grant_case("two grants for one stream and signer",
                       [grant(until_utc=inside), grant(since_utc=revoked, until_utc=None)], "accept"),
            grant_case("a grant that starts before its activated_utc (§13.7 MAY)",
                       [grant(activated_utc=inside)], "accept"),
            grant_case("a grant whose whole window precedes its activated_utc",
                       [grant(activated_utc=adopted)], "accept"),
            grant_case("a keyless rappid as the signer", [grant(signer=station)], "refuse"),
            grant_case("a keyed signer with no spki entry in this registry", [grant(signer=unregistered)], "refuse"),
            grant_case("a kind that is not registered here", [grant(kinds=["body.heartbeat"])], "refuse"),
            grant_case("a memory kind on a body stream", [grant(kinds=["memory.save"])], "refuse"),
            grant_case("a body kind on a swarm stream", [grant(stream_id="net:wire", kinds=["body.pulse"])], "refuse"),
            grant_case("a re-genesis kind (§12.1 reserves it for the owner)",
                       [grant(kinds=["body.pulse", "body.re-genesis"])], "refuse"),
            grant_case("kinds out of bytewise order", [grant(kinds=["body.pulse", "body.notice"])], "refuse"),
            grant_case("'-' after '.' is out of bytewise order",
                       [grant(kinds=["body.pulse", "body-sensor.pulse"])], "refuse"),
            grant_case("a duplicate kind", [grant(kinds=["body.pulse", "body.pulse"])], "refuse"),
            grant_case("no kinds", [grant(kinds=[])], "refuse"),
            grant_case("until_utc equal to since_utc (an empty window)", [grant(until_utc=since)], "refuse"),
            grant_case("until_utc before since_utc", [grant(until_utc=T0)], "refuse"),
            grant_case("a stream_id with no §6.1.1 form", [grant(stream_id="net:Wire")], "refuse"),
            grant_case("until_utc omitted rather than null", [grant(until_utc=_DROP)], "refuse"),
            grant_case("an extra member", [grant(deprecated=False)], "refuse"),
            grant_case("since_utc not the fixed §7.4 form", [grant(since_utc="2026-07-10T00:00:00Z")], "refuse"),
        ]

        entries = members + [
            grant(),
            grant(stream_id=station + ":main", kinds=["memory.save"], until_utc=None),
            grant(stream_id="net:wire", kinds=["swarm.echo"], until_utc=None),
            grant(signer=retired, kinds=["body.pulse"], until_utc=None),
            {"type": "tombstone", "rappid": retired, "revoked_utc": revoked, "sig": SIG},
            grant(signer=rotating, kinds=["body.pulse"], until_utc=None),
            {"type": "re-anchor", "old_rappid": rotating, "new_rappid": successor, "case": "rotation",
             "utc": rotated_at, "sig": SIG, "old_key_sig": SIG},
            grant(signer=backfill, kinds=["body.pulse"], activated_utc=adopted),
        ]
        registry = REG.Registry(entries)

        def decision(label, stream_id, kind, utc, kid, intended):
            ok, why = registry.authority_decision(stream_id, kid, kind, utc)
            expect = "authorized" if ok else "refused"
            assert expect == intended, (label, why)
            return {"label": label, "frame_summary": {"stream_id": stream_id, "kind": kind, "utc": utc, "kid": kid},
                    "expect": expect}

        before = "2026-07-09T23:59:59.999Z"
        last = "2026-08-09T23:59:59.999Z"
        example = grant()
        return {
            "example": {
                "entry": example,
                "signing_payload": R.canonical({k: v for k, v in example.items() if k != "sig"}),
                "entry_hash": REG.entry_hash(example),
            },
            "grant_cases": {
                "note": "each case's registry is a §13.1 document whose entries are base_entries followed by "
                        "the case's entries; accept or refuse it exactly as §13.3 requires",
                "base_entries": members,
                "cases": grant_cases,
            },
            "authority": {
                "note": "decide each frame_summary against a registry holding exactly `entries`: authorized iff "
                        "kid is the estate owner in effect at utc (§13.2) or a stream-signer entry names kid as "
                        "signer on stream_id, lists kind, and has since_utc <= utc < until_utc (bytewise; null "
                        "never ends), and in both cases §10 does not refuse kid's key at utc; a grant's "
                        "activated_utc plays no part (a grant may start before it, §13.7); kid null means "
                        "unsigned and is never authorized. Every frame is assumed to have passed §7.5, step 6 "
                        "included (§13.7); signatures are out of scope for these vectors",
                "entries": entries,
                "cases": [
                    decision("the estate owner, with no grant", station, "body.twin-pulse", T0, owner, "authorized"),
                    decision("the estate owner on a stream no grant names", other, "body.pulse", inside, owner,
                             "authorized"),
                    decision("the granted signer inside its window", station, "body.pulse", inside, signer,
                             "authorized"),
                    decision("at since_utc (inclusive)", station, "body.pulse", since, signer, "authorized"),
                    decision("one millisecond before since_utc", station, "body.pulse", before, signer, "refused"),
                    decision("the last millisecond before until_utc", station, "body.pulse", last, signer,
                             "authorized"),
                    decision("at until_utc (exclusive)", station, "body.pulse", until, signer, "refused"),
                    decision("another listed kind", station, "body.notice", inside, signer, "authorized"),
                    decision("a registered kind the grant does not list", station, "body.twin-pulse", inside,
                             signer, "refused"),
                    decision("another station's body stream", other, "body.pulse", inside, signer, "refused"),
                    decision("the memory stream its own grant names", station + ":main", "memory.save", inside,
                             signer, "authorized"),
                    decision("another memory stream of the same organism", station + ":spare", "memory.save",
                             inside, signer, "refused"),
                    decision("the swarm stream its own grant names", "net:wire", "swarm.echo", inside, signer,
                             "authorized"),
                    decision("a registered key without a grant", station, "body.pulse", inside, crawler, "refused"),
                    decision("an unsigned frame (kid null)", station, "body.pulse", inside, None, "refused"),
                    decision("the keyless station as its own kid", station, "body.pulse", inside, station, "refused"),
                    decision("a tombstoned signer before revoked_utc", station, "body.pulse", inside, retired,
                             "authorized"),
                    decision("a tombstoned signer at revoked_utc", station, "body.pulse", revoked, retired, "refused"),
                    decision("a rotated signer before its re-anchor", station, "body.pulse", inside, rotating,
                             "authorized"),
                    decision("a rotated signer at its re-anchor utc", station, "body.pulse", rotated_at, rotating,
                             "refused"),
                    decision("its successor, with no grant of its own", station, "body.pulse", rotated_at,
                             successor, "refused"),
                    decision("a backdated grant adopts a frame published before its activated_utc", station,
                             "body.pulse", inside, backfill, "authorized"),
                    decision("a backdated grant at its activated_utc, after its window", station,
                             "body.pulse", adopted, backfill, "refused"),
                ],
            },
        }

    return [("13_1_document", document_cases), ("13_4_declared", declared_cases),
            ("13_release_pin", release_pin_cases), ("13_lifecycle", lifecycle_cases),
            ("13_stream_signer", stream_signer_cases)]


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
