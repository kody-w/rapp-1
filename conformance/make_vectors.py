#!/usr/bin/env python3
"""make_vectors.py — emit conformance/vectors.json, the language-neutral known-answer vectors
an implementer in any language runs to claim rapp/1 conformance, and
conformance/registry-vectors.json, the §13 registry vectors. Every answer is derived from
rapp.py (and, for the registry file, rapp_registry.py); CI re-derives and diffs, so neither
file can drift from the reference.

  python3 conformance/make_vectors.py            # write both files
  python3 conformance/make_vectors.py --check    # exit 1 if a committed file differs
"""
import base64, json, os, sys
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


def registry_sections():
    """Ordered (name, builder) pairs; each change to §13 appends its own section."""
    owner, base = _estate()

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
            grant_case("a grant that starts before its activated_utc (§13.5 MAY)",
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
                        "activated_utc plays no part (a grant may start before it, §13.5); kid null means "
                        "unsigned and is never authorized. Every frame is assumed to have passed §7.5, step 6 "
                        "included (§13.5); signatures are out of scope for these vectors",
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
