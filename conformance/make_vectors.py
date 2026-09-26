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

    def lifecycle_cases():
        """§13.5 lifecycle notices: entry rules, one chain per subject (a rappid or a repository URI),
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

    return [("13_1_document", document_cases), ("13_4_declared", declared_cases),
            ("13_lifecycle", lifecycle_cases)]


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
