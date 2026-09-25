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
        cases = [
            ("the five-member container", document(base)),
            ("unsigned draft container (sig null)", document(base, sig=None)),
            ("other top-level members carry no meaning", document(base, estate="vector", published_utc=T0)),
            ("missing canonical_source", document(base, canonical_source=_DROP)),
            ("non-HTTPS canonical_source", document(base, canonical_source="http://registry.example.test/r.json")),
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
                R.canonical(doc)
                case["document"] = doc
            except ValueError:
                # Not I-JSON at all: carried as text, like 4_refuse, so this file stays strict I-JSON.
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

    return [("13_1_document", document_cases), ("13_4_declared", declared_cases)]


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
