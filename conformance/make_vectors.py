#!/usr/bin/env python3
"""make_vectors.py — emit conformance/vectors.json, the language-neutral known-answer vectors
an implementer in any language runs to check rapp/1 conformance. Address artifacts are derived
from rapp.py; numeric known answers are independent RFC 8785 Appendix B / frozen §4 facts.

  python3 conformance/make_vectors.py            # write conformance/vectors.json
  python3 conformance/make_vectors.py --check    # exit 1 if the committed file differs
"""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import rapp as R

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
    # Independent binary64 known answers: RFC 8785, Appendix B.
    number_cases = [
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ]
    v["sections"]["4_numbers"] = [
        {"binary64_hex": bits, "canonical": text} for bits, text in number_cases
    ]
    v["sections"]["4_number_refuse"] = [
        {"binary64_hex": bits, "why": "non-finite binary64"}
        for bits in ("7fffffffffffffff", "7ff0000000000000", "fff0000000000000")
    ]
    parse_cases = [
        ("0.1", "0.1"), ("9007199254740992", "9007199254740992"),
        ("100000000000000000000000", "1e+23"),
        ("295147905179352830000", "295147905179352830000"),
        ("1.00", "1"), ("1e0", "1"), ("-0", "0"), ("-0.000e9999", "0"),
        ("1E+21", "1e+21"), ("1e20", "100000000000000000000"),
        ("1e-6", "0.000001"), ("1e-7", "1e-7"), ("5e-324", "5e-324"),
    ]
    v["sections"]["4_parse_accept"] = [
        {"json_text": token, "canonical": text} for token, text in parse_cases
    ]
    # §4 input-domain refusals: these MUST be refused, never repaired
    v["sections"]["4_refuse"] = [
        {"json_text": '{"a":1,"a":2}', "why": "duplicate member name"},
        {"json_text": '{"n": 9007199254740993}', "why": "integer does not survive binary64 round-trip"},
        {"json_text": '{"n": 1e999}', "why": "non-finite after parse"},
        {"json_text": '"\\ud800"', "why": "unpaired UTF-16 surrogate"},
    ]
    v["sections"]["4_refuse"].extend(
        {"json_text": token, "why": "lossy or non-finite number token"}
        for token in (
            "9007199254740993", "0.10000000000000001", "1.0000000000000001",
            "295147905179352825856", "1000000000000000128", "1e999", "1e-999",
            "NaN", "Infinity", "-Infinity",
        )
    )
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
    def tamper(label, frame, head, sid_of_record, mutate, rehash=False, expect_step=None):
        t = json.loads(json.dumps(frame)); mutate(t)
        if rehash:
            t["payload_hash"] = R.H("rapp/1:particle", t["payload"])
            t["frame_hash"] = R.H("rapp/1:wave", {
                key: value for key, value in t.items() if key not in ("frame_hash", "sig")
            })
        ok, step, why = R.verify_frame(t, head=head, stream_id_of_record=sid_of_record)
        assert not ok, label
        if expect_step is not None:
            assert step == expect_step, (label, step, why)
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
    tamper("rehashed broken child prev", c, g, sid,
           lambda t: t.update(prev="f" * 64), rehash=True, expect_step="4")
    tamper("rehashed skipped child seq", c, g, sid,
           lambda t: t.update(seq=2), rehash=True, expect_step="4")
    tamper("rehashed child utc before head", c, g, sid,
           lambda t: t.update(utc="2026-07-14T00:00:00.000Z"), rehash=True, expect_step="4")
    tamper("rehashed prev_wave off swarm", c, g, sid,
           lambda t: t.update(prev_wave=g["frame_hash"]), rehash=True, expect_step="5")
    tamper("stream grammar", g, None, "s-1",
           lambda t: t.update(stream_id="s-1"), rehash=True, expect_step="1")
    tamper("kind label too long", g, None, sid,
           lambda t: t.update(kind="a" * 65 + ".pulse"), rehash=True, expect_step="1")
    tamper("non-ASCII year", g, None, sid,
           lambda t: t.update(utc="\uff12\uff10\uff12\uff16-07-15T00:00:00.000Z"),
           rehash=True, expect_step="1")
    swarm = R.build_frame("swarm.echo", "net:commons", 0, g["utc"], {}, None)
    tamper("unsigned swarm", swarm, None, "net:commons", lambda t: None, expect_step="6")
    v["sections"]["7_frame"] = {"stream_id": sid, "genesis": g, "child": c, "tampers": tampers,
                                "note": "Original tamper cases retain their hashes; explicitly rehashed cases exercise chain/wire checks after integrity."}
    # §9 egg address known answer (JSON variant, no packed files)
    egg = R.pack_egg("session", sid, "2026-07-15T00:00:00.000Z", payload={"runtime": "test", "transcript": []})
    read = R.read_egg(egg)
    manifest = read[0] if isinstance(read, tuple) else read
    v["sections"]["9_egg"] = {"variant": "session", "egg_octets_hex": egg.hex(), "manifest": manifest,
                              "egg_address": R.egg_address(manifest),
                              "note": "a session egg is a JSON object; two conformant packers emit these exact octets"}
    v["reference_limits"] = [
        "Raw JSON number tokens must be validated before an ordinary JSON parser can discard their "
        "original mathematical value or fraction/exponent syntax.",
        "Registry authority and trusted signature verification remain caller-supplied; passing "
        "byte/shape vectors alone does not establish authenticated Consumer conformance.",
    ]
    return v

def main():
    out = os.path.join(ROOT, "conformance", "vectors.json")
    text = json.dumps(vectors(), indent=1, ensure_ascii=False, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        current = open(out, encoding="utf-8").read() if os.path.exists(out) else ""
        if current != text:
            print("conformance/vectors.json is stale — run python3 conformance/make_vectors.py"); sys.exit(1)
        print("vectors.json matches rapp.py"); return
    open(out, "w", encoding="utf-8").write(text); print("wrote", out)

if __name__ == "__main__":
    main()
