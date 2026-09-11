#!/usr/bin/env python3
"""parity_check.py — prove the SDK Builder agent's embedded primitives match rapp.py.

This repo deliberately carries the reference primitives twice: once in rapp.py (the
reference implementation) and once embedded in agents/rapp_sdk_builder_agent.py (so the
agent is self-contained and offline-capable). Two copies of one canonicalizer is exactly
the drift class RAPP exists to kill, so this check runs in CI on every push:

  1. source parity — the agent's own `sync` normalization (ast-parse, strip docstrings,
     unparse) applied OFFLINE against the local rapp.py, including transitive
     numeric/parser/frame helpers and their grammar/limit constants;
  2. behavioral parity — both modules run the same vectors through canonical, H, Hb,
     build_frame, verify_frame, and rappid grammar, and must emit identical bytes and
     identical verdicts, including on deliberately broken frames.

Exit 0 = the two copies are one canonicalizer. Anything else fails the build.
"""
import ast
import copy
import importlib.util
import os
import struct
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def normalized_defs(src, names):
    out = {}
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(getattr(body[0], "value", None), ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:] or [ast.Pass()]
            node.body = body
            out[node.name] = ast.unparse(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names:
                    out[target.id] = ast.unparse(node.value)
    return out


def main():
    R = load("rapp_ref", os.path.join(ROOT, "rapp.py"))
    A = load("rapp_agent", os.path.join(ROOT, "agents", "rapp_sdk_builder_agent.py"))
    failures = []

    def check(label, ok, detail=""):
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(label)

    # 1. source parity for the address core (the agent's sync contract, offline)
    prims = (
        "_canonical_number", "canonical", "_parse_json_number", "_strict_json",
        "H", "Hb", "mint_rappid", "rappid_valid", "kind_valid", "stream_form",
        "utc_valid", "_frame_shape", "build_frame", "verify_frame", "_verify_frame",
        "_signature_ok", "SPEC", "FRAME_KEYS", "MAX_CANONICAL_BYTES", "MAX_JSON_DEPTH",
        "_HEX64", "_UTC", "_LCLABEL", "_KIND", "_RAPPID",
    )
    with open(os.path.join(ROOT, "rapp.py"), encoding="utf-8") as f:
        ref_defs = normalized_defs(f.read(), prims)
    with open(os.path.join(ROOT, "agents", "rapp_sdk_builder_agent.py"), encoding="utf-8") as f:
        agent_defs = normalized_defs(f.read(), prims)
    print("source parity (ast-normalized, no network):")
    for p in prims:
        check(f"source of {p}", p in ref_defs and p in agent_defs
              and ref_defs[p] == agent_defs[p])

    # 2. behavioral parity — canonicalization and addressing
    vectors = [
        None, True, False, 0, -1, 2**53 - 1,
        "", "a", "héllo", "é", "é", "  ", "\"\\\b\f\n\r\t",
        [], [1, [2, [3]]], {}, {"b": 1, "a": [3, 2]},
        {"z": None, "a": {"nested": ["x", 0, False]}, "m": "ok"},
        {"payload": {"k": "v"}, "spec": "rapp/1"},
    ]
    print("behavioral parity — canonical / H / Hb:")
    for i, v in enumerate(vectors):
        check(f"canonical vector {i}", R.canonical(v) == A.canonical(v))
        check(f"H vector {i}", R.H("rapp/1:particle", v) == A.H("rapp/1:particle", v))
    for i, b in enumerate([b"", b"x", bytes(range(256))]):
        check(f"Hb vector {i}", R.Hb("rapp/1:egg", b) == A.Hb("rapp/1:egg", b))

    with open(os.path.join(ROOT, "conformance", "vectors.json"), "rb") as source:
        known = R._strict_json(source.read())["sections"]
    print("independently specified numeric and parse answers:")
    for section in ("4_numbers", "4_number_refuse", "4_parse_accept", "4_refuse"):
        check(f"required vector section {section}", bool(known.get(section)))
    for index, vector in enumerate(known.get("4_numbers", [])):
        value = struct.unpack(">d", bytes.fromhex(vector["binary64_hex"]))[0]
        check(f"number known answer {index}",
              R.canonical(value) == A.canonical(value) == vector["canonical"])
    for index, vector in enumerate(known.get("4_parse_accept", [])):
        check(f"raw number known answer {index}",
              R.canonical(R._strict_json(vector["json_text"]))
              == A.canonical(A._strict_json(vector["json_text"])) == vector["canonical"])
    for section in ("4_number_refuse", "4_refuse"):
        for index, vector in enumerate(known.get(section, [])):
            refused = []
            for module in (R, A):
                try:
                    if section == "4_number_refuse":
                        module.canonical(struct.unpack(">d", bytes.fromhex(vector["binary64_hex"]))[0])
                    else:
                        module._strict_json(vector["json_text"])
                except ValueError:
                    refused.append(True)
                else:
                    refused.append(False)
            check(f"{section} refusal {index}", refused == [True, True])

    # 3. behavioral parity — the frame, byte for byte
    print("behavioral parity — build_frame / verify_frame:")
    utc = "2026-01-01T00:00:00.000Z"
    stream = "rappid:@parity/fixture:" + "a" * 64 + ":instance"
    g_ref = R.build_frame("memory.note", stream, 0, utc, {"text": "hi", "n": 1}, None)
    g_agent = A.build_frame("memory.note", stream, 0, utc, {"text": "hi", "n": 1}, None)
    check("genesis frame identical", g_ref == g_agent)
    n_ref = R.build_frame("memory.note", stream, 1, utc, {"text": "next"}, g_ref["payload_hash"])
    n_agent = A.build_frame("memory.note", stream, 1, utc, {"text": "next"}, g_agent["payload_hash"])
    check("successor frame identical", n_ref == n_agent)

    def verdicts(frame, head=None, sid=None):
        return R.verify_frame(frame, head, sid), A.verify_frame(frame, head, sid)

    cases = [("valid genesis", dict(g_ref), None, stream, (True, None)),
             ("valid successor", dict(n_ref), g_ref, stream, (True, None)),
             ("cross-stream replay", dict(g_ref), None, "other-stream", (False, "1a"))]
    mutations = [
        ("missing key", lambda f: f.pop("sig")),
        ("wrong spec", lambda f: f.__setitem__("spec", "rapp/2")),
        ("bad kind grammar", lambda f: f.__setitem__("kind", "NotAKind")),
        ("seq as bool", lambda f: f.__setitem__("seq", True)),
        ("tampered payload", lambda f: f["payload"].__setitem__("text", "evil")),
        ("tampered payload_hash", lambda f: f.__setitem__("payload_hash", "0" * 64)),
        ("tampered frame_hash", lambda f: f.__setitem__("frame_hash", "f" * 64)),
        ("prev_wave off swarm", lambda f: f.__setitem__("prev_wave", "a" * 64)),
        ("genesis with prev", lambda f: f.__setitem__("prev", "b" * 64)),
        ("bad utc form", lambda f: f.__setitem__("utc", "2026-01-01T00:00:00Z")),
    ]
    for label, frame, head, sid, expected in cases:
        r, a = verdicts(frame, head, sid)
        check(f"verdict agrees: {label}", r == a and r[:2] == expected, f"ref={r} agent={a}")
    for label, mutate in mutations:
        f = {**g_ref, "payload": dict(g_ref["payload"])}
        mutate(f)
        r, a = verdicts(f)
        check(f"verdict agrees: {label}", r == a, f"ref={r} agent={a}")

    for index, vector in enumerate(known["7_frame"]["tampers"]):
        r, a = verdicts(vector["frame"], vector["head"], vector["stream_id_of_record"])
        check(f"known frame refusal {index}", r == a and r[:2] == (False, vector["expect_step"]))
    for index, malformed in enumerate((None, [], 1, {**g_ref, "payload": {"bad": "\ud800"}})):
        r, a = verdicts(malformed)
        check(f"controlled malformed frame {index}", r == a and r[:2] == (False, "1"))
    for module in (R, A):
        signed = copy.deepcopy(g_ref)
        signed["sig"] = "test-only-adapter"
        before = copy.deepcopy(signed)

        def mutating_adapter(unsigned, _signature):
            unsigned["payload"]["text"] = "changed"
            return True, "test-only adapter, not cryptographic verification"

        result = module.verify_frame(signed, signature_verifier=mutating_adapter)
        check(f"signature callback isolation: {module.__name__}", result[0] and signed == before)

    # 4. identity grammar
    print("behavioral parity — rappid grammar:")
    ids = ["rappid:@kody-w/twin:" + "a" * 64, "rappid:@A/x:" + "a" * 64,
           "rappid:@a/x:" + "a" * 63, "rappid:@a/x:" + "G" * 64, "not-a-rappid", ""]
    for i, s in enumerate(ids):
        check(f"rappid_valid vector {i}", bool(R.rappid_valid(s)) == bool(A.rappid_valid(s)))

    print(f"\n{'PARITY HOLDS' if not failures else 'PARITY BROKEN'} — "
          f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
