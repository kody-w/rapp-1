#!/usr/bin/env python3
"""parity_check.py — prove the SDK Builder agent's embedded primitives match rapp.py.

This repo deliberately carries the reference primitives twice: once in rapp.py (the
reference implementation) and once embedded in agents/rapp_sdk_builder_agent.py (so the
agent is self-contained and offline-capable). Two copies of one canonicalizer is exactly
the drift class RAPP exists to kill, so this check runs in CI on every push:

  1. source parity — the agent's own `sync` normalization (ast-parse, strip docstrings,
     unparse) applied OFFLINE against the local rapp.py, for canonical/H/Hb;
  2. behavioral parity — both modules run the same vectors through canonical, H, Hb,
     build_frame, verify_frame, and rappid grammar, and must emit identical bytes and
     identical verdicts, including on deliberately broken frames.

Exit 0 = the two copies are one canonicalizer. Anything else fails the build.
"""
import ast
import base64
import copy
import importlib.util
import os
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
    return out


def module_defs(src):
    """Every top-level function (docstring dropped) and single-name assignment, ast-normalized."""
    out = dict(normalized_defs(src, {n.name for n in ast.parse(src).body if isinstance(n, ast.FunctionDef)}))
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            out[node.targets[0].id] = ast.unparse(node)
    return out


def closure(src, roots):
    """The top-level names of `src` that `roots` use, directly or through other top-level names."""
    top = {}
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef):
            top[node.name] = node
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            top[node.targets[0].id] = node
    seen, todo = set(), list(roots)
    while todo:
        name = todo.pop()
        if name in seen or name not in top:
            continue
        seen.add(name)
        todo.extend(sub.id for sub in ast.walk(top[name]) if isinstance(sub, ast.Name) and sub.id in top)
    return seen


def main():
    R = load("rapp_ref", os.path.join(ROOT, "rapp.py"))
    A = load("rapp_agent", os.path.join(ROOT, "agents", "rapp_sdk_builder_agent.py"))
    failures = []

    def check(label, ok, detail=""):
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(label)

    # 1. source parity: every primitive the agent embeds, and everything it uses, is rapp.py's definition
    #    verbatim (the agent's sync contract, offline). verify_frame alone keeps its own inline signature
    #    check, so it is compared by behaviour below; the names it uses are still compared by source.
    with open(os.path.join(ROOT, "rapp.py"), encoding="utf-8") as f:
        ref_src = f.read()
    with open(os.path.join(ROOT, "agents", "rapp_sdk_builder_agent.py"), encoding="utf-8") as f:
        agent_src = f.read()
    ref_all, agent_all = module_defs(ref_src), module_defs(agent_src)
    behaviour_only = {"verify_frame"}
    roots = ("canonical", "H", "Hb", "_strict_json", "build_frame", "mint_rappid", "utc_valid",
             "rappid_valid", "parse_detached_jws")
    required = closure(ref_src, roots) | (closure(agent_src, ("verify_frame",)) & set(ref_all))
    compared = sorted((required | (set(ref_all) & set(agent_all))) - behaviour_only)
    print(f"source parity (ast-normalized, no network): {len(compared)} shared definitions")
    for name in compared:
        check(f"source of {name}", name in ref_all and agent_all.get(name) == ref_all[name],
              "copy rapp.py's definition verbatim into the agent")

    # 2. behavioral parity — canonicalization and addressing
    vectors = [
        None, True, False, 0, -1, 2**53 - 1,
        "", "a", "héllo", "é", "é", "  ", "\"\\\b\f\n\r\t",
        [], [1, [2, [3]]], {}, {"b": 1, "a": [3, 2]},
        {"z": None, "a": {"nested": ["x", 0, False]}, "m": "\uD800" if False else "ok"},
        {"payload": {"k": "v"}, "spec": "rapp/1"},
    ]
    print("behavioral parity — canonical / H / Hb:")
    for i, v in enumerate(vectors):
        check(f"canonical vector {i}", R.canonical(v) == A.canonical(v))
        check(f"H vector {i}", R.H("rapp/1:particle", v) == A.H("rapp/1:particle", v))
    for i, b in enumerate([b"", b"x", bytes(range(256))]):
        check(f"Hb vector {i}", R.Hb("rapp/1:egg", b) == A.Hb("rapp/1:egg", b))

    def outcome(fn, *args):
        try:
            value = fn(*args)
        except ValueError as exc:
            return ("refused", str(exc))
        return ("ok", repr(value), type(value).__name__)

    print("behavioral parity — rev-17 numbers, text and tags:")
    numbers = [0.1, 1e21, 1e-7, 1e-6, 5e-324, -0.0, 1.0, 1.5e300, 2**53, 10**21, 123456789012345680000.0,
               {"x": [0.5, -1.5e300, 2**60]}]
    for i, v in enumerate(numbers):
        check(f"canonical number {i}", outcome(R.canonical, v) == outcome(A.canonical, v))
    refused = ["\ufdd0", {"\uffff": 1}, "\U0010ffff", "\ud800", float("nan"), float("inf"), 2**53 + 1, {1: 2}]
    for i, v in enumerate(refused):
        r, a = outcome(R.canonical, v), outcome(A.canonical, v)
        check(f"canonical refusal {i}", r == a and r[0] == "refused", f"ref={r} agent={a}")
    for i, (fn, space, arg) in enumerate([("H", "rapp/1:egg", {}), ("H", "x", {}), ("Hb", "rapp/1:particle", b""),
                                          ("Hb", "rapp/1:wave", b""), ("H", "rapp/1:sealed-aad", {"a": 1})]):
        r, a = outcome(getattr(R, fn), space, arg), outcome(getattr(A, fn), space, arg)
        check(f"tag table {i} ({fn} {space})", r == a, f"ref={r} agent={a}")
    texts = [b'{"a":1E21}', b'{"a":-0}', b'{"a":9007199254740992}', b'{"a":9007199254740993}', b'{"a":1e999}',
             b'{"a":0.10000000000000001}', b'\xef\xbb\xbf{}', "{}".encode("utf-16"), '{"a":NaN}'.encode(),
             b'[' * 64 + b'1' + b']' * 64, b'[' * 65 + b']' * 65]
    for i, t in enumerate(texts):
        r, a = outcome(R._strict_json, t), outcome(A._strict_json, t)
        check(f"_strict_json text {i}", r == a, f"ref={r} agent={a}")

    # 3. behavioral parity — the frame, byte for byte
    print("behavioral parity — build_frame / verify_frame:")
    utc = "2026-01-01T00:00:00.000Z"
    owner = "rappid:@kody/parity:" + "a" * 64
    sid = owner + ":main"                      # a §6.1.1 memory-stream
    g_ref = R.build_frame("memory.note", sid, 0, utc, {"text": "hi", "n": 1}, None)
    g_agent = A.build_frame("memory.note", sid, 0, utc, {"text": "hi", "n": 1}, None)
    check("genesis frame identical", g_ref == g_agent)
    n_ref = R.build_frame("memory.note", sid, 1, utc, {"text": "next"}, g_ref["payload_hash"])
    n_agent = A.build_frame("memory.note", sid, 1, utc, {"text": "next"}, g_agent["payload_hash"])
    check("successor frame identical", n_ref == n_agent)

    def jws(kid, header=None, signature=bytes(64)):
        header = header if header is not None else R.canonical(
            {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid})
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
        return enc(header.encode("utf-8")) + ".." + enc(signature)

    def rehash(frame):
        frame["payload_hash"] = R.H("rapp/1:particle", frame["payload"])
        frame["frame_hash"] = R.H("rapp/1:wave", {k: v for k, v in frame.items()
                                                   if k not in ("frame_hash", "sig")})
        return frame

    def verdicts(frame, head=None, sid=None, **kw):
        return (R.verify_frame(copy.deepcopy(frame), head, sid, **kw),
                A.verify_frame(copy.deepcopy(frame), head, sid, **kw))

    cases = [("valid genesis", dict(g_ref), None, None),
             ("valid successor", dict(n_ref), g_ref, None),
             ("cross-stream replay", dict(g_ref), None, owner + ":other")]
    mutations = [
        ("missing key", lambda f: f.pop("sig")),
        ("wrong spec", lambda f: f.__setitem__("spec", "rapp/2")),
        ("bad kind grammar", lambda f: f.__setitem__("kind", "NotAKind")),
        ("65-character kind label", lambda f: f.__setitem__("kind", "memory." + "p" * 65)),
        ("provisional stream id", lambda f: f.__setitem__("stream_id", "rappid:@kody/parity:" + "a" * 32)),
        ("seq as bool", lambda f: f.__setitem__("seq", True)),
        ("seq as float", lambda f: f.__setitem__("seq", 0.0)),
        ("seq 2^53", lambda f: f.__setitem__("seq", 2**53)),
        ("tampered payload", lambda f: f["payload"].__setitem__("text", "evil")),
        ("tampered payload_hash", lambda f: f.__setitem__("payload_hash", "0" * 64)),
        ("tampered frame_hash", lambda f: f.__setitem__("frame_hash", "f" * 64)),
        ("prev_wave off swarm", lambda f: f.__setitem__("prev_wave", "a" * 64)),
        ("genesis with prev", lambda f: f.__setitem__("prev", "b" * 64)),
        ("bad utc form", lambda f: f.__setitem__("utc", "2026-01-01T00:00:00Z")),
        ("attached JWS", lambda f: f.__setitem__("sig", jws(owner).replace("..", ".e30."))),
        ("63-octet signature", lambda f: f.__setitem__("sig", jws(owner, signature=bytes(63)))),
        ("65-octet signature", lambda f: f.__setitem__("sig", jws(owner, signature=bytes(65)))),
        ("well-formed sig, no verifier", lambda f: f.__setitem__("sig", jws(owner))),
    ]
    for label, frame, head, case_sid in cases:
        r, a = verdicts(frame, head, case_sid)
        check(f"verdict agrees: {label}", r == a, f"ref={r} agent={a}")
    for label, mutate in mutations:
        f = {**g_ref, "payload": dict(g_ref["payload"])}
        mutate(f)
        r, a = verdicts(f)
        check(f"verdict agrees: {label}", r == a, f"ref={r} agent={a}")

    # rev-17 re-genesis and registry rules: step 1, step 4 and step 6
    body = owner                                    # a §6.1.1 body-stream
    moved = {"stream_id": body, "terminal_seal": "c" * 64, "terminal_seq": 7}
    regen = R.build_frame("body.re-genesis", body, 0, utc, {"migrated_from": moved}, None,
                          sig=jws(owner))
    unsigned_regen = dict(regen, sig=None)
    extra_member = rehash(copy.deepcopy(regen))
    extra_member["payload"]["extra"] = 1
    extra_member = rehash(extra_member)
    regen_seq1 = rehash(dict(copy.deepcopy(regen), seq=1, prev=g_ref["payload_hash"]))

    class StubRegistry:
        def __init__(self, genesis_hash=None, owner_rappid=owner, bound=True):
            self.genesis_hash, self.owner_rappid, self.bound = genesis_hash, owner_rappid, bound
        def check_frame_binding(self, frame):
            return (True, "ok") if self.bound else (False, "kind family 'memory' is incompatible with body-stream")
        def registered_genesis(self, stream_id):
            return None if self.genesis_hash is None else {"frame_hash": self.genesis_hash}
        def owner_at(self, when):
            return self.owner_rappid

    def signer_verifier(unsigned, sig, expected_signer=None):
        kid = R.parse_detached_jws(sig)[0]["kid"]
        return (expected_signer is None or kid == expected_signer), "kid is not the required signer"

    trust_all = lambda unsigned, sig, expected_signer=None: (True, "trusted")
    regen_cases = [
        ("owner-signed re-genesis", regen, None, None, dict(signature_verifier=trust_all)),
        ("unsigned re-genesis (step 6)", unsigned_regen, None, None, {}),
        ("re-genesis with an extra payload member (step 1)", extra_member, None, None, {}),
        ("re-genesis at seq 1 with a head (step 4)", regen_seq1, g_ref, None, {}),
        ("registry binding refused (step 1)", g_ref, None, None, dict(registry=StubRegistry(bound=False))),
        ("registered genesis mismatch, no head (step 4)", g_ref, None, None,
         dict(registry=StubRegistry(genesis_hash="d" * 64))),
        ("registered genesis match, no head", g_ref, None, None,
         dict(registry=StubRegistry(genesis_hash=g_ref["frame_hash"]))),
        ("no genesis entry, no head", g_ref, None, None, dict(registry=StubRegistry())),
        ("non-owner re-genesis (step 6)", regen, None, None,
         dict(registry=StubRegistry(owner_rappid="rappid:@kody/other:" + "e" * 64),
              signature_verifier=signer_verifier)),
        ("owner re-genesis with registry", regen, None, None,
         dict(registry=StubRegistry(), signature_verifier=signer_verifier)),
    ]
    for label, frame, head, case_sid, kw in regen_cases:
        r, a = verdicts(frame, head, case_sid, **kw)
        check(f"verdict agrees: {label}", r == a, f"ref={r} agent={a}")

    # the §11 producer: both copies refuse the same inputs with the same reason
    def refusal(module, args, kw):
        try:
            module.build_frame(*copy.deepcopy(args), **copy.deepcopy(kw))
        except ValueError as exc:
            return "refused: " + str(exc)
        return "built"
    swarm = "net:parity"
    producer_cases = [
        ("provisional stream id", ("memory.note", "rappid:@kody/parity:" + "a" * 32, 0, utc, {}, None), {}),
        ("65-character kind label", ("memory." + "p" * 65, sid, 0, utc, {}, None), {}),
        ("utc second 60", ("memory.note", sid, 0, "2026-01-01T00:00:60.000Z", {}, None), {}),
        ("payload not an object", ("memory.note", sid, 0, utc, [], None), {}),
        ("non-NFC payload key", ("memory.note", sid, 0, utc, {"e\u0301": 1}, None), {}),
        ("unassigned code point key", ("memory.note", sid, 0, utc, {"a": {"\U000e0080": 1}}, None), {}),
        ("seq 1 with prev null", ("memory.note", sid, 1, utc, {}, None), {}),
        ("seq 0 with a prev", ("memory.note", sid, 0, utc, {}, "b" * 64), {}),
        ("prev_wave on a body genesis", ("body.pulse", body, 0, utc, {}, None), {"prev_wave": "a" * 64}),
        ("unsigned swarm frame", ("swarm.echo", swarm, 0, utc, {}, None), {}),
        ("null prev_wave on a swarm child", ("swarm.echo", swarm, 1, utc, {}, "b" * 64), {"sig": jws(owner)}),
        ("attached JWS", ("memory.note", sid, 0, utc, {}, None), {"sig": jws(owner).replace("..", ".e30.")}),
        ("unsigned re-genesis", ("body.re-genesis", body, 0, utc, {"migrated_from": moved}, None), {}),
        ("valid signed swarm genesis", ("swarm.echo", swarm, 0, utc, {}, None), {"sig": jws(owner)}),
    ]
    for label, args, kw in producer_cases:
        r, a = refusal(R, args, kw), refusal(A, args, kw)
        check(f"producer agrees: {label}", r == a, f"ref={r} agent={a}")

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
