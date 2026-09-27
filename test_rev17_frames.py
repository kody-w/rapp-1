"""test_rev17_frames.py — the rev-17 frame items of the reference implementation.

build_frame as a §11 Producer (FR-6; E-5, E-6, E-10, E-22), the §7.5 step-1, step-4 and
step-6 checks of verify_frame (FR-7, FR-12; E-9, E-10, E-22), its duck-typed `registry`
keyword (E-11, E-12, FR-12), and the registry's kind and spki lifecycle (FR-9/E-23,
FR-10/E-21). The probes follow the Phase 4 triage report. From the repository root:

    python3 -m unittest test_rev17_frames
"""
import base64
import copy
import importlib.util
import inspect
import json
import os
import unittest

import rapp as R
import rapp_registry as REG

ROOT = os.path.dirname(os.path.abspath(__file__))
UTC = "2026-07-15T00:00:00.000Z"
LATER = "2026-07-15T00:00:01.000Z"
BODY = "rappid:@kody/twin:" + "a" * 64                    # a §6.1.1 body-stream
MEMORY = BODY + ":main"                                    # a memory-stream
SWARM = "net:commons"                                      # a swarm-stream
PROVISIONAL = "rappid:@kody/twin:9a7d2c1e5b3f4a6d8e0f1a2b3c4d5e6f"   # 32-hex tail (§6.3)
OWNER_SPKI = b"stand-in estate-owner SPKI: only its fingerprint matters here"
OLD_SPKI = b"stand-in earlier estate-owner SPKI"
OWNER = "rappid:@acme/estate-owner:" + R.Hb("rapp/1:rappid", OWNER_SPKI)
OLD_OWNER = "rappid:@acme/estate-owner:" + R.Hb("rapp/1:rappid", OLD_SPKI)
STRANGER = "rappid:@acme/stranger:" + "e" * 64
REANCHOR = {"type": "re-anchor", "old_rappid": OLD_OWNER, "new_rappid": OWNER, "case": "rotation",
            "utc": "2026-06-01T00:00:00.000Z", "sig": "owner-signed", "old_key_sig": "old-key-signed"}
BEFORE_REANCHOR = "2026-05-01T00:00:00.000Z"


def b64url(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def jws(kid=OWNER, header=None, signature=bytes(64)):
    """A detached compact JWS: a well-formed §10 one unless a test passes a broken part."""
    if header is None:
        header = R.canonical({"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid})
    return b64url(header.encode("utf-8")) + ".." + b64url(signature)


def rehash(frame):
    """Recompute both hashes, so that a later step (not 2 or 3) is the one that fails."""
    frame["payload_hash"] = R.H("rapp/1:particle", frame["payload"])
    frame["frame_hash"] = R.H(
        "rapp/1:wave", {k: v for k, v in frame.items() if k not in ("frame_hash", "sig")})
    return frame


def migrated(**members):
    moved = {"stream_id": BODY, "terminal_seal": "c" * 64, "terminal_seq": 7}
    moved.update(members)
    return {"migrated_from": moved}


def build(**fields):
    args = {"kind": "body.pulse", "stream_id": BODY, "seq": 0, "utc": UTC,
            "payload": {"n": 1}, "prev": None, "prev_wave": None, "sig": None}
    args.update(fields)
    return R.build_frame(**args)


def regenesis(kid=OWNER, utc=UTC):
    return build(kind="body.re-genesis", utc=utc, sig=jws(kid), payload=migrated())


def nest(depth):
    """A value of container depth `depth` (§4 (d): {} is 1, each nesting adds 1)."""
    value = {}
    for _ in range(depth - 1):
        value = {"a": value}
    return value


def trust_all(unsigned, sig, expected_signer=None):
    return True, "trusted"


def honours_expected_signer(unsigned, sig, expected_signer=None):
    """A stub verifier: any well-formed sig passes, but only by `expected_signer` when named."""
    kid = R.parse_detached_jws(sig)[0]["kid"]
    if expected_signer is not None and kid != expected_signer:
        return False, "kid is not the required signer"
    return True, "ok"


def spki_entry(rappid, spki, deprecated=False):
    return {"type": "spki", "rappid": rappid, "deprecated": deprecated,
            "spki_der_b64": base64.b64encode(spki).decode("ascii")}


def kind_entry(kind, family, deprecated=False):
    return {"type": "kind", "kind": kind, "family": family, "deprecated": deprecated}


def registry(*extra):
    return REG.Registry([
        {"type": "estate_owner", "rappid": OWNER},
        spki_entry(OWNER, OWNER_SPKI),
        kind_entry("body.pulse", "body"),
        kind_entry("body.re-genesis", "body"),
        kind_entry("memory.chat-turn", "memory", deprecated=True),
        kind_entry("swarm.echo", "swarm"),
        *extra,
    ])


class RecordingRegistry:
    """A duck-typed registry that records which §13 questions verify_frame asks."""

    def __init__(self, bound=(True, "ok"), genesis=None, owner=OWNER):
        self.bound, self.genesis, self.owner, self.calls = bound, genesis, owner, []

    def check_frame_binding(self, frame):
        self.calls.append("check_frame_binding")
        return self.bound

    def registered_genesis(self, stream_id):
        self.calls.append("registered_genesis")
        return self.genesis

    def owner_at(self, utc):
        self.calls.append("owner_at")
        return self.owner


def malformed_sigs():
    """The report's JWS-form probes (F005, F006, F008, F012, CI-7), each a §7.5 step-1 refusal."""
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": OWNER}
    protected, _, signature = jws().partition("..")
    reordered = json.dumps({"kid": OWNER, "alg": "EdDSA", "b64": False, "crit": ["b64"]},
                           separators=(",", ":"))
    return {
        "attached JWS": protected + "." + b64url(b"{}") + "." + signature,
        "non-canonical header order": jws(header=reordered),
        "extra typ member": jws(header=R.canonical(dict(header, typ="JOSE"))),
        "padded base64url": jws() + "==",
        "63-octet signature": jws(signature=bytes(63)),
        "65-octet signature": jws(signature=bytes(65)),
        "alg none": jws(header=R.canonical(dict(header, alg="none"))),
        "b64 true": jws(header=R.canonical(dict(header, b64=True))),
        "not a JWS": "not-a-jws",
        "not a string": 5,
    }


class TestProducer(unittest.TestCase):
    """FR-6 (+ E-5, E-6, E-10, E-22): build_frame refuses what a §11 Producer must not emit."""

    def refused(self, pattern, **fields):
        with self.assertRaisesRegex(ValueError, pattern):
            build(**fields)

    def test_valid_frames_build_verify_and_keep_their_hashes(self):
        g = build()
        child = build(seq=1, utc=LATER, payload={"n": 2}, prev=g["payload_hash"])
        swarm = build(kind="swarm.echo", stream_id=SWARM, sig=jws())
        swarm_child = build(kind="swarm.echo", stream_id=SWARM, seq=1, utc=LATER,
                            prev=swarm["payload_hash"], prev_wave=swarm["frame_hash"], sig=jws())
        memory = build(kind="memory.chat-turn", stream_id=MEMORY, seq=2**53 - 1, prev="b" * 64)
        for frame, head in ((g, None), (child, g), (swarm, None), (swarm_child, swarm), (memory, None)):
            self.assertEqual(set(frame), R.FRAME_KEYS)
            self.assertEqual(frame["payload_hash"], R.H("rapp/1:particle", frame["payload"]))
            self.assertEqual(frame["frame_hash"], R.H("rapp/1:wave", {
                k: v for k, v in frame.items() if k not in ("frame_hash", "sig")}))
            if frame is not memory:
                ok, step, why = R.verify_frame(frame, head=head, stream_id_of_record=frame["stream_id"],
                                               signature_verifier=trust_all)
                self.assertTrue(ok, (step, why))

    def test_published_vector_still_reproduces(self):
        with open(os.path.join(ROOT, "conformance", "vectors.json"), encoding="utf-8") as f:
            section = json.load(f)["sections"]["7_frame"]
        self.assertEqual(R.build_frame("body.pulse", section["stream_id"], 0, UTC, {"hello": "world"},
                                       prev=None), section["genesis"])

    def test_provisional_stream_id_refused(self):
        self.refused("stream_id", stream_id=PROVISIONAL)
        self.refused("stream_id", kind="memory.chat-turn", stream_id=PROVISIONAL + ":main")

    def test_stream_id_must_be_a_6_1_1_form(self):
        for bad in ("s-1", "net:", "net:Main", MEMORY[:-4] + ":" + "i" * 65, BODY.upper(), 7, None):
            self.refused("stream_id", stream_id=bad)

    def test_kind_grammar_and_label_lengths(self):
        self.refused("kind", kind="body." + "p" * 65)
        self.refused("kind", kind="b" * 65 + ".pulse")
        for bad in ("body", "Body.Pulse", "body.pulse.x", "body.-pulse", "body.pulse\u0301", 5):
            self.refused("kind", kind=bad)
        self.assertEqual(build(kind="body." + "p" * 64)["kind"], "body." + "p" * 64)

    def test_utc_leap_second_and_calendar(self):
        self.refused("utc", utc="2026-07-15T00:00:60.000Z")
        for bad in ("2026-13-45T25:61:61.999Z", "2026-07-15T00:00:00Z", "2026-07-15 00:00:00.000Z", 0):
            self.refused("utc", utc=bad)
        self.assertEqual(build(utc="2026-07-15T23:59:59.999Z")["utc"], "2026-07-15T23:59:59.999Z")

    def test_seq_must_be_uint53(self):
        for bad in (True, False, 0.0, -0.0, 1.0, -1, 2**53, "0", None):
            self.refused("seq must be a uint53", seq=bad)

    def test_prev_and_prev_wave_form(self):
        for bad in ("B" * 64, "b" * 63, 5, ""):
            self.refused("prev must be null or 64", seq=1, prev=bad)
            self.refused("prev_wave must be null or 64", kind="swarm.echo", stream_id=SWARM, seq=1,
                         prev="b" * 64, prev_wave=bad, sig=jws())

    def test_seq_zero_iff_prev_null(self):
        self.refused("genesis has seq 0", seq=1, prev=None)
        self.refused("genesis has seq 0", seq=0, prev="b" * 64)

    def test_prev_wave_iff_swarm_child(self):
        rule = "prev_wave is non-null iff"
        self.refused(rule, prev_wave="a" * 64)                                   # body genesis
        self.refused(rule, seq=1, prev="b" * 64, prev_wave="a" * 64)             # body child
        self.refused(rule, kind="memory.chat-turn", stream_id=MEMORY, seq=1, prev="b" * 64,
                     prev_wave="a" * 64)
        self.refused(rule, kind="swarm.echo", stream_id=SWARM, prev_wave="a" * 64, sig=jws())
        self.refused(rule, kind="swarm.echo", stream_id=SWARM, seq=1, prev="b" * 64, sig=jws())

    def test_unsigned_swarm_frame(self):
        self.refused("must be signed", kind="swarm.echo", stream_id=SWARM)
        self.refused("must be signed", kind="swarm.echo", stream_id=SWARM, seq=1, prev="b" * 64,
                     prev_wave="a" * 64)

    def test_sig_must_be_a_10_detached_jws(self):
        for label, bad in malformed_sigs().items():
            with self.subTest(label):
                self.refused("§10 detached JWS", sig=bad)
        self.assertEqual(build(sig=jws())["sig"], jws())

    def test_payload_must_be_an_object(self):
        for bad in (None, [], "x", 1, True):
            self.refused("payload must be a JSON object", payload=bad)
        self.assertEqual(build(payload={})["payload"], {})

    def test_nesting_depth_limit(self):
        value = [1]                                # a scalar adds no depth
        for _ in range(61):
            value = [value]                        # 62 arrays
        self.assertEqual(build(payload={"a": value})["payload"], {"a": value})   # the frame: depth 64
        self.refused("nesting depth", payload={"a": [value]})                   # depth 65
        self.refused("nesting depth", payload=nest(64))

    def test_canonical_size_limit(self):
        room = R.MAX_CANONICAL_BYTES - len(R.canonical(build(payload={"pad": ""})).encode("utf-8"))
        at_limit = build(payload={"pad": "x" * room})
        self.assertEqual(len(R.canonical(at_limit).encode("utf-8")), R.MAX_CANONICAL_BYTES)
        self.refused("1048577 octets", payload={"pad": "x" * (room + 1)})        # 1 MiB + 1 octet
        self.refused("over the 1 MiB", payload={"pad": "\u00e9" * (room // 2 + 1)})  # UTF-8 octets count
        self.refused("over the 1 MiB", payload={"pad": "\x01" * (room // 6 + 1)})    # JCS escapes count

    def test_member_names_nfc_and_assigned_at_any_depth(self):
        for key in ("e\u0301", "\u212b", "\u0378"):   # decomposed é, ANGSTROM SIGN, unassigned U+0378
            for payload in ({key: 1}, {"outer": {key: 1}}, {"list": [{"x": [{key: 1}]}]}):
                with self.subTest(key=key, payload=payload):
                    self.refused("NFC|unassigned", payload=payload)
        self.assertEqual(build(payload={"text": "e\u0301"})["payload"]["text"], "e\u0301")  # values verbatim
        self.assertEqual(build(payload={"\u00e9": {"\u00c5": 1}})["payload"], {"\u00e9": {"\u00c5": 1}})

    def test_regenesis_producer_rules(self):
        ok, step, why = R.verify_frame(regenesis(), head=None, stream_id_of_record=BODY,
                                       signature_verifier=trust_all)
        self.assertTrue(ok, (step, why))
        build(kind="memory.re-genesis", stream_id=MEMORY, sig=jws(), payload=migrated())
        build(kind="swarm.re-genesis", stream_id=SWARM, sig=jws(), payload=migrated(stream_id=SWARM))
        self.refused("re-genesis", kind="body.re-genesis", payload=migrated())             # unsigned
        self.refused("re-genesis", kind="body.re-genesis", payload=migrated(), sig=jws(), seq=1,
                     prev="b" * 64)
        for payload in ({}, {"migrated_from": {}}, {"migrated_from": [1]}, dict(migrated(), extra=1),
                        migrated(extra=1), migrated(stream_id=PROVISIONAL),
                        migrated(terminal_seal="C" * 64), migrated(terminal_seq=True),
                        migrated(terminal_seq=2**53), migrated(terminal_seq=7.0)):
            with self.subTest(payload=payload):
                self.refused("re-genesis", kind="body.re-genesis", payload=payload, sig=jws())
        self.assertIsNone(build(kind="body.re-genesis-note")["sig"])   # not exactly "re-genesis"


def verify(frame, head=None, sid=BODY, verifier=trust_all, **kw):
    return R.verify_frame(copy.deepcopy(frame), head=head, stream_id_of_record=sid,
                          signature_verifier=verifier, **kw)


class TestConsumerStep1(unittest.TestCase):
    """FR-7 (+ E-9, E-10, E-22): the registry-free part of §7.5 step 1."""

    def assertStep(self, result, step, fragment=""):
        ok, got, why = result
        self.assertFalse(ok, why)
        self.assertEqual(got, step, why)
        self.assertIn(fragment, why)

    def test_provisional_stream_id_refused_at_step_1_without_registry(self):
        frame = rehash(dict(build(), stream_id=PROVISIONAL))       # C014/06, R017
        self.assertStep(verify(frame, sid=None), "1", "stream_id")
        self.assertStep(verify(frame, sid=PROVISIONAL), "1", "stream_id")    # before 1a
        self.assertStep(verify(rehash(dict(build(), stream_id="s-1")), sid=None), "1", "stream_id")

    def test_kind_label_lengths_at_step_1(self):
        for bad in ("body." + "p" * 65, "b" * 65 + ".pulse"):       # L4 / R078 probe
            with self.subTest(kind=bad):
                self.assertStep(verify(rehash(dict(build(), kind=bad))), "1", "kind")
        self.assertTrue(verify(rehash(dict(build(), kind="body." + "p" * 64)))[0])

    def test_malformed_sig_is_step_1_never_step_6(self):
        for label, bad in malformed_sigs().items():                 # F005, F006, F008, F012, CI-7
            with self.subTest(label):
                frame = build()
                frame["sig"] = bad                                   # frame_hash excludes sig
                self.assertStep(verify(frame), "1", "§10 detached JWS")
                self.assertStep(verify(frame, verifier=None), "1", "§10 detached JWS")

    def test_well_formed_sig_reaches_step_6(self):
        frame = dict(build(), sig=jws())
        self.assertStep(verify(frame, verifier=None), "6", "trusted signature verifier is required")
        self.assertTrue(verify(frame)[0])

    def test_seq_not_uint53_refused_at_step_1(self):
        # E-9 and FR-2 at the frame, with dict values (the hashes are not recomputed:
        # step 1 comes first, and the reference canonicalizer refuses floats and 2^53).
        for bad in (-0.0, 0.0, 1.0, 2**53, 2**53 + 1, -1, True, False, "0", None):
            with self.subTest(seq=bad):
                self.assertStep(verify(dict(build(), seq=bad)), "1", "seq not uint53")
        self.assertTrue(verify(rehash(dict(build(), seq=2**53 - 1, prev="b" * 64)), sid=BODY,
                               head={"seq": 2**53 - 2, "payload_hash": "b" * 64, "utc": UTC})[0])

    def test_regenesis_payload_shape_at_step_1(self):
        self.assertTrue(verify(regenesis())[0])
        for payload in (dict(migrated(), extra=1), migrated(extra=1), {"migrated_from": None},
                        {}, migrated(stream_id=PROVISIONAL), migrated(terminal_seal="c" * 63),
                        migrated(terminal_seq=-1), migrated(terminal_seq=True),
                        migrated(terminal_seq=7.0)):
            with self.subTest(payload=payload):
                frame = dict(regenesis(), payload=payload)
                try:
                    rehash(frame)
                except ValueError:
                    pass        # a float the reference canonicalizer refuses; step 1 comes first
                self.assertStep(verify(frame), "1", "re-genesis")

    def test_near_miss_regenesis_kind_is_an_ordinary_kind(self):
        self.assertTrue(verify(build(kind="body.re-genesis-note", payload={}))[0])
        self.assertTrue(verify(build(kind="body.regenesis", payload={}))[0])

    def test_payload_names_are_never_checked_at_verify(self):
        for payload in ({"e\u0301": 1}, {"\u0378": 1}, {"a": [{"\u212b": {"e\u0301": 2}}]}):
            with self.subTest(payload=payload):
                frame = rehash(dict(build(), payload=payload))
                self.assertEqual(verify(frame), (True, None, "ok"))

    def test_a_non_object_frame_is_step_1(self):
        for bad in ([], "frame", None):
            self.assertEqual(R.verify_frame(bad)[:2], (False, "1"))


class TestConsumerStep4And6(unittest.TestCase):
    """FR-12, E-22: re-genesis at step 4 (seq 0, prev null) and step 6 (signed)."""

    def test_regenesis_at_seq_1_refused_at_step_4_even_with_a_head(self):
        head = build()
        frame = rehash(dict(regenesis(), seq=1, prev=head["payload_hash"], utc=LATER))
        ok, step, why = verify(frame, head=head)
        self.assertEqual((ok, step), (False, "4"), why)
        self.assertIn("re-genesis", why)
        ok, step, why = verify(frame)
        self.assertEqual((ok, step), (False, "4"), why)

    def test_regenesis_with_a_prev_refused_at_step_4(self):
        frame = rehash(dict(regenesis(), prev="b" * 64))
        ok, step, why = verify(frame)
        self.assertEqual((ok, step), (False, "4"), why)
        self.assertIn("re-genesis", why)

    def test_unsigned_regenesis_refused_at_step_6(self):
        frame = dict(regenesis(), sig=None)                          # R037 probe
        for kw in ({}, {"registry": registry()}):
            ok, step, why = verify(frame, **kw)
            self.assertEqual((ok, step), (False, "6"), why)
            self.assertIn("owner-signed", why)


class TestRegistryIntegration(unittest.TestCase):
    """E-11, E-12, FR-12: verify_frame(registry=...) at steps 1, 4 and 6."""

    def test_registry_is_a_keyword_only_parameter(self):
        params = inspect.signature(R.verify_frame).parameters
        self.assertEqual(list(params)[:4], ["frame", "head", "stream_id_of_record", "signature_verifier"])
        self.assertEqual(params["registry"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(params["registry"].default)
        self.assertEqual(list(inspect.signature(R.build_frame).parameters),
                         ["kind", "stream_id", "seq", "utc", "payload", "prev", "prev_wave", "sig"])
        spec = importlib.util.spec_from_file_location(
            "rapp_agent_rev17", os.path.join(ROOT, "agents", "rapp_sdk_builder_agent.py"))
        agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(agent)
        agent_registry = inspect.signature(agent.verify_frame).parameters["registry"]
        self.assertEqual((agent_registry.kind, agent_registry.default), (inspect.Parameter.KEYWORD_ONLY, None))

    def test_deprecated_kind_accepted_at_step_1(self):
        frame = build(kind="memory.chat-turn", stream_id=MEMORY)       # F007 probe
        self.assertEqual(verify(frame, sid=MEMORY, registry=registry()), (True, None, "ok"))

    def test_family_stream_mismatch_and_unregistered_kind_refused_at_step_1(self):
        for kind, stream in (("body.pulse", MEMORY), ("memory.chat-turn", BODY),
                             ("swarm.echo", BODY), ("acme.unknown", BODY)):
            with self.subTest(kind=kind, stream=stream):
                ok, step, why = verify(build(kind=kind, stream_id=stream), sid=stream, registry=registry())
                self.assertEqual((ok, step), (False, "1"), why)
                self.assertIn("registry binding", why)

    def test_registered_genesis_mismatch_without_head_refused_at_step_4(self):
        genesis = build()
        mismatch = registry({"type": "genesis", "stream_id": BODY, "frame_hash": "d" * 64, "deprecated": False})
        ok, step, why = verify(genesis, registry=mismatch)                # FR-15 probe
        self.assertEqual((ok, step), (False, "4"), why)
        self.assertIn("registered genesis", why)
        match = registry({"type": "genesis", "stream_id": BODY, "frame_hash": genesis["frame_hash"],
                          "deprecated": False})
        self.assertEqual(verify(genesis, registry=match), (True, None, "ok"))
        child = build(seq=1, utc=LATER, payload={"n": 2}, prev=genesis["payload_hash"])
        self.assertEqual(verify(child, head=genesis, registry=mismatch), (True, None, "ok"))

    def test_no_genesis_entry_accepted(self):
        self.assertEqual(verify(build(), registry=registry()), (True, None, "ok"))
        elsewhere = registry({"type": "genesis", "stream_id": MEMORY, "frame_hash": "d" * 64, "deprecated": False})
        self.assertEqual(verify(build(), registry=elsewhere), (True, None, "ok"))

    def test_regenesis_must_be_signed_by_the_owner(self):
        reg = registry()
        self.assertEqual(verify(regenesis(), registry=reg, verifier=honours_expected_signer), (True, None, "ok"))
        ok, step, why = verify(regenesis(kid=STRANGER), registry=reg, verifier=honours_expected_signer)
        self.assertEqual((ok, step), (False, "6"), why)
        self.assertIn("required signer", why)
        ok, step, why = verify(dict(regenesis(), sig=None), registry=reg, verifier=honours_expected_signer)
        self.assertEqual((ok, step), (False, "6"), why)

    def test_regenesis_owner_is_the_one_in_effect_at_its_utc(self):
        reg = registry(spki_entry(OLD_OWNER, OLD_SPKI, deprecated=True), REANCHOR)
        for kid, when, accepted in ((OLD_OWNER, BEFORE_REANCHOR, True), (OWNER, BEFORE_REANCHOR, False),
                                    (OWNER, UTC, True), (OLD_OWNER, UTC, False)):
            with self.subTest(kid=kid, utc=when):
                ok, step, why = verify(regenesis(kid=kid, utc=when), registry=reg,
                                       verifier=honours_expected_signer)
                self.assertEqual((ok, step), (True, None) if accepted else (False, "6"), why)

    def test_regenesis_shape_and_position_with_a_registry(self):
        reg = registry()
        extra = rehash(dict(regenesis(), payload=dict(migrated(), extra=1)))
        self.assertEqual(verify(extra, registry=reg, verifier=honours_expected_signer)[:2], (False, "1"))
        head = build()
        seq1 = rehash(dict(regenesis(), seq=1, prev=head["payload_hash"], utc=LATER))
        self.assertEqual(verify(seq1, head=head, registry=reg, verifier=honours_expected_signer)[:2], (False, "4"))

    def test_registry_questions_follow_the_checklist_order(self):
        rec = RecordingRegistry()
        self.assertEqual(verify(rehash(dict(build(), stream_id=PROVISIONAL)), sid=None, registry=rec)[1], "1")
        self.assertEqual(rec.calls, [])                          # every registry-free step-1 check first
        rec = RecordingRegistry(bound=(False, "kind family mismatch"))
        ok, step, why = verify(build(), sid=MEMORY, registry=rec)   # step 1 is reported before 1a
        self.assertEqual((step, rec.calls), ("1", ["check_frame_binding"]))
        rec = RecordingRegistry(genesis={"frame_hash": "d" * 64})
        self.assertEqual(verify(dict(build(), payload={"n": 2}), registry=rec)[1], "2")   # 2 before 4
        self.assertEqual(rec.calls, ["check_frame_binding"])
        rec = RecordingRegistry()
        self.assertEqual(verify(build(), registry=rec), (True, None, "ok"))
        self.assertEqual(rec.calls, ["check_frame_binding", "registered_genesis"])
        rec = RecordingRegistry()
        self.assertEqual(verify(regenesis(), registry=rec, verifier=honours_expected_signer), (True, None, "ok"))
        self.assertEqual(rec.calls, ["check_frame_binding", "registered_genesis", "owner_at"])
        rec, genesis = RecordingRegistry(), build()
        child = build(seq=1, utc=LATER, prev=genesis["payload_hash"])
        self.assertEqual(verify(child, head=genesis, registry=rec), (True, None, "ok"))
        self.assertEqual(rec.calls, ["check_frame_binding"])    # a head: no genesis lookup

    def test_a_failing_registry_refuses_and_never_crashes(self):
        class Broken(RecordingRegistry):
            def check_frame_binding(self, frame):
                raise RuntimeError("registry unavailable")
        self.assertEqual(verify(build(), registry=Broken())[:2], (False, "1"))


class TestRegistryLifecycle(unittest.TestCase):
    """FR-9 / E-23 (kind deprecation) and FR-10 / E-21 (the spki `deprecated` flag)."""

    SIGNER_SPKI = b"stand-in signer SPKI"
    SIGNER = "rappid:@acme/signer:" + R.Hb("rapp/1:rappid", SIGNER_SPKI)

    def test_family_of_a_deprecated_kind(self):
        reg = registry()
        self.assertEqual(reg.family("memory.chat-turn"), "memory")      # deprecated entry
        self.assertEqual(reg.family("body.pulse"), "body")
        self.assertIsNone(reg.family("acme.unknown"))
        self.assertEqual(reg.check_frame_binding(build(kind="memory.chat-turn", stream_id=MEMORY)), (True, "ok"))

    def test_deprecated_spki_with_no_reanchor_is_acceptable(self):
        reg = registry(spki_entry(self.SIGNER, self.SIGNER_SPKI, deprecated=True))   # F023 probe
        self.assertEqual(reg.signer_acceptable(self.SIGNER, UTC), (True, "ok"))
        self.assertEqual(reg.spki_der(self.SIGNER), self.SIGNER_SPKI)             # still resolves the key

    def test_reanchor_supersession_and_tombstones_still_refuse(self):
        reg = registry(spki_entry(OLD_OWNER, OLD_SPKI, deprecated=True), REANCHOR)
        self.assertEqual(reg.signer_acceptable(OLD_OWNER, BEFORE_REANCHOR), (True, "ok"))
        ok, why = reg.signer_acceptable(OLD_OWNER, UTC)
        self.assertFalse(ok)
        self.assertIn("superseded", why)
        tomb = {"type": "tombstone", "rappid": self.SIGNER, "revoked_utc": BEFORE_REANCHOR, "sig": "owner-signed"}
        for deprecated in (False, True):
            reg = registry(spki_entry(self.SIGNER, self.SIGNER_SPKI, deprecated=deprecated), tomb)
            self.assertEqual(reg.signer_acceptable(self.SIGNER, "2026-04-01T00:00:00.000Z"), (True, "ok"))
            ok, why = reg.signer_acceptable(self.SIGNER, UTC)
            self.assertFalse(ok)
            self.assertIn("tombstoned", why)

    def test_unknown_kid_is_still_refused(self):
        ok, why = registry().signer_acceptable(STRANGER, UTC)
        self.assertFalse(ok)
        self.assertIn("no spki entry", why)


if __name__ == "__main__":
    unittest.main()
