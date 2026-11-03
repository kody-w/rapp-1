"""Real Ed25519 lifecycle, state-boundary, and adversarial succession vectors."""

from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import rapp as R
import rapp_succession as S

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "protocols/examples/succession-lifecycle.json"


def identity(slug):
    private = ed25519.Ed25519PrivateKey.generate()
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    rid = R.mint_rappid("succession", slug, der)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return {"rappid": rid, "spki_der_b64": base64.b64encode(der).decode()}, S.SigningKey(pem, rid)


def nomination(owner, successor, *, silence=2, confirm=1):
    return {"schema": S.PROFILE, "owner": copy.deepcopy(owner),
            "successor": dict(successor, name="Test heir"),
            "window": {"silence_days": silence, "confirm_days": confirm}}


class RappSuccessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner, cls.owner_pem = identity("owner")
        cls.heir, cls.heir_pem = identity("heir")
        cls.next_heir, cls.next_pem = identity("next-heir")
        cls.stranger, cls.stranger_pem = identity("stranger")

    def setUp(self):
        shape = json.loads((ROOT / "protocols/examples/layer-lifecycle.json").read_text())[0]["payload"]
        self.stream = self.owner["rappid"] + ":device"
        self.frames = [R.build_frame("shape.genesis", self.stream, 0,
                                    "2026-01-01T00:00:00.000Z", shape, None)]
        self.append("succession.name", nomination(self.owner, self.heir), self.owner_pem)

    def append(self, kind, payload, pem, utc=None):
        frame = S.sign_frame(kind, self.stream, len(self.frames),
                             utc or self.frames[-1]["utc"], payload,
                             self.frames[-1]["payload_hash"], pem)
        self.frames.append(frame)
        return frame

    def pulse(self, pem=None, utc="2026-01-02T00:00:00.000Z"):
        return self.append("succession.pulse",
                           {"schema": S.PROFILE, "head": self.frames[-1]["frame_hash"]},
                           pem or self.owner_pem, utc)

    def handoff(self, reason="silence", *, at="2026-01-04T00:00:00.000Z",
                utc=None, pem=None):
        return self.append("succession.handoff",
                           {"schema": S.PROFILE, "from_head": self.frames[-1]["frame_hash"],
                            "reason": reason, "at": at},
                           pem or (self.owner_pem if reason == "owner" else self.heir_pem),
                           utc or at)

    def test_real_fixture_every_signature_verifies(self):
        frames = S.load_chain(FIXTURE)
        self.assertEqual(len(frames), 5)
        self.assertEqual([f["kind"] for f in frames],
                         ["shape.genesis", "succession.name", "succession.pulse",
                          "succession.handoff", "succession.name"])
        S.validate_chain(frames)
        keys = {}
        for frame in frames:
            if frame["kind"] == "succession.name":
                for key in (frame["payload"]["owner"], frame["payload"]["successor"]):
                    keys[key["rappid"]] = base64.b64decode(key["spki_der_b64"])
            if frame["sig"] is not None:
                header, _, _ = R.parse_detached_jws(frame["sig"])
                self.assertEqual(header["alg"], "EdDSA")
                ok, why = R.verify_detached_jws(
                    {k: v for k, v in frame.items() if k != "sig"},
                    frame["sig"], keys[header["kid"]], header["kid"])
                self.assertTrue(ok, why)
        self.assertEqual(S.state(frames, frames[-1]["utc"])["owner"],
                         frames[-1]["payload"]["owner"]["rappid"])
        self.assertEqual(len({f["stream_id"] for f in frames}), 1)

    def test_state_exact_shape_and_unnamed(self):
        result = S.state(self.frames[:1], self.frames[0]["utc"])
        self.assertEqual(result, {"owner": None, "successor": None, "last_owner_utc": None,
                                  "silence_deadline": None, "confirm_deadline": None,
                                  "status": "unnamed"})
        result = S.state(self.frames, self.frames[-1]["utc"])
        self.assertEqual(set(result), {"owner", "successor", "last_owner_utc",
                                      "silence_deadline", "confirm_deadline", "status"})
        self.assertEqual(result["successor"], {"name": "Test heir", "rappid": self.heir["rappid"]})

    def test_status_boundaries_are_inclusive_to_the_millisecond(self):
        for now, expected in [
            ("2026-01-02T23:59:59.999Z", "owned"),
            ("2026-01-03T00:00:00.000Z", "silent"),
            ("2026-01-03T23:59:59.999Z", "silent"),
            ("2026-01-04T00:00:00.000Z", "handoff-open"),
        ]:
            with self.subTest(now=now):
                result = S.state(self.frames, now)
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["silence_deadline"], "2026-01-03T00:00:00.000Z")
                self.assertEqual(result["confirm_deadline"], "2026-01-04T00:00:00.000Z")

    def test_zero_confirmation_days_opens_without_silent_interval(self):
        self.frames = self.frames[:1]
        self.append("succession.name", nomination(self.owner, self.heir, confirm=0), self.owner_pem)
        self.assertEqual(S.state(self.frames, "2026-01-03T00:00:00.000Z")["status"], "handoff-open")
        self.handoff(at="2026-01-03T00:00:00.000Z")
        S.validate_chain(self.frames)

    def test_pulse_resets_both_windows_even_after_window_opened(self):
        self.pulse(utc="2026-01-08T00:00:00.000Z")
        result = S.state(self.frames, self.frames[-1]["utc"])
        self.assertEqual(result["last_owner_utc"], self.frames[-1]["utc"])
        self.assertEqual(result["silence_deadline"], "2026-01-10T00:00:00.000Z")
        self.assertEqual(result["confirm_deadline"], "2026-01-11T00:00:00.000Z")
        self.handoff(at="2026-01-10T23:59:59.999Z")
        with self.assertRaisesRegex(ValueError, "handoff before the window"):
            S.validate_chain(self.frames)

    def test_early_silence_handoff_is_refused(self):
        self.handoff(at="2026-01-03T23:59:59.999Z")
        with self.assertRaisesRegex(ValueError, "^handoff before the window$"):
            S.validate_chain(self.frames)

    def test_frame_utc_must_reach_claimed_handoff_at(self):
        self.handoff(at="2026-01-04T00:00:00.000Z", utc="2026-01-03T23:59:59.999Z")
        with self.assertRaisesRegex(ValueError, "handoff before the window"):
            S.validate_chain(self.frames)

    def test_silence_handoff_exact_deadline_and_nomination_consumption(self):
        self.handoff()
        result = S.state(self.frames, self.frames[-1]["utc"])
        self.assertEqual(result["owner"], self.heir["rappid"])
        self.assertEqual(result["status"], "inherited")
        self.assertIsNone(result["successor"])
        self.assertIsNone(result["silence_deadline"])
        self.assertIsNone(result["confirm_deadline"])
        self.assertEqual(result["last_owner_utc"], self.frames[-1]["utc"])
        self.pulse(self.heir_pem, utc=self.frames[-1]["utc"])
        S.validate_chain(self.frames)

    def test_owner_handoff_is_deliberate_and_has_no_wait(self):
        self.handoff("owner", at="2025-01-01T00:00:00.000Z",
                     utc="2026-01-01T00:00:00.000Z")
        self.assertEqual(S.state(self.frames, self.frames[-1]["utc"])["owner"], self.heir["rappid"])

    def test_no_nomination_no_pulse_or_handoff(self):
        for kind in ("pulse", "handoff"):
            with self.subTest(kind=kind):
                self.frames = self.frames[:1]
                if kind == "pulse":
                    self.pulse()
                else:
                    self.handoff()
                with self.assertRaisesRegex(ValueError, "no public key|no prior succession name"):
                    S.validate_chain(self.frames)

    def test_no_repeat_handoff_without_new_successor(self):
        self.handoff()
        self.handoff("owner", pem=self.heir_pem)
        with self.assertRaisesRegex(ValueError, "no current successor"):
            S.validate_chain(self.frames)

    def test_new_owner_names_next_successor_and_can_transfer_again(self):
        self.handoff()
        self.append("succession.name", nomination(self.heir, self.next_heir), self.heir_pem)
        self.assertEqual(S.state(self.frames, self.frames[-1]["utc"])["status"], "owned")
        self.handoff("owner", pem=self.heir_pem)
        self.assertEqual(S.state(self.frames, self.frames[-1]["utc"])["owner"], self.next_heir["rappid"])

    def test_previous_owner_is_refused_at_and_after_handoff_utc(self):
        for kind in ("pulse", "name", "handoff"):
            with self.subTest(kind=kind):
                self.frames = self.frames[:2]
                self.handoff()
                if kind == "pulse":
                    self.pulse(utc=self.frames[-1]["utc"])
                elif kind == "name":
                    self.append("succession.name", nomination(self.owner, self.next_heir),
                                self.owner_pem)
                else:
                    self.handoff("owner")
                with self.assertRaisesRegex(ValueError, "superseded owner"):
                    S.validate_chain(self.frames)

    def test_wrong_signers_are_refused_for_every_kind(self):
        attempts = [
            ("succession.name", nomination(self.heir, self.next_heir), self.heir_pem, "current owner"),
            ("succession.pulse", {"schema": S.PROFILE, "head": self.frames[-1]["frame_hash"]},
             self.heir_pem, "current owner"),
            ("succession.handoff", {"schema": S.PROFILE, "from_head": self.frames[-1]["frame_hash"],
                                   "reason": "owner", "at": "2026-01-04T00:00:00.000Z"},
             self.heir_pem, "current owner"),
            ("succession.handoff", {"schema": S.PROFILE, "from_head": self.frames[-1]["frame_hash"],
                                   "reason": "silence", "at": "2026-01-04T00:00:00.000Z"},
             self.owner_pem, "current successor"),
        ]
        for kind, payload, pem, message in attempts:
            with self.subTest(kind=kind, pem=pem.rappid):
                self.frames = self.frames[:2]
                self.append(kind, payload, pem)
                with self.assertRaisesRegex(ValueError, message):
                    S.validate_chain(self.frames)
        self.frames = self.frames[:2]
        self.pulse(self.stranger_pem)
        with self.assertRaisesRegex(ValueError, "no public key"):
            S.validate_chain(self.frames)

    def test_replacing_successor_withdraws_old_nomination(self):
        self.append("succession.name", nomination(self.owner, self.next_heir), self.owner_pem)
        self.handoff()
        with self.assertRaisesRegex(ValueError, "current successor"):
            S.validate_chain(self.frames)

    def test_all_payload_and_nested_objects_are_closed(self):
        name = nomination(self.owner, self.heir)
        values = [(name, lambda p: S.validate_payload("succession.name", p))]
        for field in ("owner", "successor", "window"):
            values.append((name[field], lambda value, field=field:
                           S.validate_payload("succession.name", dict(name, **{field: value}))))
        values += [
            ({"schema": S.PROFILE, "head": "a" * 64},
             lambda p: S.validate_payload("succession.pulse", p)),
            ({"schema": S.PROFILE, "from_head": "a" * 64, "reason": "silence",
              "at": "2026-01-04T00:00:00.000Z"},
             lambda p: S.validate_payload("succession.handoff", p)),
        ]
        for value, validator in values:
            with self.subTest(keys=tuple(value)):
                with self.assertRaises(ValueError):
                    validator(dict(value, extra=True))
                for key in value:
                    with self.subTest(missing=key), self.assertRaises(ValueError):
                        validator({k: v for k, v in value.items() if k != key})

    def test_window_integer_limits_and_boolean_refusals(self):
        for field, invalid in {"silence_days": [0, 3651, True, 1.0, "2", None],
                               "confirm_days": [-1, 366, False, 0.0, "0", None]}.items():
            for value in invalid:
                payload = nomination(self.owner, self.heir)
                payload["window"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    S.validate_payload("succession.name", payload)
        S.validate_payload("succession.name", nomination(self.owner, self.heir, silence=3650, confirm=365))

    def test_plain_name_length_and_nfc(self):
        for value in ("", "x" * 121, None, 1, "cafe\u0301"):
            payload = nomination(self.owner, self.heir)
            payload["successor"]["name"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                S.validate_payload("succession.name", payload)
        for value in ("x", "x" * 120, "Fran\u00e7oise"):
            payload = nomination(self.owner, self.heir)
            payload["successor"]["name"] = value
            S.validate_payload("succession.name", payload)

    def test_both_key_tails_and_real_spki_are_checked(self):
        for field in ("owner", "successor"):
            for update in ({"rappid": self.stranger["rappid"]},
                           {"spki_der_b64": self.stranger["spki_der_b64"]},
                           {"spki_der_b64": "!!!"}, {"spki_der_b64": ""},
                           {"spki_der_b64": None}, {"rappid": "rappid:@a/b:" + "0" * 32},
                           {"spki_der_b64": base64.b64encode(b"not DER").decode()}):
                payload = nomination(self.owner, self.heir)
                payload[field].update(update)
                with self.subTest(field=field, update=update), self.assertRaises(ValueError):
                    S.validate_payload("succession.name", payload)
        payload = nomination(self.owner, self.heir)
        encoded = payload["owner"]["spki_der_b64"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        payload["owner"]["spki_der_b64"] = encoded[:-2] + alphabet[alphabet.index(encoded[-2]) + 1] + "="
        with self.assertRaisesRegex(ValueError, "canonical padded base64"):
            S.validate_payload("succession.name", payload)

    def test_p256_is_not_an_ed25519_nominee(self):
        key = ec.generate_private_key(ec.SECP256R1())
        der = key.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        payload = nomination(self.owner, self.heir)
        payload["successor"].update(rappid=R.mint_rappid("succession", "p256", der),
                                    spki_der_b64=base64.b64encode(der).decode())
        with self.assertRaisesRegex(ValueError, "Ed25519 DER SPKI"):
            S.validate_payload("succession.name", payload)

    def test_unsigned_and_malformed_signatures_are_refused(self):
        for sig in (None, "not-a-jws"):
            frames = copy.deepcopy(self.frames)
            frames[-1]["sig"] = sig
            with self.subTest(sig=sig), self.assertRaisesRegex(ValueError, "signed|JWS"):
                S.validate_chain(frames)

    def test_fake_signature_and_cryptographically_wrong_key_are_refused(self):
        frame = copy.deepcopy(self.frames[-1])
        header, protected, _ = R.parse_detached_jws(frame["sig"])
        frame["sig"] = protected + ".." + base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
        with self.assertRaisesRegex(ValueError, "RAPP refusal at step 6"):
            S.validate_chain(self.frames[:-1] + [frame])
        private = serialization.load_pem_private_key(self.heir_pem, password=None)
        unsigned = {k: v for k, v in self.frames[-1].items() if k != "sig"}
        wrong = private.sign(protected.encode() + b"." + R.canonical(unsigned).encode())
        frame["sig"] = protected + ".." + base64.urlsafe_b64encode(wrong).rstrip(b"=").decode()
        with self.assertRaisesRegex(ValueError, "RAPP refusal at step 6"):
            S.validate_chain(self.frames[:-1] + [frame])
        self.assertEqual(header["kid"], self.owner["rappid"])

    def test_rehashed_payload_and_envelope_tamper_cannot_reuse_signature(self):
        frame = self.frames[-1]
        for payload, utc in [
            (dict(frame["payload"], successor=dict(frame["payload"]["successor"], name="Forged")),
             frame["utc"]),
            (frame["payload"], "2026-01-02T00:00:00.000Z"),
        ]:
            forged = R.build_frame(frame["kind"], self.stream, frame["seq"], utc,
                                   payload, frame["prev"], sig=frame["sig"])
            with self.assertRaisesRegex(ValueError, "RAPP refusal at step 6"):
                S.validate_chain(self.frames[:-1] + [forged])

    def test_wave_references_are_not_particle_links_or_old_heads(self):
        for kind, field in (("succession.pulse", "head"), ("succession.handoff", "from_head")):
            for target in (self.frames[-1]["payload_hash"], self.frames[0]["frame_hash"], "0" * 64):
                payload = {"schema": S.PROFILE, field: target}
                if kind == "succession.handoff":
                    payload.update(reason="owner", at=self.frames[-1]["utc"])
                frames = self.frames + [S.sign_frame(
                    kind, self.stream, 2, self.frames[-1]["utc"],
                    payload, self.frames[-1]["payload_hash"], self.owner_pem)]
                with self.subTest(kind=kind, target=target), self.assertRaisesRegex(ValueError, "previous frame hash"):
                    S.validate_chain(frames)

    def test_base_link_seq_stream_timestamp_and_hash_checks_are_preserved(self):
        for update in ({"prev": "f" * 64}, {"seq": 4},
                       {"stream_id": self.heir["rappid"] + ":device"},
                       {"utc": "2025-01-01T00:00:00.000Z"}):
            old = self.frames[-1]
            fields = dict(kind=old["kind"], stream_id=old["stream_id"], seq=old["seq"],
                          utc=old["utc"], payload=old["payload"], prev=old["prev"],
                          private_key_pem=self.owner_pem)
            fields.update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                S.validate_chain(self.frames[:-1] + [S.sign_frame(**fields)])
        frames = copy.deepcopy(self.frames)
        frames[-1]["payload"]["successor"]["name"] = "Tampered"
        with self.assertRaisesRegex(ValueError, "step 2"):
            S.validate_chain(frames)
        with self.assertRaisesRegex(ValueError, "genesis"):
            S.validate_chain([])

    def test_wrong_schema_hash_reason_and_time_are_refused(self):
        for kind, payload in [
            ("succession.pulse", {"schema": "wrong/1", "head": "a" * 64}),
            ("succession.pulse", {"schema": S.PROFILE, "head": "A" * 64}),
            ("succession.handoff", {"schema": S.PROFILE, "from_head": "a" * 64,
                                    "reason": "death", "at": "2026-01-04T00:00:00.000Z"}),
            ("succession.handoff", {"schema": S.PROFILE, "from_head": "a" * 64,
                                    "reason": "silence", "at": "2026-02-30T00:00:00.000Z"}),
        ]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                S.validate_payload(kind, payload)
        with self.assertRaisesRegex(ValueError, "now_utc"):
            S.state(self.frames, "not a timestamp")

    def test_unknown_succession_kind_is_not_ignored(self):
        frames = self.frames + [R.build_frame(
            "succession.unknown", self.stream, 2, self.frames[-1]["utc"], {},
            self.frames[-1]["payload_hash"])]
        with self.assertRaisesRegex(ValueError, "unknown succession kind"):
            S.validate_chain(frames)

    def test_memory_family_stream_is_required(self):
        frames = [R.build_frame("body.pulse", self.owner["rappid"], 0,
                                "2026-01-01T00:00:00.000Z", {}, None)]
        with self.assertRaisesRegex(ValueError, "memory stream"):
            S.validate_chain(frames)

    def test_interleaving_both_readers_ignore_other_payload_semantics(self):
        import rapp_layer as L

        payload = {"object": L.perform(self.frames[0]["payload"], {"action": "safe_mode", "on": True}),
                   "derived_from": self.frames[0]["frame_hash"],
                   "lens": {"name": "shape_lens", "sha256": L.SOURCE_LENS_SHA256},
                   "params": {"action": "safe_mode", "on": True},
                   "params_hash": R.H("rapp/1:particle", {"action": "safe_mode", "on": True}),
                   "slush_in": None, "caller": {"kind": "person", "name": "Test owner"}, "lease": None}
        self.frames.append(R.build_frame("shape.tile", self.stream, 2,
                                         "2026-01-02T00:00:00.000Z", payload,
                                         self.frames[-1]["payload_hash"]))
        self.pulse(utc="2026-01-02T00:00:00.000Z")
        self.frames.append(R.build_frame(
            "shape.gate", self.stream, 4, "2026-01-03T00:00:00.000Z",
            {"tile": self.frames[2]["frame_hash"], "gate": "live", "passed": True, "evidence": {}},
            self.frames[-1]["payload_hash"]))
        self.assertEqual(S.state(self.frames, self.frames[-1]["utc"])["last_owner_utc"],
                         "2026-01-02T00:00:00.000Z")
        self.handoff(at="2026-01-05T00:00:00.000Z")
        self.assertTrue(L.ShapeChain(self.frames).authorised()[0]["safe_mode"])
        S.validate_chain(self.frames)
        frames = copy.deepcopy(self.frames)
        frames[-1]["sig"] = None
        with self.assertRaisesRegex(ValueError, "signed"):
            L.ShapeChain(frames)

    def test_signed_unrelated_frame_is_checked_but_never_counts_as_life(self):
        original = self.frames[-1]
        unsigned = R.build_frame("shape.gate", self.stream, 2, "2026-01-02T00:00:00.000Z",
                                 {"uninterpreted": True}, original["payload_hash"])
        header, protected, _ = R.parse_detached_jws(original["sig"])
        key = serialization.load_pem_private_key(self.owner_pem, password=None)
        signature = key.sign(protected.encode() + b"." + R.canonical(
            {k: v for k, v in unsigned.items() if k != "sig"}).encode())
        unsigned["sig"] = protected + ".." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        self.frames.append(unsigned)
        self.assertEqual(S.state(self.frames, unsigned["utc"])["last_owner_utc"], original["utc"])
        unsigned["sig"] = protected + ".." + base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
        with self.assertRaisesRegex(ValueError, "step 6"):
            S.validate_chain(self.frames)
        self.assertEqual(header["kid"], self.owner["rappid"])

    def test_year_zero_leap_days_and_overflow_are_explicit(self):
        for value, tomorrow in [
            ("0000-02-28T23:59:59.999Z", "0000-02-29T23:59:59.999Z"),
            ("0000-12-31T00:00:00.000Z", "0001-01-01T00:00:00.000Z"),
            ("2028-02-28T12:34:56.789Z", "2028-02-29T12:34:56.789Z"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(S._stamp(S._instant(value, "test") + S.DAY_MS), tomorrow)
        with self.assertRaisesRegex(ValueError, "past year 9999"):
            S._stamp(S._instant("9999-12-31T00:00:00.000Z", "test") + S.DAY_MS)

    def test_signing_helper_needs_public_identity_not_hidden_state(self):
        payload = {"schema": S.PROFILE, "head": self.frames[-1]["frame_hash"]}
        with self.assertRaisesRegex(ValueError, "SigningKey"):
            S.sign_frame("succession.pulse", self.stream, 2, self.frames[-1]["utc"],
                         payload, self.frames[-1]["payload_hash"], bytes(self.owner_pem))
        wrong = S.SigningKey(self.owner_pem, self.heir["rappid"])
        with self.assertRaisesRegex(ValueError, "keyed rappid"):
            S.sign_frame("succession.pulse", self.stream, 2, self.frames[-1]["utc"],
                         payload, self.frames[-1]["payload_hash"], wrong)
        first = self.pulse()
        self.frames.pop()
        second = self.pulse()
        self.assertEqual(first, second)

    def test_loader_strict_jsonl_and_no_input_mutation(self):
        original = copy.deepcopy(self.frames)
        S.validate_chain(self.frames)
        projection = S.state(self.frames, self.frames[-1]["utc"])
        projection["successor"]["name"] = "Changed locally"
        self.assertEqual(self.frames, original)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "chain.jsonl"
            path.write_text("\n".join(R.canonical(f) for f in self.frames) + "\n")
            self.assertEqual(S.load_chain(path), self.frames)
            path.write_text('{"kind":"succession.name","kind":"succession.pulse"}\n')
            with self.assertRaises(ValueError):
                S.load_chain(path)


if __name__ == "__main__":
    unittest.main()
