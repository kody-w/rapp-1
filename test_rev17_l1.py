"""rev-17 L1: canonicalization, hashing, identity and time (SPEC §4, §5, §6.2, §7.4 utc).

One test class per item of the Phase 4 triage report; probe names (F000, C021/07,
vendor 6_rappid.keyed_mint, ...) are the report's. Run: python3 -m unittest test_rev17_l1
"""
import hashlib
import importlib.util
import math
import os
import struct
import unittest
import uuid
from unittest import mock

import parity_check
import rapp as R
import rapp_profile as P
import rapp_registry as REG

ROOT = os.path.dirname(os.path.abspath(__file__))
ED25519_PREFIX = "302a300506032b6570032100"
P256_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200"
# The RFC 8032 §7.1 TEST 1 public key under the RFC 8410 prefix, and the P-256 base point G (SEC 2 §2.4.2).
ED_TEST1 = bytes.fromhex(ED25519_PREFIX + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
P256_G = bytes.fromhex(
    P256_PREFIX + "04"
    + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)


class RefusalCase(unittest.TestCase):
    def assertRefused(self, fn, *args):
        with self.subTest(fn=fn.__name__, args=ascii(args)[:80]):
            with self.assertRaises(ValueError):
                fn(*args)


class TestCI1Noncharacters(RefusalCase):
    """CI-1 / E-3, §4 (b): no noncharacter or unpaired surrogate in any string or member name."""
    BAD = ["\ufdd0", "\ufdef", "\ufffe", "\uffff", "\U0001fffe", "\U0001ffff", "\U0010fffe", "\U0010ffff",
           "\ud800", "\udfff", "a\udc00b"]
    GOOD = ["\ufdcf", "\ufdf0", "\ufffd", "\U0010fffd", "\ufeff", "\U0001f600", "\ue000", "\u00e9"]

    def test_canonical_refuses_strings_and_member_names(self):
        for s in self.BAD:
            for value in (s, [s], {"k": s}, {s: 1}, {"a": {"b": [s]}}):
                self.assertRefused(R.canonical, value)

    def test_every_hash_over_a_value_refuses(self):
        for s in self.BAD:
            self.assertRefused(R.H, "rapp/1:particle", {"text": s})
            self.assertRefused(R.H, "rapp/1:wave", {s: None})

    def test_neighbouring_code_points_accepted(self):
        for s in self.GOOD:
            with self.subTest(cp=ascii(s)):
                self.assertEqual(R.canonical({s: s}), '{"' + s + '":"' + s + '"}')

    def test_strict_json_refuses_the_probes(self):
        for text in (bytes.fromhex("22f48fbfbf22"),                        # F000: "U+10FFFF" as UTF-8
                     b'"\\ufdd0"', b'"\\uFFFE"', b'"\\udbff\\udfff"',          # escaped noncharacters
                     b'"\\ud800"', b'"\\udc00x"', b'["\\ud800\\u0041"]',       # unpaired surrogates
                     b'{"\\uffff":1}', '{"\ufdd0":1}'.encode("utf-8"), b'["\xef\xbf\xbe"]'):
            self.assertRefused(R._strict_json, text)

    def test_strict_json_accepts_a_surrogate_pair_and_an_inner_bom(self):
        self.assertEqual(R._strict_json(b'"\\ud83d\\ude00"'), "\U0001f600")
        self.assertEqual(R._strict_json(b'["\\ufeff"]'), ["\ufeff"])
        self.assertEqual(R._strict_json('["\ufeff"]'.encode("utf-8")), ["\ufeff"])


class TestCI2CI3Encoding(RefusalCase):
    """CI-2, CI-3 / E-4, §4: UTF-8 only; a leading byte-order mark is refused, never stripped."""

    def test_leading_bom_refused(self):
        for text in (b"\xef\xbb\xbf{}", bytes.fromhex("efbbbf2222"), "\ufeff{}", "\ufeff[1]"):   # F002, F018
            self.assertRefused(R._strict_json, text)

    def test_utf16_and_utf32_never_transcoded(self):
        texts = [bytes.fromhex("22002200"), bytes.fromhex("5b005d00")]                           # F004, F021
        for codec in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"):
            texts.append('{"a":[1]}'.encode(codec))
        for text in texts:
            self.assertRefused(R._strict_json, text)

    def test_ill_formed_utf8_refused(self):
        for text in (b'"\xff"', b'"\xc0\xaf"', b'"\xed\xa0\x80"', b'"\xe2\x82"', b'"\xf4\x90\x80\x80"'):
            self.assertRefused(R._strict_json, text)

    def test_utf8_text_accepted(self):
        self.assertEqual(R._strict_json('{"\u00e9":"\u00e8"}'.encode("utf-8")), {"\u00e9": "\u00e8"})
        self.assertEqual(R._strict_json(' {"a" : [1 , 2]}\n'), {"a": [1, 2]})
        self.assertEqual(R._strict_json(bytearray(b"[true,null]")), [True, None])


class TestCI10DepthAndSize(RefusalCase):
    """CI-10, §4 (d): only objects and arrays add depth; only the canonical form is bounded by 1 MiB."""

    def test_scalar_inside_the_64th_container_accepted(self):
        value = R._strict_json(("[" * 64 + "1" + "]" * 64).encode())
        for _ in range(63):
            value = value[0]
        self.assertEqual(value, [1])
        R._strict_json(('{"a":' * 63 + "[1]" + "}" * 63).encode())
        R._strict_json(("[" * 64 + "]" * 64).encode())
        self.assertEqual(R._strict_json(b"7"), 7)

    def test_65_nested_containers_refused(self):
        for text in ("[" * 65 + "]" * 65, "[" * 65 + "1" + "]" * 65, '{"a":' * 64 + "{}" + "}" * 64,
                     "[" * 100000 + "]" * 100000):
            self.assertRefused(R._strict_json, text.encode())

    def test_only_the_canonical_form_is_bounded(self):
        body = '"' + "a" * (R.MAX_CANONICAL_BYTES - 2) + '"'
        padded = (" " * 4096 + body + "\n" * 4096).encode()
        self.assertGreater(len(padded), R.MAX_CANONICAL_BYTES)
        self.assertEqual(len(R.canonical(R._strict_json(padded))), R.MAX_CANONICAL_BYTES)
        self.assertEqual(R._strict_json(b" " * (2 * R.MAX_CANONICAL_BYTES) + b"{}"), {})
        self.assertRefused(R._strict_json, ('"' + "a" * (R.MAX_CANONICAL_BYTES - 1) + '"').encode())

    def test_raw_input_guard_is_64_mib(self):
        self.assertEqual(R.MAX_JSON_INPUT_BYTES, 64 * 1024 * 1024)
        self.assertRefused(R._strict_json, b" " * (R.MAX_JSON_INPUT_BYTES + 1))


# RFC 8785 Appendix B, Table 1 (IEEE 754 bit pattern, JSON representation); NaN and Infinity have none.
RFC8785_APPENDIX_B = [
    ("0000000000000000", "0"), ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"), ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"), ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"), ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"), ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def binary64(bits):
    return struct.unpack(">d", bytes.fromhex(bits))[0]


class TestFR1Numbers(RefusalCase):
    """FR-1 / E-2, §4 (c): numbers are binary64, serialized with ECMA-262 Number::toString."""

    def test_rfc8785_appendix_b(self):
        for bits, text in RFC8785_APPENDIX_B:
            with self.subTest(bits=bits):
                self.assertEqual(R.canonical(binary64(bits)), text)
                if bits[0] not in "89" or bits == "8000000000000000":
                    parsed = R._strict_json(text.encode())
                    self.assertEqual(R.canonical(parsed), text)

    def test_rfc8785_appendix_b_nan_and_infinity_refused(self):
        for bits in ("7fffffffffffffff", "7ff0000000000000", "fff0000000000000"):
            self.assertRefused(R.canonical, binary64(bits))
            self.assertRefused(R.H, "rapp/1:particle", {"n": binary64(bits)})

    def test_brief_serializations(self):
        cases = [(0.1, "0.1"), (1e21, "1e+21"), (1e-7, "1e-7"), (5e-324, "5e-324"), (-0.0, "0"), (1.0, "1"),
                 (2**53, "9007199254740992"), (10**21, "1e+21"), (1e20, "100000000000000000000"),
                 (-2**53, "-9007199254740992"), (2**60, "1152921504606847000"), (1.5, "1.5"),
                 (123456789.0, "123456789"), (1e-6, "0.000001"), (1.2e-5, "0.000012"), (-1e300, "-1e+300")]
        for value, text in cases:
            with self.subTest(value=value):
                self.assertEqual(R.canonical(value), text)
                self.assertEqual(R.canonical([value]), "[" + text + "]")

    def test_ints_up_to_2_53_minus_1_unchanged(self):
        for n in (0, 1, -1, 42, 10**15, 2**53 - 1, -(2**53 - 1)):
            self.assertEqual(R.canonical(n), str(n))
        self.assertEqual(R.H("rapp/1:particle", {"x": 1}),
                         hashlib.sha256(b'rapp/1:particle\n{"x":1}').hexdigest())

    def test_inexact_ints_refused(self):
        for n in (2**53 + 1, -(2**53 + 1), 10**23, 2**1024, -(10**400)):
            self.assertRefused(R.canonical, n)

    def test_bool_is_not_a_number(self):
        self.assertEqual(R.canonical([True, False]), "[true,false]")

    def test_f001_probe_hash_matches_the_five(self):
        value = R._strict_json(b'{"@":1E21}')
        self.assertEqual(R.canonical(value), '{"@":1e+21}')
        # The report tags an accept with sha256(canonical({"hash": H})); the five print c5057534f6.
        digest = hashlib.sha256(R.canonical({"hash": R.H("rapp/1:particle", value)}).encode()).hexdigest()
        self.assertTrue(digest.startswith("c5057534f6"))


class TestFR1RoundTripParse(RefusalCase):
    """FR-1, FR-2 / E-2, E-9, §4 (c): a number token is refused iff its binary64 d is not finite or
    Number::toString(d) denotes a different value."""

    def test_refused_tokens(self):
        for token in ("9007199254740993", "-9007199254740993", "1e999", "-1e999", "0.10000000000000001",
                      "1e-400", "100000000000000000000001", "1" * 400, "NaN", "Infinity", "-Infinity",
                      "2.00000000000000000001"):
            self.assertRefused(R._strict_json, token.encode())
            self.assertRefused(R._strict_json, ('{"n":' + token + "}").encode())

    def test_accepted_tokens_and_types(self):
        cases = [("0.1", 0.1, float), ("1E21", 1e21, float), ("9007199254740992", 2**53, int),
                 ("1.0", 1.0, float), ("1e0", 1.0, float), ("0.0", 0.0, float), ("5", 5, int),
                 ("-7", -7, int), ("1e23", 1e23, float), ("2.5E-3", 0.0025, float),
                 ("0e999999999999999999999999", 0.0, float), ("5e-324", 5e-324, float)]
        for token, value, kind in cases:
            with self.subTest(token=token):
                parsed = R._strict_json(token.encode())
                self.assertEqual(parsed, value)
                self.assertIs(type(parsed), kind)

    def test_minus_zero_is_a_float(self):
        parsed = R._strict_json(b"-0")
        self.assertIs(type(parsed), float)
        self.assertEqual(math.copysign(1.0, parsed), -1.0)
        self.assertEqual(R.canonical(parsed), "0")
        self.assertIs(type(R._strict_json(b"0")), int)

    def test_integer_token_that_rounds_parses_to_its_binary64_value(self):
        parsed = R._strict_json(b"100000000000000000000000")          # 10**23 -> d, printed "1e+23"
        self.assertEqual(parsed, int(1e23))
        self.assertEqual(R.canonical(parsed), "1e+23")


def _frame(seq):
    frame = R.build_frame("memory.note", "rappid:@kody/twin:" + "a" * 64, 0, "2026-01-01T00:00:00.000Z",
                          {"n": 1}, None)
    frame["seq"] = seq
    pre = {k: frame[k] for k in frame if k not in ("frame_hash", "sig")}
    frame["frame_hash"] = R.H("rapp/1:wave", pre)
    return frame


class TestFR2SeqAtStepOne(unittest.TestCase):
    """FR-2 / E-2, E-9: seq 2^53, 0.0, 1e0 and -0 pass §4 and are refused at §7.5 step 1."""

    def test_non_uint53_seq_refused_at_step_1(self):
        for token in ("9007199254740992", "0.0", "1e0", "-0", "-1"):
            with self.subTest(seq=token):
                frame = _frame(0)
                octets = R.canonical(frame).replace('"seq":0', '"seq":' + token).encode()
                parsed = R._strict_json(octets)                         # a §4 value: no step-null refusal
                self.assertEqual(R.verify_frame(parsed)[:2], (False, "1"))

    def test_seq_2_53_frame_hashes(self):
        frame = _frame(2**53)
        self.assertEqual(R.verify_frame(frame)[:2], (False, "1"))
        self.assertEqual(R.verify_frame(_frame(0)), (True, None, "ok"))

    def test_spec_as_a_number_refused_at_step_1(self):
        octets = R.canonical(_frame(0)).replace('"spec":"rapp/1"', '"spec":2.1').encode()
        self.assertEqual(R.verify_frame(R._strict_json(octets))[:2], (False, "1"))


class TestCI4Tags(RefusalCase):
    """CI-4 / E-7, §5: each tag belongs to H or to Hb; any other tag or pairing is refused."""
    H_TAGS = ("rapp/1:particle", "rapp/1:wave", "rapp/1:egg-manifest", "rapp/1:sealed-aad",
              "rapp/1:sealed-key-request")
    HB_TAGS = ("rapp/1:egg", "rapp/1:rappid", "rapp/1:grail", "rapp/1:seal")

    def test_listed_tags_hash_by_the_formula(self):
        for tag in self.H_TAGS:
            self.assertEqual(R.H(tag, {"x": 1}), hashlib.sha256(tag.encode() + b'\n{"x":1}').hexdigest())
        for tag in self.HB_TAGS:
            self.assertEqual(R.Hb(tag, b"\x00\xff"), hashlib.sha256(tag.encode() + b"\n\x00\xff").hexdigest())

    def test_the_other_function_refused(self):
        for tag in self.HB_TAGS:
            self.assertRefused(R.H, tag, [])                                  # F003: H(rapp/1:egg, [])
        octets = bytes.fromhex("905092c0460b11c2e3f86c7782323127e768faa896f3531f4d684655a38887621d8a4aae")
        for tag in self.H_TAGS:
            self.assertRefused(R.Hb, tag, octets)                             # F011: Hb(rapp/1:particle, ...)

    def test_unlisted_tags_refused(self):
        for tag in ("x", "", "rapp/1:particle\n", "RAPP/1:particle", "rapp/1:particle ", "rapp/2:particle",
                    "rapp/1:sealed-commitment", None, b"rapp/1:particle"):
            self.assertRefused(R.H, tag, [])
            self.assertRefused(R.Hb, tag, b"")


class TestCI6Utc(unittest.TestCase):
    """CI-6 / E-1, §7.4: 24 ASCII octets, years 0000-9999 on the proleptic Gregorian rule, seconds 00-59."""
    GOOD = ["0000-01-01T00:00:00.000Z", "0000-02-29T00:00:00.000Z", "2000-02-29T12:00:00.000Z",
            "2024-02-29T23:59:59.999Z", "2026-07-15T12:34:56.789Z", "9999-12-31T23:59:59.999Z",
            "0400-02-29T00:00:00.000Z", "2026-04-30T00:00:00.000Z"]
    BAD = ["２０２６-07-15T12:34:56.789Z", "٢٠٢٦-07-15T12:34:56.789Z", "1900-02-29T00:00:00.000Z",
           "2023-02-29T00:00:00.000Z", "0100-02-29T00:00:00.000Z", "2026-07-15T12:34:60.000Z",
           "2026-07-15T24:00:00.000Z", "2026-07-15T12:60:00.000Z", "2026-13-01T00:00:00.000Z",
           "2026-00-01T00:00:00.000Z", "2026-01-00T00:00:00.000Z", "2026-04-31T00:00:00.000Z",
           "2026-07-15t12:34:56.789Z", "2026-07-15T12:34:56.789z", "2026-07-15T12:34:56.78Z",
           "2026-07-15T12:34:56.7890Z", "2026-07-15T12:34:56Z", "2026-07-15T12:34:56.789+00:00",
           "2026-07-15 12:34:56.789Z", "+2026-07-15T12:34:56.789Z", "2026-07-15T12:34:56.789Z\n",
           "2026-07-1５T12:34:56.789Z", "", None, 20260715, b"2026-07-15T12:34:56.789Z"]

    def test_accepted(self):
        for value in self.GOOD:
            with self.subTest(utc=value):
                self.assertTrue(R.utc_valid(value))

    def test_refused(self):
        for value in self.BAD:
            with self.subTest(utc=ascii(value)):
                self.assertFalse(R.utc_valid(value))

    def test_report_probes(self):
        for hex_value in ("efbc92efbc90efbc92efbc962d30372d31355431323a33343a35362e3738395a",   # C021/07
                          "d9a23030302d30372d32375430353a31393a30372e3838365a",                  # F027
                          "d9a23032342d30322d32395431383a32343a31372e3339355a"):                 # F237
            self.assertFalse(R.utc_valid(bytes.fromhex(hex_value).decode("utf-8")))

    def test_frame_step_1(self):
        sid = "rappid:@kody/twin:" + "a" * 64
        ok = R.build_frame("memory.note", sid, 0, "0000-01-01T00:00:00.000Z", {"n": 1}, None)
        self.assertEqual(R.verify_frame(ok), (True, None, "ok"))
        bad = R.build_frame("memory.note", sid, 0, "２０２６-07-15T12:34:56.789Z", {"n": 1}, None)
        self.assertEqual(R.verify_frame(bad)[:2], (False, "1"))


def _uuid(hex_value):
    return mock.patch.object(R.uuid, "uuid4", lambda: uuid.UUID(hex=hex_value))


class TestCI8CI9Mint(RefusalCase):
    """CI-8, CI-9 / E-8, §6.2: a keyed mint needs a real Ed25519 or P-256 SPKI; a keyless mint a UUIDv4."""
    BAD_SPKI = [
        "302a2066616b652d73706b69",                                                      # vendor 6_rappid.keyed_mint
        "bcee54bfba6428ad483e0e5b61954e59a96677786512626e2688dc43b87065ab8b7fb07b3e94fb848dcb0873",  # F050
        ED_TEST1.hex()[:-2],                                                              # truncated
        ED_TEST1.hex() + "00",                                                            # trailing octet
        ED25519_PREFIX + "02" + "00" * 31,                                                # y = 2: not a point
        ED25519_PREFIX + "ed" + "ff" * 30 + "7f",                                         # y = p: non-canonical
        ED25519_PREFIX + "01" + "00" * 30 + "80",                                         # x = 0 with sign 1
        "302a300506032b656e032100" + "09" + "00" * 31,                                    # X25519, not Ed25519
        P256_G.hex()[:-1] + "6",                                                          # off the curve
        P256_PREFIX + "04" + "ff" * 64,                                                   # coordinates >= p
        P256_PREFIX + "06" + P256_G.hex()[54:],                                           # hybrid point
        "3039301306072a8648ce3d020106082a8648ce3d030107032200" + "03" + P256_G.hex()[54:118],  # compressed
        "",
    ]

    def test_real_spkis_minted(self):
        for spki in (ED_TEST1, P256_G):
            rid = R.mint_rappid("kody", "twin", spki_der=spki)
            self.assertEqual(rid, "rappid:@kody/twin:" + R.Hb("rapp/1:rappid", spki))
            self.assertEqual(R.mint_rappid("kody", "twin", spki), rid)
        self.assertEqual(R.mint_rappid("kody", "twin", spki_der=ED_TEST1).rsplit(":", 1)[1],
                         "ba71c721cbd5605b7e155f20d25efb77fecf935449bfc5bf7849da6d577773c4")

    def test_other_octets_refused(self):
        for hex_value in self.BAD_SPKI:
            self.assertRefused(R.mint_rappid, "kody", "twin", bytes.fromhex(hex_value))
        self.assertRefused(R.mint_rappid, "kody", "twin", ED_TEST1.hex())

    def test_non_v4_uuid_refused(self):
        for hex_value in ("af5c44dd59bbfb6f6adf72e192cf3772",      # F069: version 15
                          "00000000000000000000000000000000",      # nil
                          "af5c44dd59bb1b6f8adf72e192cf3772",      # version 1
                          "af5c44dd59bb7b6f8adf72e192cf3772",      # version 7
                          "af5c44dd59bb4b6f0adf72e192cf3772",      # variant 0b0x
                          "af5c44dd59bb4b6fcadf72e192cf3772"):     # variant 0b110
            with _uuid(hex_value):
                self.assertRefused(R.mint_rappid, "kody", "twin")

    def test_v4_uuid_minted(self):
        with _uuid("af5c44dd59bb4b6f8adf72e192cf3772"):
            rid = R.mint_rappid("kody", "twin")
        self.assertEqual(rid.rsplit(":", 1)[1],
                         R.Hb("rapp/1:rappid", bytes.fromhex("af5c44dd59bb4b6f8adf72e192cf3772")))
        a, b = R.mint_rappid("kody", "twin"), R.mint_rappid("kody", "twin")
        self.assertTrue(R.rappid_valid(a) and R.rappid_valid(b) and a != b)


class TestDownstreamIntegerFields(unittest.TestCase):
    """Item 8: canonical() now admits floats and exact binary64 ints, so integer fields check themselves."""
    NOT_UINT53 = (2**53, 1.0, -0.0, True, 10**21, -1)

    def test_registry_seq(self):
        anchor = R.mint_rappid("kody", "owner", spki_der=ED_TEST1)
        for seq in self.NOT_UINT53 + (R._strict_json(b"-0"), R._strict_json(b"1e0")):
            with self.subTest(seq=seq):
                doc = {"schema": "rapp/1-registry", "registry_seq": seq, "entries": [], "sig": None}
                self.assertEqual(
                    REG.load_document(doc, entries_member="entries", trust_anchor=anchor, allow_unsigned=True),
                    ("refused", None, "registry_seq must be uint53"))

    def test_operational_profile_integers(self):
        for value in self.NOT_UINT53:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    P.positive_int(value, "field")
                with self.assertRaises(ValueError):
                    P.bounded_int(value, "field", 0, 10000)
        self.assertEqual(P.positive_int(2**53 - 1, "field"), 2**53 - 1)
        self.assertEqual(P.bounded_int(0, "field", 0, 10000), 0)


class TestAgentSdkParity(unittest.TestCase):
    """Item 9: the agent's embedded canonical/H/Hb, their helpers and tables, mint_rappid and utc_valid."""
    FUNCTIONS = ("canonical", "H", "Hb", "_ijson_string", "_number_to_string", "_ed25519_point_decodes",
                 "_p256_point_on_curve", "_spki_ok", "mint_rappid", "utc_valid")
    TABLES = ("_NOT_IJSON_CHAR", "_H_SPACES", "_HB_SPACES", "_UTC", "_LCLABEL", "_ED25519_SPKI_PREFIX",
              "_P256_SPKI_PREFIX", "_ED25519_P", "_ED25519_D", "_P256_P", "_P256_B")

    @classmethod
    def setUpClass(cls):
        cls.agent_path = os.path.join(ROOT, "agents", "rapp_sdk_builder_agent.py")
        cls.A = parity_check.load("rapp_agent_rev17_l1", cls.agent_path)

    @staticmethod
    def _tables(path, names):
        import ast
        with open(path, encoding="utf-8") as source:
            tree = ast.parse(source.read())
        return {node.targets[0].id: ast.unparse(node) for node in tree.body
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in names}

    def test_source_identical(self):
        with open(os.path.join(ROOT, "rapp.py"), encoding="utf-8") as source:
            ref = parity_check.normalized_defs(source.read(), self.FUNCTIONS)
        with open(self.agent_path, encoding="utf-8") as source:
            agent = parity_check.normalized_defs(source.read(), self.FUNCTIONS)
        for name in self.FUNCTIONS:
            with self.subTest(function=name):
                self.assertIn(name, ref)
                self.assertEqual(ref[name], agent.get(name))
        ref_tables = self._tables(os.path.join(ROOT, "rapp.py"), self.TABLES)
        self.assertEqual(set(ref_tables), set(self.TABLES))
        self.assertEqual(ref_tables, self._tables(self.agent_path, self.TABLES))

    def test_same_behaviour(self):
        A = self.A
        for bits, text in RFC8785_APPENDIX_B:
            self.assertEqual(A.canonical(binary64(bits)), text)
        for value in TestCI6Utc.GOOD + TestCI6Utc.BAD:
            self.assertEqual(A.utc_valid(value), R.utc_valid(value), ascii(value))
        self.assertEqual(A.mint_rappid("kody", "twin", ED_TEST1), R.mint_rappid("kody", "twin", ED_TEST1))
        for hex_value in TestCI8CI9Mint.BAD_SPKI:
            with self.assertRaises(ValueError):
                A.mint_rappid("kody", "twin", bytes.fromhex(hex_value))
        with _uuid("af5c44dd59bbfb6f6adf72e192cf3772"), self.assertRaises(ValueError):
            A.mint_rappid("kody", "twin")
        for bad in ("\ufdd0", {"\uffff": 1}, 2**53 + 1, float("nan")):
            with self.assertRaises(ValueError):
                A.canonical(bad)
        with self.assertRaises(ValueError):
            A.H("rapp/1:egg", [])
        with self.assertRaises(ValueError):
            A.Hb("rapp/1:particle", b"")


if __name__ == "__main__":
    unittest.main()
