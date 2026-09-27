"""rev-17 end to end: the §4 parse-side number and text rules meet the §7.5 checklist (E-2, E-4, E-9; FR-1, FR-2).

A frame's octets are parsed with rapp._strict_json and the value is handed to rapp.verify_frame, as a consumer does.
Run: python3 -m unittest test_rev17_integration
"""
import unittest

import rapp as R

SID = "rappid:@kody-w/twin:" + "a" * 64
UTC = "2026-09-27T00:00:00.000Z"


def genesis_octets(payload=None):
    frame = R.build_frame("body.pulse", SID, 0, UTC, {"n": 1} if payload is None else payload, None)
    return frame, R.canonical(frame).encode("utf-8")


def with_token(octets, member, token):
    """Replace the value of a top-level scalar member in canonical frame octets with a raw number token."""
    text = octets.decode("utf-8")
    key = '"%s":' % member
    start = text.index(key) + len(key)
    end = start
    while text[end] not in ",}":
        end += 1
    return (text[:start] + token + text[end:]).encode("utf-8")


def consume(octets):
    """None when §4 refuses the octets before the checklist, else verify_frame's (ok, step, reason)."""
    try:
        frame = R._strict_json(octets)
    except ValueError:
        return None
    return R.verify_frame(frame, head=None, stream_id_of_record=SID)


class SeqTokens(unittest.TestCase):
    """E-2 and E-9: a token §4 (c) admits but that is not a uint53 is refused at step 1, never before."""

    def test_valid_genesis_round_trips(self):
        _, octets = genesis_octets()
        self.assertEqual(consume(octets), (True, None, "ok"))

    def test_step_1_refusals(self):
        _, octets = genesis_octets()
        for token in ("-0", "9007199254740992", "0.0", "1e0", "-1", "0.5"):
            with self.subTest(token=token):
                result = consume(with_token(octets, "seq", token))
                self.assertIsNotNone(result, "§4 (c) admits %s, so the frame reaches the checklist" % token)
                self.assertEqual(result[:2], (False, "1"))

    def test_refused_before_the_checklist(self):
        _, octets = genesis_octets()
        for token in ("9007199254740993", "1e999", "-1e999", "0.10000000000000001"):
            with self.subTest(token=token):
                self.assertIsNone(consume(with_token(octets, "seq", token)))

    def test_spec_as_a_number_is_step_1(self):
        """C017/05: `spec` 2.1 is a §4 value, so step 1 refuses it (spec != "rapp/1")."""
        _, octets = genesis_octets()
        result = consume(with_token(octets, "spec", "2.1"))
        self.assertEqual(result[:2], (False, "1"))


class PayloadNumbers(unittest.TestCase):
    """FR-1: every §4 (c) number is a value; frames carrying them build, hash and verify."""

    def test_float_payload_builds_and_verifies(self):
        payload = {"ratio": 0.1, "big": 1e21, "tiny": 5e-324, "neg": -0.0, "two53": 2 ** 53}
        frame, octets = genesis_octets(payload)
        self.assertIn('"big":1e+21', octets.decode("utf-8"))
        self.assertIn('"neg":0', octets.decode("utf-8"))
        self.assertIn('"two53":9007199254740992', octets.decode("utf-8"))
        self.assertEqual(consume(octets), (True, None, "ok"))
        self.assertEqual(frame["payload_hash"], R.H("rapp/1:particle", R._strict_json(R.canonical(payload))))

    def test_equal_numbers_hash_equal(self):
        self.assertEqual(R.H("rapp/1:particle", {"x": 1.0}), R.H("rapp/1:particle", {"x": 1}))
        self.assertEqual(R.canonical(R._strict_json(b'{"x":1E21}')), '{"x":1e+21}')


class InputText(unittest.TestCase):
    """E-4: a byte-order mark or UTF-16 frame text is refused before the checklist."""

    def test_bom_and_utf16(self):
        _, octets = genesis_octets()
        self.assertEqual(consume(octets)[0], True)
        self.assertIsNone(consume(b"\xef\xbb\xbf" + octets))
        self.assertIsNone(consume(octets.decode("utf-8").encode("utf-16-le")))
        self.assertIsNone(consume(octets.decode("utf-8").encode("utf-16")))


if __name__ == "__main__":
    unittest.main()
