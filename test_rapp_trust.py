#!/usr/bin/env python3
"""RAPP Trust vectors: the score moves only on evidence, and binds autonomy."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

import rapp as R
import rapp_trust as T

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "protocols/examples/trust-lifecycle.json"
T0 = "2026-11-08T14:00:00.000Z"
LATER = "2026-11-08T15:00:00.000Z"
MUCH_LATER = "2026-11-09T15:00:00.000Z"


def wager(claim="the gates are green", klass="release", stake=10, counter=0, by=MUCH_LATER):
    return {"schema": "trust.wager", "claim": claim, "class": klass, "stake": stake, "counter": counter,
            "evidence_required": ["run URL"], "settles_by": by}


def settle(h, outcome="lost", evidence=("https://example.test/run/1",), note=""):
    return {"schema": "trust.settle", "wager": h, "outcome": outcome, "evidence": list(evidence), "note": note}


class RappTrustTests(unittest.TestCase):
    def fresh(self):
        frames = [T.genesis_frame("kody-w", "claude-fable", T0)]
        return T.TrustLedger(frames, LATER)

    def add(self, led, kind, payload, when=LATER):
        frame = led.append(kind, payload, when)
        return T.TrustLedger(led.frames + [frame], led.now), frame

    def test_fixture_replays_and_scores(self):
        if not FIXTURE.exists():
            self.skipTest("fixture not built yet")
        led = T.TrustLedger(json.loads(FIXTURE.read_text()), MUCH_LATER)
        self.assertEqual(led.score, 91)          # lost 10, won 1
        self.assertEqual(led.autonomy, "ordinary")

    def test_genesis_starts_at_100_and_is_single(self):
        led = self.fresh()
        self.assertEqual((led.score, led.autonomy), (100, "ordinary"))
        g = copy.deepcopy(led.frames[0]["payload"])
        with self.assertRaises(ValueError):
            self.add(led, "trust.genesis", g)

    def test_lost_wager_costs_the_stake_and_win_returns_a_tenth(self):
        led = self.fresh()
        led, w = self.add(led, "trust.wager", wager(stake=20, klass="destructive"))
        led, _ = self.add(led, "trust.settle", settle(w["frame_hash"], "lost"))
        self.assertEqual(led.score, 80)
        led, w2 = self.add(led, "trust.wager", wager(stake=30, klass="release"))
        led, _ = self.add(led, "trust.settle", settle(w2["frame_hash"], "won"))
        self.assertEqual(led.score, 83)

    def test_owner_counter_is_what_a_win_pays(self):
        led = self.fresh()
        led, w = self.add(led, "trust.wager", wager(stake=10, counter=25))
        led, _ = self.add(led, "trust.settle", settle(w["frame_hash"], "won"))
        self.assertEqual(led.score, 125)

    def test_void_moves_nothing(self):
        led = self.fresh()
        led, w = self.add(led, "trust.wager", wager())
        led, _ = self.add(led, "trust.settle", settle(w["frame_hash"], "void"))
        self.assertEqual(led.score, 100)

    def test_stake_minimums_by_class_and_maximum(self):
        led = self.fresh()
        for klass, low in (("done", 4), ("release", 9), ("destructive", 19)):
            with self.assertRaises(ValueError):
                led.append("trust.wager", wager(klass=klass, stake=low))
        with self.assertRaises(ValueError):
            led.append("trust.wager", wager(stake=51))
        led.append("trust.wager", wager(klass="statement", stake=1))

    def test_stake_cannot_exceed_score(self):
        led = self.fresh()
        for _ in range(3):
            led, w = self.add(led, "trust.wager", wager(stake=20, klass="destructive"))
            led, _ = self.add(led, "trust.settle", settle(w["frame_hash"], "lost"))
        self.assertEqual(led.score, 40)
        with self.assertRaises(ValueError):
            led.append("trust.wager", wager(stake=41, klass="release"))

    def test_settlement_needs_evidence_even_when_lost(self):
        led = self.fresh()
        led, w = self.add(led, "trust.wager", wager())
        with self.assertRaises(ValueError):
            led.append("trust.settle", settle(w["frame_hash"], "lost", evidence=()))
        with self.assertRaises(ValueError):
            led.append("trust.settle", settle(w["frame_hash"], "lost", evidence=("it failed",)))
        for ok in ("https://x.test/a", "sha256:" + "0" * 64, "path:evidence/run.log", "log:FAIL at 09:40"):
            led.append("trust.settle", settle(w["frame_hash"], "lost", evidence=(ok,)))

    def test_one_settlement_per_wager_and_no_unknown_wager(self):
        led = self.fresh()
        led, w = self.add(led, "trust.wager", wager())
        led, _ = self.add(led, "trust.settle", settle(w["frame_hash"]))
        with self.assertRaises(ValueError):
            led.append("trust.settle", settle(w["frame_hash"]))
        with self.assertRaises(ValueError):
            led.append("trust.settle", settle("f" * 64))

    def test_expired_open_wager_counts_as_lost_until_settled(self):
        led = self.fresh()
        led, w = self.add(led, "trust.wager", wager(stake=10, by=LATER))
        self.assertEqual(T.TrustLedger(led.frames, LATER).score, 100)
        self.assertEqual(T.TrustLedger(led.frames, MUCH_LATER).score, 90)
        led, _ = self.add(led, "trust.settle", settle(w["frame_hash"], "won"), MUCH_LATER)
        self.assertEqual(T.TrustLedger(led.frames, MUCH_LATER).score, 101)

    def test_autonomy_table(self):
        self.assertEqual(T.autonomy(200), "ordinary")
        self.assertEqual(T.autonomy(80), "ordinary")
        self.assertEqual(T.autonomy(79), "no-irreversible-alone")
        self.assertEqual(T.autonomy(50), "no-irreversible-alone")
        self.assertEqual(T.autonomy(49), "owner-verifies-everything")
        self.assertEqual(T.autonomy(0), "owner-verifies-everything")

    def test_score_is_clamped(self):
        led = self.fresh()
        for _ in range(5):
            led, w = self.add(led, "trust.wager", wager(stake=20, klass="destructive"))
            led, _ = self.add(led, "trust.settle", settle(w["frame_hash"], "lost"))
        self.assertEqual(led.score, 0)

    def test_tampered_frame_is_refused(self):
        led = self.fresh()
        led, w = self.add(led, "trust.wager", wager(stake=10))
        frames = copy.deepcopy(led.frames)
        frames[1]["payload"]["stake"] = 1
        with self.assertRaises(ValueError):
            T.TrustLedger(frames, LATER)

    def test_payload_key_sets_are_closed(self):
        led = self.fresh()
        bad = wager(); bad["extra"] = 1
        with self.assertRaises(ValueError):
            led.append("trust.wager", bad)
        short = wager(); del short["counter"]
        with self.assertRaises(ValueError):
            led.append("trust.wager", short)


if __name__ == "__main__":
    unittest.main()
