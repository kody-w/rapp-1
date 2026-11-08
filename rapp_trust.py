#!/usr/bin/env python3
"""Stdlib reference for the RAPP Trust profile: a per-AI trust ledger that is wagered on.

    rapp_trust.py init   LEDGER --owner kody-w --slug claude-fable
    rapp_trust.py wager  LEDGER --claim "..." --class release --stake 10 --needs "run URL" --by 2026-11-08T20:00:00.000Z
    rapp_trust.py settle LEDGER WAGER_HASH --outcome lost --evidence https://... --note "..."
    rapp_trust.py score  LEDGER [--now UTC]
    rapp_trust.py board  LEDGER...            # the estate view: one line per subject

The ledger is JSONL of RAPP/1 frames on a memory-stream. The score is never stored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import rapp as R
from rapp_profile import bounded_int, canonical_object, exact_keys, hex64, label, require, text, utc

PROFILE = "rapp-trust/1"
SPEC_PATH = "protocols/rapp-trust/1/SPEC.md"
SCHEMA = "trust-ledger/1"
KINDS = {"trust.genesis": SCHEMA, "trust.wager": "trust.wager", "trust.settle": "trust.settle"}
BASE = 100
FLOOR, CEILING = 0, 200
MIN_STAKE = {"statement": 1, "done": 5, "release": 10, "destructive": 20}
MAX_STAKE = 50
HIGH_STAKES = ("done", "release", "destructive")
AUTONOMY = ((80, "ordinary"), (50, "no-irreversible-alone"), (0, "owner-verifies-everything"))
GENESIS_KEYS = {"schema", "subject", "owner", "base"}
WAGER_KEYS = {"schema", "claim", "class", "stake", "counter", "evidence_required", "settles_by"}
SETTLE_KEYS = {"schema", "wager", "outcome", "evidence", "note"}
EVIDENCE = re.compile(r"(https://.+|sha256:[0-9a-f]{64}|path:[^\s].*|log:.+)", re.DOTALL)


def validate_genesis(payload: dict, stream_id: str) -> dict:
    p = exact_keys(payload, GENESIS_KEYS, "genesis")
    require(p["schema"] == SCHEMA, "genesis: schema must be trust-ledger/1")
    require(R.rappid_valid(p["subject"]), "genesis: subject must be a rappid")
    require(stream_id.rpartition(":")[0] == p["subject"] and stream_id.endswith(":trust"),
            "genesis: stream must be the subject's rappid with instance 'trust'")
    label(p["owner"], "genesis.owner")
    require(p["base"] == BASE, "genesis: base must be 100")
    return p


def validate_wager(payload: dict, score: int) -> dict:
    p = exact_keys(payload, WAGER_KEYS, "wager")
    require(p["schema"] == "trust.wager", "wager: schema must be trust.wager")
    text(p["claim"], "wager.claim")
    require(p["class"] in MIN_STAKE, "wager: class must be statement, done, release or destructive")
    stake = bounded_int(p["stake"], "wager.stake", 1, MAX_STAKE)
    require(stake >= MIN_STAKE[p["class"]], f"wager: {p['class']} needs a stake of at least {MIN_STAKE[p['class']]}")
    require(stake <= score, f"wager: stake {stake} exceeds the current score {score}")
    bounded_int(p["counter"], "wager.counter", 0, MAX_STAKE)
    needs = p["evidence_required"]
    require(isinstance(needs, list) and 1 <= len(needs) <= 8, "wager: one to eight evidence_required entries")
    for n in needs:
        text(n, "wager.evidence_required[]")
    utc(p["settles_by"], "wager.settles_by")
    return p


def validate_settle(payload: dict, open_wagers: dict) -> dict:
    p = exact_keys(payload, SETTLE_KEYS, "settle")
    require(p["schema"] == "trust.settle", "settle: schema must be trust.settle")
    hex64(p["wager"], "settle.wager")
    require(p["wager"] in open_wagers, "settle: wager is unknown or already settled")
    require(p["outcome"] in ("won", "lost", "void"), "settle: outcome must be won, lost or void")
    ev = p["evidence"]
    require(isinstance(ev, list) and 1 <= len(ev) <= 16, "settle: one to sixteen evidence entries")
    for e in ev:
        require(isinstance(e, str) and len(e) <= 512 and EVIDENCE.fullmatch(e),
                "settle: evidence must be https://, sha256:, path: or log:")
    require(isinstance(p["note"], str) and len(p["note"]) <= 256, "settle.note: at most 256 characters")
    return p


def points_for_win(wager: dict) -> int:
    return wager["counter"] if wager["counter"] > 0 else max(1, wager["stake"] // 10)


def clamp(score: int) -> int:
    return max(FLOOR, min(CEILING, score))


def autonomy(score: int) -> str:
    for floor, name in AUTONOMY:
        if score >= floor:
            return name
    return AUTONOMY[-1][1]


class TrustLedger:
    """Verified chain of one subject; score computed, never stored."""

    def __init__(self, frames: list, now: Optional[str] = None):
        require(isinstance(frames, list) and frames, "ledger: no frames")
        self.frames = frames
        self.now = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"
        utc(self.now, "now")
        self.open: dict = {}
        self.settled: list = []
        head = None
        stream = frames[0]["stream_id"] if isinstance(frames[0], dict) else None
        require(R.stream_form(stream) == "memory-stream", "ledger: stream must be a memory-stream")
        score = BASE
        for i, frame in enumerate(frames):
            ok, step, why = R.verify_frame(frame, head=head, stream_id_of_record=stream, signature_verifier=None)
            require(ok, f"frame {i}: RAPP refusal at step {step}: {why}")
            payload = canonical_object(frame["payload"], f"frame {i}.payload")
            kind = frame["kind"]
            require(kind in KINDS, f"frame {i}: kind {kind} is not a trust kind")
            require(payload.get("schema") == KINDS[kind], f"frame {i}: payload schema does not match kind")
            if i == 0:
                require(kind == "trust.genesis", "frame 0 must be trust.genesis")
                self.genesis = validate_genesis(payload, stream)
            else:
                require(kind != "trust.genesis", f"frame {i}: a ledger has one genesis")
                if kind == "trust.wager":
                    self.open[frame["frame_hash"]] = validate_wager(payload, score)
                else:
                    s = validate_settle(payload, self.open)
                    w = self.open.pop(s["wager"])
                    if s["outcome"] == "lost":
                        score = clamp(score - w["stake"])
                    elif s["outcome"] == "won":
                        score = clamp(score + points_for_win(w))
                    self.settled.append((w, s))
            head = frame
        self.settled_score = score

    @property
    def score(self) -> int:
        expired = sum(w["stake"] for w in self.open.values() if w["settles_by"] < self.now)
        return clamp(self.settled_score - expired)

    @property
    def autonomy(self) -> str:
        return autonomy(self.score)

    def append(self, kind: str, payload: dict, when: Optional[str] = None) -> dict:
        when = when or self.now
        if kind == "trust.wager":
            validate_wager(payload, self.score)
        elif kind == "trust.settle":
            validate_settle(payload, self.open)
        frame = R.build_frame(kind, self.frames[0]["stream_id"], len(self.frames), when,
                              payload, self.frames[-1]["payload_hash"])
        return frame


def load(path: Path, now: Optional[str] = None) -> TrustLedger:
    raw = Path(path).read_bytes()
    if raw.lstrip().startswith(b"["):
        frames = R._strict_json(raw)
    else:
        frames = [R._strict_json(line) for line in raw.splitlines() if line.strip()]
    return TrustLedger(frames, now)


def write_frame(path: Path, frame: dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(frame, sort_keys=True, separators=(",", ":")) + "\n")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def genesis_frame(owner: str, slug: str, when: Optional[str] = None) -> dict:
    subject = R.mint_rappid(owner, slug)
    payload = {"schema": SCHEMA, "subject": subject, "owner": owner, "base": BASE}
    return R.build_frame("trust.genesis", f"{subject}:trust", 0, when or now_utc(), payload, None)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("init"); a.add_argument("ledger", type=Path); a.add_argument("--owner", required=True); a.add_argument("--slug", required=True)
    a = sub.add_parser("wager"); a.add_argument("ledger", type=Path); a.add_argument("--claim", required=True)
    a.add_argument("--class", dest="klass", required=True, choices=sorted(MIN_STAKE)); a.add_argument("--stake", type=int, required=True)
    a.add_argument("--counter", type=int, default=0); a.add_argument("--needs", action="append", required=True); a.add_argument("--by", required=True)
    a = sub.add_parser("settle"); a.add_argument("ledger", type=Path); a.add_argument("wager"); a.add_argument("--outcome", required=True, choices=["won", "lost", "void"])
    a.add_argument("--evidence", action="append", required=True); a.add_argument("--note", default="")
    a = sub.add_parser("score"); a.add_argument("ledger", type=Path); a.add_argument("--now")
    a = sub.add_parser("board"); a.add_argument("ledgers", type=Path, nargs="+"); a.add_argument("--now")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "init":
            require(not args.ledger.exists(), "init: ledger already exists")
            write_frame(args.ledger, genesis_frame(args.owner, args.slug))
            print(f"ledger started at {BASE}: {args.ledger}")
        elif args.cmd == "wager":
            led = load(args.ledger)
            frame = led.append("trust.wager", {"schema": "trust.wager", "claim": args.claim, "class": args.klass,
                                               "stake": args.stake, "counter": args.counter,
                                               "evidence_required": args.needs, "settles_by": args.by}, now_utc())
            write_frame(args.ledger, frame)
            print(f"wager {frame['frame_hash'][:12]} staked {args.stake} (score {led.score}, {led.autonomy})")
        elif args.cmd == "settle":
            led = load(args.ledger)
            full = [h for h in led.open if h.startswith(args.wager)]
            require(len(full) == 1, "settle: wager prefix must match exactly one open wager")
            frame = led.append("trust.settle", {"schema": "trust.settle", "wager": full[0], "outcome": args.outcome,
                                                "evidence": args.evidence, "note": args.note}, now_utc())
            write_frame(args.ledger, frame)
            after = load(args.ledger)
            print(f"{args.outcome}: score {led.score} -> {after.score} ({after.autonomy})")
        elif args.cmd == "score":
            led = load(args.ledger, args.now)
            print(json.dumps({"subject": led.genesis["subject"], "owner": led.genesis["owner"], "score": led.score,
                              "autonomy": led.autonomy, "open": len(led.open), "settled": len(led.settled)}))
        else:
            for p in args.ledgers:
                led = load(p, args.now)
                last = led.settled[-1] if led.settled else None
                ev = f" | last: {last[1]['outcome']} '{last[0]['claim'][:50]}' {last[1]['evidence'][0][:60]}" if last else ""
                print(f"{led.score:3d} {led.autonomy:28s} {led.genesis['subject'].split(':')[1]} open={len(led.open)}{ev}")
    except (OSError, ValueError) as error:
        print(f"rapp-trust refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
