# Chapter 8 — Conformance, and Meeting a Real World

A specification you cannot test is a wish. This chapter is where RAPP stops being a document
and becomes a tool: first the conformance suite that proves the reference implementation obeys the
spec, then a harness that turns the whole apparatus loose on a **real, committed, drifted estate**
and reports, byte for byte, where reality already conforms and where it is the drift the protocol
exists to end.

## 8.1 The Conformance Suite

`conformance.py` is a set of test vectors — the executable form of the rules in chapters 2–5. Run
it:

```
python3 conformance.py
```

```
RAPP rev-5 — conformance vectors
  [PASS] V1  canonicalization is key-order independent
  [PASS] V1b array order IS significant
  [PASS] V2  domain tags separate the address space
  [PASS] V3  keyless mint is not sha256(owner/slug)
  [PASS] V3  rappid matches the §6.1 grammar
  [PASS] V3  keyed tail == Hb('rapp/1:rappid', SPKI)
  [PASS] V3  mint-once determinism for keyed identity
  [PASS] V4  genesis frame builds and verifies
  [PASS] V4  genesis has exactly 11 keys
  [PASS] V5  payload tamper caught at step 2
  [PASS] V5  envelope tamper caught at step 3 (wave)
  [PASS] V6  child frame links to genesis
  [PASS] V6  broken prev caught at step 4
  [PASS] V7  cross-stream genesis replay refused at 1a
  [PASS] V8  missing key refused at step 1 (no absent-vs-null)
  [PASS] V9  unsigned swarm frame refused at step 6
  ── 18 checks | 18 PASS | 0 FAIL
```

Each vector maps to a promise made earlier in the book: V1/V1b is canonicalization (ch. 2), V2 is
domain separation (ch. 3), V3 is mint-once identity (ch. 4), V4–V9 are the frame's build and its
six-step verify (ch. 5). This is what "conformance class" means concretely: an implementation is
RAPP-conformant when it produces and rejects exactly these bytes. Green here is not a clean
build; it is the spec exercised against its own claims.

## 8.2 The Real-World Harness

Green vectors prove *self*-consistency. The harder question is whether the spec matches the world
that already exists. `realcheck.py` answers it. It clones the actual public repositories of the
kody-w estate — `twin`, `rapp-body`, `rapp-commons`, and more — and runs the reference
implementation against **every frame and every rappid that was really committed there**, by other
programs, months before this spec was written. Run it:

```
python3 realcheck.py
```

It walks 32 committed frames and four identity records and reports two things about each: does
RAPP *reproduce* what reality stored, and does reality *conform* to the RAPP envelope.

## 8.3 Where Reality Conforms

The result that matters most:

```
── rapp-body  (29 committed frames) ──
   canonicalization reproduces real stored hash : 29/29 frames
   real chain links per RAPP §7.4 (prev=parent): 29/29 frames
── twin  (3 committed frames) ──
   canonicalization reproduces real stored hash : 3/3 frames
   real chain links per RAPP §7.4 (prev=parent): 3/3 frames
```

Thirty-two frames, written by a different program, and the reference `canonical()` reproduces
**every** stored payload hash byte-for-byte, and **every** chain link holds. This is the whole
bet of chapter 2 paying off in the field: the canonicalizer here and the canonicalizer that wrote
those frames agree, because both are JCS and JCS has one answer. The parts of RAPP that describe
*content addressing and chaining* are not aspirational — they already describe what the live
estate does.

## 8.4 Where Reality Is the Drift

And then, the same 32 frames:

```
   frames conformant to RAPP §7 envelope as-is : 0/29   (rapp-body)
   frames conformant to RAPP §7 envelope as-is : 0/3    (twin)
   real envelope keys: [kernel_version, kind, parent_sha, payload, seq, sha256, sig, spec, ts, twin_id]
```

Zero. Every real frame is rejected at step 1 of the verify checklist, and the reason is exact: the
committed envelope uses `twin_id` where RAPP has `stream_id`, `ts` where RAPP has `utc`,
`sha256` where RAPP has `payload_hash`, `parent_sha` where RAPP has `prev` — and it carries no
`frame_hash`, no `prev_wave`. This is collision **C1** from the drift ledger, live: the frame that
was minted in two incompatible envelopes under one name. The protocol does not paper over it. It
refuses it, and names the aliases.

The identity records tell the same story. Two of the four rappids conform to the §6.1 grammar with
proper 64-hex tails. The other two:

```
   [short-tail/C3]
      twin/rappid.json:        rappid:@kody-w/twin:257afa7958982c28258c1d97701182b1
      rapp-commons/rappid.json: rappid:@kody-w/rapp-commons:3929ce90ebe97fe2a95432e9f647f3a3
```

Thirty-two hex characters, not sixty-four — a 128-bit tail, the short-form name-hash lineage that
chapter 4 outlawed. And all four records still carry `schema: "rapp-rappid/2.0"` rather than
`rapp/1`. Eight drifts in total, and the harness sorts them by category:

```
🔧 IS THE DRIFT RAPP FIXES (8):
   [envelope-drift/C1]  rapp-body/frames, twin/frames
   [short-tail/C3]      twin, rapp-commons
   [schema-label]       all four rappid records
```

## 8.5 What This Proves

Read the two halves together, because together they are the entire argument for the protocol:

> RAPP's canonicalizer reproduces the real committed payload hashes **byte-for-byte** — the spec
> matches reality exactly where reality already content-addresses. RAPP then **refuses** every
> real frame's envelope and every short-tail rappid — and those refusals *are* the eight drifts
> the standard exists to end.

Nothing in that output is a bug in the spec. The refusals are the spec working. The estate is one
owner-authorized **re-genesis** per chain (chapter 5) away from full conformance: seal each legacy
chain, be reborn in the eleven-field frame with a tagged particle, re-anchor the two short-tail
identities to 64-hex, relabel the schema — and `realcheck.py` goes green. Until then, its output
*is* the drift ledger, generated by running code against real bytes rather than asserted in prose.

## 8.6 Fail Closed

One property of the harness deserves a note, because it is the difference between a gate that
protects you and a gate that lies to you. The conformance checker over the live estate is
**fail-closed**: any surface it cannot read is an `ERROR`, never a `PASS`. A checker that greens
because it could not reach a repository has told you "no drift" when it means "I did not look," and
that is the cry-wolf disease in reverse — a false all-clear is worse than a false alarm. The rule,
from Federal Constitution Article IX: law without running code is poetry, and running code that
passes when it is blind is a lie. RAPP's gate looks, or it fails.

That is the protocol, end to end: five primitives, one wire, a reference implementation that
passes its own vectors and reproduces a real estate's hashes, and a fail-closed gate that tells
conformance from drift by computing, not asserting. The appendix that follows is the terse
reference — keep it open while you build.
