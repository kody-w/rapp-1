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

§7.7 — dimensional growth: one mint-once identity, many dimensions
  [PASS] V10 a grown body-stream verifies and reconstructs
  [PASS] V10 the fold reaches the declared stage and both dimensions
  [PASS] V10 every growth frame is still exactly the 11-key §7.1 envelope
  [PASS] V10 the profile adds only registry-shaped body-family kinds
  [PASS] V11 one identity across every frame of the growth
  [PASS] V11 the stage changed while the identity did not
  [PASS] V11 an identity swap dressed as growth refused at §7.7.1
  [PASS] V11 a stage regression refused at §7.7.1
  [PASS] V11 a non-advancing dimension version refused at §7.7.4
  [PASS] V11 a dimension frame off the body-stream refused at §7.2
  [PASS] V12 a media reference is the §9 egg address of the same octets
  [PASS] V12 the reference carries domain, hash, media type, and length only
  [PASS] V12 frame size is independent of media size (§4's 1 MiB ceiling holds)
  [PASS] V12 media octets smuggled into the frame refused at §7.7.2
  [PASS] V12 a media hash in a foreign address space refused at §7.7.2
  [PASS] V12 a non-canonical media type refused at §7.7.2
  [PASS] V13 traits_hash is the particle-space address of the traits
  [PASS] V13 a traits/traits_hash mismatch refused at §7.7.3
  [PASS] V13 an asserted fold that differs from the rebuilt one refused at §7.7.6
  [PASS] V13 unordered source pointers refused at §7.7.4
  [PASS] V14 offspring verifies against the resolved parent fold
  [PASS] V14 offspring is a new identity carrying a parent pointer
  [PASS] V14 an unresolved parent fails closed at §7.7.5
  [PASS] V14 an organism claiming itself as parent refused at §7.7.1
  [PASS] V14 ancestry acquired mid-life refused at §7.7.5
  [PASS] V14 an inheritance the parent never had refused at §7.7.5

§7.8 — weight: a RAPPID's data size, in verified bytes
  [PASS] V15 weight is exact integers only — no float ever reaches a payload
  [PASS] V15 total = frames + assets
  [PASS] V15 resident + linked = total
  [PASS] V15 a frame weighs its canonical bytes
  [PASS] V16 the same frames presented twice weigh once
  [PASS] V16 one asset referenced by two dimensions weighs once
  [PASS] V17 with nothing hydrated, every asset is linked
  [PASS] V17 with the octets hydrated, the asset becomes resident
  [PASS] V17 the attested weight is habitat-independent
  [PASS] V18 a local copy that fails §5 is not counted as resident
  [PASS] V18 two sizes for one address makes that size unknown, not averaged
  [PASS] V19 the growth frame attests the weight of everything before it
  [PASS] V19 an organism claiming more weight than its bytes refused at §7.8
  [PASS] V19 weight only grows as the chain appends
  [PASS] V19 gaining weight changed no identity
  [PASS] V20 format_weight renders bytes for humans (presentation only)

§7.9 — the creature card: exact stats, presentation height, and proposals
  [PASS] V21 frame_height == accepted frames == head seq + 1
  [PASS] V21 re-presenting a frame cannot inflate the height (refused at step 4)
  [PASS] V21 …nor can it inflate the weight
  [PASS] V21 one asset under two roles weighs once
  [PASS] V22 the stat block has exactly the §7.9.3 members
  [PASS] V22 stats mirror the fold, not a claim
  [PASS] V22 an unrenderable height is null and the card says it is incomplete
  [PASS] V23 the same species, curve, and height render the same millimetres
  [PASS] V23 a different curve version renders differently and changes nothing else
  [PASS] V23 no display height appears in any frame
  [PASS] V23 changing a declared species refused at §7.9.2
  [PASS] V24 predicting mutated no canonical state
  [PASS] V24 a proposal invents no bytes — a frame that does not exist has no weight
  [PASS] V24 a proposal is not a conformant payload
  [PASS] V24 a proposal becomes authoritative only once appended and verified

§7.10 — RAPPID Calling Card and Debug Card profile
  [PASS] V25 stdlib Ed25519 signing matches RFC 8032 byte-for-byte
  [PASS] V25 a one-bit Ed25519 signature mutation is refused
  [PASS] V26 card fixture: valid
  [PASS] V26 card fixture: expired
  [PASS] V26 card fixture: revoked
  [PASS] V26 card fixture: wrong-manifest-hash
  [PASS] V26 card fixture: reconnect-during-hydration
  [PASS] V26 card fixture: duplicate-replayed-nonce
  [PASS] V26 card fixture: synthetic-key-refused-production
  [PASS] V27 physical payload fixture reproduces the canonical compact URI
  [PASS] V28 manifest bearer token mutation is refused
  [PASS] V28 a nonce awakens exactly once under real persisted replay state
  ── 147 protocol checks, including every required card fixture and mutation
```

Each vector maps to a promise made earlier in the book: V1/V1b is canonicalization (ch. 2), V2 is
domain separation (ch. 3), V3 is mint-once identity (ch. 4), V4–V9 are the frame's build and its
six-step verify (ch. 5), V10–V14 are §7.7 dimensional growth (ch. 5.6) — one organism growing under
one mint-once name, its media held by reference, its offspring minting their own identity — and
V15–V20 are §7.8 weight (ch. 5.7): verified bytes, de-duplicated by content address, resident against
linked, and incompleteness surfaced rather than estimated. V21–V24 are §7.9 stats (ch. 5.8): exact
chain depth that repetition cannot pad, a display height that is deterministic *and* labelled as
presentation, and proposals that read without writing. V25–V28 are §7.10 calling/debug cards
(ch. 5.9): RFC 8032 Ed25519, every ordered accept/refusal fixture, byte-for-byte reproduction of
the physical URI and canonical frame, production rejection of synthetic test material, and
independently re-sealed secret/auto-execute mutations that must stay red. Note how many of them are *refusals*: a
protocol is defined at least as much by what it will not accept as by what it will. This is what
"conformance class" means concretely: an implementation is RAPP-conformant when it produces and
rejects exactly these bytes. Green here is not a clean build; it is the spec exercised against its
own claims.

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
