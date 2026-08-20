---
layout: book
title: The Frame
book_label: Chapter 5
book_progress: 44
description: Build the eleven-field RAPP event envelope
---

[← Chapter 4: Identity](04-identity.md) · [Book contents](README.md) ·
[Chapter 6: The Wire →](06-the-wire.md)

# Chapter 5 — The Frame

> **In this chapter:** construct the closed eleven-field envelope, derive particle before wave,
> follow the six verification steps, detect forks, and converge an immutable legacy chain without
> rewriting it.

The frame is the heart of RAPP. It is the record of a single moment in an agent's life:
tamper-evident, content-addressed, chained to the moment before it, and verifiable by a stranger.
Chapters 2, 3, and 4 exist to make this chapter's object trustworthy. Here we specify it in full.

## 5.1 The Eleven Fields

A frame is a JSON object with **exactly** these eleven keys — always all of them, never more,
never fewer:

```python
FRAME_KEYS = {"spec", "kind", "stream_id", "seq", "utc", "payload",
              "payload_hash", "frame_hash", "prev", "prev_wave", "sig"}
```

| field          | type            | meaning                                                    |
|----------------|-----------------|------------------------------------------------------------|
| `spec`         | `"rapp/1"`      | the protocol tag; a frame that is not `rapp/1` is not one  |
| `kind`         | `"a.b"` string  | the event type — `noun.verb`, lowercase labels             |
| `stream_id`    | string          | the rappid (or `net:` swarm id) this frame belongs to      |
| `seq`          | uint53          | position in the chain; genesis is `0`, then contiguous     |
| `utc`          | fixed 24-char   | `YYYY-MM-DDTHH:MM:SS.mmmZ` — millisecond UTC, always Z     |
| `payload`      | object          | the content of the moment (any I-JSON object)              |
| `payload_hash` | 64hex           | the **particle**: `H("rapp/1:particle", payload)`          |
| `frame_hash`   | 64hex           | the **wave**: `H("rapp/1:wave", frame∖{frame_hash,sig})`   |
| `prev`         | 64hex \| null   | previous frame's particle (null only at genesis)           |
| `prev_wave`    | 64hex \| null   | previous frame's wave, on swarm streams; else null         |
| `sig`          | string \| null  | detached JWS signature (chapter 8); null if unsigned       |

The insistence on *exactly* eleven keys is deliberate and it is a lesson from real drift. When a
frame may carry arbitrary extra fields, those fields become an unversioned side-channel that two
implementations will fill differently, and you are back to two dialects under one name. The frame
is closed. New information goes in the `payload` (which is yours to shape) or becomes a new
optional field in a new revision of the *one* spec — never an ad-hoc key.

There is also no "absent vs null" ambiguity. `prev` at genesis is present and `null`, not
missing. `verify_frame` refuses a frame whose key set is not exactly the eleven — conformance
vector V8 — so a reader never has to guess whether a missing field meant null or meant the writer
used a different schema.

## 5.2 Building a Frame: Particle Then Wave

Order matters when you build. The particle is computed from the payload; the wave is computed
from the whole frame *including* the particle but *excluding* the wave itself and the signature:

```python
def build_frame(kind, stream_id, seq, utc, payload, prev, prev_wave=None, sig=None):
    payload_hash = H("rapp/1:particle", payload)          # 1. particle first
    frame = {"spec": "rapp/1", "kind": kind, "stream_id": stream_id, "seq": seq,
             "utc": utc, "payload": payload, "payload_hash": payload_hash,
             "prev": prev, "prev_wave": prev_wave, "sig": sig}
    pre = {k: frame[k] for k in frame if k not in ("frame_hash", "sig")}
    frame["frame_hash"] = H("rapp/1:wave", pre)           # 2. wave over everything else
    return frame
```

Excluding `sig` from the wave is what lets you sign a frame *after* fixing its content: the
signature covers the `frame_hash`, and the `frame_hash` is stable regardless of whether a
signature is later attached. Excluding `frame_hash` from its own preimage is the obvious
requirement that a hash cannot contain itself.

The build dependency is acyclic:

```text
payload ──particle hash──> payload_hash
   │                            │
   └──────── frame fields ──────┘
                 │
                 └──wave hash──> frame_hash ──optional signing──> sig
```

## 5.3 Verifying a Frame: the §7.5 Checklist

A consumer never trusts a frame's own hash fields; it recomputes them. `verify_frame` is the
canonical checklist, and it returns *which step* failed so that "reject" is always explainable:

1. **Shape & types.** Exactly eleven keys; `spec == "rapp/1"`; `kind` matches `noun.verb`;
   `seq` a uint53; `utc` the fixed 24-char form; `payload` an object; the four hash fields the
   right shape (`prev`/`prev_wave` may be null).
   *(1a) Stream binding.* If the reader knows which stream this should be, `stream_id` must match
   — this is what refuses a genuine frame from stream A replayed into stream B (vector V7).
2. **Particle.** `payload_hash == H("rapp/1:particle", payload)`. Recomputed, not trusted.
3. **Wave.** `frame_hash == H("rapp/1:wave", frame∖{frame_hash,sig})`. Recomputed.
4. **Chain.** At genesis (`head is None`): `seq == 0` and `prev is null`. Otherwise: `seq` is
   `head.seq + 1`, `prev == head.payload_hash`, and `utc >= head.utc` (time does not run
   backward within a chain).
5. **Wire.** On a swarm stream (`net:`) past genesis, `prev_wave == head.frame_hash`; off swarm,
   `prev_wave` must be null.
6. **Signature.** A swarm frame MUST be signed (vector V9); the cryptographic verification of the
   JWS itself is chapter 8.

Steps 2 and 3 are why forgery is a whole-chain problem, as chapter 1 demonstrated: to move a past
payload you must beat the particle, then the wave, then re-forge every `prev` to the head.

## 5.4 Streams, Heads, and Forks

A **stream** is an append-only sequence of frames sharing a `stream_id`. Its **head** is the
highest-seq frame. Appending means: build a frame whose `prev` is the head's particle and whose
`seq` is the head's `seq + 1`, then verify it against the head before you publish.

A **fork** is two frames claiming the same `seq` with the same `prev` — a genuine ambiguity about
what came next. RAPP does not pretend forks cannot happen (networks partition); it makes them
*detectable*. A consumer refuses both branches beyond the fork point. The stream authority
resolves the history through the registry and, when needed, re-genesis (chapter 9); it never
silently overwrites one addressed branch. A reader who has both frames can see the fork exactly
because both are content-addressed.

## 5.5 Re-genesis: Converging an Immutable Chain

Here is the hard case the protocol takes seriously. A chain is immutable by design — that is its
value. So what happens when a chain must change *form*? Chapter 10’s historical baseline used a
legacy envelope. Those addressed bytes could not be edited into RAPP shape, because editing an
immutable chain is a contradiction. The answer is **re-genesis** (§7.6 / §12.1):

1. Compute a terminal seal over the **exact octets** of the old head as they will be retained.
2. Emit a **new** sequence-zero frame in full RAPP form. Its registered family-specific
   `*.re-genesis` kind and payload cite the old stream and terminal seal; its signature is by the
   estate owner.
3. Append a registry `genesis` entry for the new `frame_hash` and deprecate every older genesis
   for that stream. This registry append is the point at which the new chain becomes current.
4. Retain the old frames bit-exact under `legacy/`, never serving or extending them as a live
   chain.

Re-genesis is how "no legacy, converge and delete" (chapter 9) coexists with "an immutable chain
is immutable": you do not mutate the old chain, you seal it and are reborn cleanly in the current
form. Each such rebirth is owner-authorized — it is not something an automated sweep may do,
because it is a statement about identity continuity, and only the estate owner speaks that.

## 5.6 Checkpoint: Build a Failure Matrix

Start with a verified genesis frame and make a fresh copy for each mutation:

| Mutation | Expected refusal |
|---|---|
| remove `prev_wave` | step 1, wrong key set |
| change `stream_id` in place | step 3, wave mismatch |
| present it as another stream without changing bytes | step 1a, stream binding |
| change `payload` | step 2, particle mismatch |
| change `utc` | step 3, wave mismatch |
| set genesis `seq` to 1 and rebuild hashes | step 4, genesis rule |
| set non-swarm `prev_wave` | step 5, wire rule |
| build an unsigned `net:*` frame | step 6, signature rule |

The ordering is useful operationally. A step-2 failure says the payload address is false; a step-3
failure says the envelope address is false; a step-4 failure can involve two individually valid
frames that do not form one history.

## 5.7 Exercises

**Exercise 5-1.** Run `examples/05_failure_atlas.py`, then add one malformed `kind`, one boolean
`seq`, and one invalid UTC. All three must stop at step 1.

**Exercise 5-2.** List the exact nine fields in the wave preimage. Explain why removing any field
or retaining `sig` would create a different protocol.

**Exercise 5-3.** Given an unordered set of individually valid frames, detect two children with
the same `(stream_id, seq, prev)` and different waves. Do not choose a winner. *A selected solution
appears in Appendix C.*

**Exercise 5-4.** Implement a remembered-head store that refuses lower sequences and a different
wave at an already observed sequence.

**Exercise 5-5.** Add calendar-valid UTC checking to a verifier. Test leap years, month length,
hour 24, leap second 60, offsets, and fractional precision.

## 5.8 Chapter Summary

- A frame always has exactly eleven keys; absent and null are not interchangeable.
- The producer computes particle first, then wave, then optionally signs.
- The consumer validates shape and binding before recomputing addresses and chain links.
- Biography streams chain particles; swarm streams also chain waves and require signatures.
- Forks are surfaced and owner-resolved, never auto-merged.
- Re-genesis changes the registered live beginning without changing retired bytes.

The frame is a small object with a large discipline. Next: the two forms that carry it.

---

[← Chapter 4: Identity](04-identity.md) · [Book contents](README.md) ·
[Chapter 6: The Wire →](06-the-wire.md)
