# Chapter 1 — A Tutorial Introduction

Let us begin with the smallest complete RAPP program that does something real: it creates a
record, addresses it by its content, and verifies it. In the tradition of the book this one is
named after, we do not start by explaining every rule. We start by making something work, and
then we go back and understand why it worked.

## 1.1 Getting Started

Everything in this chapter runs against `rapp.py`, which needs nothing but a Python 3
standard library. From the repository root:

```
python3 examples/01_hello_frame.py
```

Here is the program:

```python
import rapp as R

stream = R.mint_rappid("kody", "hello")          # 1. an identity for the stream
frame = R.build_frame(                             # 2. a record in that stream
    kind="note.write",
    stream_id=stream,
    seq=0,
    utc="2026-07-15T12:00:00.000Z",
    payload={"text": "hello, frame"},
    prev=None,
)
ok, step, why = R.verify_frame(frame, head=None, stream_id_of_record=stream)  # 3. check it
print("OK" if ok else f"FAILED at {step}: {why}")
```

Three calls: mint an identity, build a frame, verify it. That is a complete transaction in
RAPP. When you run it, `build_frame` prints the whole record, and the last line prints `OK`.

The record it built looks like this:

```json
{
  "spec": "rapp/1",
  "kind": "note.write",
  "stream_id": "rappid:@kody/hello:b62415b2…",
  "seq": 0,
  "utc": "2026-07-15T12:00:00.000Z",
  "payload": { "text": "hello, frame" },
  "payload_hash": "3e04704309e6069a…",
  "prev": null,
  "prev_wave": null,
  "sig": null,
  "frame_hash": "d82aea005209630d…"
}
```

Eleven fields, always exactly these eleven. Two of them are hashes the library computed for
you: `payload_hash` and `frame_hash`. Understanding what those two are — and why there are
*two* — is most of understanding RAPP.

## 1.2 The Particle and the Wave

Look at the two hashes. `payload_hash` is the SHA-256 of the payload alone. `frame_hash` is the
SHA-256 of the whole frame (minus the signature and minus itself). They answer two different
questions, and a frame is deliberately built to answer both at once.

`payload_hash` is what we call the **particle**. It is the address of *what happened* — the
content of this moment, independent of where it sits. When you chain frames into a biography,
each frame points back to the previous frame's particle. The particle is the worldline.

`frame_hash` is the **wave**. It is the address of *this exact record on the wire* — envelope
and all: the seq, the timestamp, the stream it belongs to. When a frame travels across a
network and you need to know it arrived unaltered, byte for byte, you check the wave.

A frame is one object that is both. You do not choose between them when you emit; you emit one
frame and the reader observes whichever address the situation calls for. This is the resolution
of a real bug in the ecosystem's history, where two teams built "the frame" — one hashing the
payload, one hashing the whole envelope — under the same version number, and the two could
never read each other. RAPP's frame carries both hashes so the question "which one is *the*
hash?" never has to be asked. It is a particle when you follow the worldline and a wave when
you check the wire. (Chapter 5 is entirely about the frame; this is the intuition.)

## 1.3 Chaining: a Worldline

One frame is a fact. A *chain* of frames is a biography, and it is tamper-evident. Run:

```
python3 examples/02_build_a_chain.py
```

The core of it is a loop where each frame's `prev` is the previous frame's particle:

```python
chain, head = [], None
for seq, (utc, payload) in enumerate(events):
    prev = head["payload_hash"] if head else None
    fr = R.build_frame("diary.entry", stream, seq, utc, payload, prev=prev)
    ok, step, why = R.verify_frame(fr, head=head, stream_id_of_record=stream)
    assert ok
    chain.append(fr); head = fr
```

`verify_frame` here is doing chain checks as well as content checks: it insists that `seq` is
contiguous, that `prev` equals the head's particle, and that time does not run backwards. Three
frames in, you have a verified worldline.

Now watch it defend itself. Suppose an attacker wants to rewrite the past — change what the
first frame said. The example does exactly that, in the smartest way available to the attacker,
and the chain still catches it:

```
naive edit of frame 0's payload → frame 0 verify: REJECTED at step 2 — payload_hash mismatch  ✓
attacker fixes frame 0's hash   → frame 0 verify: frame_hash mismatch
…but the chain link at frame 1  → verify: REJECTED at step 4 — prev != head payload_hash  ✓
```

Three layers, and you have to beat all three. Edit the payload and the *particle* no longer
matches (step 2). Recompute the particle to cover that, and now the *wave* no longer matches
(step 3), because the frame_hash covered the old particle. Recompute the wave too, and you have
a self-consistent forged frame 0 — but its new particle is not what frame 1 recorded as its
`prev` (step 4), and to fix *that* you must forge frame 1, and frame 2, and every frame to the
head. The chain converts "rewrite one moment" into "rewrite the entire history from that moment
forward," which is exactly the property we wanted.

## 1.4 Identity, Done Once

We called `mint_rappid("kody", "hello")` and got back a string like
`rappid:@kody/hello:b62415b2…`. The human-readable part — `@kody/hello` — is a convenience.
The identity is the 64-hex tail, and where that tail comes from is the single most important
rule in RAPP's identity system:

> The tail is minted **once**, from entropy or from a public key. It is **never** the hash of
> the name.

Run `python3 examples/03_identity.py` and it will show you the forbidden thing explicitly:
`sha256("kody/twin")` is a tail that *anyone* who names something `kody/twin` will compute — it
collides by construction. That exact mistake was live in production in this ecosystem, an
identity derived as `sha256("<owner>/<slug>")`, and chapter 4 is about why it is fatal and how
mint-once fixes it. For now, the rule: names are for humans; the minted tail is the identity.

## 1.5 Where We Are

In one chapter you have built a frame, understood it as both particle and wave, chained frames
into a tamper-evident worldline, watched the chain reject a forgery, and met the identity rule.
That is the spine of the protocol. Everything from here is precision:

- **How** exactly a value becomes bytes, so two implementations agree to the last byte
  (chapter 2).
- **How** the hashes are domain-separated so a payload address can never be confused with a
  frame address (chapter 3).
- The **full** identity grammar and the three lawful ways to re-anchor one (chapter 4).
- The **complete** frame: all eleven fields, the verify checklist, forks and re-genesis
  (chapter 5).
- The **wire** that carries frames — `POST /chat` — and the swarm streams (chapter 6).
- The **egg**, which packages an entire organism into one content-addressed file (chapter 7).
- And then chapter 8, where we point all of this at a real, drifted estate and watch the
  protocol tell conformance from drift, byte by byte.

Read `rapp.py` now if you like — it is short, and you have already used most of it.
