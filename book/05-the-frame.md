# Chapter 5 — The Frame

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
| `sig`          | object \| null  | detached JWS signature (chapter 10); null if unsigned      |

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
   JWS itself is chapter 10.

Steps 2 and 3 are why forgery is a whole-chain problem, as chapter 1 demonstrated: to move a past
payload you must beat the particle, then the wave, then re-forge every `prev` to the head.

## 5.4 Streams, Heads, and Forks

A **stream** is an append-only sequence of frames sharing a `stream_id`. Its **head** is the
highest-seq frame. Appending means: build a frame whose `prev` is the head's particle and whose
`seq` is the head's `seq + 1`, then verify it against the head before you publish.

A **fork** is two frames claiming the same `seq` with the same `prev` — a genuine ambiguity about
what came next. RAPP does not pretend forks cannot happen (networks partition); it makes them
*detectable* and gives one resolution rule: the stream's authority (its owner, or for swarm
streams the registry order of chapter 13) picks the canonical branch, and the abandoned branch is
sealed, never silently overwritten. A reader who has both frames can see the fork exactly because
both are content-addressed; nothing is hidden.

## 5.5 Re-genesis: Converging an Immutable Chain

Here is the hard case the protocol takes seriously. A chain is immutable by design — that is its
value. So what happens when a chain must change *form*? The estate's existing frames (chapter 8)
use a legacy envelope; they cannot be edited into RAPP shape, because editing an immutable
chain is a contradiction. The answer is **re-genesis** (§7.6 / §12.1):

1. The old chain is **terminated** with a final frame of a `*.re-genesis` kind, whose payload
   names the successor stream and carries a **seal** — `H("rapp/1:seal", …)` — over the old
   head. The old chain is now closed: never extended, never served as current.
2. A **new** genesis frame (seq 0) begins the successor chain in full RAPP form, its payload
   citing the sealed old head so the lineage is provable.
3. The old frames are **retained under `legacy/`** as a sealed historical record — readable as
   history, never as a live chain (Federal Constitution Amendment III-a). Retention-as-sealed-
   history is not backward compatibility and not drift; only *serving* or *extending* retired
   frames would be.

Re-genesis is how "no legacy, converge and delete" (chapter 8) coexists with "an immutable chain
is immutable": you do not mutate the old chain, you seal it and are reborn cleanly in the current
form. Each such rebirth is owner-authorized — it is not something an automated sweep may do,
because it is a statement about identity continuity, and only the estate owner speaks that.

## 5.6 Growth: One Identity, Many Dimensions

An organism is not shipped finished. It is minted small — a little memory, a name, a pulse — and
then it *grows*, by the only means an append-only chain allows: it appends. Each new faculty is a
**dimension** frame on the body-stream: a memory dimension, a skill, a sonic dimension carrying the
organism's musical DNA and the wake-call it answers to, a device dimension, a visual one, a
capability. Fold them in `seq` order and you have reconstructed what the organism currently is.

The whole of §7.7 is two `kind`s on the *same* eleven-field envelope — `body.dimension` and
`body.reconstructed` — plus the exact shape of their payloads. No new key, no new hash space, no new
wire tag. That restraint is the point: growth is a payload concern, and the envelope stays closed.

Three rules make growth lawful rather than merely possible.

**Identity is minted once and does not move.** The rappid a thing is hatched with is the rappid it
dies with. What changes is its **stage** — a `{name, ordinal}` pair carried *in a payload*, never in
an identifier. This is the distinction the protocol exists to keep straight: a stage is state, and
state has no business inside a name. So every §7.7 payload repeats the organism's `rappid` and a
verifier refuses the frame if it does not byte-equal the `stream_id`. An "upgrade" that quietly
points the biography at a different identity is not growth; it is a substitution, and the checklist
says so at §7.7.1. Stage ordinals may only go up, because a thing that has grown has grown.

**Offspring is not a stage.** Sooner or later an organism produces another organism — a fork, a
child, a variant handed to someone else. That is a *different* thing, and it mints its own rappid
and records a parent pointer in its genesis frame: `{rappid, particle}`, naming the exact frame of
the parent it was taken from. It may inherit fewer dimensions than its parent, never more — a
verifier recomputes the inherited subset against the parent's fold and refuses anything fabricated.
And a parent pointer is legal only at `seq` 0: nothing acquires ancestry in middle age. If you do
not hold the parent stream, the lineage is **unverified** — never quietly clean.

**Media lives outside the frame.** A wake-call is audio; a visual dimension is images; a device
dimension may point at firmware. None of it goes in the JSON. A dimension carries a reference —
domain, hash, media type, byte count — and nothing else:

```json
"media": { "wake-call": { "space": "rapp/1:egg", "hash": "73ee26d2…",
                          "media_type": "audio/wav", "bytes": 2444 } }
```

The `space` is the *same* one chapter 7's egg uses for the octets it packs, so a dimension's media
reference and the egg entry that stores those bytes are literally the same address: pack the wav
into an organism egg and `contents[].hash` matches the frame, byte for byte. A mebibyte of sound
grows the frame by five bytes — the extra digits in `bytes` — which is why a biography full of
music still verifies in milliseconds and still fits under chapter 2's 1 MiB ceiling. Rebuilding an
organism's state never fetches media at all; you need the media only to *play* it.

What ties it together is that the reconstruction is **computed, not asserted**. A
`body.reconstructed` frame says "here is my stage and here are my dimensions," and a conformant
reader ignores that claim, folds the stream itself, and refuses the frame if the two disagree. The
organism does not get to narrate its own history; the chain does. `examples/04_grow_a_dimension.py`
runs the whole arc — hatch, grow a sonic dimension out of real engrams, reach a later stage, pack
the media into an egg, and hatch offspring — in one file you can read in a sitting.

## 5.7 Weight: What an Identity Masses

If an organism grows, the obvious question is *how big is it now*, and RAPP answers it with a word
borrowed from the physical world: **a RAPPID's data size is its weight**. Not a gauge, not a score —
a byte count you can recompute. `frame_weight_bytes` is the canonical length of every frame the
identity has accepted; `asset_weight_bytes` is every external blob those frames reference;
`total_weight_bytes` is the sum, and it must be exactly the sum.

Two rules keep it honest. Weight counts **verified** bytes only — bytes that failed §7.5 were never
part of anything. And weight is **de-duplicated by content address**, so the same frame arriving
through five mirrors weighs once, and one wake-call referenced by six dimensions weighs once. That
is content addressing paying a second dividend: because the hash is the name, "count each thing
once" is a set operation rather than an accounting policy.

Then there is the honest half, which most systems skip. A habitat that holds the octets reports them
as `resident_weight_bytes`; one that only knows the address reports `linked_weight_bytes`, and the
two always sum to the total. If a byte count cannot be established — the same address attested with
two different sizes — that asset weighs **nothing** and is listed as **incomplete**. If a local copy
cannot be confirmed against its hash, it goes back to linked and is listed as **unverified**. Neither
is ever estimated, averaged, or quietly rounded into the total, because a number you guessed at is
not a measurement and pretending otherwise is how ledgers start lying.

What a frame attests is only the habitat-independent part, computed with no store at all, so every
reader on earth gets the same four integers no matter what their disk holds. And a frame cannot weigh
itself — its size would depend on the number it contains — so a growth frame attests the weight of
everything *before* it, which the reader recomputes and refuses on mismatch. An organism cannot
declare itself heavier than its bytes.

Two last cautions. Weight is state: it changes by appending, and it never touches the mint-once name
— a heavier RAPPID is the same RAPPID. And weight is *mass, not skill*. A stage may use it as one
growth axis, but nothing in RAPP infers capability, maturity, or authority from a byte count. What an
organism can do is written in its dimensions and its signatures. `2.4 KiB`, finally, is presentation:
the exact integer is the weight, and the pretty string never enters a payload, a hash, or a comparison.

## 5.8 The Card: Stats You Can Prove, and Guesses Labelled as Guesses

Put the growth and the weight on one card and you have a **stat block**: species, lifecycle stage,
frame height, display height, weight, dimensions, capabilities, traits, completeness. It reads like a
creature card, and that is the point — but a card is only worth as much as the discipline behind each
number, so RAPP sorts them into two piles and never lets them mix.

**Frame height** is the exact pile. It is the verified depth of the append-only chain: how many frames
this identity has actually accepted. Because verify insists on a genesis at `seq` 0 and contiguous
successors after it, the count and `head.seq + 1` are the same number, and a fold that finds them
different refuses. Notice what that buys: a duplicate frame — replayed, re-delivered, mirrored twice —
is rejected at step 4 rather than counted, so height cannot be inflated by repetition any more than
weight can. Neither number is in a payload; both are recomputed from what was accepted.

**Display height** is the presentation pile. A card wants to say a creature is 110 mm tall, so a
**versioned species growth curve** renders millimetres from frame height — in exact integer arithmetic,
so every renderer of `quill-atlas/1` draws the same creature. And the card names the curve version it
used, because a number without its provenance is a rumour. What display height is *not* is worth
stating plainly: it is not identity, it is not protocol, and it is not a physical fact. No organism has
a size in millimetres; a card does. Publish `quill-atlas/2` and the picture changes while every exact
stat stands exactly where it was. And if the species is unknown to the curve, the height is `null` and
the card reports itself incomplete — the same refusal to invent that governs weight.

Species itself sits between the piles. It is declared once in a growth frame and immutable after, for
the same reason stage is mutable: a creature that grows up is the same creature, and a creature of a
different species is a different creature — which means a new rappid, not an edit.

Finally, the card can be **autocompleted**. Given the traits and the lineage, an implementation can
propose the next dimension the way a continuation is proposed for a melody: the parent had a sonic
dimension and this one does not, so here is the obvious next move. RAPP is happy to let you predict —
and ruthless about what a prediction is worth. A proposal is marked `authoritative: false`, carries the
head particle it was computed from so a stale guess is detectable, mutates nothing, and is not even a
valid payload shape, so it cannot be mistaken for content. It projects a frame height and a display
height, both of which follow deterministically — and it refuses to project a **weight**, because a
frame that does not exist has no bytes, and guessing one would be exactly the lie the whole chapter is
built to prevent. The proposal becomes true the only way anything becomes true here: someone appends a
frame, and a verifier accepts it.

## 5.9 The Calling Card: A Non-Secret Link That Can Wake a Verified Identity

The creature card in §5.8 is a derived view for people. A **RAPPID Calling Card** is a different
kind of card: a compact link that lets a runtime find, verify, hydrate, and wake one identity. The
distinction matters. The stat card makes no authority claim; the calling card is signed and its
one-time wake path is a security boundary.

The physical payload is small enough for QR, NFC, or paper:

```text
rappid://link/<percent-encoded-rappid>?m=<manifest-hash>&e=<endpoint>&n=<nonce>
```

Nothing there is a credential. The RAPPID is public identity, `m` is a content address, `e` is an
untrusted HTTPS location ending `.rappid-card.json`, and `n` is a public one-time nonce. Photograph
the card and you have learned no password, API key, cookie, bearer token, or private memory.

Following `e` does not reveal a new card protocol. It returns the same eleven-key frame this chapter
has used all along. A production frame has `kind: "body.calling-card"` and its payload says
`profile: "rappid-card/1"`. The payload is the signed manifest; `m` equals its ordinary
`H("rapp/1:particle", payload)` address; the signature is the frame's ordinary `sig`. The frame's
`stream_id` and the manifest's `rappid` are the same mint-once identity. No wrapper, twelfth key,
new hash tag, or card-specific RAPPID appears.

The manifest binds the facts a wake must not guess: soul hash, optional parent pointer, engram root,
reflex/capability root, protocol/runtime/feature requirements, classification, requested scope,
expiry, revocation location, endpoint origin, one-time continuity challenge, hydration inventory,
and signing key id. Its inventory is an allow-list of content-addressed parts. `soul`, `engram`, and
`reflex-capability` are required, and each is addressed in the existing `rapp/1:egg` octet space.
The manifest can name private engrams by hash; it cannot carry their plaintext.

But a valid signature answers only "did this key sign these bytes?" It does not answer "may this
key issue for that subject?" RAPP answers the second question with a separate signed,
time-scoped authority view. Each issuer is bound either to one exact subject or to an explicit
`card-issuer` delegation. The verifier checks both frame issue time and current time against the
delegation tenure and revocation. A trusted attacker key with the same owner or a plausible slug
gets no inference and no card.

Two other policy inputs are signed rather than passed as convenient booleans and sets. A runtime
policy owns the accepted production/test profile, protocol, runtime, feature superset,
classification ceiling, granted scope, authority root, and registry freshness bound. A separate
revocation view is signed by that authority, sequenced against rollback, fresh, and capable of
revoking the manifest particle, issuer key, or subject independently.

Verification is intentionally sequential:

1. parse the untrusted URI and strict canonical HTTPS endpoint;
2. match `m` to the manifest particle;
3. enforce the exact frame and payload schemas;
4. verify the card JWS, signed runtime policy, signed issuer authorization, signed approved origin,
   and every observed redirect/DNS result;
5. check expiry;
6. verify the signed, fresh, anti-rollback revocation view;
7. satisfy protocol/runtime/features from authenticated policy;
8. satisfy classification and requested scope from authenticated policy;
9. transactionally commit the one-time nonce as `hydrating`;
10. hydrate only the signed inventory and verify every byte count and hash;
11. answer continuity from hydrated state and transactionally commit `awake`.

Only then is the result `awake`. That order keeps policy before disclosure and continuity before
wake. A missing engram fails rather than producing a plausible partial organism. A nonce that
already woke fails as replay. SQLite `BEGIN IMMEDIATE` is the reference linearization point:
`hydrating` survives crashes, so the original connection can resume after restart while threads,
processes, and other connections lose contention. `awake` reaches disk before success returns.

Endpoint handling is equally literal. User-info, any query or fragment marker (even empty), spaces,
backslashes, malformed or non-canonical percent encodings, and non-global IP literals are refused.
The manifest binds one origin, the signed authority policy allow-lists it, and the fetcher rechecks
every redirect URL and resolved IP. A hostname that rebinds to loopback/private/link-local/reserved
space fails before bytes are trusted. Legacy aliases such as `127.1` and `0x7f.0.0.1` never fall
through to DNS. Bounded decoding plus ASCII word boundaries also catches `épasswordé` and
`漢password漢`, matching the JavaScript verifier instead of Python's default Unicode-boundary drift.

The payload is bounded before its particle exists: nesting depth 64, canonical UTF-8 at most 1 MiB.
A 1,100-level structure becomes a named content-address refusal, not a runtime recursion crash, and
every RAPPID/hash/label/profile/connection token consumes its whole string—including rejection of a
terminal newline.

The final challenge is not a shared secret. It is the particle of the exact object containing the
RAPPID, soul hash, parent, both state roots, and URI nonce. The runtime reconstructs that object from
the body it hydrated. Matching it proves that the addressed identity and the hydrated identity are
continuous. It does not grant permission to execute anything: `awake` means verification completed,
not "run instructions found in data."

Debug cards use the same mechanics under `kind: "body.debug-card"` and the explicit
`rappid-card-test/1` token. Their issuer and policy authority RAPPIDs visibly begin
`rappid:@synthetic/`; the signed test policy selects only that profile. Production policy selects
only `rappid-card/1` and refuses synthetic keys without consulting an unauthenticated mode flag.
That refusal is what keeps a green fixture from becoming a production root of trust.

Run `examples/05_rappid_card.py` to reproduce the committed physical URI, verify its canonical
frame and Ed25519 signature, hydrate its three parts, reach `awake`, and watch the second
presentation of the same nonce fail.

The frame, then, is a small object with a large discipline: eleven closed fields, two recomputed
addresses, a six-step verify, a lawful path to converge even the immutable, and room for a thing to
grow up, put on weight, be dealt as a stat card, and wake from a signed calling card — all inside one
unchanging name. Next, how frames travel: the wire.
