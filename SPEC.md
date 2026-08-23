# The RAPP Protocol Suite
### Unified normative specification of identity, canonicalization, the frame, the wire, and the egg

**Status:** Draft standard for ratification (Kody, estate owner). **rev-5.** **Obsoletes / consolidates:**
`rapp-frame/2.0`, `rapp-frame/2.1`, `rapp-rappid-spec/2.0`, `rapp-protocol/1.0`, all scattered egg specs
(§9 subsumes them), and `OSI.md`. On ratification this is the single living standard; the consolidated
specs become retired historical record (Federal Constitution Art. X).

**Rides existing standards; invents nothing:** requirement terms [RFC 2119]/[RFC 8174]; JSON restricted to
I-JSON [RFC 7493] over [RFC 8259]; canonicalization [RFC 8785] (JCS); hashing SHA-256 [FIPS 180-4] with
git-style domain separation; identifiers on the [RFC 3986] URI model; case-sensitive grammar [RFC 7405]
over [RFC 5234] ABNF; keyless entropy UUIDv4 [RFC 9562]; keyed identity X.509 SPKI [RFC 5280]; signatures
detached unencoded JWS [RFC 7515]/[RFC 7797], EdDSA [RFC 8037] / ES256 [RFC 7518]/[RFC 6979]. RAPP is a
*profile* over these, as HTTP profiles TCP/URIs/MIME.

---

## 1. Introduction
RAPP is a content-addressed distributed organism. Its integrity rests on one invariant: **the same
concept has the same bytes everywhere.** This document specifies, normatively and completely, five
load-bearing primitives so any two independent implementations interoperate **byte-for-byte with no
out-of-band agreement**: canonicalization (§4), content addressing (§5), identity (§6), the frame (§7),
the egg (§9) — all riding one wire (§8): `POST /chat`, or a signed append-only frame. Implementations add
agents, cartridges, and registered `kind`s — never new endpoints, never new envelopes.

### 1.1 The layered model
```
  L5  EGG        cartridge packaging (§9)          — MIME-multipart analogue
  L4  FRAME      universal event envelope (§7)     — the IP packet of RAPP
  L3  WIRE       transport: /chat + frames (§8)    — HTTP-analogue single method
  L2  IDENTITY   rappid namespace + trust (§6,§10) — URI + PKI analogue
  L1  ADDRESS    canonicalization + hash (§4,§5)   — the git object model
```
A higher layer **MUST NOT** redefine a lower one. Every layer names exactly one canonical form.

## 2. Requirements language
The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **MAY** are as in [RFC 2119]/
[RFC 8174] when in **bold caps**. (The Federal Constitution adopts the same clause.)

## 3. Terminology
**organism** — a running brainstem with persistent identity. **rappid** — the eternal, mint-once name of an
organism/door/object (§6): minted once from a UUIDv4 or a public key, never derived from content or name.
**frame** — one immutable content-addressed event (§7). **stream** — an append-only hash-chained frame
sequence sharing one `stream_id`. **particle / wave** — a frame's two domain-separated addresses:
payload-hash / whole-frame-hash (§7.3). **canonical form** — the one [RFC 8785] byte string for a value
(§4). **legacy form** — any other historical encoding; legacy is drift and **MUST** be migrated out
(Fed. Const. Art. III), except sealed re-genesis history (§12.1).

## 4. Canonicalization (L1)
`canonical(v)` is the UTF-8 byte string produced by **[RFC 8785] JCS** for the value `v`, defined **only**
over I-JSON [RFC 7493]. JCS fixes member-name ordering (UTF-16 code-unit), string escaping, and number
serialization (ECMAScript `Number::toString`, [ECMA-262]); there is no insignificant whitespace and no
byte-order mark.

**RAPP input-domain profile (parse-side interoperability — this is a RAPP rule, not a JCS mandate).** An
implementation **MUST** refuse (never repair) any JSON value that, at any depth, contains: (a) duplicate
member names in one object; (b) an unpaired UTF-16 surrogate in any string; (c) a number token that does
not survive the binary64 round-trip — let `d` be the token's nearest binary64 value under `roundTiesToEven`
(the IEEE-754 default; ±∞ are admissible results); the token is refused iff `d` is not finite, or the
[RFC 8785] serialization of `d` (ECMA-262 `Number::toString`) denotes a different mathematical value than
the token (so `0.1` is accepted — it round-trips — while `9007199254740993` and `1e999` (→ +∞) are refused); (d) canonical form exceeding 1 MiB or JSON nesting depth
exceeding 64 (the root value is depth 1; each nested object/array adds 1). Refusal is whole (§7.5-style),
never partial.

The depth and 1 MiB limits are checked **before any §5 hash is computed**. A parser or canonicalizer
recursion limit is not a protocol result: an implementation **MUST** convert recursion/depth exhaustion
into the same deterministic whole-value refusal. Read paths **SHOULD** reject raw resources larger than
1 MiB before JSON parsing, then re-check the canonical byte count after parsing.

**No normalization.** RAPP applies **no** Unicode normalization when hashing, storing, or re-emitting an
existing value; strings are code-point sequences preserved verbatim and equality everywhere is code-point
equality (no canonical-equivalence matching). A producer creating a **new** human-or-identifier string
(slug, kind, label, `payload` object key) **MUST** emit it in Unicode NFC.

> **Migration note (drift C4):** the `twin`/`rapp-body` `_frame.mjs::canonicalize()` (sorted-key
> `JSON.stringify`) coincides with JCS only for string-only payloads; it **MUST** be replaced by the JCS
> implementation of record, imported (not re-typed) by every repo that content-addresses.

## 5. Content addressing (L1) — domain-separated
Every hash is **domain-separated** (git's `type\0`, Nix's tagged store — collisions across address spaces
are made unconstructible):
```
H(space, v) = lowercase_hex( SHA-256( utf8(space) || 0x0A || canonical(v) ) )     ; v a value (§4)
Hb(space, b) = lowercase_hex( SHA-256( utf8(space) || 0x0A || b ) )                ; b raw octets
```
`space` is an exact ASCII tag, none containing `0x0A`: `"rapp/1:particle"`, `"rapp/1:wave"`, `"rapp/1:egg"`,
`"rapp/1:egg-manifest"`, `"rapp/1:rappid"`, `"rapp/1:seal"`. A tag is used by either `H` or `Hb`, never
both. Output is always exactly 64 lowercase hex, **never truncated or uppercased**. Two values
are treated as the same object iff their same-space hashes are equal; SHA-256 collision resistance
[FIPS 180-4] is a security assumption of this standard (§14). A `name/X.Y` label is never identity — only
a hash is. A bare 64-hex is meaningful **only** within its space; an implementation **MUST NOT** dereference
a hash from one space as an object of another, and content-addressed stores **MUST** key by `(space, hash)`.

## 6. Identity — the rappid (L2)
### 6.1 Grammar (case-sensitive, [RFC 7405])
```abnf
rappid    = %s"rappid:@" owner "/" slug ":" hash
owner     = lclabel                       ; the lowercase GitHub login (1-39 chars)
slug      = lclabel                        ; 1-100 chars
lclabel   = lcalnum *( ["-"] lcalnum )     ; no leading/trailing/adjacent hyphen
lcalnum   = LCALPHA / DIGIT
LCALPHA   = %x61-7A                         ; a-z
hash      = 64HEXDIGLC
HEXDIGLC  = DIGIT / %x61-66                 ; 0-9 a-f
```
`owner` **MUST** be the lowercase form of the GitHub login (logins are case-insensitive; display casing is
presentation, never identity). Lengths are normative: `owner` 1–39, `slug` 1–100; an implementation
**MUST** refuse longer. This self-locating form is the **only** conformant rappid; `rappid:<slug>:<hash>`,
`rappid:v2:…`, bare UUIDs, `moment:`/name-hash derivations are legacy and **MUST** be migrated out
(Art. III), not read forever.

Every ABNF/token/hex validator consumes the **entire** string. A terminal CR/LF or any other trailing
character is data, not an end anchor, and is refused. Implementations using regular expressions
**MUST** use whole-string matching (`fullmatch` / `\Z`-equivalent), never a `$` behavior that can match
immediately before a final newline.

### 6.1.1 stream_id and kind grammar
```abnf
stream_id   = memory-stream / body-stream / swarm-stream
memory-stream = rappid ":" instance      ; one organism instance's memory
body-stream   = rappid                    ; an organism's biography
swarm-stream  = %s"net:" lclabel          ; a planetary-wire stream
instance      = lclabel                   ; 1-64 chars
kind          = lclabel "." lclabel       ; each label 1-64 chars
```
A `kind` string carries **no intrinsic family**; the §13 registry binds each registered `kind` to exactly
one family. Membership is tested by exact-match against the registry — never prefix inference, never wildcards.

### 6.2 Minting (mint-once)
The 64-hex tail is minted **exactly once** per identity, then immutable:
- **keyless:** `tail = Hb("rapp/1:rappid", uuid4_octets)`, where `uuid4_octets` is the 16-octet binary
  UUIDv4 [RFC 9562] §5.4 (field/byte order per §4 of that RFC).
- **keyed:** `tail = Hb("rapp/1:rappid", SPKI_DER)`, the DER `SubjectPublicKeyInfo` [RFC 5280] of the master key.

A producer **MUST NOT** derive the tail from owner/slug or any name (`sha256("owner/slug")` is prohibited —
drift ID-01/C3). On read of an existing `rappid.json` an implementation **MUST** reuse the stored tail
(canonicalize-on-read) and **MUST NOT** re-mint — with exactly one mechanism: the owner-authorized
**re-anchor** (§6.3), which mints a fresh 64-hex tail once per authorization and records the superseded id
in `_migrated_from`. Re-anchor is lawful in exactly three cases: (a) a 128→256-bit provisional upgrade
(§6.3); (b) §10 key rotation or compromise; (c) migrating a pre-rev-3 keyed tail minted with the un-tagged
`sha256(SPKI)` formula (which fails §10 discovery and **MUST** be re-anchored like a provisional identity).

### 6.3 Canonicalization on read; provisional identifiers
`canonicalize_rappid(s)` restructures any legacy form into §6.1, **preserving the existing hash** (never
inventing one). A restructured identifier whose tail is not exactly 64 lowercase hex (e.g. a legacy 32-hex
tail) is **provisional**: it exists only inside the reading process and **MUST NOT** appear in any emitted
frame, `stream_id`, egg, or registry entry. The one-time owner-authorized 128→256-bit re-anchor mints a
fresh 64-hex, records the old id in `_migrated_from`, and is the only way a provisional identity becomes
usable. A provisional identifier found in a stored artifact is a drift finding (Art. III). Re-anchor is the
single re-mint mechanism (§6.2), lawful only in the enumerated cases: provisional 128→256-bit upgrade,
§10 key rotation/compromise, and pre-rev-3 un-tagged-`sha256(SPKI)` keyed-tail migration.

**A re-anchor is valid only with a verifiable authorization** — a self-asserted `_migrated_from` is
insufficient (it would let anyone hijack an identity). A re-anchor **MUST** be recorded as an owner-signed
§13.3 **re-anchor record** `{old_rappid, new_rappid, case, utc, sig, old_key_sig?}`; a consumer **MUST**
refuse a `new_rappid` (and treat `_migrated_from` as drift) unless that record is present and:
- `case:"rotation"` (uncompromised): `old_key_sig` (a §10 JWS by the **old** key) verifies — proof of
  continuity;
- `case:"compromise"`: `old_key_sig` is waived but a §10 **tombstone** for `old_rappid` is registered in the
  same append;
- `case:"tag-migrate"` (pre-rev-3 keyed tail): the verifier checks `lowercase_hex(SHA-256(SPKI_DER_old))` ==
  the old tail;
- `case:"upgrade"` (provisional 128→256): the old provisional id resolved to this owner at read time.
Each mints one fresh tail. The **estate_owner's own** re-anchor record **MUST** be signed by the outgoing
`estate_owner` key (§13.2); root-key compromise is recovered only by out-of-band re-anchoring (§13.1).

## 7. The Frame (L4)
### 7.1 The envelope — exactly eleven keys
```json
{
  "spec":         "rapp/1",
  "kind":         "<klabel.klabel>",
  "stream_id":    "<stream_id>",
  "seq":          <uint53>,
  "utc":          "YYYY-MM-DDTHH:MM:SS.mmmZ",
  "payload":      { },
  "payload_hash": "<64hex>",
  "frame_hash":   "<64hex>",
  "prev":         "<64hex|null>",
  "prev_wave":    "<64hex|null>",
  "sig":          "<jws|null>"
}
```
- **`spec` MUST be the exact string `"rapp/1"`** in every frame. `rapp-frame/2.0`/`2.1` are legacy tokens
  and **MUST NOT** be emitted. Any revision changing the key set, any field's grammar, or either hash rule
  **MUST** change this token and land an Art. III total migration; revisions adding only new registered
  `kind`s/registry entries keep the token (Fed. Const. Art. II).
- **Exactly these eleven keys, always present**, none missing, none extra. A field that does not apply is
  present with value `null` (`prev`/`prev_wave` at genesis and on non-swarm streams; `sig` when unsigned) — never omitted,
  because [RFC 8785] hashes `null` and an absent key differently. Extra or missing keys are refused (§7.5).
- **`payload` MUST be a JSON object** (possibly empty `{}`); never `null`, array, string, number, or bool.
- `seq` is `uint53` (§7.4). A producer **MUST NOT** emit a frame whose canonical form exceeds 1 MiB or
  nesting depth 64 (§4).

### 7.2 Kind families (one envelope, registry-bound families)
| family | example registered kinds | `stream_id` form | logs |
|---|---|---|---|
| `memory` | `memory.chat-turn`, `memory.tool-call`, `memory.save`, `memory.reconstructed` | memory-stream | one organism's life |
| `swarm`  | `swarm.guidance`, `swarm.echo`, `swarm.telemetry`, `swarm.reconstructed` | swarm-stream | the planetary wire |
| `body`   | `body.pulse`, `body.twin-pulse`, `body.dimension`, `body.reconstructed`, `body.calling-card`, `body.debug-card`, `body.re-genesis` | body-stream | an organism's biography |
Each family also has a `*.re-genesis` kind (`memory.re-genesis`, `swarm.re-genesis`, `body.re-genesis`)
used only by §12.1. The family is **not** the kind's prefix — it is the §13 registry binding (so
`body.twin-pulse` is family `body`). Adding a family or event is a new registered `kind` on the **same** envelope (Art. IV), never a
new frame type. A frame's `kind` family **MUST** be compatible with its `stream_id` form (table column 3).

### 7.3 Particle and wave (the unification)
A frame carries **both** of its domain-separated addresses; a reader collapses it to whichever it needs.
Computed in order:
- **particle** — `payload_hash = H("rapp/1:particle", payload)`. The **worldline identity and chain link**.
- **wave** — `frame_hash = H("rapp/1:wave", frame \ {frame_hash, sig})` — the frame with **exactly** the
  `frame_hash` and `sig` keys removed, all nine remaining keys (including `payload_hash`) present.
Because `payload_hash` is in the wave pre-image, `frame_hash` attests the particle; because only
`frame_hash` (cannot hash itself) and `sig` (signs the result) are removed, the pre-image is unambiguous
and non-circular. Both hashes are always present (never `null`).

### 7.4 Chaining, time, and merge order
- **`utc`** **MUST** be exactly the 24-byte form `YYYY-MM-DDTHH:MM:SS.mmmZ` — uppercase `T`/`Z`, exactly
  three fractional digits, no numeric offset; the seconds field **MUST NOT** be `60` (a leap second clamps
  to `59.999`). All `utc` comparisons are **bytewise** over this fixed form (identical to chronological order).
- **Worldline chain (particle):** the **genesis** frame has `seq`=0 and `prev`=null; every later frame has
  `seq` = predecessor's `seq`+1 (contiguous) and `prev` = predecessor's `payload_hash`. `seq` is `uint53`
  (JSON integer, 0 ≤ seq ≤ 2^53−1, no fraction/exponent; a stream nearing 2^53−1 converges by re-genesis).
- **Wire chain (wave):** `prev_wave` **MUST** be non-null **iff** `stream_id` is a swarm-stream **and**
  `seq` > 0, in which case it equals the predecessor's `frame_hash`; in every other frame (all memory/body
  streams, every genesis) it **MUST** be `null`. (Presence is a function of stream family, not transport.)
- A frame is **immutable**: a new state is a new frame at a new hash; the head pointer (§7.6) re-points.
- **Cross-stream merge order** (Dream-Catcher) is the total order: ascending `utc` (bytewise), ties broken
  by ascending `frame_hash` (bytewise); no further ties are possible (§5).

### 7.5 Verification (the complete consumer checklist)
Before accepting a frame, a consumer **MUST**, in order, **refuse** (never repair/reparent) on any failure:
1. **Shape & types:** exactly the eleven §7.1 keys; `spec`==`"rapp/1"`; `kind` a string matching §6.1.1
   ABNF and registered (§13); `stream_id` a string matching §6.1.1; `seq` a `uint53`; `utc` matching the
   §7.4 fixed form **and** a calendar-valid [RFC 3339] `date-time` (so `2026-13-45T25:61:61.999Z` is
   refused); `payload` a JSON object; `payload_hash`/`frame_hash` `64HEXDIGLC`; `prev`/`prev_wave` each
   `null` or `64HEXDIGLC`; `sig` `null` or a §10 JWS string.
1a. **Stream binding:** `frame.stream_id` **MUST** byte-equal the identifier of the stream being extended
   or read (its declared `stream_id` at the head pointer / repo path of record). A genesis frame is
   accepted only for the stream it names. (Defeats cross-stream genesis/segment replay — §14.)
2. **Particle:** `payload_hash` == `H("rapp/1:particle", payload)`.
3. **Wave:** `frame_hash` == `H("rapp/1:wave", frame \ {frame_hash, sig})`.
4. **Chain:** `seq`==head.`seq`+1 and `prev`==head.`payload_hash` (or `seq`==0 ∧ `prev`==null at genesis);
   `utc` ≥ head.`utc` (bytewise).
5. **Wire:** if `stream_id` is a swarm-stream and `seq`>0, `prev_wave`==head.`frame_hash`; else
   `prev_wave`==null.
6. **Signature:** if `sig`≠null, verify per §10 (present-but-invalid is refusal); a swarm-stream frame with
   `sig`==null is refused (§8/§10).
Steps 1–5 are **time-independent** (kind lookups only append, §13), so a frame passing them passes forever;
step 6 alone may flip pass→fail when a §10 tombstone with `revoked_utc` ≤ the frame's `utc` is later
registered — the one time-dependent check.

### 7.6 Heads and forks
A stream's **head** is the frame with the greatest verified `seq` descending from its registered genesis
(§13). A consumer **MUST** persist, per stream, the highest `(seq, frame_hash)` it verified and **MUST**
refuse any presented head with lower `seq`, or a different `frame_hash` at an already-verified `seq` (no
rollback, no silent reorg). Two distinct valid frames with equal `stream_id`, `seq`, and `prev` are a
**fork**: a consumer **MUST** refuse both branches past the fork point and surface a drift finding; only
the owner resolves a fork (Art. X), by re-genesis (§12.1) if needed.

**Exception (re-genesis head reset).** The no-rollback rule above refuses a lower-`seq` head — but a
legitimate §12.1 re-genesis presents a new genesis at `seq`=0. When (and only when) the §13 registry maps a
`stream_id` to a new genesis `frame_hash` (§12.1 step 3), a consumer **MUST** verify that registered
genesis (§7.5) and then **reset** its persisted head for that `stream_id` to it. Only a registry-published
genesis authorizes a reset; any other lower-`seq` head remains a refused rollback.

### 7.7 Dimensional growth (body-family payload profiles)
An organism is not shipped whole. It is minted small and **grows by appending frames** — a memory
dimension, then a skill, a sonic, a device, a visual, a capability dimension — until it runs a large
body. §7.7 profiles the two `body`-family `kind`s that carry that growth. It adds **no** envelope key,
no wire tag, no canonicalization rule, no hash space, and no identity grammar: it is two §13.3 `kind`
entries and the exact `payload` shape each one carries.

#### 7.7.1 The law of identity through growth
- An organism's `rappid` is minted **exactly once** (§6.2) and is the **same string** at every later
  stage. Growth **MUST NOT** re-mint, re-anchor, or re-point it; the §6.3 re-anchor cases are closed and
  growth is not among them.
- A **lifecycle stage is state**, carried in a `payload`, never in an identifier. A stage **MUST NOT**
  appear in a `rappid`, a `stream_id`, a `kind`, or any hash-bearing identity field, and a stage change
  **MUST NOT** change any of them. In every §7.7 payload `rappid` **MUST** byte-equal the frame's
  `stream_id`; a consumer **MUST** refuse a frame that fails this (it is a re-identification wearing
  growth's clothes — §14 identity forgery), not repair it.
- A stage carries an `ordinal`; along one body-stream the ordinal **MUST** be monotonically
  non-decreasing. A stage **ladder** (which names exist, in what order) is **not** protocol: it is the
  organism's own, and only the token grammar and the monotonicity are normative here.
- **Offspring is not a stage.** A true offspring or fork is a *different organism*: it **MUST** mint a
  new `rappid` (§6.2), begin its own body-stream, and record a **parent pointer** (§7.7.5). An organism
  **MUST NOT** be its own parent, and a parent pointer is lawful **only** in a stream's genesis frame —
  no organism acquires ancestry mid-life. At rest, the offspring's `rappid.json` **SHOULD** also carry
  `parent_rappid` (§6.3), which **MUST** itself be a §6.1 rappid.

#### 7.7.2 Media references (content-addressed, always external)
A frame **MUST NOT** carry media octets. It carries the §5 address of media held outside it:
```json
{ "space": "rapp/1:egg", "hash": "<64hex>", "media_type": "<type/subtype>", "bytes": <uint53> }
```
- **Exactly** those four members; any additional member (a `data`, `data_b64`, `uri`, …) is refused.
  This is the rule that keeps a frame small, a payload under §4's 1 MiB ceiling, and a chain cheap to
  verify regardless of how much sound, image, or firmware an organism owns.
- `space` **MUST** be exactly `"rapp/1:egg"` — the existing §5/§9.1 **octet** space; `hash` **MUST** be
  `Hb("rapp/1:egg", octets)` and `bytes` the octet count. **No new domain tag is introduced.** Because
  §9.1 addresses egg `contents[]` in the same space, a media reference and the egg entry that stores
  those octets are the *same address*, so media resolves out of any store keyed by
  `("rapp/1:egg", hash)` (§5) — an egg, a mirror, or a cache.
- `media_type` is a lowercase [RFC 6838] `type/subtype` with no parameters — a hint for playback,
  never identity (§5: only a hash names an object):
  ```abnf
  media-type      = restricted-name "/" restricted-name
  restricted-name = ( LCALPHA / DIGIT ) *126( LCALPHA / DIGIT / "!" / "#" / "$" / "&" /
                                              "^" / "_" / "." / "+" / "-" )
  ```
- A consumer **MUST NOT** dereference a media `hash` in any other space (§5, §14 address-space confusion),
  and **MUST** refuse the reference rather than guess when `space` is anything else.

#### 7.7.3 The trait snapshot
`traits` is a §4 object — the dimension's declared, machine-comparable properties (no media octets).
`traits_hash` **MUST** equal `H("rapp/1:particle", traits)`. This reuses the existing particle space
deliberately: a traits object has the same address whether it is snapshotted inside a dimension or
carried as a frame `payload`, so two organisms' dimensions are comparable by one 64-hex string without
re-canonicalizing either payload. A consumer **MUST** recompute it and refuse a mismatch.

#### 7.7.4 `body.dimension` — one appended dimension
`payload` has **exactly** these members:
```json
{ "rappid": "<§6.1 rappid>", "dimension": "<lclabel>", "version": <uint53 ≥ 1>,
  "stage": {"name": "<lclabel>", "ordinal": <uint53>}, "traits": { }, "traits_hash": "<64hex>",
  "media": { "<lclabel role>": <§7.7.2 media reference>, … },
  "sources": [ {"stream_id": "<§6.1.1 stream_id>", "particle": "<64hex>"}, … ] }
```
- `stream_id` **MUST** be a **body-stream** (§6.1.1); `body.dimension` on a memory- or swarm-stream is
  refused (§7.2 family↔stream compatibility). `rappid` **MUST** byte-equal it (§7.7.1).
- `dimension` is the dimension's name. The estate's baseline names are `memory`, `skill`, `sonic`,
  `device`, `visual`, `capability`; a producer **SHOULD** use them where they fit and **MUST** emit any
  other name as an `lclabel`.
- `version` **MUST** be ≥ 1 and, for a given (`stream_id`, `dimension`), **MUST** be **strictly greater**
  than that dimension's version of record in the fold so far — including one seeded by inheritance
  (§7.7.5), so an offspring revises an inherited dimension by appending a higher version. A dimension is
  revised by appending, never by editing a frame (§7.4 immutability).
- `media` maps a role `lclabel` to a §7.7.2 reference; `{}` when the dimension owns no media. Object
  members are ordered by §4 at hash time, so no sort rule is needed.
- `sources` are the engram/frame pointers this dimension was reconstructed **from** — typically
  memory-stream particles. It **MUST** be sorted ascending by the UTF-8 bytes of (`stream_id`,
  `particle`) with no duplicate pointer, so two producers folding the same sources emit the same bytes.
  It is a provenance record: a consumer **MUST** check its shape and order, and **MAY** resolve the
  pointers when it holds those streams.

#### 7.7.5 `body.reconstructed` — the growth / reconstruct event
`payload` has **exactly** these members:
```json
{ "rappid": "<§6.1 rappid>", "species": null | "<lclabel>",
  "stage": {"name": "<lclabel>", "ordinal": <uint53>},
  "dimensions": { "<lclabel>": {"version": <uint53 ≥ 1>, "particle": "<64hex>"}, … },
  "traits_hash": "<64hex>",
  "weight": <§7.8.2 attested weight>,
  "sources": [ {"stream_id": "<stream_id>", "particle": "<64hex>"}, … ],
  "parent": null | {"rappid": "<§6.1 rappid>", "particle": "<64hex>"} }
```
It declares the stage the organism has reached and the dimension set it is reconstructed from; each
`dimensions` entry names the `body.dimension` frame of record by its **particle** (§7.3). `species` is
the §7.9.2 classification. It is `null` until declared; after the first non-null declaration, every
later `body.reconstructed` frame **MUST** repeat that same value.
- **`parent` = null** (growth of oneself): `dimensions`, `traits_hash`, and `weight` **MUST** equal the
  fold §7.7.6 computes over the frames preceding this one on this same stream. `stage` is what this
  frame *declares* and is bound only by §7.7.1 monotonicity.
- **`parent` ≠ null** (an offspring's birth): the frame **MUST** be that stream's genesis (`seq` = 0),
  `parent.rappid` **MUST** be a §6.1 rappid different from `rappid`, and `parent.particle` **MUST** be
  the particle of a verified frame on the parent's body-stream. Every `dimensions` entry **MUST**
  byte-equal an entry in the parent's fold at that particle, and `traits_hash` **MUST** equal the trait
  snapshot of exactly that inherited subset: an offspring may inherit **less** than its parent, never
  something its parent never had. `weight` **MUST** be the §7.8.2 weight of exactly the inherited
  assets with `frame_weight_bytes` = 0 — a newborn owns what it inherited and not one frame of its own.
- A consumer that cannot resolve the parent stream **MUST** report the lineage **unverified** — never
  verified, and never silently clean (the §13.1 staleness discipline). Unresolved fails closed.

#### 7.7.6 Reconstruction (the deterministic fold)
Given a body-stream whose every frame passed §7.5, a consumer reconstructs the organism's current state
by one pass in ascending `seq`, and **MUST** compute it rather than believe any frame that asserts it:
1. state starts empty: no stage, no dimensions, `traits_hash` = `H("rapp/1:particle", {})`.
2. on a `body.dimension` frame: check §7.7.4, refuse a non-advancing `version` for that dimension name,
   refuse a stage regression, then set `dimensions[name]` = `{version, particle:` the frame's
   `payload_hash}`, `traits[name]` = the frame's `traits`, and the stage.
3. on a `body.reconstructed` frame: check §7.7.5, refuse a stage regression, and **recompute** — for
   `parent` = null the asserted `dimensions`/`traits_hash` **MUST** equal the state built so far; for an
   offspring genesis they **MUST** equal the lawfully inherited subset of the resolved parent's fold,
   which then seeds this organism's own state (its dimensions, its traits, its media, and therefore its
   §7.8 weight). The frame's `weight` is recomputed the same way and refused on mismatch (§7.8.2).
   A `species` (§7.9.2) is adopted when first declared. Afterward every reconstructed frame **MUST**
   repeat it; both `null` and a different token are refused.
4. any other registered `body` kind (`body.pulse`, …) does not change dimensional state.
5. `traits_hash` of a fold is `H("rapp/1:particle", {dimension: traits, …})` over the folded traits.

Reconstruction reads **frames only**: media octets are never needed to rebuild state, only to *play* it,
so an organism's whole biography verifies without fetching a byte of media. The fold is a pure function
of a verified stream, so two independent implementations reconstruct the same state — and the same
`traits_hash` — from the same frames.

#### 7.7.7 Registry entries
§7.7 requires exactly two §13.3 `kind` entries, appended like any other (Art. IV, `spec` token unchanged):
```json
{"type":"kind","kind":"body.dimension","family":"body","deprecated":false}
{"type":"kind","kind":"body.reconstructed","family":"body","deprecated":false}
```
`body.reconstructed` is the already-listed §7.2 body-family kind; §7.7.5 is its payload profile. A
`kind` carries no intrinsic family (§6.1.1) — both are bound to `body` by the registry entry, and a
consumer tests membership by exact match, never by prefix.

### 7.8 Weight — a RAPPID's data size
**A RAPPID's data size is its weight.** Weight is the count, in **bytes**, of the data an identity has
verifiably accumulated: `frame_weight_bytes` for the frames it has appended, `asset_weight_bytes` for
the external blobs those frames reference. It is measured, never estimated; it is de-duplicated by §5
content address, so no frame and no asset can ever be weighed twice however many times it is
referenced; and it is **state**, like a stage — it never touches the mint-once identity (§7.8.5).

#### 7.8.1 What weighs, and how much
- **A frame weighs the length in octets of its §4 canonical form**, and only once it has been
  **accepted** (it passed §7.5). Bytes that failed verification are not weight. A frame is identified
  for de-duplication by its `frame_hash` (§7.3), so one frame delivered through five mirrors weighs once.
- **An asset weighs the `bytes` member of its §7.7.2 media reference**, de-duplicated by its content
  address `(space, hash)` (§5): one wake-call referenced by six dimensions weighs once. Assets are the
  §7.7.2 references carried by `body.dimension` frames — an implementation **MUST NOT** scan payloads
  for hash-shaped strings and count them, because guessing is not weighing.
- An implementation **MUST NOT** weigh a stored file's on-disk size, a compressed size, an indented
  serialization, or any other non-canonical encoding: those vary by writer, and weight must not.

#### 7.8.2 The attested weight (habitat-independent)
A `body.reconstructed` frame carries **exactly** these four members as its `weight` (§7.7.5):
```json
{ "frame_weight_bytes": <uint53>, "asset_weight_bytes": <uint53>,
  "total_weight_bytes": <uint53>, "complete": <bool> }
```
- `total_weight_bytes` **MUST** equal `frame_weight_bytes` + `asset_weight_bytes`; a consumer **MUST**
  refuse a ledger that fails this arithmetic without looking at anything else.
- All three counts are **exact integers**. A weight **MUST NOT** be a float, a rounded value, an
  approximation, or a human-readable string (§7.8.4).
- The attestation is computed **with no habitat store** — it is a pure function of the accepted frames,
  so every reader anywhere computes the same integers, and one habitat's missing or corrupt copy can
  never change what an organism weighs.
- A frame **cannot weigh itself** (its canonical size depends on the number it would contain), so a
  `body.reconstructed` frame attests the weight of every frame **preceding** it on its stream. A
  consumer **MUST** recompute that weight per §7.7.6 and **MUST** refuse a frame that asserts any other
  value: an organism does not get to declare itself heavier than its bytes.
- `complete` is `true` **iff** every accounted asset's size was established. It is `false` when any
  content address is attested with two different `bytes` values: that asset's size is then **unknown**,
  it contributes **zero** to every count, and it is listed (§7.8.3). A missing or contradictory size is
  **MUST**-surfaced as incomplete weight and **MUST NOT** be estimated, averaged, inferred, or dropped.

#### 7.8.3 The habitat ledger (a reader's view)
A reader additionally computes, and **MUST NOT** attest in any frame:
```json
{ "resident_weight_bytes": <uint53>, "linked_weight_bytes": <uint53>, "verified": <bool>,
  "incomplete": [ {"object","space","hash","reason","bytes"}, … ], "unverified": [ … ] }
```
- `resident_weight_bytes` is what is **actually hydrated on this habitat**: every accepted frame (it is
  in hand by definition) plus every asset whose octets this habitat holds and which **verified** —
  `Hb(space, octets)` equals the address **and** the octet count equals the attested `bytes`.
- `linked_weight_bytes` is **known but not resident**. `resident_weight_bytes + linked_weight_bytes`
  **MUST** equal `total_weight_bytes`.
- `incomplete` lists objects whose size could not be **established** (`size-conflict`), with
  `bytes: null`; they weigh nothing and set `complete` false.
- `unverified` lists objects whose size is attested but whose local copy could not be **confirmed**
  (`store-mismatch`); they remain **linked**, never resident, and set `verified` false. A habitat
  **MUST NOT** count an unconfirmed local copy as resident weight, and **MUST NOT** report a ledger
  carrying either list as clean.
- Residency is a property of a reader, never of the organism: the same identity is heavy-and-resident
  on the machine that holds its media and heavy-and-linked on the one that does not, at the **same**
  attested weight.

#### 7.8.4 Readable weight is presentation only
An implementation **MAY** render a weight as `2.4 KiB`. That string is **presentation over the exact
integer**: it **MUST NOT** appear in a `payload`, be canonicalized, be hashed, be parsed back into a
count, or be used for any comparison. The integer is the weight; the rendering is a courtesy.

#### 7.8.5 Weight is state, and what it does not mean
- A weight change is recorded the only way an append-only chain records anything: by **appending** a
  §7.7 frame. Appending a `body.dimension` frame adds weight; the next `body.reconstructed` frame
  attests it. Weight **MUST NOT** appear in a `rappid`, a `stream_id`, or any identity field, and a
  change in weight **MUST NOT** re-mint, re-anchor, or otherwise disturb the canonical identity (§7.7.1,
  §6.2). Weight is what an identity *carries*, never what it *is*.
- Because frames are immutable and retained, weight along one stream is **monotonically
  non-decreasing**; a consumer **MUST** refuse a `body.reconstructed` frame attesting a lower
  `total_weight_bytes` than an earlier one on the same stream. The §7.7.6 fold tracks the last
  accepted reconstruction and performs this check explicitly. A later size conflict still makes that
  asset unknown and zero-weight per §7.8.2; if the recomputed total falls below the prior attestation,
  the producer cannot append a reconstruction until retained verified bytes restore the floor.
- A lifecycle stage **MAY** use weight as one growth axis. An implementation **MUST NOT** infer
  capability, maturity, correctness, or authority from weight, and **MUST NOT** derive a stage from
  weight alone: bytes are mass, not skill. A large organism is a large organism; what it can *do* is
  established by its dimensions and its §10 signatures, never by its size.

### 7.9 Stats — the card an organism can prove
An organism's **stat block** is a card: species, stage, height, weight, dimensions, traits,
capabilities, completeness. Every number on it is either **derived from verified frames** or marked
**presentation**, and the two are never mixed. A stat block is a **view**: it is never a frame, never
hashed, never an identifier, and never authoritative on its own — the chain is.

#### 7.9.1 Frame height (exact)
`frame_height` is the **verified depth of the append-only body-chain**: the number of frames accepted
under §7.5 for that `stream_id`. Because §7.5 step 4 admits a genesis at `seq` 0 and then only
contiguous successors, the accepted-frame count **MUST** equal the head's `seq` + 1, and an
implementation **MUST** refuse a fold where the two disagree. It follows that:
- a frame re-presented (a duplicate delivery, a replayed segment) is **refused** by §7.5 step 4, so it
  cannot raise the height; and a `body.reconstructed` frame's attested §7.8 weight covers exactly the
  `seq` frames before it. Height, like weight, cannot be padded by repetition.
- `frame_height` is **not** carried in a payload: it is `seq` + 1 and would be a second, disagreeable
  copy of a number the envelope already fixes.

#### 7.9.2 Species and display height (presentation)
`species` is a classification token (`lclabel`) declared in a `body.reconstructed` payload (§7.7.5),
`null` until declared. Once non-null on a stream it is **immutable**: every later
`body.reconstructed` frame **MUST** repeat that token, and a consumer **MUST** refuse either `null` or
a different species. A species is not a stage and not an identity — an organism that would be a
different species is a different organism, and mints its own rappid (§7.7.1).

`display_height_mm` is an **optional presentation** rendering: millimetres produced by a **versioned
species growth curve** applied to `frame_height`. The curve is identified by an opaque versioned id
(e.g. `"rapp-height/1"`) and **MUST** be evaluated in exact integer arithmetic, so two implementations
of the same curve version render the same millimetres. A stat block carrying a display height **MUST**
also name the curve version that produced it.

- Display height **MUST NOT** appear in any `payload`, be canonicalized, be hashed, be part of any
  identifier, or be used in any verification decision. It is **not protocol identity and not a
  physical fact** — no organism has a size in millimetres; a card does.
- When the species is `null` or unknown to the curve, `display_height_mm` **MUST** be `null` and the
  stat block **MUST** report the height as unresolved. It is never approximated from another species,
  another curve version, or from weight.
- Curve definitions are presentation data and live **outside** this standard. Changing a curve changes
  a picture; it **MUST NOT** change any exact stat, and a new curve is a new version, never a
  redefinition of an existing one.

#### 7.9.3 The stat block
A stat block is a §4 value with **exactly** these members:
```json
{ "rappid": "<§6.1 rappid>", "species": null|"<lclabel>",
  "lifecycle_stage": null|{"name","ordinal"}, "frame_height": <uint53>,
  "display_height_mm": null|<uint53>, "height_curve": null|"<curve id>",
  "dimension_count": <uint53>, "capabilities": ["<lclabel>", …], "traits": { }, "traits_hash": "<64hex>",
  "total_weight_bytes": <uint53>, "resident_weight_bytes": <uint53>, "linked_weight_bytes": <uint53>,
  "completeness": {"weight_sizes_established": <bool>, "local_copies_verified": <bool>,
                   "display_height_resolved": <bool>}, "complete": <bool> }
```
- Every member except `display_height_mm`/`height_curve` is **exact and derived** from a §7.7.6 fold:
  `capabilities` is the sorted set of folded dimension names, `dimension_count` its size, `traits` and
  `traits_hash` the folded snapshot, the three weight counts the §7.8 ledger.
- `complete` **MUST** be the conjunction of `completeness`; a card with any unresolved stat **MUST**
  say so rather than present a plausible number (§7.8.2's discipline, applied to the whole card).
- Because the weight members carry the reader's residency split, a stat block is **habitat-scoped**:
  the same organism cards identically everywhere except in `resident`/`linked`.

#### 7.9.4 Proposals — autocomplete that is not authority
An implementation **MAY** autocomplete an organism's next dimension or next stat block from its traits
and its lineage, the way a continuation is proposed for a melody. Such a **proposal**:
- **MUST** be marked as a proposal and as **not authoritative**, and **MUST** carry the basis it was
  computed from (the rappid, the head particle, the frame height at that head) so a reader can tell a
  stale proposal from a fresh one;
- **MUST NOT** be appended, hashed, canonicalized into a payload, counted in any stat, or treated as
  canonical state in any way. Computing one **MUST NOT** mutate anything;
- **MUST NOT** project a weight. A frame that does not exist has no bytes, so a projection reports its
  weight as unknown and **MUST NOT** estimate one (§7.8);
- becomes real **only** by the ordinary path: a producer appends a §7.7 frame and a consumer verifies
  it under §7.5 and §7.7. Until then the organism is exactly what its chain says it is.

A proposal is deliberately not a conformant `payload` shape (§7.7.4/§7.7.5 close their key sets), so a
proposal cannot be mistaken for a frame's content by any conformant implementation.

### 7.10 RAPPID Calling Card and Debug Card profile
A **RAPPID Calling Card** is a signed, content-addressed wake manifest for one canonical RAPPID. A
**Debug Card** is the same shape under a visibly synthetic test profile. Neither is a new envelope:
the manifest is the `payload` of an ordinary §7.1 frame, `m` in the compact link is that payload's
existing §7.3 particle, and the signature is the frame's existing §10 `sig` member. A producer
**MUST NOT** wrap those eleven fields in a card-specific object, add a twelfth frame key, mint a
card-specific identity, or introduce another hash space.

The two additive profile bindings are:

| use | frame `kind` | payload `profile` | signed policy class |
|---|---|---|---|
| production calling card | `body.calling-card` | **`rappid-card/1`** | production |
| conformance/debug card | `body.debug-card` | **`rappid-card-test/1`** | test only |

The production and test tokens are intentionally explicit and distinct. Both frames ride the
subject's body-stream, so `payload.rappid` **MUST** byte-equal `frame.stream_id`, and the complete
§7.5 frame/chain rules still apply. An endpoint serving a non-genesis card therefore also requires
the predecessor needed to verify its body-chain; a card never creates a parallel unchained history.
The registry additions are exactly:

```json
{"type":"kind","kind":"body.calling-card","family":"body","deprecated":false}
{"type":"kind","kind":"body.debug-card","family":"body","deprecated":false}
```

#### 7.10.1 Virtual resource and compact non-secret link
The virtual resource extension is the literal **`.rappid-card.json`**. Resolving one yields the
canonical JSON serialization of the eleven-key card frame, not a private manifest envelope. A
compact card carried by QR, NFC, paper, or another physical medium has exactly this form:

```text
rappid://link/<percent-encoded-rappid>?m=<manifest-hash>&e=<endpoint>&n=<nonce>
```

- The authority is the exact string `link`. The path is one §6.1 RAPPID percent-encoded using the
  canonical [RFC 3986] UTF-8 form (uppercase percent hex; reserved characters encoded).
- Query members occur exactly once and in canonical order `m`, `e`, `n`; no other member or URI
  fragment is permitted.
- `m` is exactly 64 lowercase hex and **MUST** equal both `frame.payload_hash` and
  `H("rapp/1:particle", frame.payload)`. It is the existing particle space, not a new
  `rappid-card:*` address.
- `e` is a percent-encoded, canonical HTTPS URL whose decoded path ends `.rappid-card.json`.
  Before percent decoding it is ASCII and at most 2048 octets, with a lowercase canonical host,
  no user-info, port, query marker (including a trailing empty `?`), fragment marker (including a
  trailing empty `#`), space/control, backslash, malformed percent triplet, encoded unreserved
  character, empty path segment, or `.`/`..` segment. Percent hex is uppercase. An IP-literal host
  **MUST** be globally routable; loopback, private, link-local, unspecified, multicast,
  documentation/reserved, and other non-global literals are refused.
- A host that fails canonical IP parsing but whose labels are all decimal or `0x`-hex numeric forms
  **MUST NOT** fall through to DNS. Legacy aliases such as `127.1`, `0177.0.0.1`,
  `0x7f.0.0.1`, and `192.168.1` are refused before resolution; URL libraries and resolvers have
  historically interpreted them as private IPv4 addresses.
- The manifest's signed `endpoint_origin` is exactly `https://<canonical-host>`. URI `e` **MUST**
  have that origin, and that origin **MUST** occur in the signed authority view's
  `approved_origins` (§7.10.5); the signed `revocation_url` origin **MUST** also be approved there.
  The fetcher **MUST** re-run the URL/origin checks and reject any
  non-global DNS result before every request and after every redirect (maximum eight observed
  hops). A redirect to another origin or a DNS rebinding to private/reserved space is refused.
  `e` locates immutable frame bytes; it is not a second RAPP command endpoint.
- Reference fetch evidence is a 1–8 element array of exact
  `{"url":"<observed URL>","resolved_ip":"<observed IP>"}` objects. The first URL equals `e`;
  every hop's origin is signed-approved and every observed IP is globally routable; the final URL
  ends `.rappid-card.json`. Production fetchers enforce the same facts on live socket results.
- `n` is 16–64 unpadded base64url characters. It is a one-time, **non-secret** nonce. It carries no
  authority by itself and **MUST NOT** be treated as a password or bearer credential.

The URI is deliberately safe to photograph or copy. It **MUST NOT** contain a password, API key,
cookie, bearer token, private-memory plaintext, or executable instruction. Secret scanning is over
the raw component and at most two bounded UTF-8 percent-decoding rounds; structural canonicalization
still permits exactly one encoding round, so double-encoding never creates an alternate accepted
URL. Word boundaries for prohibited ASCII terms are themselves ASCII boundaries: decoded
`épasswordé` and `漢password漢` contain the forbidden token and are refused identically to JavaScript.

#### 7.10.2 Exact manifest payload
The frame `payload` has **exactly** these members; nullable `parent` is how the optional parent is
represented (the key is never absent):

```json
{
  "profile": "rappid-card/1",
  "rappid": "<§6.1 rappid>",
  "soul_hash": "<64hex>",
  "parent": null | {"rappid":"<§6.1 rappid>","particle":"<64hex>"},
  "engram_root": "<64hex>",
  "reflex_capability_root": "<64hex>",
  "compatibility": {
    "protocol": "rapp/1",
    "runtime": "<versioned-token>",
    "features": ["<versioned-token>", "…"]
  },
  "classification": "public|internal|confidential|restricted",
  "requested_scope": ["<lclabel>", "…"],
  "expires_utc": "<§7.4 utc>",
  "revocation_url": "<https-url>",
  "endpoint_origin": "https://<canonical-host>",
  "wake_challenge": "<64hex>",
  "inventory": [
    {"part":"<lclabel>","space":"rapp/1:egg","hash":"<64hex>",
     "bytes":<uint53>,"required":<bool>}
  ],
  "key_id": "<§6.1 keyed rappid>"
}
```

`compatibility.protocol`, `compatibility.runtime`, and every `features[]` value use the versioned
token grammar `lclabel "/" 1*DIGIT` with a non-zero first digit. `features` and `requested_scope`
**MUST** each be sorted, duplicate-free arrays. `classification` is ordered from least to most
restrictive exactly as shown above. `expires_utc` **MUST** be calendar-valid and later than the
frame's `utc`. `revocation_url` obeys §7.10.1's same strict canonical HTTPS rules (without the
`.rappid-card.json` suffix) and identifies the exact signed revocation-view provenance checked by
§7.10.6. `endpoint_origin` binds URI/fetch selection as specified in §7.10.1.

The payload has no free-form command, credential, cookie, memory, or authorization slot. A producer
**MUST NOT** put a password, API key, cookie, bearer token, plaintext private memory, `auto-execute`
instruction, or equivalent material anywhere in the manifest; a consumer **MUST** refuse one even
if its frame hash and signature verify. Hydrated parts are inert, content-addressed data. Reaching
`awake` authorizes no automatic execution: capability use remains an explicit local policy decision.

#### 7.10.3 Identity roots and permitted hydration inventory
`soul_hash`, `engram_root`, and `reflex_capability_root` are addresses of the corresponding octets:

```text
root = Hb("rapp/1:egg", part_octets)
```

This reuses §7.7.2/§9's existing octet space. The `inventory` is the complete allow-list of parts a
card may hydrate. Entries have exactly `{part,space,hash,bytes,required}`, are sorted ascending by
the UTF-8 bytes of `part`, and contain no duplicate part. `space` is always `"rapp/1:egg"`.
The three core entries named `soul`, `engram`, and `reflex-capability` **MUST** be present,
`required:true`, and their hashes **MUST** equal the corresponding signed root. Other entries
**MAY** be listed and are permitted only at their signed address.

During hydration a consumer **MUST** refuse an unlisted part, a missing required part, a byte-count
mismatch, or octets whose `Hb(space, octets)` differs from the inventory hash. Private engrams may
therefore be fetched only after classification/scope policy passes and are never plaintext in the
link or manifest.

A presentation verifier **MUST** receive hydration as a lazy, bounded per-entry callback (or an
equivalent explicit preflight/post-claim phase), not as an already-hydrated byte map. The verifier
invokes that callback at most once for each signed inventory entry, supplies the exact signed
`{part,space,hash,bytes,required}` bound, and **MUST NOT** invoke it until steps 1–8 have passed and
step 9 has durably committed `hydrating`. Any policy, scope, origin, expiry, revocation, replay, or
contention refusal therefore touches zero confidential part bytes.

`parent` is `null` or the exact §7.7.5 `{rappid,particle}` pointer and **MUST NOT** name the card's
own RAPPID. It binds lineage for continuity; it does not create or change identity.

#### 7.10.4 One-time continuity challenge
Let `continuity` be the exact §4 object:

```json
{
  "rappid": "<payload.rappid>",
  "soul_hash": "<payload.soul_hash>",
  "parent": "<payload.parent>",
  "engram_root": "<payload.engram_root>",
  "reflex_capability_root": "<payload.reflex_capability_root>",
  "nonce": "<URI n>"
}
```

Then:

```text
payload.wake_challenge = H("rapp/1:particle", continuity)
```

This again introduces no address space. After hydrating, the runtime constructs the same exact
object from the state it actually hydrated and the parsed URI nonce. Both the manifest's challenge
and the hydrated response **MUST** reproduce the same particle; a mismatch is refused. The
challenge proves continuity of the addressed identity state, not possession of a shared secret.

#### 7.10.5 Signature, authenticated runtime policy, and issuer authorization
The card frame's `sig` is REQUIRED and follows §10 detached, unencoded JWS, selecting §10's
`alg:"EdDSA"` alternative (Ed25519) for this profile. `key_id` **MUST** be a keyed §6.2 RAPPID,
**MUST** equal the JWS protected header's `kid`, and the discovered SPKI **MUST** hash back to that
RAPPID tail. The signature covers `canonical(frame \ {sig})`, including the complete manifest,
particle, metadata, and `key_id`; no nested signature is added.

Cryptographic trust is not issuing authority. A consumer **MUST NOT** infer authorization from a
trusted key, common owner/slug, repository location, or successful JWS. Two additional signed
documents are required.

**Authenticated runtime policy.** The out-of-band runtime-policy trust anchor signs this exact
closed document:

```json
{
  "schema":"rappid-card-runtime-policy/1", "policy_seq":<uint53>,
  "generated_utc":"<utc>", "effective_utc":"<utc>", "expires_utc":"<utc>",
  "authority_rappid":"<policy root>", "signer_key_id":"<same policy root>",
  "provenance":{"source":"<canonical https URL>","channel":"<lclabel>"},
  "card_authority":"<trusted card-authority rappid>",
  "protocol":"rapp/1", "runtime":"<versioned-token>",
  "features":["<versioned-token>",…], "profiles":["rappid-card/1"],
  "max_classification":"<classification>", "granted_scope":["<lclabel>",…],
  "max_registry_age_seconds":<uint53 greater than zero>, "sig":"<JWS>"
}
```

This signed value—not caller booleans/sets—owns the accepted profile, actual protocol/runtime,
supported feature superset, maximum classification, granted scopes, card-authority root, and
registry freshness bound. It is current only when
`effective_utc <= generated_utc <= now < expires_utc`. `policy_seq` is persisted per policy
authority; lower sequence or different bytes at an already-seen sequence are refused.

**Signed card-authority view.** `card_authority` signs this exact closed §13 view:

```json
{
  "schema":"rappid-card-authority/1", "registry_seq":<uint53>,
  "generated_utc":"<utc>", "effective_utc":"<utc>", "expires_utc":"<utc>",
  "authority_rappid":"<card authority>", "signer_key_id":"<same card authority>",
  "provenance":{"source":"<canonical https URL>","channel":"<lclabel>"},
  "approved_origins":["https://<canonical-host>",…],
  "authorizations":[{
    "issuer_key_id":"<keyed rappid>", "subject_rappid":null|"<subject rappid>",
    "role":"subject"|"card-issuer", "not_before_utc":"<utc>",
    "not_after_utc":"<utc>", "revoked_utc":null|"<utc>"
  }], "sig":"<JWS>"
}
```

Arrays are sorted and duplicate-free. The view must be effective, unexpired, generated no more than
the signed runtime policy's `max_registry_age_seconds` ago, and non-rollback by `(authority,
registry_seq, particle-of-view-without-sig)`.

An authorization is valid only when its `issuer_key_id` equals manifest `key_id`, the frame's `utc`
and verifier `now` are both inside `[not_before_utc, not_after_utc)`, and `revoked_utc` is null or
later than `now`. Role `subject` requires byte-exact `subject_rappid == manifest.rappid`. Role
`card-issuer` is an explicit delegation and may bind one subject or use `subject_rappid:null` for
the authority's deliberate all-subject issuer role. No matching current record means refusal,
even for an otherwise trusted key.

A test issuer and test policy authority **MUST** be visibly synthetic: their RAPPID owner is the
literal `synthetic`. Test policy selects only `rappid-card-test/1`; production policy selects only
`rappid-card/1`. Production **MUST** refuse a visibly synthetic manifest key or policy authority,
and test profile **MUST** require them. No unauthenticated `mode` or `synthetic` boolean exists.

#### 7.10.6 Verification and wake order
The revocation location yields exactly this signed §13 wire document:

```json
{
  "schema":"rappid-card-revocations/1", "registry_seq":<uint53>,
  "generated_utc":"<utc>", "effective_utc":"<utc>", "expires_utc":"<utc>",
  "authority_rappid":"<card authority>", "signer_key_id":"<same card authority>",
  "provenance":{"source":"<manifest.revocation_url>","channel":"<lclabel>"},
  "entries":[{
    "target_type":"manifest-hash"|"key-id"|"subject-rappid",
    "target":"<64hex or rappid>", "effective_utc":"<utc>", "reason":"<lclabel>"
  }], "sig":"<JWS>"
}
```

The signer **MUST** equal the runtime policy's `card_authority`; provenance source **MUST**
byte-equal the signed manifest `revocation_url`; entries are sorted and duplicate-free. The view
must be effective, unexpired, fresh under signed `max_registry_age_seconds`, and anti-rollback by
persisted `(authority, registry_seq, particle-of-view-without-sig)`. A lower sequence or different
view at an already-seen sequence is refused. An entry applies when its target byte-equals the
manifest particle, `key_id`, or subject `rappid` for its declared type and `effective_utc <= now`.
Forged, stale, unavailable, rollback, or wrong-provenance views fail closed.

Replay and sequence state **MUST** use an injected transactional durable backend; an in-memory
set/check, snapshot, or caller promise is non-conformant. For the reference SQLite backend,
`BEGIN IMMEDIATE` plus a unique nonce row is the linearization point:

- step 9 commits `(nonce, connection_id, "hydrating")` **before** hydration;
- a crash/restart preserves that row; only the same connection id may resume it;
- another thread, process, connection, or already-`awake` presentation is refused;
- after step 11, the backend commits `"awake"` **before** success is returned.

The same backend persists the highest runtime-policy, authority-view, and revocation-view
sequence+hash per authority, so independent processes share one rollback floor.

A consumer treats the URI, fetch trace, frame, manifest, three signed policy/view documents, and
hydrated octets as untrusted. It **MUST** perform these checks in the exact order below, stop at the
first failure, and reach `awake` only after all eleven succeed:

1. **Parse untrusted URI:** enforce §7.10.1's exact scheme/authority/path/query grammar, canonical
   percent encoding, strict HTTPS virtual endpoint, prohibited material, hash, and nonce forms.
2. **Content-address match:** recompute the payload particle and require it and
   `frame.payload_hash` to equal URI `m`. A hostile location cannot substitute another manifest.
3. **Exact schema:** require the eleven-key §7.1 frame; run §7.5 steps 1–5 including stream and
   predecessor binding; enforce the exact §7.10.2 payload, profile/kind binding, signed endpoint
   origin, root/inventory relationships, and prohibited-material rule.
4. **Signature/key trust and authorization:** verify the card JWS and SPKI→RAPPID binding; verify
   the signed runtime policy and its anti-rollback sequence; verify the signed authority view,
   issuer delegation/tenure, and approved origins; then validate every observed fetch/redirect URL
   and resolved IP against that signed origin policy. A trusted but unauthorized issuer is refused.
5. **Expiry:** require verifier time before `expires_utc`.
6. **Revocation:** verify the exact signed view above, freshness, provenance, sequence, and
   manifest/key/subject entries. Unavailable is failure, never an empty result.
7. **Compatibility:** require exact manifest protocol/runtime equality with the authenticated
   runtime policy and require every manifest feature to be in its signed feature superset.
8. **Classification/scope:** require classification no higher than the authenticated policy and
   every requested scope in its signed grant.
9. **Replay nonce:** transactionally commit URI `n` as `hydrating`, bound to this connection,
   before hydration. Same-connection crash recovery may resume; all contention/replay is refused.
10. **Permitted hydration inventory:** hydrate only §7.10.3's allow-list and verify every required
    part's count and address. A failed attempt keeps its nonce claim so another connection cannot
    race the retry.
11. **Continuity challenge:** reconstruct §7.10.4 from hydrated state and require the signed
    challenge to match. Transactionally commit `awake`; only after that commit may success return.

Implementations **MUST NOT** move replay, policy, hydration, or continuity earlier to improve
convenience: the order is the security boundary. In particular, hydration before
classification/scope can disclose private state, trusting a caller list can silently un-revoke a
card, and returning before the `awake` commit creates a replay window.

#### 7.10.7 Deterministic conformance deck
The required deterministic deck is `vectors/rappid-card/deck.json`, generated and diff-checked by
`vectors/rappid-card/generate.py`. Its mandatory scenario names are exactly, in this order:

```text
valid-test, valid-production, expired, manifest-revoked, key-revoked, subject-revoked,
wrong-manifest-hash, deep-payload, oversized-payload, newline-rappid,
newline-manifest-hash, newline-lclabel, newline-profile-token, newline-connection-id,
unknown-signing-key, attacker-key-impersonation, subject-not-yet-effective,
delegation-not-yet-effective, delegation-expired, delegation-revoked,
forged-revocation-view, stale-revocation-view,
unavailable-revocation-view, rollback-revocation-view, protocol-incompatible,
runtime-incompatible, unsupported-feature, feature-superset, classification-violation,
insufficient-scope, missing-engram-part, continuity-challenge-failure,
reconnect-during-hydration, duplicate-replayed-nonce, physical-payload-reproduction,
test-profile-production, synthetic-key-production, auto-execute, endpoint-userinfo,
endpoint-empty-query, endpoint-empty-fragment, endpoint-space, endpoint-backslash,
endpoint-bad-percent, endpoint-double-encoding, endpoint-numeric-127-1,
endpoint-numeric-octal, endpoint-numeric-hex, endpoint-numeric-short-private,
endpoint-loopback-literal, endpoint-private-literal,
endpoint-ipv4-multicast-literal, endpoint-ipv6-multicast-literal,
fetch-ipv4-multicast, fetch-ipv6-multicast,
endpoint-link-local-literal, endpoint-reserved-literal, endpoint-unapproved-origin,
endpoint-redirect-origin, endpoint-private-dns, fetch-numeric-alias,
secret-endpoint-password, secret-password,
secret-api-key, secret-cookie, secret-bearer, secret-private-memory,
secret-unicode-latin-adjacency, secret-unicode-cjk-adjacency
```

Conformance asserts exact list equality, not subset membership. `valid-production` uses a
non-synthetic key with explicit signed issuer delegation. Protocol-only, runtime-only,
unsupported-feature, and feature-superset are orthogonal. Prohibited-material fixtures mutate
existing schema fields; the mutation control disables only the scanners and requires every one to
turn green, proving schema rejection does not mask the policy. `physical.rappid-card.json` is the
canonical frame resource and `physical-payload.txt` the exact compact URI. A conformant
implementation accepts the positive vectors and refuses each negative vector at its declared step.

## 8. The Wire (L3)
All interaction rides one of exactly two forms:
1. **Synchronous — `POST /chat`, `application/json` both ways.** Request: `user_input` (string, REQUIRED);
   `session_id` (string, OPTIONAL — omit to start a session); `idempotency_key` (string, OPTIONAL — a repeat
   with the same key returns the original response, not a new turn or duplicate session; scoped to
   `session_id` when present, else to the key alone so session-creation is also de-duplicated); unrecognized members **MUST** be
   ignored, never refused. Success: HTTP 200 with **exactly** `{response:string, agent_logs:[string],
   session_id:string}` (no extra members). An unknown `session_id`, a refusal, or a malformed request
   **MUST** be HTTP 422, `{error:{code:string, step:string|null}}` where `code` is a §13-registered error
   code (e.g. `"unknown-session"`) and `step` is the failing §7.5 step as a string — one of
   `"1","1a","2","3","4","5","6"` — or `null`. No other shape is conformant. New capability is a new agent
   behind `/chat`, never a sibling REST route.
2. **Asynchronous — an append-only frame (§7) published to a stream** (a repo path, an `events/` log). A
   frame on a **swarm-stream MUST** carry `sig`≠null (§10); memory/body-stream frames **MAY** be unsigned.
   Any *history* is safe to read given a trusted head (§14); the hash chain (§5) makes tampering
   detectable.

## 9. The Egg (L5) — the single egg spec of record
An **egg** is a cartridge packing a unit of the estate. **RAPP §9 is the one egg spec of record** (it
subsumes and retires `EGG_FAMILY.md`, `NEIGHBORHOOD_EGG_SPEC.md`, `ESTATE_SPEC.md`, `rappterbook/EGG_SPEC.md`,
and the rest — drift C7). No other document may re-specify eggs; they cite this section.

### 9.1 Container, manifest, and egg address
An egg is either a JSON object (`invite`/`session` variants) or a ZIP whose root is `manifest.json` (tree
variants). The manifest is a §4 value with exactly these members:
```json
{ "schema": "rapp/1-egg", "variant": "<variant>", "rappid": "<§6.1 rappid>",
  "created_utc": "<§7.4 utc>", "contents": [ {"path":"<rel>","hash":"<64hex>"}, … ], "payload": { },
  "sig": "<jws|null>" }
```
- `contents` **MUST** list every packed file **except `manifest.json` itself**, exactly once each, with
  `hash = Hb("rapp/1:egg", file_octets)` (§5) over the raw stored octets. `contents` is **always present**;
  for JSON (pointer/session) variants it **MUST** be exactly `[]`.
- `path` **MUST** be a relative POSIX path: `/`-separated NFC UTF-8 segments, no `.`/`..` segment, no
  leading `/`, no backslash, no duplicate `path` in one manifest. `contents` **MUST** be sorted ascending
  by the UTF-8 bytes of `path`.
- `payload` is a §4 object (variant-specific). `sig` is a §10 JWS over `canonical(manifest \ {sig})`, or
  `null`. For the `invite` variant `sig` is REQUIRED and **MUST** verify with `kid` in the §13.2 estate-owner
  succession (invites are estate-issued; a `sig` by any other key, even a validly registered one, is
  refused — otherwise an attacker mints a fresh rappid and forges invites). For other variants a non-null
  `sig` **MUST** verify per §10 with `kid` == a keyed rappid the consumer resolves via §13; a consumer
  presented a signed egg **MUST** verify it.
- **The egg's one §5 address is** `egg_hash = H("rapp/1:egg-manifest", manifest \ {sig})` — the manifest with
  exactly the `sig` key removed (mirroring §7.3's wave rule: `sig` authenticates the egg, `egg_hash` names
  it, so re-signing never changes identity). Stores key eggs by `("rapp/1:egg-manifest", egg_hash)`.
  (`"rapp/1:egg"` addresses file octets; `"rapp/1:egg-manifest"` addresses the egg as a whole.)
- **Container determinism.** A ZIP variant **MUST** use compression method `stored` (0) for **every** entry
  — no deflate in any variant (deflate is library-dependent, so it cannot be byte-reproducible; transport
  compression, if any, wraps the egg and is not the egg). Entries appear in `contents` order with
  `manifest.json` first; the `manifest.json` entry's octets **MUST** be exactly `canonical(manifest)`; all
  timestamps `1980-01-01 00:00:00`; no extra fields; UTF-8 filename flag set; `contents[].hash` is over the
  file octets (identical to the archive octets under method 0). A JSON-variant egg's serialized form
  **MUST** be exactly `canonical(manifest)`. Two conformant packers of the **same manifest value** thus emit
  byte-identical eggs.

### 9.2 Variants (the ratified set — closes EGG-01)
| variant | container | packs | required members |
|---|---|---|---|
| `organism` | ZIP | a full brainstem instance | contents (sorted) MUST include `rappid.json`, `soul.md`; MAY include `agents/*`, `organs/*`, memory files |
| `rapplication` | ZIP | one rapp | contents MUST include `rappid.json` and exactly one `agent.py` at the root (the agent of record); MAY include one `ui.html` and files under `state/` |
| `session` | JSON | one runtime + transcript | `payload` = `{runtime:<string>, transcript:[<object>]}`; contents `[]` |
| `invite` | JSON | a QR-sized pointer (**no packed files**) | `payload` = `{target_rappid:<rappid>, target_url:<string>, target_kind:("neighborhood" / "estate")}`; contents `[]`; `sig` REQUIRED |
| `neighborhood` | ZIP | several organisms meant to live together | `payload` = `{members:[<rappid>,…]}`; contents = one sub-egg per member, named `<owner>--<slug>.egg` at the root, matched by the sub-egg manifest's `rappid` == the `payload.members[]` entry |
| `estate` | ZIP | several neighborhoods | `payload` = `{neighborhoods:[<rappid>,…]}`; contents = one sub-egg per neighborhood, named `<owner>--<slug>.egg` at root, matched by sub-egg `rappid` |

The QR-sized invite that caused EGG-01 is the **`invite`** variant: a signed pointer object, not a
member-packing `neighborhood` egg. The banned legacy stamps (`brainstem-egg/2.3-neighborhood`,
`neighborhood-egg/1.0`) migrate to `{schema:"rapp/1-egg", variant:"invite" / "neighborhood"}` (Art. III).

### 9.3 Conformance
- **Producer** **MUST** emit only `schema:"rapp/1-egg"` with a variant from §9.2, a §6.1 rappid, and, for
  ZIP variants, a `contents` list whose every hash verifies. It **MUST NOT** emit any legacy egg schema.
- **Consumer** **MUST** read every §9.2 variant, dispatch on `variant`, verify **integrity then viability** —
  (0) the manifest is a §4 value satisfying **every §9.1 rule** — exact member set, `path` grammar (no `..`,
  no leading `/`, no backslash), no duplicate paths, sort order, and for ZIP variants the archive entry set
  equals `contents` ∪ {`manifest.json`} in the §9.1 deterministic order (this is the zip-slip defense; an
  unenforced path grammar defends nothing); (1) every `contents[].hash` recomputes per §5; (2) the variant's
  §9.2 structural requirements hold — and refuse whole on any failure; it **MUST NOT** reparent on transport.

## 10. Trust and signatures (L2)
`sig` is OPTIONAL on memory/body streams and REQUIRED on swarm streams (§8). Chain integrity comes from the
hash links (§5), not signatures. When present, `sig` **MUST** be JWS Compact Serialization with **detached,
unencoded payload** ([RFC 7515] App. F + [RFC 7797]):
- protected header members are **exactly** `alg` (`"EdDSA"` or `"ES256"`), `b64` (`false`), `crit`
  (`["b64"]`), `kid` (signer's §6.1 rappid), no others; the header octets **MUST** be `canonical(header)`
  (§4 — JCS orders them `alg`, `b64`, `crit`, `kid`, no whitespace);
- the `sig` string is the detached compact form `BASE64URL(canonical(header)) || ".." || BASE64URL(signature)`;
- JWS signing input = `BASE64URL(canonical(header)) || "." || canonical(frame \ {sig})`;
- `alg`: `EdDSA`/Ed25519 [RFC 8037] or `ES256` [RFC 7518]; ES256 signers **SHOULD** sign deterministically
  [RFC 6979] (Ed25519 is deterministic by construction) so signed frame files stay byte-reproducible.

**Key discovery.** A keyed rappid's tail is one-way (`Hb("rapp/1:rappid",SPKI)`). A verifier resolves the
signer's SPKI (DER) **from the §13 registry** entry (`rappid` → `spki_der_b64`); the door-of-record
`rappid.json` is the publication venue the registry entry is generated from, not itself a verification
source. The verifier **MUST** check `Hb("rapp/1:rappid", SPKI_DER)` == the rappid's tail and refuse on
mismatch or registry absence.

**Key lifecycle.** Rotation is an identity re-anchor (§6.3, case `rotation`) with new `tail =
Hb("rapp/1:rappid", newSPKI)` and a §13.3 re-anchor record. A re-anchor **deprecates** the superseded
rappid's §13 `spki` entry: a verifier **MUST** refuse a `sig` whose `kid` is a superseded rappid on any
frame with `utc` ≥ the re-anchor record's `utc` (rotation gives forward security; earlier frames verify as
before). Compromise is declared by an owner-signed **tombstone** in the §13 registry `{rappid, revoked_utc}`; a verifier **MUST** refuse any `sig` by a
tombstoned key on a frame whose `utc` ≥ `revoked_utc`, checking tombstones at verification time (§7.5 step
6). "Owner-signed" means a `sig` verifying with `kid` == the registry's designated `estate_owner` rappid
(§13). A consumer **MUST NOT** infer authorship from an unsigned frame (keyless rappids assert location,
not authorship).

## 11. Conformance classes
- **Producer:** emits only §4 JCS/I-JSON bytes, §5 domain-separated full-SHA-256 addresses, §6 rappids
  minted per §6.2, §7.1 eleven-key frames, §7.10 cards when emitting wake links, §9 `rapp/1-egg`
  variants — and **no legacy form**.
- **Consumer:** runs the full §7.5 checklist (incl. 1a binding), §9.3 egg verification, §10 signature +
  key-discovery + tombstone checks, the ordered §7.10 card gate when resolving a card,
  canonicalizes legacy ids on read (§6.3), refuses on any failure, never repairs/reparents/rolls back
  (§7.6).
- **Router/Mirror:** invents no endpoints (§8), declares subordination to `kody-w/RAPP` (Fed. Const.
  Art. VII), serves only provenance-stamped hash-matching mirrors (Art. VIII).

## 12. Versioning, evolution, no-legacy
RAPP is a **living standard** (WHATWG): revised in place, never forked into parallel versions; a `name/X.Y`
label **MUST NOT** ever denote two shapes (Art. II) — a shape change moves the token (§7.1). Published
content-addressed artifacts are **immutable** (SemVer/crates). Because the estate has **no uncontrolled
userspace**, there is **no perpetual backward compatibility** (Art. III): a change to a canonical form is a
**total migration** of every instance + **deletion** of the old form. Sealed re-genesis history (§12.1) is
the one retained exception and is not "legacy compatibility."

### 12.1 Re-genesis (converging an immutable chain — one owner-authorized operation)
1. **Terminal seal:** `seal = Hb("rapp/1:seal", head_octets)`. `head_octets` is the exact octets of the old
   head's record **as retained under `legacy/`** (step 4): for a one-frame-per-file store, the retired
   file's full octets; for a line-oriented log, the head's line **excluding** its trailing terminator. The
   retained `legacy/` artifact is the verification reference for the seal, and retirement **MUST** preserve
   those octets bit-exact. The step-3 `genesis` registry entry **SHOULD** record the `legacy/` artifact's
   repo+path so a consumer **MAY** verify the seal against it. (Defined for every legacy shape, including
   ones that cannot be §7.3-hashed.)
2. **New genesis:** emit `seq`=0, `prev`=null, `kind` = the registered re-genesis kind **of the stream's
   family** — `memory.re-genesis`, `swarm.re-genesis`, or `body.re-genesis` (three §13 kinds, used only
   here) so the frame satisfies §7.2 family↔stream compatibility for any stream — `sig`≠null owner-signed
   (§10, §13 `estate_owner`), `payload` = `{"migrated_from":{"stream_id":<old>,"terminal_seal":<seal>,
   "terminal_seq":<n>}}` and no other members. A consumer **MUST** treat any `*.re-genesis` kind as the sole
   re-genesis marker for its family and refuse an unsigned/non-owner one.
3. **Register (the linearization point):** append a §13.3 `genesis` entry mapping the `stream_id` to the new
   genesis's `frame_hash`, **and flag every prior `genesis` entry for that `stream_id` `deprecated`** — the
   first convergence included (it deprecates the creation-time genesis), so exactly one non-deprecated entry
   always remains. A consumer resolves the current genesis **only** via that sole non-deprecated entry. A
   **concurrent** second registration fails closed (the append is the linearization point, Art. IX); a
   later fork/brick (§7.6/§14) is a fresh owner-authorized convergence that appends again and re-deprecates.
4. **Retire:** move old frames under `legacy/` — retained as immutable sealed history, never served as
   current, never extended, never read as live chain. No live frame may set `prev`/`prev_wave` to a retired
   hash (a dangling ref is a drift finding).
5. Keep the old `stream_id` unless the identity itself re-anchored (§6.3), in which case the registry entry
   also records `old_stream_id → new_stream_id`.
6. Two frames with equal `stream_id`+`seq` from different eras are disambiguated **solely** by descent from
   the current registered genesis. Re-genesis is one-time per convergence; a repeat *of the same
   convergence* is the concurrent case (step 3, fails closed).

## 13. The registry — the estate's signed root of trust (append-only)
`rapp-map/ecosystem-spec.json` (`canonical_source` `kody-w/RAPP`) is the estate's IANA. Because §7.6 head
resets, §10 key discovery, tombstone revocation, and ownership all resolve through it, it is the **root of
trust** and is itself authenticated (an unsigned mutable file at the root of the trust graph would forge the
whole estate).

### 13.1 Trust anchor and registry authentication
- The one bootstrap axiom is the **`estate_owner` rappid string** itself: since a keyed tail is
  `Hb("rapp/1:rappid", SPKI_DER)`, the rappid **is** a self-certifying key fingerprint, distributed
  out-of-band exactly once (QR, invite, docs) the way a root-CA certificate is.
- The registry document **MUST** carry a top-level `registry_seq` (uint53) and a detached §10 JWS `sig` over
  `canonical(registry \ {sig})` with `kid` = the `estate_owner` rappid. A consumer **MUST** verify this
  signature against an SPKI whose `Hb("rapp/1:rappid", SPKI_DER)` equals the anchor rappid's tail (the SPKI
  may travel alongside the registry — the tail check authenticates it) and **MUST** refuse an unsigned or
  non-verifying registry.
- **No rollback:** a consumer persists the highest `registry_seq` it verified and refuses any registry with
  a lower one (mirrors §7.6). **Freshness:** a consumer **MUST** obtain the registry from `canonical_source`
  or a provenance-stamped (Art. VIII) mirror of it, **SHOULD** refresh before any §7.5-step-6 or §7.6
  head-reset decision, and **MUST** report a verification made against a registry older than its staleness
  policy as *stale*, not *clean*.

### 13.2 Owner succession (time-scoped authority)
"Owner-signed" means: the `sig` verifies per §10 **and** `kid` is the estate-owner **in effect at the
artifact's `utc`** — the current `estate_owner` or any predecessor reachable through the registry's
re-anchor records (§13.3), with the artifact's `utc` inside that owner's tenure `[record.utc, successor.utc)`.
Verification uses the owner in effect at the artifact's time, **never only the current one** (so a routine
owner key rotation never invalidates historical re-genesis frames or tombstones). Estate-owner **root-key
compromise** is recovered only by re-distributing a new trust anchor out-of-band (§13.1) — it cannot be
expressed inside the registry it signs.

### 13.3 Entry types (each a §4 value; document `schema:"rapp/1-registry"`)
The registry is an I-JSON document; every entry is append-only (never removed/renamed; retirement is a
`deprecated:true` flag). Entry types and their exact members:
- **protocol** `{type:"protocol", name, spec_repo, spec_path, spec_hash, deprecated}`
- **kind** `{type:"kind", kind, family, deprecated}` (incl. the three `*.re-genesis` kinds)
- **egg-variant** `{type:"egg-variant", variant, deprecated}` · **error-code** `{type:"error-code", code}`
  (both closed namespaces; unregistered value = not conformant)
- **genesis** `{type:"genesis", stream_id, frame_hash, deprecated, old_stream_id?, new_stream_id?}` — **every**
  stream registers its creation genesis; re-genesis appends a new one and deprecates all prior (§12.1 step 3);
  §7.6's "registered genesis" is the sole non-deprecated `genesis` for a `stream_id`.
- **spki** `{type:"spki", rappid, spki_der_b64, deprecated}` — the §10 key-discovery source.
- **tombstone** `{type:"tombstone", rappid, revoked_utc, sig}`, `sig` owner-signed over `canonical(entry \ {sig})`.
- **re-anchor** `{type:"re-anchor", old_rappid, new_rappid, case:("upgrade"|"rotation"|"compromise"|"tag-migrate"),
  utc, sig, old_key_sig?}` — `sig` owner-signed; `old_key_sig` a §10 JWS by the **old** key over
  `canonical(entry \ {sig,old_key_sig})`, REQUIRED for `case:"rotation"`. This is the normative succession record (§13.2).
- **estate_owner** `{type:"estate_owner", rappid}` (exactly one non-deprecated) · **master-plan**
  `{type:"master-plan", repo, path}` (Fed. Const. Art. VII).

§7.5 steps 1–5 are time-independent (append-only lookups); **only** step 6 (tombstones) and §13.2 owner
tenure are time-scoped, and both are monotone given the §13.1 no-rollback rule.

## 14. Security considerations
- **Integrity:** every object is domain-separated content-addressed (§5); a hostile mirror cannot alter
  bytes without breaking the hash, so *history is safe given a trusted head*.
- **Head freshness is not self-certifying:** the chain authenticates history, not which head is current; a
  hostile mirror may serve a stale/forked head. Consumers counter with the §7.6 monotonic-head rule; swarm
  heads **SHOULD** be owner-signed.
- **Cross-stream replay:** without §7.5 step 1a, any genesis/segment of stream A replays as stream B (seq=0,
  prev=null always pass). Step 1a's stream binding is mandatory.
- **Address-space confusion:** §5 domain tags make a particle, wave, egg, or rappid tail with equal hex
  non-interchangeable; stores key by `(space, hash)`.
- **Canonicalization attacks:** the §4 I-JSON input-domain profile (no duplicate keys, no lone surrogates,
  exact binary64, no normalization ambiguity) removes hash-splitting and NFC-twin vectors.
- **Identity forgery / key compromise:** authorship requires a keyed rappid + valid §10 `sig`; rotation is
  §6.3 re-anchor (verifiable authorization, §6.3/§13.3 — a self-asserted `_migrated_from` is refused);
  compromise is a §13 tombstone enforced at verify time. Because a tombstone gates on the frame's
  producer-controlled `utc`, a compromised key can still emit frames stamped just below `revoked_utc`; after
  a compromise the owner **SHOULD** advance affected stream heads (or re-genesis) past `revoked_utc`.
- **Root of trust:** the registry is the estate's signed root (§13.1); it is authenticated by an owner
  signature anchored to the out-of-band `estate_owner` rappid fingerprint, `registry_seq`-monotonic against
  rollback, and freshness-checked (a stale registry silently un-revokes keys and hides re-geneses).
- **Producer-controlled `utc` (DoS/merge bias):** a future-dated head can brick a stream (successors refused
  as earlier) and bias UTC-first merges. A consumer **SHOULD** refuse a frame whose `utc` exceeds receipt
  time by >300 s, and adversarial-scope merges **SHOULD** rank by `min(utc, first-seen)`; a bricked stream
  converges by re-genesis (§12.1).
- **Card disclosure/replay:** a §7.10 URI is public, non-secret data. Its endpoint is untrusted and
  authenticated by particle+JWS, signed origin policy, and per-hop URL/DNS revalidation. A trusted key
  gains no issuer power without explicit signed subject/role delegation. Signed fresh anti-rollback
  revocation and runtime policy replace caller lists/booleans. Transactional durable `hydrating`/`awake`
  commits prevent crash, thread, process, and connection replay races; content-addressed inventory plus
  final continuity prevents a partial/substituted body from reaching `awake`.

## 15. References
[RFC 2119] [RFC 8174] requirement terms · [RFC 8259] JSON · [RFC 7493] I-JSON · [RFC 8785] JCS ·
[FIPS 180-4] SHA-256 · [RFC 3986] URI · [RFC 5234] ABNF · [RFC 7405] case-sensitive ABNF · [RFC 9562] UUID
(obsoletes RFC 4122) · [RFC 5280] X.509 SPKI · [RFC 7515] JWS · [RFC 7797] unencoded JWS payload ·
[RFC 7518] JWA/ES256 · [RFC 8037] EdDSA in JOSE · [RFC 6979] deterministic ECDSA · [RFC 3339] timestamps ·
[RFC 6838] media type grammar · [ECMA-262] ECMAScript.

---

### Revision log
- **rev-5 · §7.10 addendum (RAPPID Calling Card and Debug Card)** — adds
  `body.calling-card` and `body.debug-card` as registered body-family payload profiles on the existing
  eleven-key `rapp/1` frame. Defines the `.rappid-card.json` virtual resource, explicit and distinct
  `rappid-card/1` / `rappid-card-test/1` tokens, compact non-secret `rappid://link/…` URI, exact signed
  identity/root/compatibility/classification/scope/expiry/revocation/challenge/inventory/key manifest,
  production refusal of visibly synthetic test keys, signed runtime policy and time-scoped issuer
  authorization, strict signed-origin endpoint/redirect/DNS policy, closed signed sequenced revocation
  views, transactional SQLite replay/rollback state across processes, final continuity-before-awake
  commit, bounded depth/size canonicalization before hashing, whole-string token validation,
  pre-DNS rejection of legacy numeric host aliases, ASCII-consistent secret boundaries, and
  deterministic physical/mutation/concurrency fixtures. **Additive only:**
  `m` is the existing payload particle, inventory octets use `rapp/1:egg`, the signature is the existing
  §10 `sig`, and neither the frame key set, `rapp/1` token, RAPPID grammar, canonicalization, nor hash
  spaces change.
- **rev-5 · §7.7–§7.9 addendum (dimensional growth, weight, stats)** — profiles how one mint-once organism
  grows: the
  registered `body.dimension` kind and a payload profile for the already-registered `body.reconstructed`
  kind, plus content-addressed external media references (in the existing `rapp/1:egg` octet space), the
  particle-space trait snapshot, the deterministic fold, and the offspring/parent rule. **Additive only:**
  the eleven-key envelope, the `rapp/1` token, §4 canonicalization, §5 hashing and its tag set, and the
  §6 identity grammar are untouched — this is two §13.3 `kind` entries on the same envelope (§7.1,
  Fed. Const. Art. IV), so `spec` does not move. §7.8 adds **weight** — a RAPPID's data size, in
  verified bytes de-duplicated by content address, attested in the growth frame, split into
  frame/asset/total and the reader's resident/linked view, with missing or unconfirmable sizes surfaced
  as incomplete rather than estimated. Weight is state: it never touches identity, and capability is
  never inferred from it. §7.9 adds the **stat block** — exact `frame_height` (verified chain depth,
  unpaddable by repetition), the declared-once `species`, an optional `display_height_mm` rendered by a
  versioned species growth curve in exact integers and marked presentation (never identity, never a
  physical fact), the weight split, dimensions/traits/capabilities, and explicit completeness — plus
  **proposals**: trait- and lineage-autocompleted next steps that read without writing, project no
  weight, and are worth nothing until appended and verified.
- **rev-5 (war-game round 3 fold)** — folded 5 blockers + 7 majors + 7 minors, all clustered on the trust
  model that rev-4's fixes made load-bearing: the **registry is now a signed root of trust** (§13.1) —
  owner-signed, anchored to the out-of-band `estate_owner` rappid fingerprint, `registry_seq`-monotonic,
  freshness-checked (B-1); **re-anchor requires a verifiable §13.3 authorization record** with old-key
  continuity proof / tombstone / SPKI-tail check (B-2, mint-once now enforceable); **owner-succession is
  time-scoped** so a key rotation never invalidates historical signatures (B-3); **eggs are `stored`-only**
  (deflate is non-deterministic) with `canonical(manifest)` bytes (B-4); **invites sign under the
  estate-owner succession** not the egg's own rappid (B-5); `egg_hash` excludes `sig` (M-1); first
  re-genesis deprecates the creation genesis (M-2); full **registry entry schema** §13.3 (M-3); registry
  freshness rule (M-4); egg consumer enforces §9.1 (zip-slip, M-5); rotated key refused on new frames (M-6);
  `rapplication` exact `agent.py` (M-7); rev label, `invite` naming, sub-egg collision, rounding rule,
  idempotency, compromise-window, seal-path (m-1…m-7).
- **rev-4 (war-game round 2 fold)** — folded 6 blockers + 14 majors + 8 minors: domain-tagged mint
  reconciled across Constitution/ledger (B1); §4(c) binary64 round-trip test so `0.1` is accepted (B2);
  re-genesis head-reset exception so it isn't refused as rollback (B3); family-matched `*.re-genesis` kinds
  so memory/swarm streams can converge (B4); whole-egg address `H("rapp/1:egg-manifest",…)` + signed invites
  + manifest self-reference resolved + deterministic ZIP/`contents` ordering (B5, M2–M4); re-anchor
  enumerated three cases incl. key rotation (B6, M-rotation); `head_octets` pinned to the retained `legacy/`
  artifact (M6); subsequent-convergence via `deprecated` (M7); every stream registers its genesis (M8); JWS
  header canonical bytes + registry key-discovery + `estate_owner` designation (M9–M11); `/chat` error `step`
  as string incl. `"1a"` + code namespace + session semantics (M12, m5); tombstone as the one time-dependent
  verify check (M13); egg draft-artifact + dangling `§4` reference removed (M1, M5); calendar-valid `utc`,
  depth convention, kind dedup/bounds (m2, m7, m8).
- **rev-3 (war-game round 1 fold)** — folded 7 blockers + 19 majors + 12 minors from the Fable adversarial last-call:
  I-JSON input domain + no-normalization/NFC (§4); **domain-separated hashing** (§5, the stronger option);
  fixed `utc` byte form (§7.4); `prev_wave` by stream family not transport (§7.4); **stream-binding**
  anti-replay (§7.5.1a); `spec` token pinned to `rapp/1` (§7.1); full JWS profile + key discovery + rotation/
  tombstone (§10); hardened re-genesis with raw-byte terminal seal + registry linearization (§12.1); heads &
  forks (§7.6); `/chat` fully specified (§8); **egg variants ratified into the standard**, killing the
  6-spec collision and closing EGG-01 (§9); registry append-only (§13); type-validated verify (§7.5.1);
  cross-stream merge tie-break (§7.4); provisional-identifier rule (§6.3); all references added (§15).
- **rev-2** — first last-call tightening (7 self-review defects).
- **rev-1** — initial unified draft.

*Drafted, not merged. Belongs at `kody-w/RAPP/specs/RAPP-1.md`; governed by the Federal Constitution.*
