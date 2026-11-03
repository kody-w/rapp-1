# RAPP Layer
## Device-local living holograms for the Brainstem's shape

**Protocol identifier:** `rapp-layer/1`
**Status:** Proposed subordinate RAPP/1 profile; not a signed registry adoption
**Parent:** [`rapp/1`](../../../SPEC.md)
**Depends on:** `rapp/1` only
**Schema:** [`schema.json`](schema.json)

A Brainstem is a living hologram: its identity is its device-local stream,
its substance is its whole append-only chain, and its present is its verified
head. The carried object is the Brainstem's **shape**, not its user data.
Only a pure lens changes that object. Only a passing host gate authorises a
shape to run. The chain is authority for the local shape; `applied.json`,
an `enabled` file, a pack, and a status display are projections or discovery,
never competing sources of authority.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are
used as defined by RAPP/1 section 2.

## 1. Substrate and adoption

All payloads **MUST** be canonical RAPP/1 I-JSON, identified by
`H("rapp/1:particle", payload)`, inside the unchanged eleven-key frame.
This profile adds no endpoint, envelope member, hash domain, registry-entry
type, or alternative wire form. It **MUST NOT** weaken RAPP/1 section 11.1.
An adopting estate registers this specification with an ordinary `protocol`
entry and proposes these ordinary `kind` entries in the `memory` family:

| Kind | Payload |
| --- | --- |
| `shape.genesis` | A `brainstem-shape/1` object |
| `shape.tile` | The closed tile described in section 4 |
| `shape.gate` | The closed gate described in section 5 |

These are proposals until adopted in an authenticated registry. Their payload
shapes, not new `schema` members, distinguish tiles and gates.
They are device-local memory occurrences; `sig:null` is permitted by the
base protocol. A hash chain establishes integrity, not the identity or
authority of whoever can rewrite the device's files.
The host **MUST** protect its stream and gate writer. An exported unsigned
chain **MUST NOT** authorise effects on another device or override its owner.
External authoritative adoption requires the existing signed RAPP/1 rules.

Every frame **MUST** pass the ordinary RAPP/1 consumer checklist, including
stream identity, predecessor links, sequence and timestamp checks. Order is
verified chain position, never a sort by UTC or a file modification time.
Equal timestamps do not make frames interchangeable. The base requirement
that UTC not regress still applies.

## 2. Shape and parts

The object has exactly `schema, grail, safe_mode, parts`.
`schema` is exactly `brainstem-shape/1`.
`grail` is exactly `{sha256, bytes}`: the lowercase SHA-256 of the unchanged
safe-mode `brainstem.py` and its positive integer byte length.
The Grail pin **MUST NOT** change through this lens. A production consumer
**MUST** bind it to its activated section 13.3 declaration and execution under
section 11.1, rather than accepting a new local file as equivalent.
`safe_mode` is boolean. When true, no part executes.

`parts` is an ordered array of at most **64** entries. This is the runtime's
defensive work bound for a small device shape, not an eviction limit.
The current six named points make the effective maximum six occupants;
the larger array bound does not create unnamed slots.
Empty parts mean plain Grail. No part is reordered by id or locator.

Every part is exactly `id, kind, point, file, sha256, locator`:

- `id` is publisher-scoped, matching
  `^@[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9_]+(?:[-.][a-z0-9_]+)*$`.
  This runtime grammar deliberately includes underscores and dots in names;
  it is not the narrower RAPP label grammar. Bare names are refused.
- `kind` is `layer` or `kernel`. `sidecar` is unavailable and refused.
- `point` is `provider`, `auth`, `storage`, `agents`, `transport`, or `kernel`.
  Only a kernel occupies `kernel`; a kernel occupies no other point.
- `file` is one Python filename matching
  `^[A-Za-z0-9_][A-Za-z0-9_.-]*\.py$`, with no directory traversal.
- `sha256` pins the exact part file bytes in lowercase hexadecimal.
- `locator` begins with `https://` and is discovery only. Fetching succeeds
  only if the resulting bytes match the pin. A changed URL cannot change
  identity or authorise different bytes.

Ids, filenames, and extension points **MUST** each be unique in a shape.
Two occupants are a refusal, not a later-wins merge or a runtime skip.
The namespace-to-disk projection is `parts/<publisher>/<name>/<file>`.
Existing and fetched files **MUST** match their pins before execution.
Layer hook compatibility (`PROVEN_GRAIL`, `TOUCHES`) remains an execution
check, not extra members of the shape or a substitute authority document.

A layer runs in process over the untouched Grail. A kernel part is a
separately pinned whole-Brainstem candidate, not changed bytes under the
Grail's identity. It **MUST** pass the same oracle, preserve plain-Grail
fallback, and satisfy section 11.1's separate-identity and release rules.

## 3. Genesis and the one lens

Frame zero **MUST** be `shape.genesis`, carrying the shape directly:
no parts and `safe_mode:false`. The existing device stream id is retained
exactly; a new fixture, cache or checkout does not mint a replacement.
All later frames are `shape.tile` or `shape.gate`. A second genesis is refused.
The genesis object is the authorised plain-Grail state until a gate passes.

The one lens is `shape_lens.perform(object, params)`.
It **MUST** be pure: no model, clock, randomness, network, filesystem,
or hidden carried state. It returns a new object without mutating its input.
Invalid input **MUST** be refused, never repaired and appended as success.
Its four actions are:

| Action | Required input and effect |
| --- | --- |
| `add` | `part`; replace the same id if present, then append it at the end |
| `remove` | `id`; refuse if absent, otherwise remove that part |
| `safe_mode` | Boolean `on`; retain parts and set safe mode |
| `set` | Ordered `parts`; optional boolean `safe_mode`, otherwise retain it |

After each action, uniqueness and part rules still hold. `set` is the undo
mechanism: an old shape is reapplied as a new tile, never by rewriting history.
Extra parameter data is retained and hashed but has no transition effect;
the runtime parameter object is not a closed per-action envelope.
An add may replace or move a part, but never silently occupy another part's
point. Every transition preserves `grail`.

## 4. Tiles, derivation and replay

A tile payload has exactly:

`object, derived_from, lens, params, params_hash, slush_in, caller, lease`.

`object` is the resulting validated shape. `derived_from` is the frame hash
of the **currently authorised tile**, or genesis when no tile is authorised,
at this tile's append position. It is not necessarily the latest tile or
the immediately preceding gate. A failed or ungated tile is a dead end for
the next derivation. A changed base cannot be disguised by rehashing a tile.

`lens` is exactly `{name, sha256}`, with `name:"shape_lens"` and the raw
SHA-256 of the lens source bytes, including descriptions. Source identity
is pinned; a name or URL alone never selects executable behavior.
`params` records exactly the caller's JSON object.
`params_hash` **MUST** equal `H("rapp/1:particle", params)`.
This bounded device lens has no slush or lease: both fields are exactly null.
`caller` is exactly `{kind, name}`, with `kind` `person` or `process` and
a nonempty name. This is a local attribution claim, not a verified signature.

A verifier **MUST** reproduce every tile through its recorded lens from
the authorised input shape, then compare canonical output byte-for-byte
with `object`. A valid frame hash without replay is insufficient.
Unknown lens pins, wrong parameter particles, wrong bases, and different
outputs **MUST** be refused. No historical tile is retagged to a newer lens.

The real-chain fixture records source pin
`91279ca0cc6f7bab461f96f8123046d3952e292d9cc7611c409d2d0d325a3a22`.
The supplied current runtime source measures
`e404727c61a9d3e2afeeb4967a7283ecdcacc8ece36d5f23cb15a48b10ac8160`.
The reference explicitly recognises these two distinct identities and
reproduces the fixture's transitions. This is behavioral replay, not proof
that the unavailable historical source bytes equal the current source.
A verifier requiring source-possession proof **MUST** obtain and verify the
recorded historical bytes; this repository does not fabricate that proof.

## 5. Gates and authorisation

A gate payload is exactly `tile, gate, passed, evidence`.
`tile` is the frame hash of an earlier tile in this stream.
`gate` is `lab` or `live`; `passed` is boolean.
`evidence` is a canonical JSON object of host-run observations. Its keys are
open: the runtime emits `why` and may include `applied`, `skipped`, shortened
`grail`, or unavailable `parts`. These are diagnostics, not a second SBOM.
Evidence from a previous run **MUST NOT** substitute for checking the candidate.

The **newest passing gate by chain position** authorises its referenced
tile. With none, genesis is authorised. A later failed gate records failure
but does not by itself replace the previous passing authorisation.
The current object (newest tile) and authorised running object are distinct
projections. Both **MUST** be derived from the verified chain.

The supervisor's agent path is lens, tile, spare-port lab boot, health/chat
probe, gate. A lab pass authorises the next restart, not an in-place mutation
of a serving Brainstem. A live boot takes the authorised shape and records
a live gate. Only the host gate writer may attest those effects.
Oracle compatibility uses the existing `layers:` candidate mode; a health
probe alone does not establish all wire-conformance or execution guarantees.

## 6. Failure isolation, flap guard and GODD data

Plain Grail **MUST** remain independently bootable without importing a part.
Safe mode selects it without changing pinned kernel bytes.
Missing or changed part bytes **MUST NOT** execute.
An unsuccessful shaped boot **MUST** stop and attempt plain Grail.
Failure of plain Grail **MUST** be surfaced, not reported as a successful boot.

The flap guard counts failed **live** gates scanning backward until **any**
passing gate. Two live failures trigger the previous distinct passing tile,
or genesis if none exists. The threshold is two to avoid permanently
flapping a candidate after a transient first failure.
Intervening failed lab gates do not count; a lab pass resets this counter.
Fallback startup and its actual candidate **MUST** be measured truthfully.

GODD data follows every shape: the user's `agents/` and `soul.md` are
retained and supplied to a kernel candidate through `AGENTS_PATH` and
`SOUL_PATH`. Parts **MUST NOT** contain, own, migrate or erase user data.
Device-specific facts belong to data, never a published part's bytes.
Removing a part changes desired code, not the user's identity or history.

Chains exceeding **50 000** frames produce a warning because replay reads
the entire device history at boot. This is a checkpoint prompt, not a
capacity cutoff or permission to delete. Owner-authorised re-genesis follows
RAPP/1 section 12.1; absent its signing authority, retain the whole chain.

## 7. Conformance

`python3 layer_conformance.py <chain.jsonl>` checks profile registration,
frame integrity, closed payloads, authorisation, derivation and replay.
Without an argument it uses the committed nine-frame real lifecycle.
That fixture retains its stream id, payloads and all frame hashes.
The stdlib reference is [`rapp_layer.py`](../../../rapp_layer.py).
Schema validates structure; replay and host execution remain separate checks.
Passing these vectors does not certify local file security, gate independence,
process liveness, source possession, or production Grail conformance.
