---
layout: book
title: Glossary and Failure Atlas
book_label: Appendix B
book_progress: 96
book_order: 130
description: RAPP terms, address spaces, and verification failures at a glance
---

[← Appendix A: Reference Manual](A-reference-manual.md) · [Book contents](README.md) ·
[Appendix C: Selected Exercise Solutions →](C-selected-exercise-solutions.md)

# Appendix B — Glossary and Failure Atlas

This appendix is the vocabulary of the book in one place. Definitions summarize the teaching
text; `SPEC.md` remains normative.

## B.1 Core Terms

**address space**

A named domain in which a hash has meaning. RAPP stores and dereferences by `(space, hash)`, never
by a bare 64-hex string.

**authorship**

The claim that a particular key signed an artifact. Authorship requires a valid §10 signature and
does not by itself prove that the key was authorized.

**authority**

The right of a signer to make a decision at a particular time. RAPP derives authority from the
authenticated registry and its owner-succession records.

**biography stream**

A body stream identified directly by a rappid. It chains particles through `prev`; `prev_wave`
is null.

**canonical form**

The one RFC 8785 JCS byte representation of an admissible I-JSON value.

**consumer**

An implementation that validates frames, eggs, signatures, registry state, and all refusal
conditions before accepting input.

**content address**

A SHA-256 digest computed in a named RAPP domain over canonical values or raw octets. The address
changes if the addressed content changes.

**domain separation**

Prefixing hash input with an exact space tag and newline so the same bytes in different roles have
different addresses.

**egg**

A `rapp/1-egg` manifest plus, for tree variants, deterministic stored-ZIP contents. An egg packages
an organism, rapplication, session, invite, neighborhood, estate, or sealed ciphertext artifact.

**estate**

A governed collection of RAPP organisms and neighborhoods sharing an authenticated registry and
owner succession.

**fail closed**

Refuse or report unknown when required evidence is malformed, missing, unreachable, stale, or
unverifiable. Never convert inability to check into a pass.

**frame**

The closed eleven-field RAPP event envelope. It carries a payload particle, a whole-frame wave,
chain links, and an optional signature.

**freshness**

Confidence that authenticated mutable state is recent enough for a decision. A valid registry
signature proves authenticity, not freshness.

**genesis**

The sequence-zero frame from which the current live chain descends. Every stream has exactly one
non-deprecated genesis entry in the registry.

**head**

The highest verified frame descending from the registered genesis. Consumers persist heads to
detect rollback and silent reorganization.

**identity**

Continuity across changing content. In RAPP, identity is the minted tail of a rappid, not its
human-readable owner/slug.

**integrity**

Evidence that bytes or chain links have not changed. Integrity does not imply authorship.

**I-JSON**

The interoperable JSON profile from RFC 7493 on which RAPP canonicalization is defined.

**JCS**

JSON Canonicalization Scheme, RFC 8785. It fixes member order, escaping, number form, and
whitespace so a value has one serialized form.

**kind**

A registered `noun.verb` event name. The registry, not the prefix alone, binds a kind to its
stream family.

**legacy form**

A historical encoding that is not the one current canonical form. Live legacy is drift; sealed
re-genesis history is retained evidence, not a compatibility dialect.

**particle**

`H("rapp/1:particle", payload)`, stored as `payload_hash`. It addresses what happened and links a
worldline through `prev`.

**producer**

An implementation that emits only current canonical values, addresses, identities, frames, and
egg variants.

**provisional identity**

A legacy rappid that can be recognized while reading but whose tail is not a conformant 64
lowercase hex characters. It must not be emitted; becoming current requires owner-authorized
re-anchoring.

**rappid**

The self-locating RAPP identifier
`rappid:@<owner>/<slug>:<64-lowercase-hex>`. Its tail is minted from UUIDv4 octets or SPKI DER,
never from the owner/slug name.

**re-anchor**

An owner-authorized identity transition for exactly one allowed case: provisional upgrade, key
rotation, key compromise, or pre-standard key-tag migration.

**re-genesis**

The owner-authorized convergence operation that seals an old chain, publishes a new sequence-zero
frame, updates the registry, and retires the old bytes under `legacy/`.

**registry**

The signed, append-only estate root of trust for keys, kinds, genesis records, re-anchors,
tombstones, owner succession, and canonical-source pointers.

**router/mirror**

An implementation that transports or serves RAPP artifacts without inventing endpoints or
rewriting addressed bytes.

**stream**

An append-only sequence of frames sharing one `stream_id`.

**swarm stream**

A shared `net:*` stream. It chains particles through `prev`, waves through `prev_wave`, and
requires a signature on every frame.

**tombstone**

An owner-signed registry record that revokes a keyed rappid from `revoked_utc` forward.

**wave**

`H("rapp/1:wave", frame - {frame_hash, sig})`, stored as `frame_hash`. It addresses the exact
unsigned envelope and protects wire integrity.

**worldline**

The particle-linked history of an organism or stream.

## B.2 Address Spaces

| Space | Function | Input |
|---|---|---|
| `rapp/1:particle` | frame payload address | canonical value via `H` |
| `rapp/1:wave` | unsigned frame-envelope address | canonical value via `H` |
| `rapp/1:rappid` | identity tail | UUID or SPKI octets via `Hb` |
| `rapp/1:egg` | packed file address inside an egg | raw octets via `Hb` |
| `rapp/1:egg-manifest` | whole egg identity | manifest without `sig` via `H` |
| `rapp/1:seal` | retired-head seal | exact retained head octets via `Hb` |

A bare digest should always make you ask: **in which space?**

## B.3 Frame Verification Failure Atlas

| Step | Consumer checks | Typical failure |
|---|---|---|
| `1` | exact keys, types, grammar, registry values, fixed UTC | dialect, missing/null confusion, malformed field |
| `1a` | `stream_id` equals the stream of record | cross-stream replay |
| `2` | recomputed particle equals `payload_hash` | payload changed |
| `3` | recomputed wave equals `frame_hash` | envelope changed |
| `4` | genesis or contiguous particle chain and nondecreasing UTC | gap, fork, wrong parent, time reversal |
| `5` | swarm `prev_wave` rule; null elsewhere | wrong wire discipline |
| `6` | required/present signature, key binding, tenure, tombstone | missing authorship or unauthorized signer |

The step is a refusal location, not a repair instruction. Correct the producer or perform an
authorized migration; do not mutate the received frame until it passes.

## B.4 Notation

| Notation | Meaning |
|---|---|
| `canonical(v)` | UTF-8 JCS serialization of admissible value `v` |
| `H(space, v)` | SHA-256 of `utf8(space) + 0x0A + canonical(v)` |
| `Hb(space, b)` | SHA-256 of `utf8(space) + 0x0A + raw octets b` |
| `x - {a,b}` | object `x` with exactly members `a` and `b` removed |
| `64hex` | exactly 64 lowercase hexadecimal characters |
| `uint53` | integer from 0 through 2^53−1 |
| SPKI DER | canonical DER encoding of a SubjectPublicKeyInfo public key |

---

[← Appendix A: Reference Manual](A-reference-manual.md) · [Book contents](README.md) ·
[Appendix C: Selected Exercise Solutions →](C-selected-exercise-solutions.md)
