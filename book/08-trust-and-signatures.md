---
layout: book
title: Trust and Signatures
book_label: Chapter 8
book_progress: 68
description: Add authorship and authority to RAPP integrity
---

[← Chapter 7: The Egg](07-the-egg.md) · [Book contents](README.md) ·
[Chapter 9: The Registry, Evolution, and Security →](09-registry-evolution-and-security.md)

# Chapter 8 — Trust and Signatures

> **In this chapter:** where content addressing stops, what a signature adds, the exact RAPP JWS
> profile, how a verifier discovers keys, and why rotation and revocation are questions about
> time rather than hash links.

A hash tells you whether bytes changed. A chain tells you whether a history was rewritten after
a trusted head. Neither tells you who wrote the bytes. That last claim — authorship — begins only
when a key signs a frame and a verifier can connect that key to an authoritative identity.

RAPP keeps these claims separate on purpose. Systems become unsafe when “the hash checks” quietly
turns into “therefore Alice wrote it,” or when “this key signed it” quietly turns into “therefore
this key was authorized here.” Integrity, authorship, authority, and freshness are four different
questions.

## 8.1 Four Claims, Four Checks

| Claim | Evidence | What it does **not** prove |
|---|---|---|
| these are the original payload bytes | recomputed `payload_hash` | who produced them |
| this is the original frame envelope | recomputed `frame_hash` | that it is the current head |
| this key signed this frame | valid §10 JWS | that the key was authorized at that time |
| this key was authoritative then | verified, fresh registry + succession records | that a newer head does not exist |

The first two checks are local and time-independent. Given a frame, you can recompute them without
contacting anyone. The last two cross a trust boundary: you need a public key, an authenticated
registry, and a policy about whether that registry is fresh enough.

This is why signatures do not replace the particle or the wave. The hash chain gives every frame
a stable identity and makes history tamper-evident. A signature adds a statement by a key about
that already-stable frame.

## 8.2 When a Signature Is Required

RAPP has two signing disciplines:

- A **memory or body stream** may be unsigned. Its particle chain still protects integrity given
  a trusted head, but an unsigned frame makes no authorship claim.
- A **swarm stream** (`net:*`) must be signed. Several actors may append to one shared wire, so
  every envelope needs an attributable producer. `verify_frame` refuses an unsigned swarm frame
  at step 6.

Optional does not mean decorative. If `sig` is non-null, it must verify completely. A consumer
must never treat an invalid signature as if the frame had simply been unsigned.

## 8.3 The Exact JWS Profile

RAPP uses detached, unencoded JWS: RFC 7515 Appendix F plus RFC 7797. The protected header has
**exactly** four members:

```json
{
  "alg": "EdDSA",
  "b64": false,
  "crit": ["b64"],
  "kid": "rappid:@owner/agent:<64hex>"
}
```

`alg` is `EdDSA` (Ed25519) or `ES256`. `kid` is the signer’s keyed rappid. There are no optional
header extensions, because an open-ended protected header would create dialects that verifiers
interpret differently.

The header is canonicalized before base64url encoding. The frame signing input is:

```text
BASE64URL(canonical(protected-header))
    + "."
    + canonical(frame without sig)
```

The stored `sig` is the detached compact serialization:

```text
BASE64URL(canonical(protected-header)) .. BASE64URL(signature-bytes)
```

The empty middle segment is not a missing value. It is the visual marker that the payload travels
outside the compact JWS string. In RAPP, that external payload is the canonical frame with only
`sig` removed; `frame_hash` remains present and signed.

The complete dependency is:

```text
payload
   │ canonicalize + H("rapp/1:particle", ...)
   ▼
payload_hash
   │ included in frame preimage
   ▼
frame_hash = H("rapp/1:wave", frame - {frame_hash, sig})
   │ included in signed frame
   ▼
JWS(frame - {sig})
```

Changing the payload breaks the particle, the wave, and the signature. Changing only envelope
metadata breaks the wave and the signature. Re-signing does not change the wave, because `sig`
was never in its preimage.

## 8.4 Key Discovery Is Part of Verification

A JWS can be mathematically valid under any public key an attacker supplies. The verifier must
therefore answer a harder question: *is this the public key bound to the `kid`?*

RAPP resolves the signer’s SPKI DER through the authenticated §13 registry, then checks:

```text
Hb("rapp/1:rappid", SPKI_DER) == tail(kid)
```

Only after that binding succeeds does it verify the JWS. The `rappid.json` published at an
organism’s door is useful source material for producing the registry entry, but it is not itself
the verification authority. Otherwise an attacker could publish a new file containing both the
identity and the key they wanted you to trust.

A complete signature check therefore has four stages:

1. parse the detached JWS and require the exact protected-header shape;
2. obtain the signer’s SPKI from a verified, sufficiently fresh registry;
3. recompute the keyed rappid tail and require it to equal `kid`;
4. verify the signature over the exact canonical signing input.

Any missing registry entry, tail mismatch, unsupported algorithm, extra header member, stale
revocation state, or bad signature is a refusal.

## 8.5 Rotation, Compromise, and Time

Keys expire socially even though old hashes remain mathematically valid. RAPP records that change
without rewriting history.

### Rotation

A routine rotation creates a new keyed rappid and a registry re-anchor record. The record carries
continuity proof from the old key. Frames before the re-anchor time may still verify under the old
key; frames at or after that time must not.

### Compromise

When the old key cannot safely authorize its successor, the estate owner records a tombstone and a
`case:"compromise"` re-anchor. The tombstone has a `revoked_utc`. A verifier refuses old-key
signatures on frames whose `utc` is at or after that instant.

### Why the comparison uses time

Revocation should not erase valid history. If a key was legitimate on Monday and compromised on
Thursday, Monday’s signed frames remain evidence. Thursday-and-later frames do not. That makes
signature verification the one §7.5 step whose answer may change as new registry facts arrive.

There is a limit worth naming: frame `utc` is producer-controlled. A stolen key can backdate a
frame to just before `revoked_utc`. After a compromise, the operator should advance or re-genesis
affected stream heads past the revocation boundary instead of trusting the timestamp alone.

## 8.6 What the Small Reference Profile Does

`rapp.py` intentionally keeps cryptographic dependencies out of the stdlib-only teaching core. It
computes particles and waves, enforces chain rules, and refuses an unsigned swarm frame. It does
**not** perform Ed25519/ES256 verification, registry key discovery, rotation, or tombstone checks.

That boundary is a teaching aid, not a reduction of the protocol:

| Surface | Signature coverage |
|---|---|
| `rapp.py` | presence rule for swarm frames |
| `conformance.py` | vector V9 proves unsigned swarm refusal |
| a full RAPP consumer | all §10 JWS, discovery, succession, and revocation checks |

An implementation claiming full **Consumer** conformance must cross the whole boundary. Passing
the small reference vectors proves the byte primitives; it does not waive the trust checks.

## 8.7 Checkpoint: Review a Signature Without Trusting It

Take any signed-frame design and ask these questions in order:

1. Which exact bytes are signed?
2. Can two serializations of the same value produce different signing inputs?
3. Where does the verifier obtain the public key?
4. What binds that key to the claimed identity?
5. What says the key was authoritative at the frame’s `utc`?
6. What prevents a stale registry from silently un-revoking it?

If any answer is “the sender tells us,” the design has not completed verification. It has only
checked a signature.

## 8.8 Chapter Summary

- Hashes prove byte integrity; signatures add authorship; the registry adds authority.
- Memory and body streams may be unsigned; swarm streams must be signed.
- RAPP uses one exact detached, unencoded JWS profile with EdDSA or ES256.
- A keyed rappid is verified by recomputing its tail from registry-provided SPKI DER.
- Rotation and tombstones are time-scoped so history survives while new misuse is refused.
- The stdlib reference demonstrates the signing boundary but does not implement the full PKI.

The remaining question is where the trusted key records, current genesis, kind registry, and owner
succession live. They all meet in one place.

---

[← Chapter 7: The Egg](07-the-egg.md) · [Book contents](README.md) ·
[Chapter 9: The Registry, Evolution, and Security →](09-registry-evolution-and-security.md)
