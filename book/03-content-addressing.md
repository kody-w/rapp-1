---
layout: book
title: Content Addressing
book_label: Chapter 3
book_progress: 28
book_order: 30
description: Name RAPP values with domain-separated content addresses
---

[← Chapter 2: Canonicalization](02-canonicalization.md) · [Book contents](README.md) ·
[Chapter 4: Identity →](04-identity.md)

# Chapter 3 — Content Addressing

> **In this chapter:** turn canonical values and raw octets into typed addresses, see exactly what
> domain separation prevents, and learn why stores must key by both space and digest.

Once a value has exactly one byte representation (chapter 2), we can name it by its hash. This
is content addressing, and it is the mechanism that makes "the hash is the name" true: identical
content always yields an identical address, so *two things with the same address are the same
thing*, and two things that differ anywhere differ in their address. git built its whole object
store on this; so does RAPP.

But there is a subtlety that, gotten wrong, reintroduces exactly the collision we are trying to
eliminate. That subtlety is the subject of this short, load-bearing chapter.

## 3.1 The Problem: One Hash Function, Many Meanings

Suppose you hash a payload to get its particle, and you hash a rappid's public key to get an
identity tail, and you hash an egg's manifest to get its address — all with plain SHA-256. Now
imagine a value that can legitimately appear in more than one of those roles. Its address is the
same 64-hex string in every role, because SHA-256 does not know or care what you *meant* the
bytes to be. You have built a system where a payload address and an identity tail can collide,
not because of a hash weakness, but because you used the raw hash as if it were an address in
several distinct namespaces at once.

This is not hypothetical. The disease this protocol treats is precisely "the same derivation used
for different jobs." The fix is **domain separation**.

## 3.2 The Rule: Tag the Space, Then Hash

RAPP §5 defines exactly one hashing construction, and it never hashes canonical bytes bare. It
prefixes a **domain tag** — a short string naming the address space — and a newline, then hashes:

```python
def H(space, v):                 # hash a value
    return sha256(space.encode() + b"\x0a" + canonical(v).encode("utf-8")).hexdigest()

def Hb(space, b):                # hash raw octets (for keys, UUIDs)
    return sha256(space.encode() + b"\x0a" + b).hexdigest()
```

The `0x0A` (newline) separator is the same trick git and Nix use: it makes the tag
unambiguously delimited from the content, so no tag can be a prefix of another's content. The
defined spaces are:

| space                | addresses…                                  |
|----------------------|---------------------------------------------|
| `rapp/1:particle`    | a frame's payload (the worldline link)      |
| `rapp/1:wave`        | a whole frame (wire integrity)              |
| `rapp/1:rappid`      | an identity tail (from entropy or a key)    |
| `rapp/1:egg`         | one file's raw octets inside an egg         |
| `rapp/1:egg-manifest`| a whole egg through its canonical manifest  |
| `rapp/1:seal`        | a terminal re-genesis seal (chapter 5)      |

Because the tag is part of the preimage, the *same value* produces a *different address* in each
space, by construction:

```python
>>> val = {"x": 1}
>>> R.H("rapp/1:particle", val)[:8], R.H("rapp/1:wave", val)[:8], R.H("rapp/1:egg-manifest", val)[:8]
('…', '…', '…')     # three distinct addresses
```

That is conformance vector V2. Reusing identical underlying bytes cannot accidentally turn a
payload address into a frame address or an identity, because each role has a different preimage.
Address equality across spaces would require an actual SHA-256 collision rather than a type
confusion, and SHA-256 collision resistance is an explicit security assumption of the protocol.

## 3.3 A Consequence Worth Stating

Domain separation means RAPP addresses are **deliberately incompatible** with an untagged
`sha256(canonical(value))`. This matters when you meet historical data. In chapter 10 you will see
that the estate’s baseline frames stored an *untagged* payload hash. The reference `canonical()`
reproduced that untagged value exactly — proving the canonicalization agreed — but
`H("rapp/1:particle", payload)` is a different 64-hex string, on purpose. The difference is not a
bug on either side; it is the §5 hardening. An implementation adopting RAPP tags its hashes;
that is part of what “adopting RAPP” means. The current estate now stores the tagged form; the
migration was a genuine convergence, not a no-op relabel.

## 3.4 Why SHA-256

RAPP fixes the hash: **SHA-256**, FIPS 180-4, lowercase hex, 64 characters. Not a menu, not a
negotiation. A protocol whose hash is negotiable has, in effect, several protocols, and an
attacker who can pick the weakest wins. One hash, everywhere, is the same discipline as one
canonicalizer and one frame. If SHA-256 must ever be retired, that is a new major version of the
whole protocol — a deliberate, estate-wide, owner-authorized event — not a per-message option.

With canonical bytes (chapter 2) and tagged addresses (this chapter), we have everything needed
to name content unambiguously. Next we use that to build the one name that is *not* derived from
content at all — because deriving identity from content is the one place content addressing must
not be used.

## 3.5 Addresses Are Pairs

A 64-hex digest is not a self-describing global identifier. The complete lookup key is:

```text
(space, digest)
```

This matters at storage boundaries. A table keyed only by `digest` invites later code to fetch a
particle as if it were a wave or a file blob as if it were an egg manifest. Keep the space in the
path, column, object key, or API type:

```text
objects/rapp-1-particle/<digest>
objects/rapp-1-wave/<digest>
objects/rapp-1-egg/<digest>
```

The exact storage layout is application policy; preserving the pair is protocol safety.

## 3.6 Checkpoint: Same Value, Different Roles

```bash
python3 - <<'PY'
import rapp as R

value = {"x": 1}
for space in ("rapp/1:particle", "rapp/1:wave", "rapp/1:egg-manifest"):
    print(space, R.H(space, value))
PY
```

Run it twice: each line is stable across runs, and all three lines differ from one another. Then
change `"x"` to `"y"` and observe that every address changes. Stability comes from canonical
bytes; role separation comes from the tag.

## 3.7 Exercises

**Exercise 3-1.** Extend the checkpoint to print all value-address spaces for one value and all
byte-address spaces for one byte string. State why calling `H` and `Hb` with the same tag is
forbidden.

**Exercise 3-2.** Implement an immutable `Address(space, digest)` and a store that accepts only
that type. Prove a particle digest cannot be fetched as a wave. *A selected solution appears in
Appendix C and `examples/04_typed_addresses.py`.*

**Exercise 3-3.** Design a migration for a table currently keyed by bare digest. How will you
identify the original space without guessing?

**Exercise 3-4.** Write a negative test that rejects uppercase, truncated, and 65-character
digests before any store lookup occurs.

## 3.8 Chapter Summary

- RAPP uses SHA-256 with a newline-delimited domain tag.
- `H` addresses canonical values; `Hb` addresses raw octets.
- The same bytes in two roles have different preimages and therefore different expected addresses.
- A store treats `(space, digest)` as the address, never the digest alone.
- Untagged historical hashes may prove canonicalization agreement while still being non-conformant
  RAPP addresses.

---

[← Chapter 2: Canonicalization](02-canonicalization.md) · [Book contents](README.md) ·
[Chapter 4: Identity →](04-identity.md)
