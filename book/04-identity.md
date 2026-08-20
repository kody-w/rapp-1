---
layout: book
title: Identity — the rappid
book_label: Chapter 4
book_progress: 36
description: Mint durable RAPP identities without hashing human names
---

[← Chapter 3: Content Addressing](03-content-addressing.md) · [Book contents](README.md) ·
[Chapter 5: The Frame →](05-the-frame.md)

# Chapter 4 — Identity: the rappid

> **In this chapter:** distinguish location from identity, mint keyed and keyless rappids, reject
> the name-hash trap, and follow the only authorized transitions from one identity anchor to
> another.

An agent needs a name that stays the same as its content changes. Its biography grows every day;
its address must not. This is the one place in RAPP where content addressing is *wrong*, and
understanding why is understanding the `rappid`.

## 4.1 The Grammar

A rappid is a string:

```
rappid:@<owner>/<slug>:<64hex>
```

- `owner` and `slug` are lowercase labels — `[a-z0-9]` with internal single hyphens
  (the same shape as a DNS label, case-sensitive per RFC 7405).
- `64hex` is the minted tail: exactly 64 lowercase hex characters.

For example: `rappid:@kody-w/rapp-body:324197c16e7e0ca78e19f8a4e1aef76ed34b6694527bb566753c4c89a8ba71f6`.

The reference implementation validates the grammar with one regular expression:

```python
_RAPPID = re.compile(r"^rappid:@([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:-[a-z0-9]+)*):([0-9a-f]{64})$")
def rappid_valid(s):  return bool(_RAPPID.match(s))
```

The `@owner/slug` part is **self-locating** — it tells a human (and a resolver) where to look.
But it is not the identity. The identity is the 64-hex tail, and everything important is in how
that tail is born.

## 4.2 Mint-Once: the One Rule

> The tail is minted **once**, from entropy or from a public key. It is **never** a hash of the
> name, and never recomputed from mutable facts.

There are exactly two lawful mints, both domain-tagged through the `rapp/1:rappid` space of
chapter 3:

```python
def mint_rappid(owner, slug, spki_der=None):
    if spki_der is not None:
        tail = Hb("rapp/1:rappid", spki_der)        # KEYED: from the public key (SPKI DER)
    else:
        tail = Hb("rapp/1:rappid", uuid.uuid4().bytes)  # KEYLESS: from fresh entropy
    return f"rappid:@{owner}/{slug}:{tail}"
```

- **Keyless.** The tail is `Hb("rapp/1:rappid", uuid4_octets)` — a stable, opaque *join key*
  anchored on a random UUID (RFC 9562). Use it for organisms that hold no keypair; identity is
  anchored on entropy, and integrity comes from the frame chain (chapter 5), with a signature
  optional.
- **Keyed.** The tail is `Hb("rapp/1:rappid", SPKI_DER)` — derived from the DER-encoded
  SubjectPublicKeyInfo (RFC 5280) of the actor's public key. This tail is *verifiable*: anyone
  holding the public key can recompute the tail and confirm the binding. Use it whenever the
  actor signs.

Because the mint is deterministic in its input, a keyed identity is reproducible — mint it twice
from the same key and you get the same rappid (conformance vector V3). That is what "minted once"
means operationally: not "computed once and stored," but "a function of a fixed anchor, forever."

## 4.3 Why a Name-Hash Is Fatal

The forbidden mint is `sha256("<owner>/<slug>")`. It is seductive because it needs no state: any
program can "recover" the identity from the name. That is exactly the catastrophe. Run
`examples/03_identity.py`:

```
FORBIDDEN name-hash tail: 2479029e83eda461795703fae7d1fa790e9c79f3404bb79d81ad1720c155bf69
  → collides for every actor that ever names something 'kody/twin'.
```

If identity is a hash of the name, then identity *is* the name, dressed in hex. Two different
agents that happen to choose the same `owner/slug` get the same tail and become, cryptographically,
the same agent. Worse, an identity minted this way cannot be bound to a key — there is nothing
secret behind it — so it can be impersonated by anyone who can type the name. This precise mistake
was live in production in this ecosystem: `_frame.mjs` computed `sha256("<owner>/<slug>")` as an
"eternity hex." RAPP §6.2 outlaws it. Names are chosen; identities are minted. They must not be
the same operation.

## 4.4 Re-anchoring: the Closed Set of Cases

A minted tail is immutable. When continuity must move to a new anchor, §6.3 requires an
owner-signed registry re-anchor record and limits its `case` to a closed set:

1. **`upgrade`.** A provisional 32-hex historical identity becomes a conformant 64-hex identity.
   The old identifier must already resolve to this owner at read time.
2. **`rotation`.** An uncompromised keyed actor moves to a new SPKI-derived tail. The old key signs
   the transition as continuity proof.
3. **`compromise`.** A compromised key cannot safely sign its successor. The estate owner records
   the transition together with a tombstone for the old rappid.
4. **`tag-migrate`.** A pre-rev-3 keyed tail made with bare `sha256(SPKI_DER)` moves once to the
   domain-separated form after the verifier proves the old derivation.

The first, third, and fourth cases rely on estate-owner authority because the old identity cannot
provide ordinary continuity proof. The second requires both owner authorization and the old key.
Chapter 8 develops the JWS, discovery, tenure, and tombstone checks.

The `_migrated_from` field in an application record is evidence to inspect, not authority to
trust. Without the registry authorization, anyone could claim to be the successor of anyone else.

## 4.5 One Namespace, One Authority

Estate-wide there is one rappid form and one authority over it (the owner). Not a bare
`rappid:<slug>:<hash>` in one repo and a self-locating `rappid:@owner/slug:<hash>` in another —
one form. Chapter 10’s baseline report meets rappids whose tails are 32 hex characters instead of
64 and records whose schema says `rapp-rappid/2.0` instead of `rapp/1`. The reference checker
flags them as facts, not value judgments. Its current report then proves that all four inspected
identity records completed the migration.

Identity is the hard floor of the protocol. Get the mint wrong and every signature and every
chain above it is anchored to a lie. Get it right — mint once, tag the space, never hash the
name — and the frame can safely be built on top of it. Which is chapter 5.

## 4.6 The Identity Lifecycle

```text
mint once
   │
   ├── keyless: Hb(rappid, UUIDv4 octets)
   └── keyed:   Hb(rappid, SPKI DER)
   │
   ▼
use stored tail unchanged
   │
   └── exceptional owner-authorized re-anchor
          ├── upgrade
          ├── rotation
          ├── compromise + tombstone
          └── tag-migrate
```

Renaming the human-readable slug does not create identity continuity by recomputation. Moving
owners, adopting a key, or changing naming policy needs an explicit application/registry operation
whose continuity rules are defined; the protocol never “recovers” identity from the new name.

## 4.7 Checkpoint: Prove the Name Is Not the Tail

Run:

```bash
python3 examples/03_identity.py
```

Then mint two keyless rappids with the same owner and slug. Their human-readable prefixes match,
but their tails differ because each mint uses fresh entropy. Mint twice from the same SPKI bytes;
those tails match because the public key is the stable anchor.

This is the intended split:

| Input | Same name? | Same anchor? | Same identity tail? |
|---|---:|---:|---:|
| two keyless mints | yes | no | no |
| two mints from one SPKI | yes | yes | yes |
| raw `sha256(owner/slug)` | yes | no anchor exists | forbidden |

## 4.8 Chapter Summary

- A rappid contains a self-locating owner/slug and a 64-hex minted identity tail.
- Keyless identity anchors on fresh UUIDv4 octets; keyed identity anchors on SPKI DER.
- Hashing the human name creates a public collision recipe, not an identity.
- Existing tails are reused on read; they are never silently re-minted.
- Re-anchoring is registry-authorized and limited to upgrade, rotation, compromise, or tag
  migration.

---

[← Chapter 3: Content Addressing](03-content-addressing.md) · [Book contents](README.md) ·
[Chapter 5: The Frame →](05-the-frame.md)
