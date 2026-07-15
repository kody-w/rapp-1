# Chapter 4 — Identity: the rappid

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

## 4.4 Re-anchoring: the Three Lawful Cases

A minted tail is permanent, but there are three situations where an identity legitimately needs a
*new* anchor, and §6.3 enumerates them exhaustively so that "re-anchoring" can never become a
loophole for silent re-minting:

1. **Keyless → keyed.** An organism that started keyless later adopts a keypair. It re-anchors
   from `Hb(uuid)` to `Hb(SPKI)` — with a signed frame in its chain that records the old tail, the
   new tail, and a signature under the new key proving the same actor authorized the move.
2. **Key rotation.** A keyed actor rotates to a new keypair. The re-anchor frame is signed by the
   *old* key (proving authority) and names the new SPKI-derived tail (chapter 10 covers the JWS
   profile and key rotation/tombstone mechanics).
3. **Pre-standard tail.** An identity minted before the domain-tag rule (an untagged
   `sha256(SPKI)` or a short 32-hex name-hash) is re-anchored to the tagged form once, in the
   migration window, and the old form is then deleted, not read forever.

In every case the re-anchor is **verifiable** — it lives as a signed frame in the identity's own
biography, so the succession from old tail to new tail is itself part of the tamper-evident
record. There is no out-of-band "trust me, this is the same agent."

## 4.5 One Namespace, One Authority

Estate-wide there is one rappid form and one authority over it (the owner). Not a bare
`rappid:<slug>:<hash>` in one repo and a self-locating `rappid:@owner/slug:<hash>` in another —
one form. When chapter 8 meets a rappid whose tail is 32 hex characters instead of 64, or whose
schema says `rapp-rappid/2.0` instead of `rapp/1`, the reference checker flags it, not as a
value judgment but as a fact: it is not the one form, so it is drift on the way to being migrated.

Identity is the hard floor of the protocol. Get the mint wrong and every signature and every
chain above it is anchored to a lie. Get it right — mint once, tag the space, never hash the
name — and the frame can safely be built on top of it. Which is chapter 5.
