# Chapter 3 — Content Addressing

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
| `rapp/1:egg`         | a packed egg archive                        |
| `rapp/1:egg-manifest`| an egg's manifest                           |
| `rapp/1:seal`        | a terminal re-genesis seal (chapter 5)      |

Because the tag is part of the preimage, the *same value* produces a *different address* in each
space, by construction:

```python
>>> val = {"x": 1}
>>> R.H("rapp/1:particle", val)[:8], R.H("rapp/1:wave", val)[:8], R.H("rapp/1:egg-manifest", val)[:8]
('…', '…', '…')     # three distinct addresses
```

That is conformance vector V2. A payload address can never be a frame address can never be an
identity, even if the underlying bytes are identical, because they live in different, tagged
spaces. Cross-space collision is not merely unlikely; it is *unrepresentable*.

## 3.3 A Consequence Worth Stating

Domain separation means RAPP addresses are **deliberately incompatible** with an untagged
`sha256(canonical(value))`. This matters when you meet real data. In chapter 8 you will see that
the estate's existing frames store an *untagged* payload hash. The reference `canonical()`
reproduces that untagged value exactly — proving the canonicalization agrees — but
`H("rapp/1:particle", payload)` is a different 64-hex string, on purpose. The difference is not a
bug on either side; it is the §5 hardening. An implementation adopting RAPP tags its hashes;
that is part of what "adopting RAPP" means, and it is why the migration in chapter 8 is a
genuine re-genesis and not a no-op relabel.

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
