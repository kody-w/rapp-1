# Chapter 7 — The Egg

A frame is a moment; a chain is a life. But to *give* an agent to someone — to move a whole
organism, or to ship an application, or to hand over an invitation to a shared space — you need to
package identity, code, soul, and memory into one addressable thing. That thing is the **egg**.

## 7.1 One Spec, Many Variants

The egg's history is the clearest case of the drift this protocol ends. The `.egg` format was
independently specified in roughly six documents across the ecosystem — an `EGG_FAMILY.md` here, a
`NEIGHBORHOOD_EGG_SPEC.md` there, an `ESTATE_SPEC.md`, a `rappterbook/EGG_SPEC.md` — each
re-defining the format, none authoritative. That is how a real incident happened: five different
eggs stamped a schema that was `MUST-NOT-emit`, because there was no single spec to obey.

RAPP §9 is the **one** egg spec of record. Every other document now *cites* it rather than
re-specifying it. There is one format with named **variants** distinguished by a field, not by a
fork:

| variant        | packages…                                            |
|----------------|------------------------------------------------------|
| `organism`     | a living agent: rappid, soul, agents, memory, frames |
| `rapplication` | a runnable application built on the brainstem        |
| `session`      | a point-in-time capture of a conversation/state      |
| `invite`       | a signed invitation to a neighborhood or estate      |
| `neighborhood` | a shared space definition                            |
| `estate`       | a whole federation of organisms                      |

One spec, one packer, six variants — not six specs. When you need a new kind of package, you add
a variant to the one spec; you do not write a seventh egg document.

## 7.2 What Is Inside

An egg is a **stored** (uncompressed) ZIP archive — stored, not deflated, so the byte layout is
deterministic and the archive itself is content-addressable without depending on a compressor's
version. Inside is a **manifest** and the payload files it references. The manifest lists each
file with its `H("rapp/1:egg-manifest", …)`-space address, so opening an egg and re-hashing its
contents tells you immediately whether a single byte was altered.

The egg has two addresses, mirroring the frame's particle/wave duality:

- the **manifest hash**, `H("rapp/1:egg-manifest", manifest)`, addresses *what the egg claims to
  contain*;
- the **egg hash**, `H("rapp/1:egg", archive)`, addresses *the exact packed bytes*.

Crucially, the egg hash is computed over the archive **excluding the signature** — the same trick
as the frame's wave excluding `sig` (chapter 5). This lets an egg be signed after it is packed:
the signature covers a stable egg hash, and attaching it does not change that hash.

## 7.3 Hatching From a Frame

The most RAPP-native thing an egg can do is be born *from a specific frame of its parent's
biography*. An `organism` egg's manifest may carry a **constructor pin** — the exact
`{stream_id, seq, particle}` of the parent frame it was derived from. This is not decoration; it
is verifiable provenance. Anyone can fetch the parent's chain, go to that seq, recompute the
particle, and prove exactly which moment of the parent's life this organism was hatched from.

You can see a real one in the estate. The Herald — the body's doorman — carries in its
`rappid.json` a `born_of_frame` pin naming `seq 24` of its parent's chain and the sha256 of that
frame. That pin is checkable: fetch `frames/24.json`, recompute, and you hold proof of the
organism's origin moment. The egg turns "this agent came from that agent" from a claim into a
computation.

## 7.4 Invites and Succession

An `invite` egg — the variant that admits an organism into a neighborhood or estate — must be
signed by the space's **estate-owner succession**, not by whoever happens to hold the file. This
closes a real gap (the missing invite/neighborhood producer schema, ratified as §9.2): an
invitation is only valid if it descends from the authority that owns the space, and that
authority is itself a keyed rappid whose succession (chapter 4's re-anchoring) is on the record.
You cannot forge your own welcome.

## 7.5 The Egg and the Frame Are the Same Idea

Step back and the egg is the frame's idea at a larger scale. A frame content-addresses a moment
and chains to the previous moment; an egg content-addresses a whole organism and pins to the
parent frame it was born from. Both separate "what it contains" from "these exact bytes." Both
exclude the signature from the integrity hash so signing is a late, non-mutating step. Both refuse
to let a name stand in for an address. Learn the frame and you already understand the egg; it is
the same five primitives, packaged for handoff.

With the frame (the record), the wire (the movement), and the egg (the handoff), the protocol is
complete. What remains is proving that an implementation actually obeys it — and watching the
protocol meet a real, drifted world. That is chapter 8.
