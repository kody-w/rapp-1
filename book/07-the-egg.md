---
layout: book
title: The Egg
book_label: Chapter 7
book_progress: 60
book_order: 70
description: Package RAPP organisms and applications into deterministic eggs
---

[← Chapter 6: The Wire](06-the-wire.md) · [Book contents](README.md) ·
[Chapter 8: Trust and Signatures →](08-trust-and-signatures.md)

# Chapter 7 — The Egg

> **In this chapter:** package a whole unit of the RAPP world, distinguish JSON and tree
> containers, derive the egg’s address from its manifest, reject unsafe archive paths, and build a
> deterministic organism egg with the reference profile.

A frame is a moment; a chain is a life. To hand an agent to someone else — identity, soul, code,
and state together — we need a content-addressed package larger than one event. RAPP calls that
package an **egg**.

The egg reuses every earlier lesson: canonical values, named hash spaces, minted identity, exact
schemas, optional signatures, and refusal rather than repair.

## 7.1 One Spec, Six Variants

The egg’s history is the clearest case of the drift this protocol ends. The format was once
re-specified by several documents, each naming a slightly different archive and each believing it
was authoritative. RAPP §9 replaces that family of dialects with one manifest and six registered
variants:

| Variant | Container | Packages | Minimum viability |
|---|---|---|---|
| `organism` | stored ZIP | one living agent | `rappid.json`, `soul.md` |
| `rapplication` | stored ZIP | one runnable application | `rappid.json`, exactly one root `agent.py` |
| `session` | canonical JSON | runtime and transcript | payload `{runtime, transcript}` |
| `invite` | canonical JSON | signed pointer to a space | target fields + estate-owner signature |
| `neighborhood` | stored ZIP | a set of member organism eggs | members list and matching sub-eggs |
| `estate` | stored ZIP | a set of neighborhood eggs | neighborhoods list and matching sub-eggs |

The `variant` member changes the viability rules, not the manifest shape. Adding a package kind is
a registry and standard change, not permission to mint `my-new-egg/1.0`.

## 7.2 The Seven-Member Manifest

Every egg has exactly this manifest:

```json
{
  "schema": "rapp/1-egg",
  "variant": "organism",
  "rappid": "rappid:@owner/agent:<64hex>",
  "created_utc": "2026-08-20T12:00:00.000Z",
  "contents": [
    {"path": "rappid.json", "hash": "<64hex>"},
    {"path": "soul.md", "hash": "<64hex>"}
  ],
  "payload": {},
  "sig": null
}
```

`contents` lists every packed file except `manifest.json`, exactly once. Paths are relative POSIX
paths with no empty, `.` or `..` segment, no leading slash, and no backslash. They are sorted by
their UTF-8 bytes.

JSON variants have no packed files, so `contents` is exactly `[]`. Tree variants carry one
`manifest.json` plus the listed files.

## 7.3 Two Address Roles

The current standard does **not** name the raw archive with `rapp/1:egg`. It uses the two egg
spaces for different levels:

```text
one packed file:
    Hb("rapp/1:egg", file_octets)

the egg as a whole:
    H("rapp/1:egg-manifest", manifest without sig)
```

Each `contents[].hash` protects one file’s exact octets. The manifest binds those paths and hashes
to the variant, rappid, timestamp, and payload. The manifest address is therefore the identity of
the whole egg.

`sig` is excluded from the egg address. Signing or re-signing authenticates the same addressed
package instead of creating a new package identity. The serialized container bytes may change
when a signature is attached; the egg address does not.

This is parallel to a frame, but not identical:

| Frame | Egg |
|---|---|
| particle addresses payload value | `rapp/1:egg` addresses each file’s raw octets |
| wave addresses unsigned envelope | manifest address names the unsigned package claim |
| `sig` authenticates the frame | `sig` authenticates the manifest |

## 7.4 Deterministic Containers

### JSON variants

`session` and `invite` are serialized as the exact UTF-8 bytes of `canonical(manifest)`. There is
no wrapper object and no pretty-printing.

### Tree variants

The other four variants use ZIP with a deliberately narrow profile:

- compression method `stored` for every entry;
- `manifest.json` first;
- remaining entries in `contents` order;
- manifest bytes exactly `canonical(manifest)`;
- timestamps fixed to `1980-01-01 00:00:00`;
- UTF-8 filename flag set; and
- no extra fields.

Compression is transport policy outside the egg. Deflate is not used inside because different
library versions can encode the same files differently. Two conformant packers given the same
manifest value and file octets emit byte-identical containers.

Deterministic packing is useful even though the public egg identity comes from the manifest: it
makes cache comparison, fixture generation, and cross-language conformance much easier to prove.

## 7.5 Verify Integrity, Then Viability

An egg consumer has two jobs, in order.

### Integrity

1. Parse the JSON or ZIP without extracting it.
2. Require exactly the seven manifest members and a registered variant.
3. Enforce path grammar, uniqueness, sort order, and exact archive entry set.
4. Recompute every `contents[].hash` from the stored file octets.
5. Verify a present signature; require it for `invite`.

### Viability

Only after the bytes are safe does the consumer check whether the package can serve its declared
purpose: required organism files, exact session payload fields, one root application agent, member
sub-eggs, and so on.

The order matters. Code that first extracts `../../outside` and only later notices the path was
invalid has already lost. A safe consumer treats the archive as untrusted data until every path
and entry-set rule passes.

## 7.6 Invites and Owner Succession

An `invite` is a QR-sized pointer, not a ZIP of neighborhood members. Its payload has exactly:

```json
{
  "target_rappid": "<rappid>",
  "target_url": "<string>",
  "target_kind": "neighborhood"
}
```

`target_kind` is `neighborhood` or `estate`. The signature is required and must verify under the
estate-owner succession in effect at `created_utc`. A signature by a newly minted but otherwise
valid rappid is insufficient: anyone can mint an identity, but only the space authority can admit
members.

Chapter 8 explains signature verification; chapter 9 explains time-scoped owner succession.

## 7.7 Checkpoint: Pack and Verify an Organism

From the repository root:

```bash
python3 - <<'PY'
import rapp as R

rid = R.mint_rappid("reader", "first-organism")
files = {
    "rappid.json": ('{"rappid":"' + rid + '"}').encode(),
    "soul.md": b"# A small, portable organism\n",
}

blob = R.pack_egg(
    variant="organism",
    rappid=rid,
    created_utc="2026-08-20T12:00:00.000Z",
    files=files,
)
ok, step, why = R.verify_egg(blob)
manifest, unpacked = R.read_egg(blob)

print("bytes:", len(blob))
print("address:", R.egg_address(manifest))
print("files:", sorted(unpacked))
print("verify:", ok, step, why)
PY
```

Run it twice with a fixed `rid`: the bytes and address match. Change one byte of `soul.md`: its
file address changes, then the manifest and egg address change. Change only `sig`: the serialized
container changes, while `egg_address(manifest)` remains stable.

Then try adding a file named `../escape`. `verify_egg` must refuse the whole package before any
file is written.

## 7.8 The Egg Is the Same Discipline at Package Scale

A frame says, “these canonical bytes are this event in this history.” An egg says, “these addressed
files and this canonical manifest are this portable unit.” Both close their schemas, type their
hash spaces, exclude signatures from stable identity, and require consumers to recompute rather
than trust stored digests.

## 7.9 Exercises

**Exercise 7-1.** Run `examples/06_pack_an_egg.py`. Add a third file and predict which file hash,
manifest field, egg address, and container bytes will change.

**Exercise 7-2.** Implement the complete relative POSIX path predicate and exact archive-entry-set
check without extracting. *A selected solution appears in Appendix C.*

**Exercise 7-3.** Change one stored file byte inside an otherwise unchanged ZIP. Show that
`verify_egg` refuses the file hash before variant viability is considered.

**Exercise 7-4.** Build a canonical JSON `session` egg by hand. Compare its bytes with `pack_egg`
and explain why pretty printing is non-conformant.

**Exercise 7-5.** Pack the same manifest and files with another language or ZIP library. Continue
until the complete byte strings match, not only the extracted files.

## 7.10 Chapter Summary

- RAPP defines one seven-member egg manifest and six registered variants.
- `session` and `invite` are canonical JSON; the four tree variants are deterministic stored ZIP.
- `rapp/1:egg` addresses individual file octets.
- `rapp/1:egg-manifest` addresses the whole manifest with `sig` removed.
- Consumers verify path safety and integrity before variant viability.
- Invite authority comes from the estate-owner succession, not merely from any valid signer.

The byte model is now complete. The next chapter crosses the boundary from integrity to
authorship.

---

[← Chapter 6: The Wire](06-the-wire.md) · [Book contents](README.md) ·
[Chapter 8: Trust and Signatures →](08-trust-and-signatures.md)
