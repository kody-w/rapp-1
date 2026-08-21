---
layout: book
title: The Registry, Evolution, and Security
book_label: Chapter 9
book_progress: 76
book_order: 90
description: Operate the RAPP root of trust and evolve immutable histories
---

[← Chapter 8: Trust and Signatures](08-trust-and-signatures.md) ·
[Book contents](README.md) ·
[Chapter 10: Conformance, and Meeting a Real World →](10-conformance-and-drift.md)

# Chapter 9 — The Registry, Evolution, and Security

> **In this chapter:** the estate’s signed root of trust, append-only authority, owner
> succession, the living-standard rule, re-genesis, and the threats that remain after every hash
> verifies.

Content addressing removes many trust decisions. If you know an address, an untrusted mirror can
serve the object without being able to alter it invisibly. But a hash cannot tell you which
address is current, which key may sign, which event kinds exist, or who is allowed to reset a
stream’s genesis. Those are authority questions.

RAPP concentrates them in one authenticated, append-only registry rather than scattering them
through code, repositories, and human convention.

## 9.1 The Registry Is the Root of Trust

The estate registry, `rapp-map/ecosystem-spec.json`, plays several roles at once:

- it binds keyed rappids to public keys;
- it registers frame kinds and their stream families;
- it records the current genesis of every stream;
- it carries key tombstones and identity re-anchors;
- it names the estate owner and that owner’s succession; and
- it points at the canonical protocol and master plan.

Those powers make the registry security-critical. An unsigned mutable registry would let an
attacker replace a signing key, hide a tombstone, authorize a forged genesis, or redefine a kind.
The rest of the protocol could verify perfectly against an attacker-chosen root.

The registry must therefore authenticate itself.

## 9.2 The Bootstrap Axiom

Every trust graph starts somewhere. RAPP’s one out-of-band bootstrap value is the
`estate_owner` keyed rappid string.

Because its tail is:

```text
Hb("rapp/1:rappid", estate-owner-SPKI-DER)
```

the rappid acts as a public-key fingerprint. It can be distributed once through a QR code,
invitation, documentation, or another trusted channel. The SPKI may travel with the registry;
the verifier accepts it only if hashing that SPKI reproduces the already-trusted rappid tail.

This is not “trust on first use” every time the registry is fetched. It is one explicit bootstrap
decision, followed by computation.

## 9.3 Signed, Monotonic, and Fresh

The registry document carries:

- `schema:"rapp/1-registry"`;
- a `registry_seq` uint53;
- append-only entries; and
- a detached §10 signature by the estate owner.

A consumer persists the highest `registry_seq` it has verified and refuses lower values. That
single monotonic counter defeats rollback to a registry snapshot from before a key revocation or
re-genesis.

Rollback resistance is not freshness. A hostile mirror can keep serving the highest sequence it
has seen while withholding a newer one. Consumers should refresh before trust-sensitive decisions
and must report an over-age registry as **stale**, not **clean**. “The signature verifies” answers
authenticity; “this is recent enough for my policy” answers freshness.

The safe retrieval path is:

```text
out-of-band estate_owner rappid
        │
        ▼
SPKI tail check
        │
        ▼
registry signature
        │
        ▼
registry_seq monotonicity + freshness policy
        │
        ▼
keys, kinds, genesis records, succession, tombstones
```

## 9.4 The Append-Only Entry Types

Entries are added, never silently rewritten or removed. Retirement is explicit with
`deprecated:true`.

| Entry | What it authorizes or records |
|---|---|
| `protocol` | canonical spec repository, path, and hash |
| `kind` | one exact event kind and its stream family |
| `egg-variant` | one allowed §9 package variant |
| `error-code` | one machine-readable `/chat` failure code |
| `genesis` | the authoritative starting frame for a stream |
| `spki` | the public key bound to a keyed rappid |
| `tombstone` | owner-signed key revocation time |
| `re-anchor` | identity continuity across upgrade, rotation, compromise, or tag migration |
| `estate_owner` | the owner currently in force |
| `master-plan` | the governing estate plan |

Closed registries are a protocol feature. If producers can invent kind names, egg variants, or
error codes without registration, consumers must guess what those names mean. Registration lets
the envelope remain stable while the vocabulary grows deliberately.

## 9.5 Owner Succession Is Historical

“Owner-signed” means the owner whose tenure covered the artifact’s `utc`, not always the owner who
holds the key today.

Suppose owner key A served until a rotation at `2026-08-01T00:00:00.000Z`, then key B took over:

```text
──────────── A tenure ────────────│──────────── B tenure ────────────>
                                 2026-08-01
```

A re-genesis frame signed by A in July remains valid after the rotation. A frame signed by A in
August does not. Checking every historical artifact only against B would destroy valid history;
checking every artifact against either key without tenure boundaries would preserve retired
authority forever.

The succession records make authority time-scoped and auditable.

## 9.6 One Living Standard, Not Permanent Dialects

RAPP is revised in place as a living standard. That does **not** mean the same wire token can
quietly acquire a second shape.

- A new registered `kind` can use the existing eleven-field frame.
- A changed key set, field grammar, or hash rule requires a new token and a total migration.
- Published content-addressed artifacts remain immutable.
- Retired live forms are migrated out rather than supported forever as parallel dialects.

This rule is strict because protocol ambiguity compounds. Every legacy reader path doubles the
number of producer/consumer combinations that can disagree. RAPP chooses convergence: one current
form, with old immutable history retained only when it has been sealed through re-genesis.

## 9.7 Re-genesis: Change Without Rewriting History

When an immutable chain uses an obsolete envelope, editing its frames would destroy the property
the chain was built to provide. Re-genesis changes which history is live without changing the old
bytes.

The operation has four essential phases:

1. **Seal the old head.** Hash its exact retained octets in the `rapp/1:seal` space.
2. **Emit a new genesis.** Use the registered family-specific `*.re-genesis` kind, `seq:0`,
   `prev:null`, an owner signature, and a payload naming the old stream and terminal seal.
3. **Register the new genesis.** Append the new mapping and deprecate every prior genesis for
   that stream. This append is the linearization point.
4. **Retire the old files.** Preserve them bit-exact under `legacy/`, never serve or extend them
   as the live chain.

Only the registry-published genesis permits a consumer to reset its remembered head to sequence
zero. A lower-sequence head from any other source remains a rollback attack.

Re-genesis is intentionally not an automatic “repair.” It is an owner-authorized statement about
continuity. A checker may identify the need and prepare evidence; it must not invent authority.

## 9.8 What Correct Hashes Still Cannot Solve

The security model becomes clearer when its remaining limits are explicit:

| Threat | Hashes catch it? | Required control |
|---|---:|---|
| mirror changes an object | yes | recompute same-space address |
| mirror serves an old but valid head | no | persisted head + current genesis registry |
| attacker replays stream A into stream B | not by hash alone | §7.5 step 1a binding |
| attacker swaps a signing key | no | registry SPKI lookup + rappid tail check |
| mirror hides a key tombstone | no | registry sequence and freshness |
| producer future-dates a frame | no | receipt-time skew policy; re-genesis if bricked |
| archive uses `../` paths | no | §9 path grammar and entry-set verification |

The principle is consistent: use content addressing for immutable bytes, and use explicit,
authenticated state for facts that can change.

## 9.9 Operator Checkpoint

Before calling an estate clean, collect evidence for each boundary:

```text
[ ] current registry signature verifies from the pinned estate_owner rappid
[ ] registry_seq is not below the last accepted sequence
[ ] registry age satisfies the local freshness policy
[ ] every stream descends from its sole non-deprecated genesis
[ ] every signed frame resolves a matching SPKI and valid tenure
[ ] tombstones and re-anchors are applied at the frame's utc
[ ] no live frame points into sealed legacy history
[ ] every untrusted egg passed path, entry-set, hash, and variant checks
```

This is the operational meaning of “fail closed.” Unknown does not become pass, and stale does not
become clean.

## 9.10 Exercises

**Exercise 9-1.** Draw the complete bootstrap path from an out-of-band estate-owner rappid to an
accepted frame signature. Mark every hash, signature, and freshness decision.

**Exercise 9-2.** Implement persisted `registry_seq` rollback protection. Treat equal sequence
with different bytes as equivocation. *A selected solution appears in Appendix C.*

**Exercise 9-3.** Write a re-genesis plan for a three-frame legacy stream, including exact sealed
octets, new payload, registry append, and retired path.

**Exercise 9-4.** Define `fresh`, `stale`, `rollback`, and `unavailable` as four distinct API
states. Do not collapse any of them to a boolean.

**Exercise 9-5.** Threat-model a mirror that serves authentic objects and an authentic but old
registry. List what verifies and what remains unsafe.

## 9.11 Chapter Summary

- The registry is the one signed root for keys, kinds, genesis, succession, and revocation.
- Its bootstrap anchor is the out-of-band estate-owner keyed rappid.
- Signatures prove authenticity; `registry_seq` prevents rollback; freshness policy detects
  withheld updates.
- Owner authority is time-scoped so rotation preserves valid history without preserving old power.
- The living-standard rule converges current forms instead of accumulating dialects.
- Re-genesis changes the authoritative beginning of a live chain while preserving old bytes as
  sealed history.
- Correct hashes are necessary, but trusted heads and fresh authority state remain necessary too.

We now have every layer of the model. The final chapter runs them as code against both controlled
vectors and the committed artifacts of a real estate.

---

[← Chapter 8: Trust and Signatures](08-trust-and-signatures.md) ·
[Book contents](README.md) ·
[Chapter 10: Conformance, and Meeting a Real World →](10-conformance-and-drift.md)
