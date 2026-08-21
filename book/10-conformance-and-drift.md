---
layout: book
title: Conformance, and Meeting a Real World
book_label: Chapter 10
book_progress: 84
book_order: 100
description: Run RAPP against controlled vectors and committed estate artifacts
---

[← Chapter 9: The Registry, Evolution, and Security](09-registry-evolution-and-security.md) ·
[Book contents](README.md) · [Chapter 11: Implementing the Language →](11-implementing-rapp.md)

# Chapter 10 — Conformance, and Meeting a Real World

> **In this chapter:** how controlled vectors turn prose into an interoperability claim, how a
> synchronized real-world harness separates compatible bytes from protocol drift, and how one
> estate moved from eight precise failures to 46 verified frames without teaching the verifier to
> tolerate a legacy dialect.

A specification you cannot test is a wish. This chapter is where RAPP stops being only a document
and becomes a tool: first controlled vectors that hold the implementation still, then a harness
that turns the same byte rules loose on mutable public repositories.

The estate changed while this book was being written. Its first captured audit found compatible
canonical bytes inside non-conformant envelopes. The current audit finds a converged estate. That
before-and-after is stronger evidence than either snapshot alone: the checker identified the gap,
the owners migrated the artifacts, and the current canonical rules now accept them.

## 10.1 The Controlled Conformance Suite

`conformance.py` is the executable form of the rules in chapters 2–5. Run it:

```bash
python3 conformance.py
```

The controlled section prints:

```text
RAPP rev-5 — conformance vectors
  [PASS] V1  canonicalization is key-order independent
  [PASS] V1b array order IS significant
  [PASS] V2  domain tags separate the address space
  [PASS] V3  keyless mint is not sha256(owner/slug)
  [PASS] V3  rappid matches the §6.1 grammar
  [PASS] V3  keyed tail == Hb('rapp/1:rappid', SPKI)
  [PASS] V3  mint-once determinism for keyed identity
  [PASS] V4  genesis frame builds and verifies
  [PASS] V4  genesis has exactly 11 keys
  [PASS] V5  payload tamper caught at step 2
  [PASS] V5  envelope tamper caught at step 3 (wave)
  [PASS] V6  child frame links to genesis
  [PASS] V6  broken prev caught at step 4
  [PASS] V7  cross-stream genesis replay refused at 1a
  [PASS] V8  missing key refused at step 1 (no absent-vs-null)
  [PASS] V9  unsigned swarm frame refused at step 6
  ── 16 controlled checks | 16 PASS | 0 FAIL
```

Each vector maps to a promise made earlier in the book. V1/V1b is canonicalization, V2 is domain
separation, V3 is mint-once identity, and V4–V9 exercise the frame build and verification steps.
Green here is not a generic “clean build.” It is a selected set of protocol claims exercised
against fixed inputs.

The fixed inputs are important. A controlled conformance suite must not start failing merely
because somebody successfully migrated a public repository.

### The live observation is separate

After the vectors, `conformance.py` fetches one public frame and describes what it sees:

```text
LIVE OBSERVATION — kody-w/twin/frames/0.json (non-gating)
  [CURRENT] frame uses the rapp/1 envelope
       particle reproduces stored payload_hash: True
       frame verifies as its stream genesis: True
```

That observation is useful evidence, but it is not part of the exit condition. It may change,
and it may be unavailable offline. Mutable remote state belongs to the estate audit.

## 10.2 The Real-World Harness

`realcheck.py` asks the harder question: *what does the current public estate actually contain?*
It clones or fast-forwards `twin`, `rapp-body`, `rapp-commons`, `rapp-map`, and `RAR`, then walks
every numbered frame and every `rappid.json` it finds.

```bash
python3 realcheck.py
```

For each frame chain, it asks:

1. does the reference canonicalizer reproduce the stored address?
2. does each `prev` link equal the previous payload address?
3. does the complete envelope pass `verify_frame` against its actual head and stream?

For each identity record, it checks the §6.1 grammar, 64-hex tail, forbidden name-hash derivation,
and current schema label.

Refreshing existing clones is part of the test. A report against a stale local cache is a captured
snapshot pretending to be live.

## 10.3 The Baseline: Bytes Already Agreed

The first captured report, before convergence, contained 32 frames: 29 in `rapp-body` and three in
`twin`. The old envelopes used untagged payload hashes, but the reference canonicalizer reproduced
all of them:

```text
── rapp-body  (29 committed frames) ──
   canonicalization reproduces real stored hash : 29/29 frames
   real chain links per RAPP §7.4 (prev=parent): 29/29 frames

── twin  (3 committed frames) ──
   canonicalization reproduces real stored hash : 3/3 frames
   real chain links per RAPP §7.4 (prev=parent): 3/3 frames
```

This was not yet RAPP content-addressing: the hashes lacked the chapter 3 domain tags. But it was
powerful migration evidence. Two independently written programs agreed on the canonical payload
bytes, and all 32 historical chain links held.

The lower layer was already compatible. The envelope above it was not.

## 10.4 The Baseline: Eight Exact Drifts

The same baseline frames failed the current envelope check:

```text
frames conformant to RAPP §7 envelope as-is : 0/29   (rapp-body)
frames conformant to RAPP §7 envelope as-is : 0/3    (twin)
real envelope keys:
  [kernel_version, kind, parent_sha, payload, seq, sha256, sig, spec, ts, twin_id]
```

Every frame was rejected at step 1. The reason was structural and specific:

| Historical field | Current field |
|---|---|
| `twin_id` | `stream_id` |
| `ts` | `utc` |
| `sha256` | `payload_hash` |
| `parent_sha` | `prev` |
| absent | `frame_hash` |
| absent | `prev_wave` |

The identity scan found two 32-hex provisional tails and four old schema labels:

```text
IS THE DRIFT RAPP FIXES (8):
  [envelope-drift/C1]  rapp-body/frames, twin/frames
  [short-tail/C3]      twin, rapp-commons
  [schema-label]       all four rappid records
```

This was the checker doing its job. Renaming those fields while reading would have hidden the
fact that the historical hashes were untagged and that the wave did not exist. A compatibility
shim could make the object look current without making it current.

## 10.5 The Current Estate: Convergence Verified

After the owner-authorized identity re-anchors and frame convergence, the synchronized harness
now reports:

```text
── rapp-body  (43 committed frames) ──
   canonicalization reproduces stored address  : 43/43 frames
   chain links per RAPP §7.4 (prev=parent)     : 43/43 frames
   frames conformant to RAPP §7 envelope as-is : 43/43

── twin  (3 committed frames) ──
   canonicalization reproduces stored address  : 3/3 frames
   chain links per RAPP §7.4 (prev=parent)     : 3/3 frames
   frames conformant to RAPP §7 envelope as-is : 3/3

Inspected frames: 46
Current RAPP envelopes accepted: 46/46
Remaining drift findings: 0
```

All four inspected identity records now use `schema:"rapp/1"` and valid 64-hex tails. Live frames
carry `payload_hash`, `frame_hash`, `prev`, `prev_wave`, `stream_id`, and fixed-form `utc`. The
legacy aliases are absent.

The result went green because the estate changed, not because `verify_frame` learned to
reinterpret legacy bytes as current frames. Repository history and sealed legacy artifacts keep
the before-state available as evidence; the live paths contain the current form.

## 10.6 What Before and After Prove

Read the two snapshots together:

> Before migration, RAPP reproduced the historical canonical bytes and refused the wrong
> envelopes. After migration, it reproduces the domain-tagged addresses and accepts all 46
> current frames. The red report described the work; the green report proves that work reached
> the public artifacts.

That is a complete protocol story:

1. **discover** agreement at a lower layer;
2. **refuse** ambiguity at the higher layer;
3. **classify** each mismatch by a normative rule;
4. **authorize** identity and genesis changes;
5. **migrate** producers and current artifacts;
6. **rerun** the unchanged acceptance rules; and
7. **retain** historical evidence without serving it as a live dialect.

The objective was never to make the report green by any means. It was to make reality satisfy the
one form the checker already required.

## 10.7 Fail Closed

The live harness must distinguish **clean**, **drift**, and **not inspected**.

- If a repository cannot be cloned or fast-forwarded, the run fails.
- If an artifact cannot be parsed, it becomes a finding.
- If a stored address cannot be recomputed, it becomes a finding.
- If a frame cannot be verified in sequence, it becomes a finding.
- If zero findings remain after all surfaces were refreshed and read, the report is clean.

A checker that greens because it could not reach a repository has said “no drift” when it means “I
did not look.” A stale cache can tell the reverse lie: “drift remains” after owners already
converged. Fail-closed evidence must fail on blindness in either direction.

## 10.8 Reading a Red Report

A refusal is most useful when it identifies the boundary that failed:

| Failure | Meaning | Correct response |
|---|---|---|
| canonical bytes differ | producer and consumer do not share §4 | replace the canonicalizer; regenerate unpublished output |
| same bytes, wrong domain-tagged hash | object was named in the wrong address space | migrate through the current producer; do not alias hashes |
| rappid grammar or tail fails | identity is provisional or non-canonical | owner-authorized re-anchor |
| frame step 1/1a fails | wrong shape, type, registry value, or stream binding | reject; re-genesis if committed history is immutable |
| frame step 2/3 fails | payload or envelope integrity failed | reject as corruption or tampering |
| frame step 4/5 fails | chain or wire continuity failed | surface fork or drift; never reparent automatically |
| frame step 6 fails | authorship or authority failed | refresh registry, then reject if still invalid |
| egg integrity/viability fails | unsafe bytes or incomplete package | reject the whole egg |

The repeated instruction is **reject first, migrate deliberately**. A consumer should not mutate
the received artifact until it passes.

## 10.9 From Finding to Convergence

A disciplined migration has a beginning and an end:

1. capture the failing artifacts and exact checker output;
2. classify every mismatch by normative section;
3. identify the current owner and authority record;
4. generate conformant artifacts without modifying published addressed bytes;
5. re-anchor identity or re-genesis history when continuity requires authorization;
6. update the append-only registry;
7. rerun both controlled conformance and the synchronized real-world harness; and
8. delete retired live forms, retaining only sealed history where §12.1 requires it.

The current report demonstrates the last step that many standards efforts omit: go back to the
world and prove that the migration landed.

## 10.10 Exercises

**Exercise 10-1.** Run both `conformance.py` and `realcheck.py`. Explain why only the first can be
a stable offline protocol gate.

**Exercise 10-2.** Create six synthetic findings: canonical mismatch, wrong address space, shape
drift, stream replay, chain break, and stale registry. Classify each at its first normative
boundary. *A selected solution appears in Appendix C.*

**Exercise 10-3.** Capture a small estate fixture for offline regression without calling it
“live.” Record source repository, commit, path, and capture time.

**Exercise 10-4.** Make a local estate clone one commit stale, run an intentionally non-refreshing
audit, then run `realcheck.py`. Explain the evidence difference.

**Exercise 10-5.** Write an acceptance statement for a migration that names the red baseline, the
owner authorization, the changed producer, the current green result, and the retained history.

## 10.11 Chapter Summary

- Controlled vectors prove selected implementation claims without depending on mutable remote
  state.
- A synchronized estate audit proves what current committed artifacts actually do.
- Historical canonical bytes can agree while their legacy envelopes correctly fail.
- The baseline report found eight actionable drifts; the current report verifies 46/46 frames and
  zero remaining drift.
- Fail-closed checks distinguish clean, drift, unavailable, and stale.
- Every refusal should map to an authorized migration, never an invisible repair.

That is RAPP end to end: a language of five primitives, one wire, explicit trust, portable
packages, and executable evidence that a real estate can move from incompatible history to one
current form.

---

[← Chapter 9: The Registry, Evolution, and Security](09-registry-evolution-and-security.md) ·
[Book contents](README.md) · [Chapter 11: Implementing the Language →](11-implementing-rapp.md)
