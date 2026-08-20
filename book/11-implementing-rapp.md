---
layout: book
title: Implementing the Language
book_label: Chapter 11
book_progress: 88
description: Build a conforming RAPP core in dependency order
---

[← Chapter 10: Conformance, and Meeting a Real World](10-conformance-and-drift.md) ·
[Book contents](README.md) · [Appendix A: Reference Manual →](A-reference-manual.md)

# Chapter 11 — Implementing the Language

> **In this chapter:** choose a conformance target, build the language from canonical values
> upward, keep address spaces in the type system, separate mint from load, make verification pure,
> and turn an append into one atomic programming operation.

The shortest path to a RAPP implementation is not to begin with `/chat`, ZIP, or signatures. It is
to follow the dependency graph. Every upper layer assumes the lower layer has exactly one answer:

```text
safe I-JSON parser
      ↓
canonical bytes
      ↓
H / Hb and typed addresses
      ↓
rappid mint and load
      ↓
frame build and verification
      ↓
egg pack and verification
      ↓
JWS, registry, succession, and current heads
```

An implementation built in another order tends to hide lower-layer ambiguity behind a convenient
API. RAPP asks you to expose the bytes first.

## 11.1 Choose the Claim You Are Making

The standard defines three conformance classes:

| Class | Minimum responsibility |
|---|---|
| producer | emit only current canonical values, addresses, identities, frames, and eggs |
| consumer | run every applicable frame, egg, signature, registry, and freshness check |
| router/mirror | preserve addressed bytes and provenance without inventing protocol surfaces |

One program may implement more than one class, but the claims should remain explicit. A producer
that can build a valid frame is not automatically a full consumer. The small `rapp.py` profile
demonstrates canonicalization, addressing, identity, frames, and eggs; it does not become a full
consumer until §10 cryptography and §13 authority checks are supplied.

Write the target at the top of the port:

```text
Target: RAPP rev-5 Producer + byte-core Consumer
Implemented: §§4–7, §9 integrity/viability
External adapters required: §10 JWS, §13 registry and freshness
```

That note prevents a passing byte fixture from being advertised as complete trust verification.

## 11.2 Start With Admissible Values

Canonicalization cannot repair a permissive parser after the fact. The parse boundary must reject:

- duplicate object member names;
- unpaired UTF-16 surrogates;
- numbers outside the RAPP binary64 round-trip domain;
- values deeper than 64 levels; and
- canonical output larger than 1 MiB.

The teaching profile then makes one deliberate restriction: no floats. Its recursive shape is
small enough to inspect:

```python
def canonical(v):
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, int):
        return json.dumps(v)
    if isinstance(v, float):
        raise ValueError("full JCS number serialization required")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical(v[k])
            for k in sorted(v)
        ) + "}"
    raise ValueError("non-I-JSON value")
```

Do not copy that sample into a production port and claim complete RFC 8785 support. A production
implementation either imports a tested JCS implementation or supplies the exact UTF-16 key order
and ECMAScript binary64 serialization with the edge vectors to prove it.

The first cross-language fixture should contain nested objects, arrays, empty values, non-ASCII
text, and key-order permutations. Compare UTF-8 **bytes**, not pretty-printed strings.

## 11.3 Put the Address Space in the Type

The hashing functions are mechanically simple:

```python
def H(space, value):
    preimage = space.encode() + b"\x0a" + canonical(value).encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()

def Hb(space, octets):
    preimage = space.encode() + b"\x0a" + octets
    return hashlib.sha256(preimage).hexdigest()
```

The design work happens at their boundary. A bare digest should not move through the program
without its space:

```python
@dataclass(frozen=True)
class Address:
    space: str
    digest: str

class Store:
    def put(self, address: Address, value): ...
    def get(self, address: Address): ...
```

This changes address-space confusion from a convention into an API error. Run
`python3 examples/04_typed_addresses.py` to see a cross-space lookup fail even when the caller
reuses a valid 64-hex digest.

Use different constructors when the input domain differs:

```text
Address.of_value("rapp/1:particle", value)  → H
Address.of_bytes("rapp/1:egg", octets)      → Hb
```

Do not expose a generic helper that silently guesses between them.

## 11.4 Separate Mint From Load

Identity code needs two visibly different operations:

```python
mint_rappid(owner, slug, spki_der=None)  # creates one new anchor
load_rappid(stored_record)               # reuses the stored tail
```

Never implement `get_or_create_rappid(owner, slug)`. That name invites a fallback from failed
storage into a new mint, which turns a transient read error into an identity change.

The load path should:

1. parse and canonicalize the existing identifier without inventing a tail;
2. classify a non-64-hex historical tail as provisional;
3. refuse to emit provisional identity into a current frame or egg; and
4. require a verified registry re-anchor before accepting a successor.

The mint path should validate owner and slug **before** consuming entropy or accepting SPKI bytes.
The returned identity is then stored durably before any frame refers to it.

## 11.5 Make Frame Construction Boring

A frame builder should be a pure function of explicit inputs. It does not read the clock, load the
head, choose a kind, or publish:

```python
frame = build_frame(
    kind=kind,
    stream_id=stream_id,
    seq=head.seq + 1,
    utc=utc,
    payload=payload,
    prev=head.payload_hash,
    prev_wave=head.frame_hash if swarm else None,
    sig=None,
)
```

The caller supplies policy; the builder supplies the exact envelope and addresses. This separation
makes fixtures deterministic and makes review possible.

Compute in one direction:

1. validate the input domains;
2. compute `payload_hash`;
3. assemble all fields except `frame_hash`;
4. compute the wave over the frame without `frame_hash` and `sig`;
5. attach `frame_hash`; and
6. sign later if required.

Never mutate a built frame in place to append it. A changed field produces a new frame candidate
and a new wave.

## 11.6 Keep Verification Pure and Ordered

The verifier receives a candidate, an optional head, the stream identifier of record, and the
authority state it needs. It returns a result; it does not repair, persist, or reparent.

```text
verify(candidate, head, stream_of_record, registry_snapshot)
    → accepted
    → refused(step, reason)
```

The step order is observable protocol behavior. Shape precedes hashing so malformed input cannot
drive surprising code paths. Particle precedes wave so the refusal identifies the changed layer.
Chain precedes trust so a cryptographically signed orphan still fails as an orphan.

`examples/05_failure_atlas.py` constructs seven independent candidates and asserts refusal at
steps 1, 1a, 2, 3, 4, 5, and 6. Keep an equivalent negative suite in every port. Positive
round-trips alone do not prove that two consumers reject the same language.

## 11.7 Treat Append as a Transaction

Building a valid child is not enough. Two writers can both read head 7 and build different frame
8 values. The storage operation must compare the head it read with the head it is replacing:

```text
append(stream, payload):
    observed = load_current_head(stream)
    candidate = build_child(observed, payload)
    verify(candidate, observed, stream.id)
    write_object_if_absent(candidate.frame_hash, candidate)
    compare_and_swap_head(
        expected=(observed.seq, observed.frame_hash),
        replacement=(candidate.seq, candidate.frame_hash),
    )
```

If the compare-and-swap fails, do not silently rebuild on the new head under the same idempotency
key. Return the existing result for a replay or surface a concurrent append so the caller can make
a new semantic decision.

Writing the addressed frame before moving the head is safe: an unreferenced immutable object can
be garbage-collected. Moving the head before the object is durable creates a dangling current
history.

## 11.8 Verify Eggs Before Extraction

The egg implementation follows the same split:

```text
pack(manifest value, files) → deterministic bytes
read(bytes)                 → manifest + in-memory entry map
verify(manifest, entries)   → integrity, then viability
extract(verified entries)   → application policy
```

The verifier compares the archive entry set to `contents` and validates every path before writing
anything. A convenience API such as `zip.extractall()` must never be the parser.

Run `python3 examples/06_pack_an_egg.py`. It proves stable bytes for the same inputs, a changed egg
address after one file changes, and refusal of `../escape`.

Independent packers should exchange fixtures for all six variants. “My packer can read its own
output” is a unit test, not interoperability.

## 11.9 Put Cryptography Behind a Narrow Adapter

Do not implement Ed25519, ES256, DER, or JWS primitives from scratch. Wrap a maintained
cryptographic library with the exact RAPP profile:

```text
sign(canonical_header, canonical_frame_without_sig, private_key) → detached JWS
verify(detached_jws, canonical_frame_without_sig, SPKI_DER)      → bool
```

The RAPP adapter owns:

- the exact four-member protected header;
- JCS header bytes;
- detached, unencoded payload construction;
- allowed algorithms;
- `kid` parsing; and
- registry key lookup and rappid-tail binding.

The crypto library owns scalar arithmetic, signature encoding, and key parsing. This boundary lets
the protocol tests remain stable when the underlying library changes.

## 11.10 Build a Port Matrix, Not One Golden File

A useful cross-language matrix has four dimensions:

| Dimension | Examples |
|---|---|
| value domain | nested values, Unicode, boundary integers, refused numbers |
| address space | particle, wave, rappid, file, manifest, seal |
| structure | genesis, child, swarm, each egg variant |
| failure | malformed shape, tamper, replay, fork, unsafe path, stale key |

For every positive fixture, record:

```text
input value
canonical UTF-8 hex
space tag
complete hash preimage hex
expected digest
expected frame or manifest
```

For every negative fixture, record the refusal step and reason category. An implementation that
accepts extra forms is no more conformant than one that rejects valid forms.

## 11.11 Definition of Done

Before calling a new implementation RAPP:

```text
[ ] parser enforces the RAPP I-JSON input domain
[ ] canonical bytes match an independent implementation
[ ] address values always retain their spaces
[ ] mint and load are separate identity operations
[ ] builder emits exactly eleven frame keys
[ ] verifier observes the complete ordered checklist
[ ] append uses an atomic remembered-head comparison
[ ] egg verification precedes extraction
[ ] JWS adapter uses the exact protected header and signing input
[ ] registry sequence, freshness, succession, and tombstones are enforced
[ ] controlled positive and negative vectors pass
[ ] at least one independently produced artifact round-trips
```

The final item is the one most often skipped. A standard exists so programs written by people who
never met can agree. Test with one.

## 11.12 Exercises

**Exercise 11-1.** Choose Producer, Consumer, or Router/Mirror for a small program you want to
build. Write its conformance declaration and list every normative section it must implement.

**Exercise 11-2.** Implement the transactional `append` operation above with an in-memory
compare-and-swap head store. Simulate two writers that observe the same head and prove only one
becomes current. *A selected solution appears in Appendix C.*

**Exercise 11-3.** Port `examples/05_failure_atlas.py` to another language. Require the same seven
step identifiers rather than only “accepted/refused.”

**Exercise 11-4.** Produce one organism egg with two independent ZIP libraries or languages.
Compare the complete bytes and explain every difference before changing code.

**Exercise 11-5.** Add a full-consumer test matrix for a key rotation at time `T`: one old-key
frame before `T`, one at `T`, one after `T`, and one new-key frame after `T`.

## 11.13 Chapter Summary

- Implement RAPP from the value domain upward; every layer depends on exact lower-layer bytes.
- State the conformance class and the boundaries a small profile does not implement.
- Keep the address space in the type system and keep mint separate from load.
- Make builders and verifiers pure; make append transactional.
- Verify eggs before extraction and use maintained crypto behind a narrow RAPP adapter.
- Test rejection behavior and exchange artifacts with an independent implementation.

The appendices condense the rules, vocabulary, and selected exercise solutions for use while
building.

---

[← Chapter 10: Conformance, and Meeting a Real World](10-conformance-and-drift.md) ·
[Book contents](README.md) · [Appendix A: Reference Manual →](A-reference-manual.md)
