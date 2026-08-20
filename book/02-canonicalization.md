---
layout: book
title: Canonicalization
book_label: Chapter 2
book_progress: 20
description: Turn one RAPP value into exactly one sequence of bytes
---

[← Chapter 1: A Tutorial Introduction](01-a-tutorial-introduction.md) ·
[Book contents](README.md) · [Chapter 3: Content Addressing →](03-content-addressing.md)

# Chapter 2 — Canonicalization

> **In this chapter:** see why semantic equality is not byte equality, inspect canonical bytes,
> understand the reference profile’s number boundary, and learn which “helpful” normalizations a
> conformant consumer must refuse.

Every hash in RAPP is a hash of *bytes*. But agents exchange *values* — objects, arrays,
strings, numbers. Between a value and its hash sits a question that has sunk more distributed
systems than any other: **which bytes?** `{"a":1,"b":2}` and `{"b":2,"a":1}` are the same value
and different bytes. If two implementations disagree about which byte string represents a value,
they compute different hashes for the same content, and every downstream promise — content
addressing, chaining, signatures — silently breaks.

Canonicalization is the rule that makes the answer unique. RAPP §4 adopts **RFC 8785, JSON
Canonicalization Scheme (JCS)**, because this is a solved problem and inventing a fourth JSON
canonicalizer is exactly the kind of drift this protocol exists to end.

## 2.1 The Rules

A canonical RAPP value is **I-JSON** (RFC 7493) serialized by JCS. In practice:

- **Object keys are sorted** by their UTF-16 code units, ascending.
- **No insignificant whitespace.** `{"a":1}`, never `{ "a": 1 }`.
- **Strings** use the shortest escaping; non-ASCII is emitted as raw UTF-8, not `\uXXXX`.
- **Duplicate keys are forbidden.** An object with two `"a"` keys is not a value; it is an error.
- **Arrays keep their order.** Order is significant in an array and insignificant in an object,
  and canonicalization respects exactly that distinction.

The reference implementation is a direct transcription of these rules:

```python
def canonical(v):
    if v is None or isinstance(v, bool):   return json.dumps(v)
    if isinstance(v, int):                 return json.dumps(v)
    if isinstance(v, float):               raise ValueError("floats need full JCS number form")
    if isinstance(v, str):                 return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):                return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys())
        if len(keys) != len(set(keys)):    raise ValueError("duplicate keys")
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v[k])
                              for k in keys) + "}"
    raise ValueError("non-I-JSON value")
```

You can watch the property it guarantees — the same value canonicalizes identically regardless
of how it was constructed:

```python
>>> R.canonical({"b": 1, "a": [3, 2]}) == R.canonical({"a": [3, 2], "b": 1})
True
>>> R.canonical([1, 2]) == R.canonical([2, 1])
False
```

Key order is erased; array order is preserved. This is conformance vector V1, and it is the
foundation the whole tower stands on.

## 2.2 Numbers, and Why the Reference Profile Has None

Numbers are where JSON canonicalization gets genuinely hard. Is `1`, `1.0`, `1e0`, and `10e-1`
the same number? RFC 8785 specifies an exact IEEE-754 serialization (the ECMAScript
`Number.prototype.toString` algorithm) so that every binary64 value has one canonical form. A
production RAPP implementation MUST implement it, and the test is a round-trip: `0.1` must
survive canonicalization unchanged.

The **reference profile** in `rapp.py` deliberately refuses floats and accepts only exact
integers, strings, booleans, null, arrays, and objects. This is not a weaker canonicalizer; it
is the same canonicalizer over the value domain where the answer is unambiguous on every
platform. The reference vectors use integer payloads so the published hashes are reproducible
byte-for-byte anywhere, on any language, without depending on a float-formatting library. When
you need floats in real payloads, implement RFC 8785 §3.2.2 and keep the round-trip test in your
conformance suite. When you can express a quantity as an integer or a decimal string, do — it is
one less thing that can differ between two honest implementations.

## 2.3 What Canonicalization Does Not Do

Two temptations, both refused, both for the same reason: they make the same bytes hash
differently on different machines.

- **No Unicode normalization (no NFC) for new content.** It is tempting to NFC-normalize strings
  so that visually identical text hashes identically. RAPP does not, for new content: NFC
  behavior varies across library versions, so folding it into canonicalization would make the
  hash depend on which Unicode table you linked against. The rule is: the bytes you put in are
  the bytes that are hashed. Normalize *before* you hand a value to the protocol if your
  application needs it.
- **No schema coercion.** Canonicalization does not know or care what a field "should" be. It
  serializes the value it is given. `"1"` (string) and `1` (integer) are different values with
  different canonical forms and different hashes, and that is correct.

## 2.4 The Payoff

Because canonicalization is exact and shared, everything above it can be exact and shared. The
first chapter 10 audit ran the reference `canonical()` against 32 historical frames written by a
different program and reproduced every stored payload hash byte-for-byte. After migration, the
current sweep reproduces the domain-tagged addresses of 46/46 frames. That is the whole point:
independent producers and consumers agree because JCS has exactly one answer.

## 2.5 Failure Modes: Refuse, Do Not Normalize

| Input | Why it is unsafe | Consumer action |
|---|---|---|
| duplicate object member | parsers may keep the first or last value | refuse the whole value |
| lone UTF-16 surrogate | not interoperable I-JSON text | refuse |
| non-round-tripping number | two runtimes may see different mathematical values | refuse |
| value deeper than 64 levels | parser/resource attack surface | refuse |
| canonical form over 1 MiB | unbounded hashing and memory cost | refuse |
| visually equal but code-point-different strings | normalization would change addressed bytes | preserve as distinct values |

Canonicalization is not cleanup. A consumer that silently repairs an unsafe value may hash bytes
the producer never sent and then claim agreement.

## 2.6 Checkpoint: Inspect the Bytes

From the repository root:

```bash
python3 - <<'PY'
import rapp as R

a = {"message": "café", "n": 1, "items": [3, 2, 1]}
b = {"items": [3, 2, 1], "n": 1, "message": "café"}

ca, cb = R.canonical(a), R.canonical(b)
print(ca)
print(ca.encode("utf-8").hex())
print("same bytes:", ca.encode("utf-8") == cb.encode("utf-8"))
PY
```

Observe three things: the object construction order disappears, the array order remains, and the
non-ASCII `é` is emitted as UTF-8 rather than a `\u` escape.

Then replace integer `1` with float `0.1`. The small reference profile refuses it. That refusal
does not mean RAPP forbids all binary64 values; it means a production implementation that accepts
them must implement the complete RFC 8785 number form rather than inheriting a language’s default
formatter.

## 2.7 Chapter Summary

- Hashes consume bytes, so interoperable hashes require one byte representation per value.
- RAPP uses I-JSON serialized by RFC 8785 JCS.
- Object order is canonicalized; array order is data.
- New strings are created in NFC, but existing values are never normalized during verification.
- The small reference profile accepts exact integers and refuses floats; full producers implement
  the RFC 8785 binary64 rules.
- Malformed or ambiguous input is refused whole, never repaired.

Next we turn canonical bytes into addresses — carefully, so a payload address cannot be confused
with a frame address even when the underlying bytes are identical.

---

[← Chapter 1: A Tutorial Introduction](01-a-tutorial-introduction.md) ·
[Book contents](README.md) · [Chapter 3: Content Addressing →](03-content-addressing.md)
