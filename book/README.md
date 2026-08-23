# The RAPP Programming Language

## A tutorial, programming workbook, and field reference for verifiable agents

**RAPP rev-5 · Book edition**

RAPP is a small programming language, expressed as a wire protocol, with a large promise: two independent implementations can write down
what an agent did, give that record an address, join it to a verifiable history, and exchange it
without privately agreeing on what the bytes mean.

**[Read the styled GitHub Pages edition →](https://kody-w.github.io/rapp-1/book/)** ·
**[Open the complete print edition](https://kody-w.github.io/rapp-1/book/print.html)** ·
**[Download the 6×9 PDF](https://kody-w.github.io/rapp-1/book/the-rapp-programming-language.pdf)**

This book teaches that promise from the first frame to the estate root of trust, then builds a
conforming implementation in dependency order. It is written to be read in order, but each chapter
is also a reference and workbook you can return to while implementing.

> **The short version:** values become canonical bytes; canonical bytes become domain-separated
> addresses; a minted identity owns a stream; frames make the stream tamper-evident; signatures
> bind selected frames to keys; eggs package whole organisms; the registry tells consumers which
> keys, kinds, and heads are authoritative.

**[Begin with the preface →](00-preface.md)**

---

## What you will be able to do

By the end of the book, you will be able to:

- build and verify an eleven-field RAPP frame;
- explain why a frame has both a particle and a wave;
- produce the same address as another implementation, byte for byte;
- mint a `rappid` without confusing a human name for an identity;
- distinguish chain integrity, authorship, authority, and freshness;
- package and verify each of the six egg variants;
- read a conformance failure as a precise migration instruction; and
- decide where trust enters a system that otherwise names everything by content;
- structure a new implementation from safe parsing through transactional append; and
- test both acceptance and refusal behavior against an independent implementation.

The examples use Python because the reference implementation is deliberately small and
stdlib-only. The protocol is language-independent.

## Contents

### Front matter

- **[Preface](00-preface.md)** — what RAPP is, who this book is for, and how to use it

### Part I — From values to addresses

1. **[A Tutorial Introduction](01-a-tutorial-introduction.md)** — build and attack a real chain
2. **[Canonicalization](02-canonicalization.md)** — one value, exactly one sequence of bytes
3. **[Content Addressing](03-content-addressing.md)** — the hash is the name, in a named space

### Part II — From identity to a portable organism

4. **[Identity: the rappid](04-identity.md)** — mint once; never hash a name
5. **[The Frame](05-the-frame.md)** — one record, both particle and wave
6. **[The Wire](06-the-wire.md)** — one synchronous door and one asynchronous form
7. **[The Egg](07-the-egg.md)** — deterministic packaging and handoff

### Part III — Trust, authority, and proof

8. **[Trust and Signatures](08-trust-and-signatures.md)** — from byte integrity to authorship
9. **[The Registry, Evolution, and Security](09-registry-evolution-and-security.md)** — the root
   of trust and the lawful path through change
10. **[Conformance, and Meeting a Real World](10-conformance-and-drift.md)** — executable proof
    from a drifted baseline to a conformant live estate

### Part IV — Implementing the language

11. **[Implementing the Language](11-implementing-rapp.md)** — build a conforming core in
    dependency order

### Back matter

- **[Appendix A — Reference Manual](A-reference-manual.md)** — the terse build-time companion
- **[Appendix B — Glossary and Failure Atlas](B-glossary-and-failure-atlas.md)** — terms,
  address spaces, and verification steps at a glance
- **[Appendix C — Selected Exercise Solutions](C-selected-exercise-solutions.md)** — worked
  solutions for one exercise from each chapter

## Choose a reading path

| If you are… | Read… | Then run… |
|---|---|---|
| building your first RAPP tool | 1 → 7 → 11 | `examples/01_hello_frame.py`, `05_failure_atlas.py` |
| porting RAPP to another language | 2 → 5 → 7 → 8 → 11 → Appendix A | `conformance.py` |
| operating an estate or mirror | 5 → 8 → 9 → 10 | `realcheck.py`, then `rapp_check.py` |
| reviewing the trust model | 3 → 4 → 8 → 9 | the §7.5 and §10 checklists in `SPEC.md` |
| working through exercises | each chapter → Appendix C | `examples/04` through `06` |
| looking up one rule | Appendix A or B | the normative section cited beside it |

Chapter 1 remains the best entrance even for experienced distributed-systems engineers. It gives
the later vocabulary something concrete to name.

## Read with a terminal open

Clone the repository and prove the starting state:

```bash
git clone https://github.com/kody-w/rapp-1
cd rapp-1

python3 examples/01_hello_frame.py
python3 examples/02_build_a_chain.py
python3 examples/05_failure_atlas.py
python3 examples/06_pack_an_egg.py
python3 conformance.py
```

The book uses four recurring forms:

- **Protocol rule** — a requirement the normative standard actually makes.
- **Why the rule exists** — the ambiguity or attack the rule removes.
- **Try it** — a small observation you can reproduce with the checked-in code.
- **Failure mode** — the exact point at which a consumer must refuse rather than guess or repair.

When prose and code disagree, stop. `SPEC.md` is normative; `rapp.py` is the executable reference
profile; `conformance.py` is the proof surface; this book is the explanation. A useful book keeps
all four aligned.

## The companion shelf

| Artifact | Role |
|---|---|
| [`SPEC.md`](../SPEC.md) | normative RAPP rev-5 standard |
| [`rapp.py`](../rapp.py) | small, stdlib-only reference profile |
| [`conformance.py`](../conformance.py) | producer/consumer interoperability vectors |
| [`realcheck.py`](../realcheck.py) | evidence from committed estate artifacts |
| [`examples/`](../examples/) | six runnable programs used throughout the tutorial and workbook |
| [`print.html`](print.html) | all chapters and appendices assembled as one printable volume |
| [`the-rapp-programming-language.pdf`](the-rapp-programming-language.pdf) | generated 6×9 single-volume PDF |
| [`build-pdf.sh`](build-pdf.sh) | regenerates the PDF from the Jekyll manuscript with Chrome |
| [`test-docs.sh`](test-docs.sh) | deterministic Jekyll, generated DOM, render, and PDF regression gate |
| [`test-pdf.py`](test-pdf.py) | verifies 108-page geometry and HTTPS allowlisted PDF annotations |
| [`guide/`](../guide/) | the visual, one-idea-per-spread companion book |
| [`book-sdk/`](../book-sdk/) | the conversational SDK Builder textbook |

The book does not replace the standard and the standard does not replace the book. The standard
must be exact enough to implement; the book must make the exactness understandable.

With Jekyll, Chrome, Python, and Poppler installed, run `./book/test-docs.sh` to execute the same
documentation gate used by the public pull-request workflow.

---

**Next:** [Preface — what RAPP is and how to read this book →](00-preface.md)
