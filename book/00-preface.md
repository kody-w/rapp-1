---
layout: book
title: Preface
book_label: Preface
book_progress: 4
book_order: 0
description: What RAPP is and how to read The RAPP Programming Language
---

[Book contents](README.md) · [Chapter 1: A Tutorial Introduction →](01-a-tutorial-introduction.md)

# The RAPP Programming Language

### A tutorial and reference manual for verifiable agents

*Written against RAPP rev-5. Every code fragment in this book runs on `rapp.py`, the
stdlib-only reference implementation that ships beside it, and every claim about "the real
world" is checked by `realcheck.py` against the actual committed artifacts of a live estate.*

---

## Preface

RAPP is a programming language for **agents that keep a verifiable memory and talk over one
wire**, and this book teaches it. A RAPP program is not a source file full of expressions. It is a
durable sequence of canonical values, addressed events, identity transitions, and portable
packages whose meaning another implementation can verify.

Its executable grammar is a *protocol*, in the sense that HTTP, JSON, and git’s object model are
protocols: a small number of exact rules that let independent programs, written by people who
never met, produce bytes the other side can trust. RAPP is not a general-purpose replacement for
Python or JavaScript. Those languages implement agents; RAPP is the language in which their
durable behavior crosses runtimes. It gives us a way to write down what an agent did, address it
by its content, chain it into a biography, and hand it to anyone.

The protocol is built from **five primitives**, and this book is organized around them:

1. **Canonicalization** — turning a value into exactly one sequence of bytes (chapter 2).
2. **Content addressing** — naming those bytes by their hash, with domain separation (chapter 3).
3. **Identity** — the `rappid`, a name minted once and never a hash of a name (chapter 4).
4. **The frame** — one record that is both a *particle* (a link in a worldline) and a *wave*
   (an integrity-checked unit on the wire) (chapter 5).
5. **The egg** — a content-addressed package that carries an organism or an application (chapter 7).

Everything else — the `/chat` endpoint (chapter 6), conformance classes, versioning — is how
those five are carried and governed.

### The layered map

The primitives are small because each layer has one job and may not redefine the layer beneath
it:

```text
L5  EGG       packages a portable unit
L4  FRAME     records one immutable event
L3  WIRE      carries requests and append-only frames
L2  IDENTITY  names actors and binds keys
L1  ADDRESS   turns values and octets into stable names
```

You can use only the lower layers — content-address a payload without ever packing an egg — but
you cannot skip them. A frame that invents its own canonicalizer is not a second kind of frame; it
is a different protocol wearing the same word.

### Why this book exists

The RAPP ecosystem is real and it drifted. The same concept — "a frame," "a rappid" — got
implemented more than once, in incompatible ways, each copy claiming the same name. A frame
was minted twice under one version string with two different hash rules. An identity was
computed three different ways in production, one of them the cardinal sin of hashing a *name*
into an address. This is not exotic; it is the oldest failure in distributed systems, and it
has been solved before — by Linux's one-mainline rule, by the Web's single living standard, by
git making the hash the name. RAPP is the convergence: **one spec, one canonicalizer, one
mint, one frame.** This book teaches that spec so completely that the drift cannot come back,
because everyone building on it turns the same bytes into the same tree.

### How to read it

If you have written a little Python and seen a hash function before, you can read this book
start to finish. Chapter 1 is a fast, complete tour — by the end of it you will have built and
verified a real chain of frames. Chapters 2 through 7 take the five primitives one at a time.
Chapters 8 and 9 add signatures, authority, evolution, and the security boundaries hashes cannot
cross. Chapter 10 follows a live estate from a drifted baseline to verified convergence. Chapter
11 turns the whole dependency graph into an implementation plan. Appendix A is the terse
reference; Appendix B is the vocabulary and failure atlas; Appendix C contains selected exercise
solutions.

Run everything. The reference implementation is 140 lines; you are meant to read it, and the
book will tell you when. A protocol you have only read about is a rumor. A protocol whose
conformance suite you have watched go green, against your own bytes, is a tool.

### Who this book is for

| Reader | What the book gives you |
|---|---|
| agent builder | a portable record and package model that does not depend on one runtime |
| protocol implementer | byte rules, verification order, and conformance boundaries |
| estate operator | head, key, registry, migration, and fail-closed discipline |
| security reviewer | an explicit separation of integrity, authorship, authority, and freshness |

You do not need prior cryptography work. The book explains what each primitive proves and, just
as importantly, what it does not prove.

### The contract with the standard

This book is explanatory.
[`SPEC.md`](https://github.com/kody-w/rapp-1/blob/afc913ca3fe7dbc9da97871e67240f34416e5929/SPEC.md)
is normative. The distinction matters:

- the standard says what every implementation **must** do;
- the reference profile makes the byte and package core executable;
- the conformance suite proves selected interoperability claims; and
- the book supplies intuition, worked observations, and operating consequences.

If a sentence here cannot be traced to a normative rule or clearly marked as application
guidance, it is a book bug.

Let's build a frame.

---

[Book contents](README.md) · [Chapter 1: A Tutorial Introduction →](01-a-tutorial-introduction.md)
