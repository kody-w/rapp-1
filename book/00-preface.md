# The RAPP Protocol

### A tutorial and reference for the wire that carries agents

*Written against RAPP rev-5. Every code fragment in this book runs on `rapp.py`, the
stdlib-only reference implementation that ships beside it, and every claim about "the real
world" is checked by `realcheck.py` against the actual committed artifacts of a live estate.*

---

## Preface

RAPP is a protocol for **agents that keep a verifiable memory and talk over one wire**, and this
book teaches it. (Like C has its standards, RAPP has spec revisions and a wire tag, `rapp/1` — but
the thing itself is just RAPP.)

That is the whole ambition. Not a framework, not an SDK, not a product — a *protocol*, in the
sense that HTTP and JSON and git's object model are protocols: a small number of exact rules
that let independent programs, written by people who never met, produce bytes the other side
can trust. When RAPP is called "the AI medium," this is the medium: a way to write down what an
agent did, address it by its content, chain it into a biography, and hand it to anyone.

The protocol is built from **five primitives**, and this book is organized around them:

1. **Canonicalization** — turning a value into exactly one sequence of bytes (chapter 2).
2. **Content addressing** — naming those bytes by their hash, with domain separation (chapter 3).
3. **Identity** — the `rappid`, a name minted once and never a hash of a name (chapter 4).
4. **The frame** — one record that is both a *particle* (a link in a worldline) and a *wave*
   (an integrity-checked unit on the wire) (chapter 5).
5. **The egg** — a content-addressed package that carries an organism or an application (chapter 7).

Everything else — the `/chat` endpoint (chapter 6), conformance classes, versioning — is how
those five are carried and governed.

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
verified a real chain of frames. Chapters 2 through 7 take the five primitives one at a time,
each ending with runnable code you already have in `examples/`. Chapter 8 turns the whole
apparatus loose on a live estate and shows you exactly where reality conforms and where it is
the drift the protocol exists to end. Appendix A is the terse reference — the thing you keep
open once you are building.

Run everything. The reference implementation is 140 lines; you are meant to read it, and the
book will tell you when. A protocol you have only read about is a rumor. A protocol whose
conformance suite you have watched go green, against your own bytes, is a tool.

Let's build a frame.
