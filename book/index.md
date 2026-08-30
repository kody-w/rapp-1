---
layout: book
title: The RAPP Programming Language
book_label: Book home
book_home: true
book_progress: 0
description: A tutorial, programming workbook, and reference manual for verifiable agents
---

<section class="book-title-sheet" aria-label="Book title page">
  <p class="book-title-kicker">RAPP rev-7 · book edition</p>
  <p class="book-title-words">The RAPP <span>Programming</span> Language</p>
  <div class="book-title-glyph" aria-hidden="true">R/1</div>
  <p class="book-title-subtitle">A tutorial, programming workbook, and reference manual for
  agents that keep a verifiable memory and communicate over one exact wire.</p>
</section>

RAPP is a programming language for durable agent behavior in the same sense that a wire format
can be a language: it gives independent programs one vocabulary for values, addresses, identity,
events, trust, and portable packages. Its executable grammar is the RAPP protocol.

The book starts with a working frame, derives every byte rule beneath it, then adds identity,
packaging, signatures, authority, migration, real-world conformance, and a complete implementation
plan. Numbered exercises turn each chapter into a workbook. No API keys or third-party packages
are needed for the core examples.

**[Begin the interactive edition →](00-preface.md)** · **[Complete print edition](print.html)** ·
**[Download the 6×9 PDF](the-rapp-programming-language.pdf)**

The interactive edition adds keyboard-accessible **Copy code** and **Copy prompt** actions plus a
stable deep link for every example. Prompts are explicitly marked, provider-neutral inert text:
nothing in the book submits them or chooses an AI for you. The PDF remains the print and download
edition.

## Ask any AI to help you explore RAPP

Copy this prompt and paste it into any AI you choose:

<pre data-copy-kind="prompt"><code>You are helping me learn the RAPP programming language.
Explain the difference between canonicalization, content addressing, and identity.
Use one short example for each, identify which bytes are hashed, and flag any assumption you make.
</code></pre>

## Contents

### Part I — From values to addresses

1. **[A Tutorial Introduction](01-a-tutorial-introduction.md)** — build and attack a real chain
2. **[Canonicalization](02-canonicalization.md)** — one value, one byte sequence
3. **[Content Addressing](03-content-addressing.md)** — one hash function, typed spaces

### Part II — From identity to a portable organism

4. **[Identity: the rappid](04-identity.md)** — mint once; never hash a name
5. **[The Frame](05-the-frame.md)** — particle, wave, chain, and fork
6. **[The Wire](06-the-wire.md)** — synchronous requests and asynchronous frames
7. **[The Egg](07-the-egg.md)** — deterministic packaging and safe handoff

### Part III — Trust, authority, and proof

8. **[Trust and Signatures](08-trust-and-signatures.md)** — byte integrity becomes authorship
9. **[The Registry, Evolution, and Security](09-registry-evolution-and-security.md)** — authority
   and lawful change
10. **[Conformance, and Meeting a Real World](10-conformance-and-drift.md)** — the code meets the
    committed estate

### Part IV — Implementing the language

11. **[Implementing the Language](11-implementing-rapp.md)** — build the parser, addresses,
    identity, frames, packages, trust adapter, and transactional append

### Reference

- **[Appendix A — Reference Manual](A-reference-manual.md)**
- **[Appendix B — Glossary and Failure Atlas](B-glossary-and-failure-atlas.md)**
- **[Appendix C — Selected Exercise Solutions](C-selected-exercise-solutions.md)**

## Start at the Terminal

```bash
git clone https://github.com/kody-w/rapp-1
cd rapp-1

python3 examples/01_hello_frame.py
python3 examples/02_build_a_chain.py
python3 examples/04_typed_addresses.py
python3 examples/05_failure_atlas.py
python3 examples/06_pack_an_egg.py
python3 conformance.py
```

The implementation is deliberately small enough to read beside the prose. The
owner-selected, hash-verified `anchor/chain.jsonl` carries normative revision
content; `SPEC.md` is its current byte-exact materialized view; this book
explains it; `rapp.py` makes the core executable; `conformance.py` makes
selected claims falsifiable.
