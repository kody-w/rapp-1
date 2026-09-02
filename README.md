# RAPP — the wire that carries agents

> The language is **RAPP**. Its durable programs travel under one wire tag, `rapp/1`, and its
> executable grammar is the protocol specified by this repository.

> **Scope boundary:** the public RAPP foundation, product, reference
> implementation, organism model, and philosophy remain in
> [`kody-w/RAPP`](https://github.com/kody-w/RAPP). This repository is the
> interoperable protocol authority only. [`FOUNDATION.json`](FOUNDATION.json)
> pins that relationship.

**One language for agents that keep a verifiable memory and talk over one wire.** Five primitives
— canonicalization, content addressing, identity, the frame, the egg — specified exactly enough
that independent implementations produce bytes each other can trust. Its executable grammar is a
protocol; this repository contains the append-only specification chain, its
content-addressed bootstrap and revision objects, a stdlib-only reference
implementation and resolver, a conformance suite, and a book that teaches it
end to end. The unsigned chain proves integrity; owner-ratified acceptance onto
protected canonical main currently selects authority.

> Not a framework or a replacement for Python. A *protocol language*, in the sense that HTTP,
> JSON, and git’s object model give independent programs a shared grammar.

---

## Quickstart (60 seconds, zero typing)

You never need to type code to use RAPP. Copy one prompt, paste it into your
**brainsurgeon** — an agentic CLI like Claude Code or GitHub Copilot CLI — and watch it work:

```text
You are my hands — I watch, you type. Clone https://github.com/kody-w/rapp-1 and prove
RAPP to me end to end: (1) run python3 conformance.py — I expect 22/22 PASS; (2) run
python3 operations_conformance.py — I expect every RAPP CI/CD and RAPP Deploy vector
to pass; (3) run python3 realcheck.py — the spec against the live public estate — and
explain the verdict in plain English; (4) run python3 examples/01_hello_frame.py and
walk me through the frame it built, one line per key. Narrate as you go, show real
output, and stop on any red result — a red check is a finding, not something to patch
around.
```

Every task in this repository has a prompt like this — the whole journey, from first frame to
implementing RAPP in your own language, is in [**`PROMPTS.md`, the prompt book**](PROMPTS.md).
Prefer to drive the machine yourself? The commands your brainsurgeon runs:

```bash
git clone https://github.com/kody-w/rapp-1
cd rapp-1

python3 conformance.py     # 22/22 — controlled protocol vectors
python3 operations_conformance.py  # CI/CD + deployment safety vectors
python3 anchor/materialize_spec.py --check SPEC.md  # current view == verified chain head
python3 realcheck.py       # the spec run against the REAL committed estate
python3 examples/01_hello_frame.py   # build and verify your first frame
```

`conformance.py` proves the reference implementation against 22 controlled checks. `realcheck.py`
synchronizes the public repos of a live estate and verifies every committed frame: the captured
2026-08-20 run accepted **46/46 committed frames**, all chain links, and four canonical identity
records with **0 drift findings**, and a 2026-08-26 re-observation of the grown estate accepted
**50/50**. The estate is live and the audit is re-run on a weekly schedule
([estate watch](.github/workflows/estate-watch.yml)) that files an issue the moment reality
drifts. The historical red report and the captured green report form the before/after case study
in chapter 10.

## What's here

| file | what it is |
|------|-----------|
| **[`anchor/chain.jsonl`](anchor/chain.jsonl)** | append-only DOGG normative content; integrity is hash-proven and authority is selected by protected canonical-main acceptance |
| **[`anchor/bootstrap/`](anchor/bootstrap/)** | frozen content-addressed bootstrap profile and exact verifier pin |
| **[`anchor/frames/`](anchor/frames/)** | immutable-by-name revision frame objects, globally retrievable by durable frame hash |
| **[`SPEC.md`](SPEC.md)** | byte-exact materialized human view of the current rev-15 chain head — 15 sections, RFC-grounded |
| **[`anchor/`](anchor/README.md)** | chain resolver/materializer, head beacon, kinds, vocabulary, and [DOGG discovery feed](https://github.com/kody-w/rapp-1/commits/main/anchor.atom) |
| **[`CONSTITUTION.md`](CONSTITUTION.md)** | the rapp/1 Protocol Constitution — the law of change: how the standard, this repo, and its claims may lawfully evolve |
| **[`FOUNDATION.json`](FOUNDATION.json)** | exact pointer to the canonical public RAPP foundation and philosophy |
| **[`PHILOSOPHY.md`](PHILOSOPHY.md)** | byte-identical public mirror of the canonical foundation philosophy, never product authority |
| **[`protocols/`](protocols/README.md)** | RAPP CI/CD and RAPP Deploy — immutable qualification, bounded rollout, and continuous AI health |
| **[`conformance/`](conformance/)** | language-neutral known-answer vectors derived from `rapp.py`; how a second implementation claims conformance |
| **[`ietf/`](ietf/)** | `draft-wildfeuer-rapp-1-00` — the spec rendered as an Internet-Draft for the Independent Submission stream; an RFC number outlives every platform |
| **[`MIRRORS.md`](MIRRORS.md)** | where else the standard lives — Software Heritage, Wayback, git mirrors, paper |
| **[`EXTENDING.md`](EXTENDING.md)** | how to extend RAPP without touching this repo — your own estate, your own signed registry, your own kinds; what still needs a revision |
| **[`rapp_registry.py`](rapp_registry.py)** | the §13 registry as executable checks, stdlib only — exact entry shapes, kind↔family↔stream binding, owner succession, tombstones; `examples/07_your_own_estate.py` drives it |
| **[`PROMPTS.md`](PROMPTS.md)** | the prompt book — every task as a copy-paste prompt for your brainstem or brainsurgeon; you never type code |
| **[`rapp.py`](rapp.py)** | the reference implementation, stdlib only, ~140 lines you are meant to read |
| **[`conformance.py`](conformance.py)** | test vectors V1–V9; run it, watch it go green |
| **[`operations_conformance.py`](operations_conformance.py)** | controlled refusal vectors for release, promotion, rollout, health, and rollback |
| **[`realcheck.py`](realcheck.py)** | runs RAPP against the live estate's real committed artifacts |
| **[`REAL-WORLD-REPORT.txt`](REAL-WORLD-REPORT.txt)** | a captured synchronized run of `realcheck.py` — the convergence ledger, generated by code |
| **`examples/`** | six runnable, tutorial-paced programs from first frame through typed addresses, failure steps, and deterministic eggs |
| **[`book/`](book/README.md)** | *The RAPP Programming Language* — tutorial, workbook, and reference; use the [interactive edition with Copy code and Copy prompt controls](https://kody-w.github.io/rapp-1/book/), [print the complete volume](https://kody-w.github.io/rapp-1/book/print.html), or [download the 6×9 PDF](https://kody-w.github.io/rapp-1/book/the-rapp-programming-language.pdf) |

## Trust anchor (out-of-band publication, §13.1)

The kody-w reference estate's owner rappid — the one bootstrap axiom every consumer of
this estate's registry needs — is:

```
rappid:@kody-w/estate-owner:b5814e45e9988df835dfd58d152a6fb05b6510a087a35c24374a1c4ab833c122
```

Its registry of record (`schema:"rapp/1-registry"`, owner-signed, append-only) is
`kody-w/rapp-map/ecosystem-spec.json`; first signed publication at commit `6883563e94054981925866a61600378ee3a7e5c3`
(registry_seq 1). It pins `rapp/1` by the anchor head's normative hash, registers the
anchor stream's genesis, and binds the fourteen reference kinds. Verify it with
`rapp_registry.load_document(doc, entries_member="entries")` — it reports `verified` only
after the §10 signature checks against that rappid. This repository stays the protocol
authority; the registry is the estate's, and the two are deliberately separate.

## License

The RAPP/1 specification, reference implementation, conformance suite,
examples, and documentation in this repository are available under the
[MIT License](LICENSE).

That license permits independent implementations of the protocol. It does not
grant rights to third-party product names, certification marks, organism
content, customer data, or proprietary services merely because those products
use RAPP/1.

## Build with it: the SDK Builder agent

Drop one file into any RAPP brainstem's `agents/` directory (no restart) and it gains a working
RAPP toolkit — mint compliant rappids, scaffold organism seeds, build/verify frames,
content-address values, and lint public repos for compliance, all drivable in plain English.
Paste this into your brainsurgeon and it installs and proves the toolkit while you watch:

```text
Install the RAPP SDK Builder agent into my local brainstem: download
https://raw.githubusercontent.com/kody-w/rapp-1/main/agents/rapp_sdk_builder_agent.py
into my brainstem's agents/ directory (find the right one — standard installs use
~/.brainstem/src/rapp_brainstem/agents/), no restart needed. Then prove it: run the
agent's sync action and show me embedded_matches_public_reference: true, and ask my
brainstem to "mint a keyless rappid for @me/hello".
```

From then on you just talk to your brainstem: *"scaffold a new RAPP organism @me/scratch"*.
The one command behind the install, if you want it:

```bash
curl -sSL https://raw.githubusercontent.com/kody-w/rapp-1/main/agents/rapp_sdk_builder_agent.py \
  -o ~/.brainstem/src/rapp_brainstem/agents/rapp_sdk_builder_agent.py
```

It's self-contained (embeds the reference primitives; its `sync` action proves byte-identical
addresses to the public `rapp.py`) and falls back to a standalone base so it also runs outside a
brainstem: `python3 agents/rapp_sdk_builder_agent.py`.

## Restricted artifacts on public mirrors

RAPP rev-10 adds the `sealed` egg variant for globally available ciphertext with restricted key release.
A GitHub Raw URL may host the sealed egg publicly because the package contains only AES-256-GCM
ciphertext. The manifest is signed and content-addressed; a RAPP key-service organism releases a
recipient-wrapped key only after scoped entitlement checks through the existing `POST /chat` wire.

This is encryption, not obfuscation:

- never put a password or key in the URL;
- never embed a shared master key in a client;
- pin raw URLs to immutable commit SHAs;
- bytecode can be inspected after an authorized recipient decrypts it;
- revocation stops future key release but cannot erase prior decrypted copies.

The normative shape and refusal rules are in [`SPEC.md` §9.2.1](SPEC.md#921-sealed-artifact-profile).

## Three books

- **[The Visual Guide — *Design & Build Agents*](https://kody-w.github.io/rapp-1/guide/)** — a
  full-colour, one-idea-per-spread visual book in the spirit of Jon Duckett's design books.
  Diagrams, colour-coded chapters, annotated code. Start here if you like to *see* it.
- **[The Reference Book — *The RAPP Programming Language*](https://kody-w.github.io/rapp-1/book/)**
  — an original, classic technical-book tutorial + reference for reading front to back.
- **[The Hands-On Textbook — *Building with RAPP*](book-sdk/00-preface.md)** — teaches the
  SDK Builder agent dropped into a grail brainstem: stand up the engine, hotload the agent, and
  build a real organism by conversation. Every command was run against a live brainstem.

## Planetary production without freezing innovation

[`RAPP CI/CD`](protocols/rapp-cicd/1/SPEC.md) and
[`RAPP Deploy`](protocols/rapp-deploy/1/SPEC.md) wrap RAPP/1 with the minimum
operational invariants needed to protect users:

- one immutable release candidate and one evidence chain;
- production-shaped Preprod with rollback and restore proof;
- isolated serving and candidate lineages;
- cellular progressive exposure and automatic containment;
- continuously expiring AI-health evidence.

The envelopes stay closed, but check names, component kinds, health objectives,
and resilience controls are policy-defined extension points. New capabilities
can be added without mutating the Grail, changing the RAPP/1 wire, or revising
the protocols for every operational innovation.

### The RAPP Programming Language

A complete tutorial, programming workbook, and reference in four parts, with a dedicated
paper-styled GitHub Pages edition. **[Open the interactive edition →](https://kody-w.github.io/rapp-1/book/)** ·
**[Print edition](https://kody-w.github.io/rapp-1/book/print.html)** ·
**[Download PDF](https://kody-w.github.io/rapp-1/book/the-rapp-programming-language.pdf)**

0. **[Preface](book/00-preface.md)** — what RAPP is and how to read this
1. **[A Tutorial Introduction](book/01-a-tutorial-introduction.md)** — build and verify a real chain in one sitting
2. **[Canonicalization](book/02-canonicalization.md)** — one value, exactly one sequence of bytes
3. **[Content Addressing](book/03-content-addressing.md)** — the hash is the name, with domain separation
4. **[Identity](book/04-identity.md)** — the rappid, minted once, never a hash of a name
5. **[The Frame](book/05-the-frame.md)** — one record that is both particle and wave
6. **[The Wire](book/06-the-wire.md)** — `POST /chat`, one door, every tier
7. **[The Egg](book/07-the-egg.md)** — a content-addressed package for a whole organism
8. **[Trust and Signatures](book/08-trust-and-signatures.md)** — from byte integrity to authorship
9. **[The Registry, Evolution, and Security](book/09-registry-evolution-and-security.md)** — authority and lawful change
10. **[Conformance, and Meeting a Real World](book/10-conformance-and-drift.md)** — the suite, and the estate
11. **[Implementing the Language](book/11-implementing-rapp.md)** — build a conforming core in dependency order
- **[Appendix A — Reference Manual](book/A-reference-manual.md)** — the terse normative mirror
- **[Appendix B — Glossary and Failure Atlas](book/B-glossary-and-failure-atlas.md)** — terms and refusal steps
- **[Appendix C — Selected Exercise Solutions](book/C-selected-exercise-solutions.md)** — worked solutions from every chapter

## The one idea

The RAPP ecosystem is real and it drifted: the same concept — "a frame," "a rappid" — got built
more than once, in incompatible ways, each copy claiming the same name. A frame was minted twice
under one version string with two different hash rules; an identity was computed three ways in
production, one of them the cardinal sin of hashing a *name* into an address. This is the oldest
failure in distributed systems, and it was solved before — by Linux's one mainline, the Web's
single living standard, git making the hash the name. **RAPP is the convergence: one specification
chain, one canonicalizer, one mint, one frame** — specified so completely that the drift cannot
come back, because everyone building on it turns the same bytes into the same tree.

## Status

RAPP rev-14 makes selected `anchor/chain.jsonl` frames carry normative content,
while owner-ratified protected-main acceptance selects the authoritative chain.
It freezes a content-addressed bootstrap, publishes hash-addressed frame
objects/indexes, embeds the current normative Markdown in a normal `body.pulse`
frame, and makes `SPEC.md` its reproducible materialized view. It changes no
envelope, canonicalization, hash, or registered-kind semantic. Rev-13's public governance,
rev-12's foundation/product boundary, rev-11's operational profiles, and
rev-10's sealed-artifact and immutable-Grail closure remain intact. The
reference profile passes 22/22 core checks plus the operational safety vectors
on every push. CI runs the suite on Python 3.9 and 3.13, verifies the
specification chain/materialized view, runs all six examples, and enforces byte
parity between `rapp.py` and the SDK agent's embedded primitives
(`parity_check.py`). The captured 2026-08-20 estate audit accepted
46/46 committed frames and four canonical identity records with zero drift; the
estate is live and re-audited weekly (the 2026-08-26 observation accepted
50/50). See [`REAL-WORLD-REPORT.txt`](REAL-WORLD-REPORT.txt) for the captured
case-study run.

*License: the protocol is meant to be implemented. Do.*
