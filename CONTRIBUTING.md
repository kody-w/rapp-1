# Contributing to rapp-1

This repository is the interoperable protocol authority for RAPP/1. Its value is that
independent implementations produce bytes each other can trust, so contributions are
judged by whether they keep that true — not by size or ambition. Everything below is
the mechanical contract; the CI oracles enforce most of it, and a red oracle is the
system working, not an obstacle to route around.

## Do you need this repository at all?

Most extension does not happen here. Your own kinds, egg variants, error codes, signers,
subordinate profiles, and tooling belong to **your estate** and its signed §13 registry.
Read [`EXTENDING.md`](EXTENDING.md) first; `examples/07_your_own_estate.py` is a complete
estate that needed nothing from rapp-1 but the pin.

## The one thing to know

**`SPEC.md` is generated.** Since rev-14 the normative text lives in the append-only
chain at `anchor/chain.jsonl`; `SPEC.md` is materialized from the selected head
byte-for-byte (`python3 anchor/materialize_spec.py --check SPEC.md` proves it). A pull
request that edits `SPEC.md` directly will fail CI and cannot be merged as-is. A
normative change is proposed as a **revision**: commit the generator inputs, run
`python3 anchor/update_anchor.py`, and include the appended frame, index, and beacon it
produces. Read `anchor/README.md` for the resolve-and-materialize model.

Ratification is the owner's act: the linearization point is owner-ratified acceptance
onto protected canonical `main`. A revision PR is held for that decision; it is not
merged by review consensus.

## Rules the oracles enforce

| Rule | Why | Enforced by |
|---|---|---|
| `rapp.py`, the checks, and the examples are **stdlib-only**, Python 3.9 and later; the one exception is the optional `cryptography` import *inside* `rapp.verify_detached_jws`, which must stay optional and must refuse (never assume) when absent | the spec floor is "any modern Python, no install"; signing needs a real library, so it lives with the signer | `protocol (3.9)` / `protocol (3.13)` jobs |
| one canonicalizer: the SDK agent's embedded primitives AST-match `rapp.py` | two canonicalizers are two protocols | `parity_check.py` |
| the anchor regenerates to itself (`update_anchor.py` is an idempotent no-op on main) | proves nothing under `anchor/` was hand-edited | `git diff --exit-code -- anchor` |
| committed RAPP artifacts (rappid, frames, eggs) pass the reference linter | the repo must obey its own standard | `rapp_check.py .` |
| the front page and the visual guide name the chain head revision | a stale front door is drift a stranger sees first | front-door label step |
| a book edit rebuilds the committed PDF | the print edition must not lag its source | PDF freshness guard |

## What a PR must not do

- Present a `kind`, egg variant, error code, or trust entry as **registered**. §13 has no
  authenticated registry yet; proposals are proposals and say so in their text.
- Add a dependency to make signing, verification, or hashing "easier". Signing tooling
  that needs a third-party library belongs with the estate that signs, in a repository
  that pins this one and imports `rapp.py`'s canonicalizer rather than re-typing it.
- Rename this repository or move a published URL. Printed editions bake in
  `kody-w.github.io/rapp-1` paths; `anchor/README.md` pins raw URLs by commit.
- Carry content from an employer, a customer, or a private estate. This is a public
  personal repository; vendor- or customer-specific kinds do not enter the canon here.

## Before you open the PR

```bash
python3 conformance.py
python3 parity_check.py
python3 rapp_check.py .
python3 -m unittest anchor.test_spec_chain
python3 anchor/materialize_spec.py --offline --check SPEC.md
for f in examples/0*.py; do python3 "$f"; done
```

Paste the tail of that output into the PR. The template asks for it.

## Licensing of contributions — the DCO

Contributions are accepted under the repository's [MIT License](LICENSE), the same terms
the code is offered under, and every commit from an outside contributor certifies the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote
it or have the right to submit it under that license. Certify by signing off each commit:

```bash
git commit -s
```

That adds `Signed-off-by: Your Name <you@example.com>` to the message. CI checks every
commit on a pull request from a fork and fails the PR if one is missing. A DCO is not a
CLA: nothing is assigned, nothing is countersigned, and no employer paperwork is needed.
Keep the copyright line in `LICENSE` as it is; the owner maintains it.

## Where discussion happens

Open an issue for a protocol ambiguity (the existing issues show the shape: a PII-free
use case, the clause that is ambiguous, the questions, and the fail-closed behaviour you
propose in the meantime). Security reports follow `SECURITY.md`, never a public issue.
