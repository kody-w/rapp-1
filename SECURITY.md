# Security Policy

This repository is the normative RAPP standard, its reference implementation, and its
conformance suite. A flaw here can propagate into every independent implementation, so
reports are taken seriously at two levels:

- **Specification flaws** — anything that lets two conformant implementations disagree,
  lets a verifier accept what §7.5/§9.3 say it must refuse, or weakens the trust model
  in §10/§13/§14 (signature bypass, replay, identity forgery, egg path escapes).
- **Implementation flaws** — bugs in `rapp.py`, `conformance.py`, the SDK Builder agent,
  or the tooling that would mislead someone relying on a green result.

## Reporting

Use [GitHub private vulnerability reporting](https://github.com/kody-w/rapp-1/security/advisories/new)
— do not open a public issue for anything exploitable before it is fixed. Include the
spec section, a minimal reproducing artifact (a frame, egg, or vector), and what a
conformant verifier did versus what it should have done.

## Verifying what you install

The SDK Builder agent is installed by fetching `agents/rapp_sdk_builder_agent.py` from
this repository. Before trusting it, run its `sync` action: it re-fetches the canonical
`rapp.py` and proves — by ast source comparison, never by executing fetched code — that
the embedded address primitives are identical to the public reference. CI enforces the
same parity on every push (`parity_check.py`).

## Scope notes

`realcheck.py` observes mutable public repositories; a red result there is an estate
finding, not a vulnerability in this repo. The registry and signature trust model is
specified in SPEC.md §10, §13, and §14 — challenges to that model are welcome as spec
flaw reports.
