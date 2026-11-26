# Lispy
## Pinned core proposal

**Protocol identifier:** `lispy/1`
**Status:** Profile stub; proposed registration, not authenticated adoption
**Parent:** [`rapp/1`](../../../SPEC.md)
**Implementation:** [kody-w/lisppy](https://github.com/kody-w/lisppy)
**Release:** `v0.26.0`
**One page:** <https://kody-w.github.io/lisppy/llms.txt>

The proposed core identity is **`lispy-core@1`**, bound to the exact raw
SHA-256 of `lisp.py`:

`5bf8de8fac8168e7850f545f9217da33a632e34221dd966fa614d92cc75f5df2`

The digest is supplied by the release owner's local source measurement.
A consumer MUST measure the actual source bytes before use; a release label,
repository, one-page URL, or copied digest file is not proof of those bytes.
The release locator is discovery, never authority.

The conformance entrypoint, run in that implementation checkout, is:

```sh
python3 -m unittest discover -s tests
```

This stub defines no new endpoint, frame member, kind, executable privilege,
or RAPP/1 encoding. It does not claim that a LisPy-hosted Brainstem already
passes the Grail oracle. A `kernel` shape part is a separate pinned host
candidate; the shape gate and RAPP/1 immutable-kernel rules still apply.
No operational schema is claimed, so this stub is not yet a full entry in
the operational profile index.
