# Claiming rapp/1 conformance

A protocol is alive when a second implementation, written by someone who never read the
first one's code, produces the same bytes. This directory is how you prove yours does.

`vectors.json` is language-neutral: values in, exact bytes and hashes out, and a set of
tampered frames each with the §7.5 step that must catch it. It is **derived from
`rapp.py`** by `make_vectors.py` and CI refuses a hand edit, so it can never disagree with
the reference.

## What to run

For each section, your implementation must:

| section | must produce / decide |
|---|---|
| `4_canonical` | exactly the `canonical` string for each `value` |
| `4_refuse` | refuse each `json_text` at parse time — never repair it |
| `5_hash` | the same `H` per space and the same `Hb` per space |
| `6_rappid` | accept `valid`, refuse every `invalid`, and mint `keyed_mint.rappid` from the SPKI bytes |
| `7_frame` | verify `genesis` and `child` as a chain; refuse every `tampers[]` frame at exactly `expect_step` |
| `9_egg` | pack a `session` egg from `manifest` that is byte-identical to `egg_octets_hex`, and compute `egg_address` |

`registry-vectors.json` does the same for the §13 registry, derived from `rapp_registry.py`.
Each section lists inputs and the verdict (`accept` or `refuse`) your registry reader must
reach. A section is named for the SPEC subsection it proves, or for its declared entry type:
`13_lifecycle` proves §13.5.

| section | must produce / decide |
|---|---|
| `13_1_document` | accept or refuse each `document` (or, for a value that is not I-JSON at all, each `json_text`) exactly as §4, §13.1 and §13.3 require |
| `13_4_declared` | the exact `signing_payload` and `entry_hash` for `example.entry`; the declared and persisted entry types |
| `13_lifecycle` | `example.first_entry_hash` (= `example.second.previous`) and `example.second_signing_payload`; accept or refuse each `cases[].entries` registry exactly as §13.3 and §13.5 require, and for each accepted one its `current` notice's `state` and `superseded_by` per subject (a rappid or a repository URI); over `state_at.entries`, the `state` and `superseded_by` in effect for every `state_at.queries` item (a `null` state is no declared lifecycle, never deprecation; a `null` `superseded_by` names no successor at that time — a scheduled notice names none before its `since_utc`) and the `current` notices |

Signatures in the registry vectors are opaque placeholders. Signature verification needs a
real key, so prove your §10 and §13.4 checks with your own keys; `registry_conformance.py`
shows the reference doing it.

Then say so in your README with the vectors' revision, the date, and the count, the way
this repository's README dates its own claims (Constitution Art. 9: claims are computed
and dated). Conformance classes (Producer, Consumer, Router/Mirror) are in SPEC §11.

## What the reference does not do

`rapp.py` refuses non-integer JSON numbers instead of implementing full RFC 8785 number
serialization. An implementation that handles them is more complete, not less conformant;
the vectors use integers only. The reference also verifies §10 signatures only when the
optional `cryptography` import is present; an implementation with native Ed25519 is fine.

## Regenerate after a revision

```bash
python3 conformance/make_vectors.py          # rewrite vectors.json and registry-vectors.json
python3 conformance/make_vectors.py --check  # what CI runs
```
