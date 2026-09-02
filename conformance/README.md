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
python3 conformance/make_vectors.py          # rewrite vectors.json from rapp.py
python3 conformance/make_vectors.py --check  # what CI runs
```
