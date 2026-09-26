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
`13_release_pin` proves §13.5, `13_lifecycle` §13.6, and `13_stream_signer` §13.7.

| section | must produce / decide |
|---|---|
| `13_1_document` | accept or refuse each `document` (or, for a value that is not I-JSON, exceeds §4's size or depth limits, or whose numbers' exact spelling matters, each `json_text`) exactly as §3's absolute HTTPS URI, §4, §13.1 and §13.3 require |
| `13_4_declared` | the exact `signing_payload` and `entry_hash` for `example.entry`; the declared and persisted entry types; accept or refuse each `first_seen_cases` `activated_utc` against its `first_seen` exactly as §13.4 item 3 requires (refused only when more than 300 s later, counted exactly — subtracting floating-point POSIX seconds misjudges the trap cases) |
| `13_release_pin` | the exact `canonical`, `manifest_hash`, and `raw_sha256` of `example.manifest` (its `release` name included), each `example.files` digest, and `example.correction.manifest_hash`; accept or refuse every `manifest_cases` (a `manifest`, or for one that is not I-JSON, its `json_text`), `octets_cases` (the pinned release selected by `manifest_hash`), `entry_cases`, `history_cases` (the `entries` of a later registry judged against the `persisted` entries a consumer accepted before: §13.4 retention and the §13.5 rule that no kernel joins a family after one of its releases was accepted), `kernel_coherence_cases`, and `identity_cases` (a door of record's identity-file octets against its component's `rappid`) entry exactly as §13.3–§13.5 require; and reproduce `channels` and `families` — each channel's `manifest_hash`es in chain order and each release family's in `entries` order (a family may span channels), the last being the channel's head or the family's current release — for each accepted entry case and for `example.release_pin` followed by `example.correction.release_pin` |
| `13_lifecycle` | `example.first_entry_hash` (= `example.second.previous`) and `example.second_signing_payload`; accept or refuse each `cases[].entries` registry exactly as §13.3 and §13.6 require, and for each accepted one its `current` notice's `state` and `superseded_by` per subject (a rappid or a repository URI); over `state_at.entries`, the `state` and `superseded_by` in effect for every `state_at.queries` item (a `null` state is no declared lifecycle, never deprecation; a `null` `superseded_by` names no successor at that time — a scheduled notice names none before its `since_utc`) and the `current` notices |
| `13_stream_signer` | the exact `signing_payload` and `entry_hash` for `example.entry`; accept or refuse each `grant_cases` registry (`base_entries` then the case's `entries`) exactly as §13.3 requires; decide `authorized` or `refused` for each `authority.cases` `frame_summary` against `authority.entries` exactly as §13.7 requires, taking §7.5 as already passed |

Signatures in the registry vectors are opaque placeholders. Signature verification needs a
real key, so prove your §10 and §13.4 checks with your own keys; `registry_conformance.py`
shows the reference doing it.

Then say so in your README with the vectors' revision, the date, and the count, the way
this repository's README dates its own claims (Constitution Art. 9: claims are computed
and dated). Conformance classes (Producer, Consumer, Router/Mirror) are in SPEC §11.

## What the reference does not do

`rapp.py` refuses non-integer JSON numbers instead of implementing full RFC 8785 number
serialization. For values checked by `vectors.json`, an implementation that handles them is more
complete, not less conformant; those vectors use integers only. A registry and an identity file are
different: §13.1 and §13.5 require every number in them to be written as an integer, so
`registry-vectors.json` expects `0.5`, `1.0`, and `1e0` to be refused there. The reference also verifies §10 signatures only when the
optional `cryptography` import is present; an implementation with native Ed25519 is fine.

## Regenerate after a revision

```bash
python3 conformance/make_vectors.py          # rewrite vectors.json and registry-vectors.json
python3 conformance/make_vectors.py --check  # what CI runs
```
