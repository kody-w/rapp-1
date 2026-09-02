# RAPP/1 as an Internet-Draft

`draft-wildfeuer-rapp-1-00` is the archival rendering of `SPEC.md` for the RFC Editor's
**Independent Submission** stream. An RFC number is permanent, mirrored worldwide, and
outlives any hosting platform or account — it is how a protocol gets a place to live that
nobody controls.

The chain of record stays `anchor/chain.jsonl`; the draft is a rendering of one revision,
and says so in its abstract.

## Files

- `draft-wildfeuer-rapp-1-00.md` — kramdown-rfc source, generated from `SPEC.md` (§1–§14,
  headings renumbered by xml2rfc, `[RFC n]` citations turned into references).
- `draft-wildfeuer-rapp-1-00.xml` — RFCXML v3, produced by `kramdown-rfc2629`.
- `draft-wildfeuer-rapp-1-00.txt` — the plain-text draft, produced by `xml2rfc` with zero errors.

## Regenerate after a revision

```bash
gem install --user-install kramdown-rfc      # once
python3 -m pip install xml2rfc               # once, in any venv
python3 ietf/make_draft.py                   # SPEC.md → ietf/draft-*.md
kramdown-rfc2629 ietf/draft-wildfeuer-rapp-1-NN.md > ietf/draft-wildfeuer-rapp-1-NN.xml
xml2rfc --text --html ietf/draft-wildfeuer-rapp-1-NN.xml
```

Bump `-00` to `-01` for each submitted version; the datatracker refuses a reused number.

## Submit (owner's step — needs a datatracker login)

1. https://datatracker.ietf.org/submit/ — upload the `.xml`.
2. Choose the **Independent Submission** stream; the draft is `category: info`.
3. After posting, request publication through the Independent Submissions Editor:
   https://www.rfc-editor.org/about/independent/ — the ISE reviews for clarity and
   non-conflict with IETF work, not for endorsement. Expect months, not days.
