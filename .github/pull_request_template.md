<!-- Read CONTRIBUTING.md first. Two rules break most PRs here:
     1. SPEC.md is generated from anchor/chain.jsonl — never hand-edit it.
     2. rapp.py and every check stay stdlib-only. -->

## What changes

## Which rule of CONTRIBUTING.md this follows
- [ ] No hand edits to `SPEC.md` or anything under `anchor/` (a revision is appended with `anchor/update_anchor.py`)
- [ ] No third-party dependency added to `rapp.py`, the checks, or the examples
- [ ] No new `kind`, egg variant, or error code presented as registered (§13 has no authenticated registry yet)
- [ ] `python3 conformance.py && python3 parity_check.py && python3 rapp_check.py . && python3 -m unittest anchor.test_spec_chain` are green locally
- [ ] Book source untouched, or `book/build-pdf.sh` was re-run and the PDF committed

## Evidence
<!-- paste the tail of the checks above -->
