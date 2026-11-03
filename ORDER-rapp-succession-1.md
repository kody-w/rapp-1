# ORDER: author `rapp-succession/1`, a subordinate RAPP/1 profile (succession: who inherits a device chain)

## Intent
A Brainstem's identity is its device-local rapp/1 chain (see `protocols/rapp-layer/1`). Today the chain proves
WHAT the Brainstem is. This profile lets it prove WHOSE it is and WHO INHERITS it, with signatures the base
protocol already defines (§10, Ed25519 detached JWS). Model: Google's Inactive Account Manager (a silence
window, then a confirmation window, then the hand-off) and PGP key-transition statements (the old key signs
the statement naming the new key). The AI never holds a secret: the chain carries public keys only.

Produce the complete package EXACTLY the way `rapp-layer/1` was added (study that commit's file list:
`git log --diff-filter=A --stat -1 -- protocols/rapp-layer/1/SPEC.md`): SPEC, schema, stdlib reference module,
unit tests, a conformance runner, a real example chain, registration in `protocols/index.json`, the anchor
generator's input list (`anchor/update_anchor.py`, same way `rapp-layer` is listed and described), and the CI
workflow steps (`.github/workflows/docs.yml` and `grail.yml`) that run the conformance runner.

## The profile (normative content to write into `protocols/rapp-succession/1/SPEC.md`)
Identifier `rapp-succession/1`. Parent `rapp/1`, depends on `rapp/1` only; adds no endpoint, envelope member,
hash domain or wire form; payloads are canonical I-JSON inside the unchanged eleven-key frame; `memory` family;
these frames MAY interleave with `rapp-layer/1` frames in one device chain (a reader of either profile ignores
the other's kinds). Three kinds, ALL with `sig` != null (detached JWS per §10, `kid` = signer's keyed rappid):

1. `succession.name` payload, exactly:
   `{"schema":"rapp-succession/1","owner":{"rappid":<keyed rappid>,"spki_der_b64":<b64 DER SPKI>},
     "successor":{"name":<plain name, 1..120 chars>,"rappid":<keyed rappid>,"spki_der_b64":<b64>},
     "window":{"silence_days":<int 1..3650>,"confirm_days":<int 0..365>}}`
   - signed by `owner` (verify with owner.spki_der_b64; the §10 tail check `Hb("rapp/1:rappid", SPKI) == tail`
     MUST hold for both owner and successor rappids).
   - The FIRST `succession.name` in a chain establishes the chain's owner key ("device-local root": there is no
     §13 registry on a device; the chain holds the public key only). Every later `succession.name` MUST be
     signed by the CURRENT owner (which changes after a valid handoff, rule 3). A `succession.name` signed by
     anyone else is refused.
2. `succession.pulse` payload, exactly `{"schema":"rapp-succession/1","head":<frame_hash of the previous frame>}`,
   owner-signed: a sign of life. Any owner-signed frame of this profile counts as life; `last_owner_utc` is the
   `utc` of the newest owner-signed frame.
3. `succession.handoff` payload, exactly
   `{"schema":"rapp-succession/1","from_head":<frame_hash of the previous frame>,"reason":"owner"|"silence","at":<utc>}`
   - `reason:"owner"`: signed by the current owner; valid any time (the owner hands over deliberately).
   - `reason:"silence"`: signed by the CURRENT successor; valid only if `at` >= `last_owner_utc` + silence_days
     + confirm_days AND the frame's `utc` >= `at`. Otherwise refused ("handoff before the window").
   - After a valid handoff the successor becomes the owner for every later frame of this profile; the previous
     owner's key is superseded for frames with `utc` >= the handoff's `utc` (mirrors §10 key lifecycle). A new
     `succession.name` by the new owner names the next successor. A handoff with no prior `succession.name`
     is refused. A handoff signed by anyone else is refused.
   The chain's `stream_id` does NOT change (the chain is the asset; the heir continues it). Moving the chain
   into the heir's own estate is an ordinary §12.1 re-genesis, outside this profile.
Reader API (stdlib module `rapp_succession.py`, mirroring `rapp_layer.py`):
   `state(frames, now_utc) -> {"owner": rappid|None, "successor": {"name","rappid"}|None, "last_owner_utc",
    "silence_deadline", "confirm_deadline", "status": "unnamed"|"owned"|"silent"|"handoff-open"|"inherited"}`
   and `validate_chain(frames)` that walks a chain in order, verifying every `succession.*` frame's signature
   against the key the chain itself established, and refusing exactly the cases above with plain messages.
   Signing helper for tests and tools: `sign_frame(kind, stream_id, seq, utc, payload, prev, private_key_pem)`
   building the §10 detached JWS with `cryptography` (Ed25519). Verification MUST reuse `rapp.verify_detached_jws`.
Lessons to cite in the SPEC's "Who paid" section: Google Inactive Account Manager; PGP key transition; Bitcoin
inheritance losses (key custody, not contracts); §10/§13 of rapp/1.

## Inputs to study (all inside this directory)
`SPEC.md` §6.1 (rappids), §7 (frames), §10 (signatures), §12.1, §13; `rapp.py` (`mint_rappid`, `build_frame`,
`verify_frame`, `verify_detached_jws`, `parse_detached_jws`); `rapp_profile.py`; `protocols/rapp-layer/1/*`,
`rapp_layer.py`, `test_rapp_layer.py`, `layer_conformance.py`, `protocols/examples/layer-lifecycle.json`,
`protocols/index.json`, `anchor/update_anchor.py`, `.github/workflows/docs.yml`, `.github/workflows/grail.yml`,
`conformance.py` (the controlled-check runner; add succession vectors the same way layer vectors were added).

## Rules / do-not-touch
- Do NOT edit `SPEC.md` (rapp/1 core) or `rapp.py`. Do NOT touch `anchor/chain.jsonl`, `anchor/orient.json`,
  `anchor/index.json`, `anchor/frames/` or `anchor/test_spec_chain.py`; Fable regenerates the anchor.
- Keep everything inside this repo; do not read outside it. Branch `rapp-succession-1` is checked out; commit
  as you go; do NOT push.
- `cryptography` may be imported (rapp.py already uses it for verification). No other new dependency.
- Example chain `protocols/examples/succession-lifecycle.json`: a REAL chain built with throwaway test keys
  generated during authoring (private keys never stored; put the public SPKIs in the frames): genesis ->
  succession.name -> succession.pulse -> (a refused early silence-handoff kept as a negative vector in the
  conformance checks, not in the chain) -> succession.handoff reason:"silence" with `at` past the window ->
  succession.name by the heir naming a next successor. The runner must verify every signature for real.
- Plain words in every refusal message (an owner reads them in chat).
- Flag uncertainty; never paper over it.

## Numbered acceptance checks (run verbatim; paste the output in the report)
1. `python3 -m unittest test_rapp_succession -v 2>&1 | tail -5`
2. `python3 succession_conformance.py protocols/examples/succession-lifecycle.json`
3. `python3 conformance.py 2>&1 | tail -2` (count must go UP from 23 by your added vectors, all PASS)
4. `python3 rapp_check.py . 2>&1 | tail -2`
5. `python3 -m unittest anchor.test_spec_chain 2>&1 | tail -1` (must still be OK: you did not touch the anchor)
6. `python3 -c "import json;i=json.load(open('protocols/index.json'));print([p['name'] for p in i['profiles']])"`
7. `git diff main --stat | tail -1` and `git log --oneline main..HEAD`

## Done-when + report
Done when 1-7 pass. End with: the file list, the exact kinds and payload shapes as written, the refusal
messages, outputs of 1-7 verbatim, and "Flags / surprises".
