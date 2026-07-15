# Chapter 6 — Linting the Stack for Compliance

The SDK does not only *build* RAPP — it *judges* it. The `check` action fetches any public repo's
identity record and verdicts it against the standard. This is how you find drift before it spreads,
and it works on any repo in the stack, live.

## 6.1 Checking a repo

Point `check` at a GitHub repo (as `owner/name` or a full URL):

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A
print(A.RappSdkBuilderAgent().perform(action="check", repo="kody-w/twin"))
PY
```

```json
{
  "status": "ok", "action": "check", "repo": "kody-w/twin", "verdict": "DRIFT",
  "findings": [
    "§6.1 identity: 32-hex short-tail (C3) — rappid:@kody-w/twin:257afa7958982c28258c1d97701182b1",
    "§12 schema label: schema='rapp-rappid/2.0', not 'rapp/1'",
    "§6.3 parent_rappid not RAPP grammar: rappid:@kody-w/kody-twin:91d006ca7bd052bfa5021d623122012f"
  ],
  "evidence": []
}
```

Three findings, each cited to a section of the standard: a 32-hex short-tail identity (§6.1), a
legacy schema label (§12), and a parent pointer that is itself a legacy id (§6.3). The agent fetched
`twin`'s real `rappid.json` from `raw.githubusercontent.com` and measured it — this is live truth,
not a cached assertion.

A compliant repo comes back clean:

```json
{"status": "ok", "action": "check", "repo": "kody-w/rapp-map",
 "verdict": "CLEAN", "note": "no rappid.json on main — no RAPP artifacts to lint"}
```

`check` reports three verdicts: **DRIFT** (has RAPP artifacts that violate the standard, with
findings), **COMPLIANT** (has artifacts, all pass), and **CLEAN** (no RAPP artifacts to judge). A
repo that greens because there was nothing to look at says `CLEAN`, not `COMPLIANT` — the SDK does
not let "I didn't look" masquerade as "no problems."

## 6.2 The relationship to the full linter

The agent's `check` is a fast, network, identity-level lint — perfect for "is this repo drifting?"
from inside a conversation. The repository also ships a deeper offline linter, `rapp_check.py`,
which additionally walks *frame chains* (verifying seq/prev/utc linkage) and can be pointed at a
local checkout. Use `check` from the brainstem for a quick read; use `rapp_check.py` in CI for the
full gate. They agree on identity findings by construction — both are the reference primitives.

> **A note on honesty.** This SDK's `check` was itself sharpened by adversarial review. An early
> version missed `parent_rappid` drift; a reviewer running it against real artifacts caught the
> blind spot, and the check now flags §6.3. The lesson, worth carrying into anything you build with
> RAPP: a green checker proves nothing until an adversary has tried to make it lie against real
> inputs. Verify your verifier.

## 6.3 Say it to the brainstem

```
curl -s -X POST http://localhost:7071/chat -H 'Content-Type: application/json' \
 -d '{"user_input": "Use RappSdkBuilder to check whether kody-w/twin is RAPP compliant, and summarize the findings by section."}'
```

The brainstem calls `perform(action="check", repo="kody-w/twin")` and gives you the verdict and
findings in prose. You now have a compliance auditor you can *ask* — "is this door compliant?" —
and it answers by fetching and measuring, live.

## 6.4 A workflow: audit before you adopt

Put the pieces together and you have a real practice. Before you build on another organism —
fork it, parent to it, invite it — ask your brainstem to `check` it. If it comes back DRIFT on
identity, you know its address is not yet stable in the RAPP sense, and you can wait for its
owner to re-anchor before you bind to it. The SDK turns "trust the ecosystem" into "measure the
ecosystem," one repo at a time.
