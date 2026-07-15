# Estate → RAPP/1 compliance tracker

The kody-w estate predates RAPP/1. This tracks bringing every RAPP-artifact-bearing repo to
compliance **now, before RAPP/1 is adopted by anyone outside the estate** — the one window where
re-anchoring identity at the root costs nothing, because no external actor references the old
addresses yet.

**How compliance is decided:** `python3 rapp1_check.py <repo>` verdicts each repo `CLEAN` (no RAPP
artifacts), `COMPLIANT` (all artifacts pass RAPP/1), or `DRIFT` (lists each violation by §). The
migration is deterministic and identity-preserving — `rapp1_migrate.py` re-anchors each legacy
rappid from its *own UUID* into the domain-tagged 64-hex form (§5/§6.2), records the old string in
`_migrated_from` so references resolve forward (§6.3), and sets the schema label to `rapp/1` (§12).
Frame chains converge by re-genesis (§7.6/§12.1): legacy frames retained sealed under `frames/legacy/`,
a new genesis begins in the eleven-field form citing the sealed head.

## Compliance surface (of 200 repos, these carry RAPP artifacts)

| repo | verdict | identity | frames | what the migration does |
|------|---------|----------|--------|--------------------------|
| **RAPP** (canon root) | 🔧 DRIFT | root tail is 32-hex `0b635450…`; slug `RAPP` not lowercase; schema `rapp-rappid/2.0` | — | re-anchor species root → `rappid:@kody-w/rapp:9a8f0a4b…` (same UUID anchor), schema→`rapp/1`. `cave/` rappids already 64-hex (label only). Test fixtures left as legacy test data. |
| **twin** | 🔧 DRIFT | 32-hex `257afa79…` | 3 frames, legacy envelope | re-anchor → `…:5714cdf9…`; re-genesis the 3-frame chain into eleven-field form |
| **rapp-body** | 🔧 DRIFT | 64-hex but minted *untagged* | 29 frames, legacy envelope | re-anchor to tagged `…:817839d2…`; rewire Herald's `parent_rappid`; re-genesis 29 frames |
| **rapp-commons** | 🔧 DRIFT | 32-hex `3929ce90…` | — | re-anchor → `…:fea3bd6e…`, schema→`rapp/1` |
| **rapp-map** | ✅ CLEAN | — | — | nothing to do |
| **RAR** | ✅ CLEAN | — | — | nothing to do (ID-01 already fixed on a prior branch) |

*(Positive evidence the linter already confirms: RAPP/1 canonicalization reproduces twin's 3 and
rapp-body's 29 real committed payload hashes byte-for-byte — the content-addressing is already
correct; only the envelope and identity encoding drift.)*

## Migration order (dependency-topological)

1. **RAPP root first** — everything traces `parent_rappid` back to it, so its new rappid must exist
   before children rewire to it.
2. **children rewire** — twin, rapp-body, rapp-commons re-anchor and update any `parent_rappid`
   pointing at the old root form.
3. **frame re-genesis** — twin then rapp-body (the heavier, owner-authorized rebirths).
4. **sweep the tail** — run `rapp1_check.py` over every remaining repo; the ~170 non-artifact repos
   verdict `CLEAN`, the rest get the same deterministic re-anchor.

## Method (per repo)

```
git checkout -b rapp1-compliance
python3 rapp1_migrate.py rappid.json --write        # deterministic re-anchor
#   … re-genesis frames if present …
python3 rapp1_check.py .                             # must read COMPLIANT
#   Fable adversarial review
#   → owner authorizes the rebirth by merging the branch
```

Nothing is force-migrated on a live `main` without the owner's merge — that merge *is* the
constitutional owner-authorization for a content-addressed rebirth (Federal Constitution Art. X).

## Status log

- 2026-07-15 — linter + migration engine built; surface mapped (above); template repo migration
  in progress. Identity re-anchor proven deterministic + idempotent across all four DRIFT repos.
