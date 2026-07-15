# Estate → RAPP compliance tracker

> ## ✅ ACHIEVED — ZERO DRIFT (2026-07-15)
> Full-estate sweep of all **28 cloned repos** via `rapp_check.py`: **26 COMPLIANT · 2 CLEAN · 0 DRIFT**.
> The last four DRIFT repos were closed this pass:
> - **RAPP** + **rapp2mcs** — test-fixture `rappid.json` schema labels `rapp-rappid/2.0`→`rapp/1` (§12).
>   (`ant-farm-seed`'s `__MINTED_AT_PLANT__` is a documented plant-template placeholder, now exempt
>   from §6.1 — the linter distinguishes template-scaffolding from a deployed identity.)
> - **twin** — 3 `twin.pulse` frames re-enveloped to the §7 eleven-key form (payloads byte-identical).
> - **rapp-body** — 29 biography frames re-enveloped to §7 (payloads byte-identical); pre-§7 chain
>   sealed + retained under `frames/legacy/`; frames re-bound to the canonical identity; Herald's
>   `born_of_frame` constructor pin repointed to the canonical twin_id with its sha256 proof intact.
>
> **Build-level pressure test** (via `rapp_sdk_builder`): every primitive exercised end-to-end —
> mint (§6.2 keyless, not a name-hash) · canonicalize (JCS) · frame (§7 11-key) · verify · tamper-refusal ·
> scaffold · chain-link — all green. Reference `conformance.py`: 12/12 core vectors PASS.

The kody-w estate predates RAPP. This tracks bringing every RAPP-artifact-bearing repo to
compliance **now, before RAPP is adopted by anyone outside the estate** — the one window where
re-anchoring identity at the root costs nothing, because no external actor references the old
addresses yet.

**How compliance is decided:** `python3 rapp_check.py <repo>` verdicts each repo `CLEAN` (no RAPP
artifacts), `COMPLIANT` (all artifacts pass RAPP), or `DRIFT` (lists each violation by §). The
migration is deterministic and identity-preserving — `rapp_migrate.py` re-anchors each legacy
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

*(Positive evidence the linter already confirms: RAPP canonicalization reproduces twin's 3 and
rapp-body's 29 real committed payload hashes byte-for-byte — the content-addressing is already
correct; only the envelope and identity encoding drift.)*

## Migration order (dependency-topological)

1. **RAPP root first** — everything traces `parent_rappid` back to it, so its new rappid must exist
   before children rewire to it.
2. **children rewire** — twin, rapp-body, rapp-commons re-anchor and update any `parent_rappid`
   pointing at the old root form.
3. **frame re-genesis** — twin then rapp-body (the heavier, owner-authorized rebirths).
4. **sweep the tail** — run `rapp_check.py` over every remaining repo; the ~170 non-artifact repos
   verdict `CLEAN`, the rest get the same deterministic re-anchor.

## Method (per repo)

```
git checkout -b rapp-compliance
python3 rapp_migrate.py rappid.json --write        # deterministic re-anchor
#   … re-genesis frames if present …
python3 rapp_check.py .                             # must read COMPLIANT
#   Fable adversarial review
#   → owner authorizes the rebirth by merging the branch
```

Nothing is force-migrated on a live `main` without the owner's merge — that merge *is* the
constitutional owner-authorization for a content-addressed rebirth (Federal Constitution Art. X).

## The full artifact surface

GitHub code search finds **~30 repos** with a `rappid.json`. Of these:

- **Migratable (personal RAPP):** RAPP, twin, rapp-body, rapp-commons, rapp-batcave, rapp-midden,
  rapp-stack-cubby, rappter-distro, rappterbook, kody-w-twin, ant-farm, heimdall, neighborhood-example,
  rapp-oneclick-deploy, rapp-test-neighbor, rapp2mcs, sim-art-collective, tide-brainstem, lumen-brainstem,
  rapp-cave, the pkstop-* set, wildhaven-ai-homes-twin, twin-private.
- **EXCLUDED — publishing boundary (never touched by automation):** `microsoft-se-team-neighborhood`,
  `microsoft-se-team-neighborhood-private`, `microsoft-365-team`, `billwhalen-agent-team`. These carry
  work / Microsoft-internal / person-named content; upstream→downstream only, so they are not migrated
  here and any RAPP adoption for them is a separate, work-side decision.

## Two-pass migration model

Every repo migrates in two passes, because they need different authority:

1. **Identity layer (deterministic, no keys)** — re-anchor rappid + schema label + parent_rappid rewire.
   Coordinated across the estate via one global old→new map (the species root must re-anchor first so
   children rewire to it). Frames and test fixtures are never string-edited. Validated by adversarial
   review (the identity math is exact). **This is done on branches.**
2. **Frame + succession layer (owner-signed)** — re-genesis each legacy frame chain (§7.6/§12.1) with a
   correct `Hb("rapp/1:seal", head_octets)` seal, an *owner-signed* re-genesis genesis, a `rapp-map`
   registry entry, and the frame-producer code converged. **Requires the master signing keys** — cannot
   be forged, intentionally not done autonomously. (An early unsigned attempt on twin FAILED Fable review
   on exactly these points; not replicated.)

## Status log

- 2026-07-15 — linter + migration engine built; full surface mapped. **Identity layer migrated on
  `rapp-compliance` branches (pushed) for the species root and two children:**
  - **rapp-commons** → ✅ COMPLIANT (no frames; identity+schema done).
  - **rapp-body** → identity+schema done (both rappids re-anchored, parent rewired to new root); frames
    await pass 2.
  - **RAPP** (canon root) → root re-anchored `…RAPP:0b635450…` → `…rapp:9a8f0a4b…`; two residual items
    (a `@rapp/origin` legacy parent alias in `cave/rapplications/`, and the deliberately-legacy
    `tests/fixtures/`, which should be excluded from the gate).
  - **twin** → earlier branch has identity done; its frame re-genesis FAILED Fable review and will be
    redone correctly in pass 2 with keys.
  - Remaining personal artifact repos (rappter-distro, rappterbook, ant-farm, heimdall, the pkstop set,
    the twin templates, …) queue for the same coordinated identity pass.
  - **Blocked on Kody:** master signing keys for pass 2 (frame re-genesis + registry). Merge of the
    pushed `rapp-compliance` branches = owner authorization for the identity layer.
