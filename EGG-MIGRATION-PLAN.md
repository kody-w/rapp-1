# Egg-manifest migration plan — `brainstem-egg/*` → `rapp/1-egg` (§9)

> **Status: PLAN for review. No edits made.** Kody chose "plan the migration" over
> doing it. This scopes the full surface, the target, the per-variant mapping, the
> non-obvious hazards, and a staged sequence — so the go/no-go and the ordering are
> a deliberate call, not a surprise mid-flight.

## Why this is a fork, not a drift fix

The estate deliberately ships `brainstem-egg/2.x` (RAPP's `CLAUDE.md` documents it
as the current egg format). But **SPEC §9 is now "the one egg spec of record"** —
it explicitly *subsumes and retires* `EGG_FAMILY.md`, `NEIGHBORHOOD_EGG_SPEC.md`,
`rappterbook/EGG_SPEC.md`, et al., and **§9.3 says a producer MUST NOT emit any
legacy egg schema.** So conformance eventually requires this migration — but it is
a format change touching packers, unpackers, every cataloged `.egg`, the zoo, and
the docs. That is a spec-ratification + coordinated-cutover decision, which is why
it was surfaced rather than executed.

## Current surface (measured)

**Legacy schema strings in play** (~1,400 occurrences across `.py/.js/.html/.md/.json`):

| legacy stamp | count | → §9 variant |
|---|---|---|
| `brainstem-egg/2.3-cubby` | 247 | **none yet** — cubby has no §9.2 variant (see Open Question 1) |
| `brainstem-egg/2.2-organism` | 171 | `organism` |
| `brainstem-egg/2.3-session` | 151 | `session` |
| `brainstem-egg/2.2-rapplication` | 145 | `rapplication` |
| `brainstem-egg/2.3-neighborhood` | 113 | **splits** → `invite` (QR pointer) **or** `neighborhood` (member-packing) |
| `brainstem-egg/2.1` | 107 | `organism` (variant-repo cartridge) — confirm |
| `brainstem-egg/2.3-estate` | 97 | `estate` |
| `brainstem-egg/2.0` | 52 | `organism` (legacy) |
| `brainstem-egg/1.0` | 3 | `organism` (legacy) |

**Canonical packers/unpackers** (the code of record):
- `rappter-distro/lib/bond.py` — `pack_organism` / `pack_rapplication` / `unpack_*`
  (stdlib-only master packer). `SCHEMA = "brainstem-egg/2.2-organism"`.
- `rappter-distro/lib/egg.py`, `twin/utils/egg.py`, `wildhaven-ai-homes-twin/utils/egg.py` — `pack_twin` et al.
- Agent packers: `@rapp/twin_agent`, `@kody-w/transcript2prototype`, `@kody-w/launch_to_public`.
- Consumers: `@rapp/egg_hatcher`, `@kody-w/twin_egg_hatcher`, `neighborhood-example/egg_hatcher`, the zoo importer.

## Target (SPEC §9, verbatim requirements)

Manifest = a §4 value with **exactly** these members:
```json
{ "schema":"rapp/1-egg", "variant":"<one of §9.2>", "rappid":"<§6.1 rappid>",
  "created_utc":"<§7.4 utc>", "contents":[{"path":"<rel POSIX>","hash":"<64hex>"},…],
  "payload":{ }, "sig":"<jws|null>" }
```
- `contents` lists every packed file **except `manifest.json`**, once, `hash = Hb("rapp/1:egg", octets)`; sorted ascending by UTF-8 bytes of `path`; **`[]` for JSON variants**.
- Egg address = `H("rapp/1:egg-manifest", manifest \ {sig})` (drop only `sig`, mirroring §7.3's wave rule).
- **ZIP `stored` (method 0) for every entry — no deflate anywhere** (deflate isn't byte-reproducible); `manifest.json` first and equal to `canonical(manifest)`; all timestamps `1980-01-01`; UTF-8 flag set.
- Producer MUST NOT emit legacy schema. Consumer MUST read every §9.2 variant, verify **integrity then viability**, refuse whole on any failure, and **MUST NOT reparent on transport**.

## The five non-obvious hazards (why a find/replace fails)

1. **`ZIP_DEFLATED` → `ZIP_STORED`.** `bond.py` packs with `zipfile.ZIP_DEFLATED` (lines 365, 600). §9.1 mandates `stored` for byte-reproducibility. This is a *container* change, not a label change — and it changes every egg's bytes (hence its address).
2. **Content hash domain.** §9 requires `Hb("rapp/1:egg", octets)` per file. Current manifests use a bare `sha256`/other. Every `contents[].hash` must be recomputed under the domain tag.
3. **Egg address is new.** `H("rapp/1:egg-manifest", manifest\{sig})` becomes the egg's identity. Anything that pins an egg by its old sha (the zoo, `bonds.json` `launch`/`hatch` events recording `egg sha256`, RAR pins) needs a re-pin pass — like the rappid version-immutability problem, one level up.
4. **Variant split + gap.** `2.3-neighborhood` is really two §9 things: the QR-sized **`invite`** (signed pointer, `contents:[]`, `sig` REQUIRED) vs the member-packing **`neighborhood`** (sub-eggs named `<owner>--<slug>.egg`). And **`2.3-cubby` (247 occ!) has no §9.2 variant** — needs a ratification call (Open Q1).
5. **Manifest member set is exact.** §9.1 is "exactly these members." Current manifests carry extra fields (`kernel_version`, `created_at`, `packed_by`, …). Those must move into `payload` or be dropped; a superset manifest fails §9.1(0).

## Staged sequence (proposed)

**Phase 0 — ratify (Kody + canon).** Resolve the two open questions below; amend RAPP `CLAUDE.md` + Constitution so §9 is the egg spec of record in the estate docs too (this is the canon half of the same reconciliation the schema-name sweep hit).

**Phase 1 — one conformant reference packer/unpacker.** Implement §9 in `rappter-distro/lib/bond.py` behind a new `pack_egg(variant, …)` / `read_egg(blob)` that emits `rapp/1-egg`, `stored`, domain-hashed `contents`, exact manifest, computed `egg_hash`. Unit-test byte-reproducibility (two packs of one manifest → identical bytes) and round-trip against a §9 validator (add `verify_egg` to `rapp.py` / `rapp_check.py`, which today does **not** lint eggs).

**Phase 2 — migrate producers to call it.** Point `egg.py`/`twin/utils/egg.py`/`wildhaven` + the three agent packers at `pack_egg`. Delete legacy `SCHEMA` constants. Re-sync downstream copies from upstream (same upstream→downstream discipline used for the batcave).

**Phase 3 — consumers read every §9.2 variant.** Update `egg_hatcher`/`twin_egg_hatcher`/zoo to dispatch on `variant`, verify integrity-then-viability, refuse-whole. Keep a **read-only** legacy shim ONLY if we must hatch pre-existing `.egg` files (a documented, dated back-compat reader — never a producer).

**Phase 4 — re-pin existing cartridges.** Re-pack every cataloged `.egg` (RAPP_Store `/api/v1/`, rapp-zoo starters, `*.well-known/*.egg`, bundled `commons.egg`) under §9; update every recorded egg-sha (`bonds.json`, zoo metadata, RAR). This is the egg analogue of the rappid version-immutability re-pin.

**Phase 5 — retire docs.** Fold `EGG_FAMILY.md` / `NEIGHBORHOOD_EGG_SPEC.md` / `rappterbook/EGG_SPEC.md` into a one-line "see SPEC §9" per §9's subsume clause.

## Open questions for Kody (block Phase 0)

1. **`2.3-cubby` (247 occ) has no §9.2 variant.** Options: (a) petition to add `cubby` to the ratified §9.2 set; (b) map cubbies onto `organism` or `neighborhood`; (c) declare cubbies a non-egg local construct. This is the single biggest unknown.
2. **`2.3-neighborhood` → `invite` vs `neighborhood`:** confirm which existing neighborhood eggs are QR pointers (→ `invite`, and note `invite` `sig` is REQUIRED and must verify under §13.2 estate-owner succession) vs true member bundles (→ `neighborhood`).
3. **Back-compat window:** do we keep a dated read-only legacy hatcher for eggs already in the wild, or hard-cut and re-pack everything (Phase 4 covers the re-pack either way)?

## Estimate

Reference packer/unpacker + validator: ~1–2 focused sessions. Producer/consumer
migration + downstream re-sync: ~1 session. Cartridge re-pin (Phase 4) is the long
pole — proportional to how many `.egg` files are cataloged live. Recommend Phases
0–1 first (ratify + one proven conformant packer) before committing to the cutover.
