# Estate drift sweep — 2026-07-15

Every public `kody-w/*` repo run through the RAPP SDK Builder agent and the reference
implementation (`rapp.py`), building **from the real committed repos** and comparing back to
the protocol. This is the "interact, break, fix" pass. Verdicts are from the tooling, not eyeballing.

## Done — verified against `rapp.py` and pushed live

| # | repo | what was drifting | fix | proof |
|---|------|-------------------|-----|-------|
| 1 | **RAR** (`@kody-w/rapp_sdk_builder`) | `sync` action ran fetched code via `exec()` (registry-forbidden); version pin | rewrote `sync` to compare primitive **source** via `ast` (parses, never executes); bumped to 1.0.1 | agent forged (card "The Sentinel", mythic), pullable, RAR copy == rapp-1 source byte-identical (`d635c90a…`) |
| 2 | **rappter-distro** | shipped a **parallel "v2 Constitution" identity model** — its own parser couldn't parse its own migrated `rappid.json` | `lib/rappid.py` → canonical §6.1 grammar + canonical root + domain-sep 64-hex keyed backing; `lib/egg.py` → canonical keyless mint (legacy identities still recognized, no re-mint); `lib/frames.py` → frames now carry `payload_hash`/`prev_hash`/`frame_hash` | all primitives byte-identical to `rapp.py`; tamper breaks the chain; rejects legacy v2 |
| 3 | **twin** | `utils/egg.py`+`utils/frames.py` = byte-identical copies of distro's pre-fix v2 drift | propagated the converged libs | compiles; canonical mint; frames content-addressed |
| 4 | **wildhaven-ai-homes-twin** | same v2 drift copies | propagated the converged libs | same |
| 5 | **RAPP** (root repo) | `tools/backfill_seeds.py` minted identity as `sha256("owner/repo")` — the **cardinal sin** | → canonical keyless `Hb("rapp/1:rappid", uuid4)` | idempotent via stored `rappid.json`; sin removed |

## The one big finding — two identity doctrines (CODE now converged; DATA re-anchor pending)

The estate carried **two conflicting identity theories**:

- **rapp-1 spec §6.2** (the standard you published): identity = `Hb("rapp/1:rappid", uuid4|SPKI)`,
  minted once, **never** a hash of the name. The canonical root `@kody-w/rapp:9a8f0a4b…`, twin,
  rapp-commons, rapp-body — all proper mints (verified: none are name-hashes).
- **"Eternity / Constitution Art. XXXIV.1"**: identity = `sha256("owner/slug")` — the cardinal
  sin, dressed in canonical §6.1 *grammar* so a linter passes it, but the **mint** is a name digest.

They compute **different** identities for the same repo. Per the spec, Eternity is the drift.

**✅ CODE — done & pushed (all 10 mint sites now canonical keyless):**
- `RAR/agents/@rapp/rapp_agent.py` — the *published* godfather agent (`@rapp/rapp`), bumped
  **1.0.0 → 1.0.1**, registry rebuilt & re-pinned (`57d7d7b0…`). This is the source all copies derive from.
- **8 copies** across rapp-batcave (5) + rapp-midden (3) — converged to match.
- `RAPP/tools/backfill_seeds.py` — root repo's minting tool.
- All verified: mints are 64-hex `Hb("rapp/1:rappid", uuid4)`, **not** `sha256(name)`; callers are
  idempotent via stored `rappid.json`, so the random tail is safe.

**⏳ DATA re-anchor — needs your greenlight (the tracked batcave illegal mint, RAR#187 / rapp-map#8):**
`rapp-batcave/rappid.json` (`72c739f2…` = `sha256("kody-w/rapp-batcave")`) and `rapp-midden/rappid.json`
(`0fb59d7d…`) still carry the legacy name-hash identity. Re-anchoring is **not** a text-edit:
the batcave id is referenced in **~15 files** (served `index.html`, `holo.md`, `card.json`, `members.json`,
specs, `cubbies/index.json`, `rar/index.json`) **+ a packed `.well-known/batcave.egg`** (must be
re-packed, not sed'd) **+ rapp-map** (`neurons.json`, `neurons-manifest.json`). Doing it blind corrupts
served history — the exact failure mode caught before. **Recommend:** greenlight and I run it as one
coordinated pass using the batcave's own re-pack tooling (it's key-free; no signatures), then update
rapp-map and close RAR#187.

## Remaining, smaller

| repo | finding | severity | note |
|------|---------|----------|------|
| **twin** | genesis frames are `spec:"rapp-frame/2.0"` citing the *old 32-hex* identity; `sig:null` (unsigned) | med | key-free re-genesis possible, but touches served `feed.json` — the thing that corrupted before; do it with a verify loop |
| **rapp-commons** | `tools/federate.py` reads legacy `rappid:v2:…`; `evolution/STATE.json` schema `rapp-commons-evolution/1.0` | low | federate is a tool (v2 read path); the evolution schema is likely a legit state schema, not identity |
| **rappter-distro** | `examples/rapp-commons/tether.html` (2600-line demo) + `federate.py` still mint/parse v2 | low | in `examples/` (not installed); teaching material — flag not hand-rewrite |
| **rappterbook** | ships its own `EGG_SPEC.md` / `FRAME_SPEC.md` | low | prose specs that can diverge from canonical SPEC; reconcile wording |
| **rapp-map** | `neurons-manifest.json` carries rappids | low | lint the referenced rappids for §6.1 |
| **rapp-oneclick-deploy** | nested `apps/@kody-w/copilot-studio-deploy/rappid.json` | ✅ compliant | earlier slug fix held (hyphenated, schema `rapp/1`, deterministic tail preserved) |

## Full 27-repo verdict matrix (SDK Builder `check`, live)

**18 COMPLIANT** · **8 "CLEAN"** (no root `rappid.json`; some had nested artifacts the root-check
missed — deep-checked above) · **1 DRIFT** at scan time (rapp-stack-cubby, schema `rapp-eternity/1.0`,
not cloned here — separate PR #12, manifest-pinned).

## Standing constraints honored
No customer/employee names or Microsoft-internal identifiers introduced. (Note: `rapp-batcave`
contains a pre-existing `cubbies/billwhalenmsft/` path — a MS-employee identifier in a public repo —
flagged, not touched.) Excluded work repos never opened. No signing keys forged. `soul.md` untouched.
