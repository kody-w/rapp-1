# RAPP/1 Pipe Conformance Ledger

> **What this is.** Not a linter report. Each entry below takes a repo's *actual
> runtime pipe* — the code that mints a rappid, records a frame, or packs an egg —
> **runs it**, and checks the artifact it produces against the reference
> implementation [`rapp.py`](./rapp.py). "Water through the pipes": if the live
> output fails `rapp.py`, the producer was broken, and we fixed the producer.
>
> Every entry doubles as a **tutorial** — it shows how to drive that repo's pipe
> and what a spec-compliant artifact looks like, so it can be lifted straight into
> guides and onboarding docs.

## How to verify anything against the reference

The whole spec surface you need lives in three `rapp.py` calls:

```python
import sys; sys.path.insert(0, "path/to/rapp-1-repo")
import rapp

# §6.1 — is this identity string a valid rappid?
rapp.rappid_valid("rappid:@kody-w/rapp:9a8f0a4b…")        # -> True / False

# §2/§3 — the domain-separated content address of any value / bytes
rapp.H("rapp/1:particle", payload)                         # hash of a canonical value
rapp.Hb("rapp/1:rappid", uuid4.bytes)                      # hash of raw bytes (keyless mint tail)

# §7 — does this frame verify (envelope shape, payload_hash, frame_hash, chain)?
rapp.verify_frame(frame, head=prev_frame_or_None, stream_id_of_record=rappid)
```

The **canonical keyless mint** (used by every producer in the estate):

```python
tail = rapp.Hb("rapp/1:rappid", uuid4.bytes)   # == sha256(b"rapp/1:rappid\n" + uuid4.bytes)
rappid = f"rappid:@{owner}/{slug}:{tail}"       # owner/slug canonicalized to §6.1 grammar
```

The tail is a mint, **never** `sha256("owner/slug")`. Hashing a *name* into an
address is the cardinal sin the spec exists to end — the owner/slug already
locate the door; the 64-hex is identity, not a name digest.

The **canonical species root** every planted kody-w door points its
`parent_rappid` at:

```
rappid:@kody-w/rapp:9a8f0a4b5a710e20f4d819a0f37d2a4c9f113b5e78fb3c29e70b54fff48a38f9
```

---

## rappter-distro — the organism/plant layer

Three identity pipes, all previously emitting the **retired v2 string**
(`rappid:v2:<kind>:@owner/repo:<uuidhex>@github.com/…`) which `rapp.rappid_valid`
**rejects**. The repo linted clean only because it commits no `rappid.json` — the
defect lived in the producers, born at plant time.

### Pipe 1 — `installer/plant.sh :: mint_rappid` (plant a front door)

**Run it** (the mint in isolation, exactly as `plant.sh` now defines it):

```bash
python3 -c '
import uuid, hashlib, re, sys
def canon(s):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-"); return s or "x"
owner, slug = canon(sys.argv[1]), canon(sys.argv[2])
tail = hashlib.sha256(b"rapp/1:rappid\n" + uuid.uuid4().bytes).hexdigest()
print(f"rappid:@{owner}/{slug}:{tail}")
' "Kody-W" "My_Cool_Repo"
# -> rappid:@kody-w/my-cool-repo:43b82ced…e99890
```

**Verify vs `rapp.py`:**

| check | before fix | after fix |
|---|---|---|
| `rapp.rappid_valid(minted)` | `False` (v2 string) | **`True`** |
| `rapp.rappid_valid(parent_rappid)` | `False` (@rapp/origin v2) | **`True`** (canonical species root) |
| `rappid.json["schema"]` | `rapp-rappid/2.0` | **`rapp/1`** (§12) |

**Fix:** `mint_rappid` → keyless §6.1 mint; `SPECIES_ROOT_RAPPID` → canonical
species root; `write_rappid_json` schema → `rapp/1`.

### Pipe 2 — `installer/initialize-variant.sh` (template clone self-initializes)

Same v2 defect in `NEW_RAPPID` (minted `rappid:v2:variant:…`) and `PARENT_RAPPID`.
**Fixed** to the identical keyless §6.1 mint + canonical species root. Verify by
running the mint snippet above with the variant's `owner`/`repo`.

### Pipe 3 — `lib/bond.py :: pack_*` (egg packer writes the identity record)

Packing an egg wrote `rappid.json` with `"schema": "rapp-rappid/2.0"`. §12
requires `rapp/1`. **Fixed** (3 schema labels). The packed rappid itself was
already keyless-canonical from a prior pass.

### Pipe 4 — `lib/frames.py :: record_frame` (the frame recorder) ✅ §7

Calling `record_frame(kind, payload)` and feeding the result to
`rapp.verify_frame` exposed a non-§7 envelope: extra keys
(`frame_id`/`local_vt`/`prev_hash`/`assimilated`), missing `seq`/`prev`/
`prev_wave`/`sig`, and `prev` linked to the previous **frame_hash** instead of
§7's previous **particle** (`payload_hash`). Every frame it minted was born
non-compliant.

**Fixed:** emits the strict 11-key §7 frame (`stream_id` = the organism's rappid,
`seq` contiguous from 0, `prev` = previous `payload_hash`, `prev_wave`/`sig`
null). Per-incarnation sync metadata moved to a `frames-meta.jsonl` sidecar keyed
by `payload_hash` — envelope stays immutable and exactly eleven keys.
Byte-propagated to `twin/utils/frames.py` and `wildhaven-ai-homes-twin/utils/frames.py`.

**Verify vs `rapp.py`:**

```python
import frames, rapp
f0 = frames.record_frame("twin.pulse", {"beat": 1})   # genesis: seq=0, prev=None
f1 = frames.record_frame("twin.chat",  {"msg": "hi"}) # child:   seq=1, prev=f0.payload_hash

# verify_frame returns (ok, err, msg):
rapp.verify_frame(f0, head=None, stream_id_of_record=f0["stream_id"])  # -> (True, None, 'ok')
rapp.verify_frame(f1, head=f0,   stream_id_of_record=f1["stream_id"])  # -> (True, None, 'ok')
assert set(f0) == {"spec","kind","stream_id","seq","utc","payload",
                   "payload_hash","frame_hash","prev","prev_wave","sig"}  # exactly 11
assert f1["prev"] == f0["payload_hash"]                                   # §7 chains on the particle
```

*Live run (2026-07-15): 11 keys ✓, genesis `(True, None, 'ok')` ✓, child `(True, None, 'ok')` ✓, `f1.prev == f0.payload_hash` ✓.*

**Status:** all four pipes committed + pushed (`rappter-distro@e130b0c`, twin, wildhaven-ai-homes-twin).

---

## RAR — the agent registry (`agents/@*/…_agent.py`)

Single-file agents that mint identity / hatch twins / plant doors at runtime.
The registry lints CLEAN (no `rappid.json` under `agents/`), yet **running each
agent's `mint` / `summon` / `batcave` / `_summon` action and validating the
produced `rappid.json` against `rapp.py` surfaced 11 real defects across 6 agents.**

### `@rapp/rapp` 1.0.4 — six defects

| # | pipe | defect | fix |
|---|---|---|---|
| 1 | `_summon` | tail `sha256("kody/<name>-twin")[:32]` — **cardinal-sin name-hash**, 32-hex, `rappid_valid==False` | keyless §6.2 mint via `mint_rappid`, minted once & reused (idempotent identity); name-hash demoted to a filesystem dir key only |
| 2 | 4 sites | `"schema":"rapp-rappid/2.0"` | `"rapp/1"` (§12) |
| 3 | `_mint`/front-door | fallback parent `f"rappid:@{RAPP_SPECIES.replace('/',':')}"` = `rappid:@kody-w:RAPP` — malformed | real `SPECIES_ROOT_RAPPID` constant |
| 4 | `mint_rappid` | owner/slug verbatim → login `Kody-W` mints an uppercase rappid, `rappid_valid==False` | canonicalize via `_slugify` before assembly |
| 5 | `_batcave` | parent = `ctx["rappid"]` = sentinel `rappid:unregistered` (truthy but invalid); `or` fallback never fired | grammar-guard on `_ETERNITY_RE`, else species root |
| 6 | `_mint` `notes` | prose claimed the tail was "the deterministic sha256 of owner/slug" — **describes the cardinal sin** | corrected to name the keyless `Hb("rapp/1:rappid", uuid4)` mint |

**Verified:** `mint` over `{Kody-W/My_Door.v2, kody-w/clean-door, ACME/Wild_Repo}`
→ all `rappid_valid + parent_valid + schema_ok` True; `batcave` with & without a
prior operator identity → both parents valid.

### Five more agents

| agent | ver | defect(s) | verified |
|---|---|---|---|
| `@rapp/twin_agent` | 1.1.2 | `WILDHAVEN_RAPPID` was 32-hex → **invalid parent on every summoned twin**; schema `2.0`; non-domain-separated tail | converged to the twin's real `df9c3f1f…` (from its own `rappid.json`); `rappid_valid` True |
| `@kody-w/twin_me` | 1.0.2 | 2× schema `rapp-rappid/2.0` | → `rapp/1` |
| `@kody-w/transcript2prototype` | 1.0.2 | schema `rapp-rappid/3.0` | → `rapp/1` |
| `@kody-w/launch_to_public` | 1.0.3 | schema `2.0`; `gh_user`/`repo_name` uncanonicalized (uppercase login → invalid rappid) | canonicalized; mint valid |
| `@kody-w/plant_seed` | 1.0.3 | 2× schema `2.0`; `_mint_rappid` no owner/name canonicalization + non-domain-separated tail | `plant_seed(Kody-W/My_Seed.v2)` → `rappid:@kody-w/my-seed-v2:…` valid |

**Kept intentionally:** `@kody-w/twin_egg_hatcher` (v2/legacy **reader** — hatches
old eggs, emits nothing), `@rapp/drift_agent` (v2 **detector** — the regexes are
what it hunts for). `registry.json` rebuilt on every version bump.

**Status:** committed + pushed (`RAR@3445f4b`, prior `@rapp/rapp` `@9b16808`).

---

## RAPP — the kernel + tools

The kernel repo commits no `bond.py`/`egg.py`/`frames.py` (those live in
`rappter-distro`, already converged) — its identity pipes are in `tools/`.

| tool | defect | fix / verify |
|---|---|---|
| `tools/sim/plant_two_brainstems.py` | 2× schema `rapp-rappid/2.0`; `_mint_rappid` = `sha256(uuid4)` (no domain-sep) + no owner/name canonicalization | schema → `rapp/1`; mint → `Hb("rapp/1:rappid", uuid4)` + §6.1-canonicalized. `_mint_rappid(Kody-W/Test.v2)` → `rappid:@kody-w/test-v2:…` **valid** |
| `tools/backfill_seeds.py` | schema `rapp-rappid/2.0` (mint already correct) | → `rapp/1` |
| `tools/ecosystem_contract.py` | **6× `expected_schemas["rappid.json"] = "rapp-rappid/2.0"`** — the door contract would REJECT the correctly-converged `rapp/1` doors it validates | → `rapp/1` (§12) |

**Resolver verified:** `door_address.door_from_rappid` round-trips a canonical
rappid unchanged (`canonical == input`, `rappid_valid` True); the retired v2 form
is correctly **refused** on the live path (`InvalidRappidError` — the migrator
handles stragglers, not the resolver). `test_door_address.py` +
`test_migrate_rappid.py`: **28 passed**.

**Status:** committed + pushed (`RAPP@40f00e1`).

---

## RAPP installer — the primary distribution path

`installer/plant.sh` + `initialize-variant.sh` are what the curl one-liner runs.
**Every door planted by the installer was born non-compliant:**

| defect | before | after |
|---|---|---|
| `mint_rappid` / `NEW_RAPPID` tail | `uuid4().hex` = **32 hex** → `rappid_valid False`; owner/repo verbatim (uppercase login) | `Hb("rapp/1:rappid", uuid4)` 64-hex + §6.1-canonicalized |
| `SPECIES_ROOT_RAPPID` / `PARENT_RAPPID` | `rappid:@kody-w/RAPP:0b635450…` — uppercase + 32-hex → **invalid parent on every door** | canonical `rappid:@kody-w/rapp:9a8f0a4b…` |
| `rappid.json` schema | `rapp-rappid/2.0` | `rapp/1` |

**Verified live:** `plant.sh` mint over `{Kody-W/RAPP, kody-w/my-mirror, ACME/Cool_Repo.v2}`
→ all `rappid_valid` True; `bash -n` clean. (`RAPP@f9102ac`)

## Two more distinct-repo producers

| repo · file | defect | verify |
|---|---|---|
| `RAR/staging/@kody-w/project_twin` 0.3.2 | `_mint_v2_rappid` = `sha256(uuid4)` (no domain-sep) + no canonicalization; schema `2.0` | `project_twin(Kody-W/My_Project)` valid |
| `RAR/stacks/fleet/twin_egg_hatcher` 1.0.2 | hatched neighborhood stamped schema `rapp-rappid/2.0` (rappid echoed from egg — reader) | schema → `rapp/1` |
| `neighborhood-example/egg_hatcher` | **airgapped fallback minted `uuid4().hex` = 32-hex** invalid rappid; host slug uncanonicalized; schema `2.0` | `egg_hatcher(Kodys-MacBook.local)` → 64-hex, valid |

**Status:** committed + pushed (`RAR@46c3f2e`, `neighborhood-example`).

---

## No regression — estate stays green

After all producer fixes, `rapp_check.py` over **all 28 repos**: every committed
`rappid.json` passes §6.1, every `frames/` log conforms to §7, **zero DRIFT**. The
producers were fixed behind the already-compliant committed artifacts.

## Deferred (scope forks — need the operator's steer, not done unilaterally)

1. **§9 egg-manifest format** — `brainstem-egg/2.2-*` → `rapp/1-egg` is a
   cross-estate format migration touching ~33 producer/consumer files; RAPP's own
   `CLAUDE.md` documents `brainstem-egg/2.2-*` as the *current, deliberate* egg
   format. A spec decision, not a drift fix.
2. **Downstream agent copies** (`rapp-batcave/`, `rapp-midden/` — 11 files) carry
   the pre-fix schema/mint. They are point-in-time distributions of the canonical
   RAR agents now fixed upstream; correct handling is re-sync-from-upstream (or
   leave as archival snapshots — `rapp-midden` is literally an archive), not
   independent edits that create divergence.
3. **Non-code data/docs** (`neighborhood.json`, `tether.html`, `rapp-map/*.json`,
   `RAPPID_SPEC.md`, trackers) with literal `rapp-rappid/2.0` strings — not a
   runtime pipe, not `rapp_check`-linted; a bulk doc sweep.

*Ledger continues per repo as each one's pipes are exercised.*
