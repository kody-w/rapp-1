# The RAPP Standing-Guard Convergence Playbook

**Audience:** any AI agent assigned to sweep one repository of the kody-w RAPP estate into full conformance with the RAPP standard (wire tag: `rapp/1`).
**Assumption:** you have read a GitHub issue on your repo that linked you here, and you have nothing else — no prior context, no memory, no access to the human. This document plus the public URLs it cites are your entire brain. Everything you need is below, including exact formulas, runnable commands, and the judgment rules for every case you will encounter.

**Prime directive:** you are performing a *deep* conformance pass, not a grep. A grep finds strings; you must exercise real code, judge each finding by category, fix producers at their real layer, and prove the result by re-running the checks until they come up empty. "Fixed" is a re-sweep verdict, never a single edit.

---

## 0. Canonical references (fetch these; they are the ground truth)

| Artifact | Raw URL |
|---|---|
| Reference implementation (`rapp.py`) | `https://raw.githubusercontent.com/kody-w/rapp-1/main/rapp.py` |
| The specification (`SPEC.md`) | `https://raw.githubusercontent.com/kody-w/rapp-1/main/SPEC.md` |
| The compliance linter (`rapp_check.py`) | `https://raw.githubusercontent.com/kody-w/rapp-1/main/rapp_check.py` |
| Constitution (Articles LIII, LIV) | `https://raw.githubusercontent.com/kody-w/RAPP/main/CONSTITUTION.md` |

`kody-w/rapp-1` is the single reference implementation of record. Where this Playbook and those files ever disagree, **SPEC.md + rapp.py win** — they are the standard; this document teaches it.

Get the whole reference in one command:

```bash
git clone --depth 1 https://github.com/kody-w/rapp-1 /tmp/rapp-1
```

---

## 1. The convergence doctrine — why you exist

The estate (~144 public repos) is converging to the RAPP standard through **alternating bidirectional sweeps**:

- **Top-down (estate → repo):** a central agent sweeps all repos at once. Broad, but necessarily shallow per repo — it cannot soak 144 full contexts.
- **Bottom-up (repo → estate):** *you*. You have one repo and unlimited depth. You soak your repo's entire context — its README, its structure, every producer, test, and artifact — and sweep from the inside, catching what the shallow central passes missed. Then you report back.
- **The loop:** passes alternate until **both directions come up empty**. A single shallow pass always leaves residue. The doctrine is deep-context passes, bidirectional, iterated to a **zero-drift fixpoint**.

Your job is one full bottom-up pass, executed to the standard of §8 below, ending in a report per §9.

---

## 2. The identity law (SPEC §6) — the cardinal sin and the one true mint

### 2.1 The rappid grammar

A RAPP identity string ("rappid") is exactly:

```
rappid:@<owner>/<slug>:<64hex>
```

- `owner` and `slug` each match `[a-z0-9]+(-[a-z0-9]+)*` — lowercase alphanumerics, single hyphens as separators, **no dots, no underscores, no uppercase, no leading/trailing/double hyphens**.
- The tail is exactly **64 lowercase hex characters** (`[0-9a-f]{64}`).
- The full validating regex (verbatim from `rapp.py`):

```python
_RAPPID = re.compile(r"^rappid:@([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:-[a-z0-9]+)*):([0-9a-f]{64})$")
```

### 2.2 The one true mint

The 64-hex tail is minted **once**, at creation, from entropy or key material — never from the name:

```python
import hashlib, uuid

def Hb(space, b):
    return hashlib.sha256(space.encode() + b"\x0a" + b).hexdigest()

# Keyless mint (the default):
tail = Hb("rapp/1:rappid", uuid.uuid4().bytes)

# Keyed mint (optional, when the identity is bound to a keypair):
tail = Hb("rapp/1:rappid", spki_der)   # SPKI DER bytes of the public key

rappid = f"rappid:@{owner}/{slug}:{tail}"
```

On read of an existing `rappid.json`, an implementation **MUST reuse the stored tail** — mint-once means never re-mint on load.

### 2.3 THE CARDINAL SIN — never hash a name into an address

```python
# ALL OF THESE ARE FORBIDDEN. If you find one, it is drift. Fix the producer.
tail = hashlib.sha256(f"{owner}/{slug}".encode()).hexdigest()   # name-hash mint  (§6.2 violation)
tail = hashlib.sha256(name.encode()).hexdigest()                # same sin, any spelling
tail = uuid.uuid4().hex                                         # only 32 hex → fails §6.1 (needs 64)
```

**Why it is the cardinal sin:** the `owner/slug` already *locate* the door — they are the name. The hash tail is *identity*: it must carry entropy (uuid4) or key-binding (SPKI) that no one can derive from the name alone. `sha256("owner/slug")` is derivable by anyone, is identical across every re-creation of the thing, and reduces the address to a pun on its own name — zero uniqueness, zero unforgeability. (The keyed mint is deterministic and that is fine: a public key *is* identity material; a name is not.)

Also retired and **never emitted**: the old v2 string form

```
rappid:v2:<kind>:@owner/repo:<hash>@github.com/...
```

`kind` lives in the **`rappid.json` record** as a field, never inside the rappid string.

### 2.4 Domain separation (SPEC §5) — the two hash functions

Everything in RAPP is addressed through two functions with an exact newline-separated domain tag:

```python
def Hb(space, b):   # over raw octets
    return hashlib.sha256(space.encode() + b"\x0a" + b).hexdigest()

def H(space, v):    # over a canonicalized JSON value (§4 JCS, no floats)
    return hashlib.sha256(space.encode() + b"\x0a" + canonical(v).encode("utf-8")).hexdigest()
```

The ratified spaces (each used by either `H` or `Hb`, never both):

| Space | Used for |
|---|---|
| `rapp/1:particle` | frame `payload_hash` (via `H`) |
| `rapp/1:wave` | frame `frame_hash` (via `H`) |
| `rapp/1:rappid` | identity tails (via `Hb`) |
| `rapp/1:egg` | egg member-file octets (via `Hb`) |
| `rapp/1:egg-manifest` | the egg's whole-address (via `H`) |
| `rapp/1:seal` | seals |

`canonical(v)` is RFC 8785 JCS restricted to strings/ints/bools/null/arrays/objects (no floats): sorted keys, no whitespace, `ensure_ascii=False`. Use the reference `rapp.canonical` — do not hand-roll.

---

## 3. The frame (SPEC §7) — the 11-key envelope

A frame has **exactly eleven keys**, no more, no fewer:

```
spec, kind, stream_id, seq, utc, payload, payload_hash, frame_hash, prev, prev_wave, sig
```

The laws, exactly:

- `spec` is the string `"rapp/1"`.
- `kind` matches `^[a-z0-9]+(-[a-z0-9]+)*\.[a-z0-9]+(-[a-z0-9]+)*$` — `namespace.name`, **exactly one dot**.
- `seq` is an integer in `[0, 2^53 − 1]` (never a bool, never a string).
- `utc` is the fixed millisecond form `YYYY-MM-DDTHH:MM:SS.mmmZ` (regex `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`), non-decreasing along the chain.
- `payload` is a JSON object.
- `payload_hash = H("rapp/1:particle", payload)`.
- `frame_hash = H("rapp/1:wave", frame_without_frame_hash_and_sig)` — the frame minus exactly the `frame_hash` and `sig` members.
- **`prev` links to the previous frame's `payload_hash` (the PARTICLE) — NOT its `frame_hash`.** This is the most commonly mis-implemented rule in the estate.
- `prev_wave` is the `frame_hash` link and is **only** non-null on swarm streams (`stream_id` starting `net:`) for `seq > 0`; off-swarm it MUST be `null`. Swarm frames MUST be signed (`sig` non-null).
- Genesis: `seq = 0`, `prev = null`, `prev_wave = null`.

**Frames are IMMUTABLE.** Editing a committed frame's bytes breaks its hash chain. NEVER hand-edit committed frames or sealed `frames/legacy/` files — not to fix a typo, not to update a retired schema string inside a payload, not for any reason. A frame correctly preserves whatever was current when it was written; history is not rewritten. If a chain is genuinely broken, the remedy is the owner-authorized re-genesis operation (SPEC §12.1), which is **not** yours to perform — report it as drift instead (§9).

Verify chains with the reference verifier, threading the head so linkage is actually checked:

```python
import sys, json, glob, os
sys.path.insert(0, "/tmp/rapp-1")
import rapp

files = sorted(glob.glob("path/to/frames/*.json"),
               key=lambda f: int(os.path.basename(f)[:-5]))
head = None
for f in files:
    fr = json.load(open(f))
    ok, step, why = rapp.verify_frame(fr, head=head, stream_id_of_record=fr.get("stream_id"))
    print(f, ok, step, why)
    assert ok, (f, step, why)
    head = fr
```

---

## 4. The egg (SPEC §9) — `rapp/1-egg`

An egg is either a JSON object (`invite`, `session` variants) or a ZIP whose root is `manifest.json` (tree variants). The manifest has **exactly** these members:

```json
{ "schema": "rapp/1-egg", "variant": "<variant>", "rappid": "<§6.1 rappid>",
  "created_utc": "<millisecond utc>", "contents": [ {"path": "<rel>", "hash": "<64hex>"} ],
  "payload": { }, "sig": null }
```

The ratified variants: **organism, rapplication, session, invite, neighborhood, estate** (see SPEC §9.2 for each one's required members). No other variant exists; no other document may re-specify eggs.

The laws:

- `contents[].hash = Hb("rapp/1:egg", file_octets)` over the raw stored octets; every packed file except `manifest.json` itself appears exactly once; **sorted ascending by the UTF-8 bytes of `path`**; JSON variants carry exactly `[]`.
- `path` is a relative POSIX path: no `.`/`..` segments, no leading `/`, no backslash, no duplicates.
- **ZIP variants MUST use compression method `stored` (0) for every entry** — no deflate anywhere (deflate is library-dependent, so not byte-reproducible). `manifest.json` first, then `contents` order; all timestamps `1980-01-01 00:00:00`; the `manifest.json` entry's octets are exactly `canonical(manifest)`.
- The egg's one address is `egg_hash = H("rapp/1:egg-manifest", manifest_without_sig)` — the manifest with exactly the `sig` key removed (re-signing never changes identity).
- `invite` eggs REQUIRE a valid estate-owner `sig`.

**Retired:** all legacy `brainstem-egg/2.x-*` stamps (e.g. `brainstem-egg/2.3-neighborhood`, `neighborhood-egg/1.0`). They MUST never be emitted. Existing legacy eggs are **RE-PACKED** into `rapp/1-egg` form — a packed `.egg` is hash-sealed like a frame, so it is never hand-edited, only re-packed by a conformant packer.

Verify an egg:

```python
import sys, json, zipfile
sys.path.insert(0, "/tmp/rapp-1"); import rapp

z = zipfile.ZipFile("thing.egg")
assert all(i.compress_type == 0 for i in z.infolist()), "deflate found — not byte-reproducible"
m = json.loads(z.read("manifest.json"))
assert set(m) == {"schema","variant","rappid","created_utc","contents","payload","sig"}
assert m["schema"] == "rapp/1-egg" and rapp.rappid_valid(m["rappid"])
paths = [c["path"] for c in m["contents"]]
assert paths == sorted(paths, key=lambda p: p.encode())
for c in m["contents"]:
    assert rapp.Hb("rapp/1:egg", z.read(c["path"])) == c["hash"], c["path"]
egg_hash = rapp.H("rapp/1:egg-manifest", {k: v for k, v in m.items() if k != "sig"})
print("egg OK:", egg_hash)
```

---

## 5. The schema-name ratification (Constitution Article LIV, 2026-07-15)

The `rappid.json` `schema` field carries **exactly one** canonical value estate-wide: **`rapp/1`**. This is the value `rapp_check.py` (§12 check) enforces.

The former names **`rapp-rappid/2.0`** and older **`rapp-rappid/1.1`** are RETIRED: read-forever (a consumer treats them as `rapp/1` on read) but **NEVER emitted** by any producer, and never left standing in a declaration.

**Identity math is unchanged.** No rappid tail, frame hash, or egg byte changes under Article LIV — this is a label ratification, not a re-mint.

The judgment taxonomy — apply it to *every* hit of a retired name (this taxonomy is the difference between a deep pass and a destructive one):

| Category | Example | Disposition |
|---|---|---|
| **Declaration** (schema-of-record statement) | `"schema": "rapp-rappid/2.0"` in a live `rappid.json`; a producer that writes that string | **Fix to `rapp/1`** (fix the producer, then its output) |
| **History / migration narrative** | a CHANGELOG or report describing what the schema *used to be* | **Keep** — falsifying history is wrong |
| **Legacy-parsing test fixture** | a test that feeds `rapp-rappid/1.1` to prove the reader still accepts it | **Keep** — the old form is the point of the test |
| **Observational finding** (drift-map, scan output) | a generated drift report that recorded the old name in another repo | **Regenerate via re-scan** — never hand-edit an observation |
| **Immutable frame / sealed egg** | old schema string inside a committed frame payload | **Never edit.** Frames stand as history; eggs are re-packed, not patched |

---

## 6. Mirrors and downstream (Constitution Article LIII.6)

A **mirror** is only ever edited by **re-syncing from its declared upstream of record**. Examples: batcave agent copies re-sync from `kody-w/RAR`; a RAPP variant re-syncs canon from `kody-w/RAPP`. If your repo contains a mirror with drift, the fix is *upstream first, then re-sync* — never an independent hand-edit that diverges the mirror. If the upstream itself is drifted, report it (§9) rather than patching your copy.

---

## 7. What NOT to do (the destructive-fix list)

1. Never hand-edit committed frames or `frames/legacy/` seals (§3).
2. Never hand-edit a packed `.egg` — re-pack (§4).
3. Never rewrite history/migration prose to pretend old names never existed (§5).
4. Never hand-edit a generated observational report — regenerate it from its scanner (§5).
5. Never hand-edit a mirror into divergence from its upstream (§6).
6. Never mass-`sed` the repo. Every hit gets a category judgment first.
7. Never "improve" anything beyond the conformance scope — surgical fixes only.
8. Note the **plant-template exemption**: a committed template `rappid.json` whose tail is a `__SENTINEL__`-style placeholder (whole tail matches `^__[A-Z0-9_]+__$`) is scaffolding whose identity is minted at plant time. `rapp_check.py` exempts it; do not "fix" it into a real rappid.

---

## 8. THE DEEP SELF-SWEEP PROCEDURE (execute exactly this)

### Step 1 — Get the reference

```bash
git clone --depth 1 https://github.com/kody-w/rapp-1 /tmp/rapp-1
```

### Step 2 — Soak the repo FIRST

Before judging anything, read: the README, the directory tree, every file that *produces* a RAPP artifact (mints a rappid, writes a frame, packs an egg, writes a `rappid.json`), every test, every committed artifact (`**/rappid.json`, `**/frames/*.json`, `*.egg`, registry indexes). Build a mental map: *what does this repo produce, what does it merely record, and what does it mirror?* Tailor everything that follows to THIS repo's shape — do not spray generic heuristics at code you have not understood.

### Step 3 — Run the shallow checker (necessary, not sufficient)

```bash
python3 /tmp/rapp-1/rapp_check.py .          # human output
python3 /tmp/rapp-1/rapp_check.py . --json   # machine output
```

Verdicts: `CLEAN` (no RAPP artifacts) or `COMPLIANT` (all pass) exit 0; `DRIFT` exits 1 and lists each finding by spec section. It checks committed `**/rappid.json` (§6.1 grammar, the name-hash sin, 32-hex short tails, §12 schema label, §6.3 parent_rappid) and `**/frames/*.json` chains (§7 envelope + linkage). **Passing this is the floor, not the finish.**

### Step 4 — Exercise the REAL pipes (the heart of the deep pass)

A repo can pass `rapp_check` on its committed artifacts while a **runtime producer** still mints garbage — that is exactly the class every shallow pass misses. For every producer you mapped in Step 2, import or run it and validate its **live output** with the reference:

```python
import sys, hashlib
sys.path.insert(0, "/tmp/rapp-1")
import rapp

# (a) Every rappid the code mints at runtime:
rid = <call the repo's own mint path>
assert rapp.rappid_valid(rid), f"invalid rappid: {rid}"
owner, slug, tail = rapp._RAPPID.match(rid).groups()
assert tail != hashlib.sha256(f"{owner}/{slug}".encode()).hexdigest(), \
    f"CARDINAL SIN: name-hash mint in live producer: {rid}"
# Mint twice — a keyless mint MUST differ each time; identical tails mean it is derived, not minted:
# rid2 = <mint again>; assert differing tails unless the mint is keyed (SPKI).

# (b) Every frame the code records at runtime:
fr = <call the repo's own frame-recording path>
ok, step, why = rapp.verify_frame(fr, head=<prior frame or None>,
                                  stream_id_of_record=fr.get("stream_id"))
assert ok, f"frame fails §7 step {step}: {why}"

# (c) Every egg the code packs: run the §4-of-this-Playbook egg verifier on the fresh output.
```

If a producer needs credentials or infrastructure you don't have, exercise the deepest layer you can reach (unit-invoke the mint function directly), and state explicitly in your report which pipes ran live and which could not — **never report a pipe as verified that you did not run**.

### Step 5 — Grep ALL source for residue, then JUDGE each hit

```bash
grep -rInE \
  --include='*.py' --include='*.sh' --include='*.js' --include='*.html' \
  --include='*.json' --include='*.md' \
  'sha256\([^)]*(owner|slug|name)|uuid4\(\)\.hex|rappid:v2:|rapp-rappid/(1\.1|2\.0)|brainstem-egg/2\.' \
  . | grep -v '/\.git/'
```

The grep is a net, not a verdict. Route every hit through the §5 taxonomy:

| Residue pattern | What it is | If it's a declaration/producer | If it's history / legacy-test / observation / immutable |
|---|---|---|---|
| `sha256(...owner...slug...)`, `sha256(name)` as a tail | the cardinal sin | fix the mint to `Hb("rapp/1:rappid", uuid4().bytes)` | keep (e.g. the test that *detects* the sin) |
| `uuid4().hex` as a tail | 32-hex short tail (fails §6.1) | fix as above | keep |
| `rappid:v2:` emission | retired (legacy) v2 string | fix producer; re-mint output | keep |
| `rapp-rappid/2.0` / `rapp-rappid/1.1` | retired schema names | update declaration to `rapp/1` | keep / regenerate / never-edit per §5 |
| `brainstem-egg/2.` | retired egg stamps | fix packer; re-pack eggs | keep |

Also grep for mint-shaped code the pattern net can miss: any `hashlib.sha256` whose input is a string literal or repo/name variable feeding into an identity, id, or address. Read the code; judge it.

### Step 6 — Fix at the real layer, re-run until green

**For legacy-identity DRIFT** (a committed `rappid.json` bearing a v2 string, a 32-hex
short tail, or a `rapp-rappid/2.0` schema), the estate-standard fix is published as a
tool: **`standing_guard_reanchor.py`** (`https://raw.githubusercontent.com/kody-w/rapp-1/main/standing_guard_reanchor.py`).
It widens the legacy 128-bit id to the §6.1 256-bit tail via `Hb("rapp/1:rappid",
bytes.fromhex(old32))` (deterministic, ordering-free — a child computes its parent's new
id identically), coordinates the replacement across every grail file, refreshes the frozen
spec's mint teaching, and records lineage in `_migrated_from`. Run it, then verify with
`rapp_check.py`. Do NOT invent a `parent_rappid` where one is absent (a missing parent is
§6.3-valid); only re-anchor an existing legacy one.


- Fix the **producer**, then regenerate its outputs through the fixed producer (never hand-patch outputs to match).
- For **version-pinned artifacts** (e.g. RAR agents): bump the artifact version and rebuild the registry index — a silent in-place change under a pinned version is itself drift.
- Re-run Steps 3–5 from scratch after fixing. The pass is complete only when `rapp_check` is COMPLIANT/CLEAN **and** every live pipe validates **and** the residue grep yields only justified keep-category hits.

### Step 7 — Report (see §9)

---

## 9. Reporting protocol — closing the loop

On the GitHub issue that sent you here, post a comment with:

1. **Verdict:** `SWEEP CLEAN` (zero drift found or all drift fixed) or `SWEEP DIRTY` (residue remains).
2. **Evidence:** the final `rapp_check.py` verdict line; which live pipes you exercised (with the observed valid outputs) and which you could not; every fix made (file, layer, before→after in one line each); every keep-category hit with its taxonomy label.
3. **Commits:** the SHAs of your fixes.

Then manage the drift ledger:

- **Search your repo's open issues** for related `drift(...)` items (search the `drift` label and `drift(` in titles). **CLOSE** any that your fixes resolve, citing the fixing commit.
- **OPEN** a fresh issue titled `drift(<code>): <one-line summary>` with the label `drift` for anything still broken that you cannot fix (an upstream mirror's source, a chain needing owner-authorized re-genesis, a credentialed pipe you couldn't run). Use the spec-section codes: `C1` frame envelope (§7), `C2` rappid grammar (§6.1), `C3` 32-hex short tail (§6.1), name-hash mint (§6.2), schema label (§12/Art. LIV), egg (§9).

Your report is what lets the top-down agent skip or target your repo on its next pass. The estate reaches its fixpoint when a full top-down pass and every repo's bottom-up pass all come back `SWEEP CLEAN` in the same round — until then, the loop continues, and an honest `SWEEP DIRTY` with a precise drift issue is worth more than an optimistic `CLEAN`.

---

## Appendix A — Formula card (everything on one screen)

```
Hb(space, b)        = sha256(space + "\x0a" + b).hexdigest()
H(space, v)         = Hb(space, canonical(v).encode())          # canonical = JCS, no floats
rappid              = "rappid:@" + owner + "/" + slug + ":" + tail
  tail (keyless)    = Hb("rapp/1:rappid", uuid4().bytes)         # 64 hex, mint-once, reuse on read
  tail (keyed)      = Hb("rapp/1:rappid", SPKI_DER)
  owner/slug        = [a-z0-9]+(-[a-z0-9]+)*
frame keys (11)     = spec kind stream_id seq utc payload payload_hash frame_hash prev prev_wave sig
  payload_hash      = H("rapp/1:particle", payload)
  frame_hash        = H("rapp/1:wave", frame \ {frame_hash, sig})
  prev              = previous frame's payload_hash  (PARTICLE — not frame_hash)
  prev_wave         = previous frame_hash, swarm-only (stream_id "net:*"), else null
  genesis           = seq 0, prev null, prev_wave null
  kind              = namespace.name (exactly one dot);  utc = YYYY-MM-DDTHH:MM:SS.mmmZ
egg manifest (7)    = schema("rapp/1-egg") variant rappid created_utc contents payload sig
  contents[].hash   = Hb("rapp/1:egg", file_octets), sorted by UTF-8 bytes of path
  egg address       = H("rapp/1:egg-manifest", manifest \ {sig})
  ZIP               = method stored(0) only; manifest.json first; timestamps 1980-01-01
schema of record    = "rapp/1"      (rapp-rappid/2.0, rapp-rappid/1.1: read-forever, never emit)
FORBIDDEN           = sha256(name) tails · uuid4().hex 32-hex tails · rappid:v2: · brainstem-egg/2.x
IMMUTABLE           = committed frames · frames/legacy seals · packed .eggs (re-pack only)
MIRRORS             = re-sync from upstream of record only (Art. LIII.6)
```

## Appendix B — One-shot sweep skeleton

```bash
set -e
git clone --depth 1 https://github.com/kody-w/rapp-1 /tmp/rapp-1
cd <your-repo-root>

# floor check
python3 /tmp/rapp-1/rapp_check.py . || echo "DRIFT — findings above"

# residue net (judge every hit by the §5 taxonomy before touching anything)
grep -rInE --include='*.py' --include='*.sh' --include='*.js' --include='*.html' \
  --include='*.json' --include='*.md' \
  'sha256\([^)]*(owner|slug|name)|uuid4\(\)\.hex|rappid:v2:|rapp-rappid/(1\.1|2\.0)|brainstem-egg/2\.' \
  . | grep -v '/\.git/' || echo "no residue strings"

# then: Step 4 live-pipe validation (repo-specific — write it against YOUR producers),
# Step 6 fix + re-run, Step 7 report.
```

The floor check and the net are the shallow pass. The live-pipe validation and the taxonomy judgment are the deep pass. Do both, iterate to green, report honestly. That is the standing guard.
