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

*Ledger continues per repo as each one's pipes are exercised.*
