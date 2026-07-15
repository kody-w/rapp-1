"""conformance.py — executable proof that RAPP (rev-5) is implementable and
self-consistent, plus a real-world check against a live estate artifact.

Run: python3 conformance.py
Exit 0 = all vectors pass.
"""
import json
import urllib.request
import hashlib
import rapp as R

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  — {detail}" if detail and not ok else ""))

print("=" * 70)
print("RAPP rev-5 — conformance vectors")
print("=" * 70)

# V1 canonicalization determinism (key order independence)
a = R.canonical({"b": 1, "a": [3, 2], "c": {"y": 1, "x": 2}})
b = R.canonical({"c": {"x": 2, "y": 1}, "a": [3, 2], "b": 1})
check("V1 canonicalization is key-order independent", a == b, f"{a} vs {b}")
check("V1b array order IS significant", R.canonical([1, 2]) != R.canonical([2, 1]))

# V2 domain separation (§5): same bytes, different space → different address
val = {"x": 1}
p, w, e = R.H("rapp/1:particle", val), R.H("rapp/1:wave", val), R.H("rapp/1:egg-manifest", val)
check("V2 domain tags separate the address space", len({p, w, e}) == 3, f"{p[:8]} {w[:8]} {e[:8]}")

# V3 identity mint (§6.2): NEVER a name-hash
name_hash = hashlib.sha256(b"kody/twin").hexdigest()
rid = R.mint_rappid("kody", "twin")
tail = rid.rsplit(":", 1)[1]
check("V3 keyless mint is not sha256(owner/slug)", tail != name_hash)
check("V3 rappid matches the §6.1 grammar", R.rappid_valid(rid), rid)
spki = b"\x30\x2a fake-spki-der-bytes-for-the-vector\x00"
rid_k = R.mint_rappid("kody", "twin", spki_der=spki)
check("V3 keyed tail == Hb('rapp/1:rappid', SPKI)", rid_k.rsplit(":", 1)[1] == R.Hb("rapp/1:rappid", spki))
check("V3 mint-once determinism for keyed identity", R.mint_rappid("kody", "twin", spki) == rid_k)

# V4 frame round-trip: build → verify
sid = "rappid:@kody/twin:" + "a" * 64
g = R.build_frame("body.pulse", sid, 0, "2026-07-15T00:00:00.000Z", {"hello": "world"}, prev=None)
ok, step, why = R.verify_frame(g, head=None, stream_id_of_record=sid)
check("V4 genesis frame builds and verifies", ok, f"step {step}: {why}")
check("V4 genesis has exactly 11 keys", set(g.keys()) == R.FRAME_KEYS)

# V5 tamper detection
t = dict(g); t["payload"] = {"hello": "evil"}
ok, step, _ = R.verify_frame(t, head=None, stream_id_of_record=sid)
check("V5 payload tamper caught at step 2", (not ok) and step == "2")
t2 = dict(g); t2["utc"] = "2099-01-01T00:00:00.000Z"
ok, step, _ = R.verify_frame(t2, head=None, stream_id_of_record=sid)
check("V5 envelope tamper caught at step 3 (wave)", (not ok) and step == "3")

# V6 chain linkage
child = R.build_frame("body.pulse", sid, 1, "2026-07-15T00:00:01.000Z", {"n": 2}, prev=g["payload_hash"])
ok, step, why = R.verify_frame(child, head=g, stream_id_of_record=sid)
check("V6 child frame links to genesis", ok, f"step {step}: {why}")
bad = R.build_frame("body.pulse", sid, 1, "2026-07-15T00:00:01.000Z", {"n": 2}, prev="f" * 64)
ok, step, _ = R.verify_frame(bad, head=g, stream_id_of_record=sid)
check("V6 broken prev caught at step 4", (not ok) and step == "4")

# V7 cross-stream replay (§7.5 step 1a) — genesis of stream A replayed as stream B
ok, step, _ = R.verify_frame(g, head=None, stream_id_of_record="rappid:@kody/other:" + "b" * 64)
check("V7 cross-stream genesis replay refused at 1a", (not ok) and step == "1a")

# V8 absent-vs-null: a frame missing a key is refused (not 11 keys)
short = {k: v for k, v in g.items() if k != "prev_wave"}
ok, step, _ = R.verify_frame(short, head=None, stream_id_of_record=sid)
check("V8 missing key refused at step 1 (no absent-vs-null)", (not ok) and step == "1")

# V9 swarm frame must be signed
sw = R.build_frame("swarm.echo", "net:commons", 0, "2026-07-15T00:00:00.000Z", {"x": 1}, prev=None, prev_wave=None)
ok, step, _ = R.verify_frame(sw, head=None, stream_id_of_record="net:commons")
check("V9 unsigned swarm frame refused at step 6", (not ok) and step == "6")

print()
print("=" * 70)
print("REAL-WORLD CHECK — RAPP vs a live estate artifact (kody-w/twin/frames/0.json)")
print("=" * 70)
try:
    raw = urllib.request.urlopen(
        "https://raw.githubusercontent.com/kody-w/twin/main/frames/0.json", timeout=20).read()
    real = json.loads(raw)
    payload = real["payload"]
    stored = real.get("sha256")
    # (a) does RAPP's canonicalize + UNTAGGED payload hash reproduce twin's stored value?
    untagged = hashlib.sha256(R.canonical(payload).encode()).hexdigest()
    check("R1 RAPP canonicalization reproduces twin's real stored sha256",
          untagged == stored, f"computed {untagged[:16]} vs stored {str(stored)[:16]}")
    # (b) RAPP's domain-tagged particle deliberately differs (the hardening)
    tagged = R.H("rapp/1:particle", payload)
    print(f"       (RAPP domain-tagged particle = {tagged[:16]}… — deliberately != untagged; §5 fix)")
    # (c) RAPP correctly identifies the legacy frame as non-conformant drift
    ok, step, why = R.verify_frame(real)
    check("R2 RAPP flags the legacy twin frame as non-conformant (the drift it fixes)",
          not ok, "")
    print(f"       → refused at step {step}: {why}")
    print(f"       real frame keys: {sorted(real.keys())}")
    print(f"       twin_id: {real.get('twin_id')}  (32-hex name-hash — the C3/ID-01 drift)")
except Exception as ex:
    check("R1 real-world fetch", False, f"network: {ex}")

print()
n = len(results); ok = sum(results)
print("-" * 70)
print(f"{n} checks | {ok} PASS | {n - ok} FAIL")
import sys
sys.exit(0 if ok == n else 1)
