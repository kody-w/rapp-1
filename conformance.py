"""conformance.py — executable proof that RAPP (rev-5) is implementable and
self-consistent, plus a real-world check against a live estate artifact.

Run: python3 conformance.py
Exit 0 = all vectors pass.
"""
import json
import urllib.request
import hashlib
import os
import tempfile
import rapp as R
import rapp_check as RC

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
print("§7.7 — dimensional growth: one mint-once identity, many dimensions")
print("=" * 70)

ORG = R.mint_rappid("kody", "quill")
MEM = ORG + ":main"
BABY = {"name": "baby", "ordinal": 0}
FLEDGLING = {"name": "fledgling", "ordinal": 1}
RAPTOR = {"name": "raptor", "ordinal": 2}
DNA = b"MThd\x00\x00\x00\x06\x00\x00\x00\x01\x00\x60MTrk\x00\x00\x00\x04\x00\xff\x2f\x00"
SRC = [{"stream_id": MEM, "particle": "a" * 64}, {"stream_id": MEM, "particle": "b" * 64}]


def reframe(fr, payload):
    """Re-seal a mutated payload into a §7.1-valid frame, so any refusal below is
    attributable to the §7.7 profile and never to a broken envelope."""
    return R.build_frame(fr["kind"], fr["stream_id"], fr["seq"], fr["utc"], payload,
                         prev=fr["prev"], prev_wave=fr["prev_wave"], sig=fr["sig"])


def body_stream():
    b = [R.build_frame("body.pulse", ORG, 0, "2026-08-01T08:00:00.000Z", {"hatched": True}, prev=None)]
    b.append(R.build_dimension_frame(ORG, 1, "2026-08-01T09:00:00.000Z", "memory", 1, BABY,
                                     traits={"engram_count": 2}, sources=SRC,
                                     prev=b[-1]["payload_hash"]))
    b.append(R.build_dimension_frame(ORG, 2, "2026-08-01T09:30:00.000Z", "sonic", 1, FLEDGLING,
                                     traits={"root_note": 60, "tempo_bpm": 96},
                                     media={"midi-dna": R.media_ref(DNA, "audio/midi")},
                                     sources=SRC, prev=b[-1]["payload_hash"]))
    _, _, _, st = R.fold_body_stream(b, stream_id_of_record=ORG)
    b.append(R.build_growth_frame(ORG, 3, "2026-08-01T10:00:00.000Z", RAPTOR, st,
                                  prev=b[-1]["payload_hash"]))
    return b


BODY = body_stream()
ok, step, why, STATE = R.fold_body_stream(BODY, stream_id_of_record=ORG)
check("V10 a grown body-stream verifies and reconstructs", ok, f"{step}: {why}")
check("V10 the fold reaches the declared stage and both dimensions",
      ok and STATE["stage"] == RAPTOR and sorted(STATE["dimensions"]) == ["memory", "sonic"])
check("V10 every growth frame is still exactly the 11-key §7.1 envelope",
      all(set(f.keys()) == R.FRAME_KEYS for f in BODY))
check("V10 the profile adds only registry-shaped body-family kinds",
      all(set(e) == {"type", "kind", "family", "deprecated"} and e["type"] == "kind"
          and e["family"] == "body" for e in R.REGISTRY_KIND_ENTRIES))

# V11 identity through growth: the stage moved, the rappid did not.
ids = {f["stream_id"] for f in BODY} | {f["payload"]["rappid"] for f in BODY[1:]}
check("V11 one identity across every frame of the growth", ids == {ORG}, str(sorted(ids)))
check("V11 the stage changed while the identity did not",
      BODY[1]["payload"]["stage"] != BODY[3]["payload"]["stage"] and ORG == STATE["rappid"])
swapped = reframe(BODY[1], {**BODY[1]["payload"], "rappid": R.mint_rappid("kody", "other")})
ok, step, _ = R.verify_dimension_payload(swapped["payload"], ORG)
check("V11 an identity swap dressed as growth refused at §7.7.1", (not ok) and step == "§7.7.1")
regress = R.build_dimension_frame(ORG, 4, "2026-08-01T11:00:00.000Z", "device", 1, BABY,
                                  traits={}, prev=BODY[-1]["payload_hash"])
ok, step, _, _ = R.fold_body_stream(BODY + [regress], stream_id_of_record=ORG)
check("V11 a stage regression refused at §7.7.1", (not ok) and step == "§7.7.1")
rewind = R.build_dimension_frame(ORG, 4, "2026-08-01T11:00:00.000Z", "sonic", 1, RAPTOR,
                                 traits={}, prev=BODY[-1]["payload_hash"])
ok, step, _, _ = R.fold_body_stream(BODY + [rewind], stream_id_of_record=ORG)
check("V11 a non-advancing dimension version refused at §7.7.4", (not ok) and step == "§7.7.4")
onmem = R.build_dimension_frame(MEM, 0, "2026-08-01T09:00:00.000Z", "sonic", 1, BABY, traits={})
ok, step, _ = R.verify_dimension_payload(onmem["payload"], MEM)
check("V11 a dimension frame off the body-stream refused at §7.2", (not ok) and step == "§7.2")

# V12 media by reference only — the octets live in a §9 egg, at the same §5 address.
ref = R.media_ref(DNA, "audio/midi")
egg = R.pack_egg("organism", ORG, "2026-08-01T10:05:00.000Z",
                 files={"rappid.json": b"{}", "soul.md": b"# quill\n", "organs/dna.mid": DNA})
man, _ = R.read_egg(egg)
egg_hashes = {c["path"]: c["hash"] for c in man["contents"]}
check("V12 a media reference is the §9 egg address of the same octets",
      ref["hash"] == R.Hb("rapp/1:egg", DNA) == egg_hashes["organs/dna.mid"])
check("V12 the reference carries domain, hash, media type, and length only",
      set(ref) == {"space", "hash", "media_type", "bytes"} and ref["bytes"] == len(DNA))
sonic = BODY[2]["payload"]
big = b"\x00" * (1 << 20)                       # a mebibyte of media …
big_frame = R.build_dimension_frame(ORG, 2, "2026-08-01T09:30:00.000Z", "sonic", 1, FLEDGLING,
                                    traits=sonic["traits"],
                                    media={"midi-dna": R.media_ref(big, "audio/midi")},
                                    sources=SRC, prev=BODY[1]["payload_hash"])
grew = len(R.canonical(big_frame).encode("utf-8")) - len(R.canonical(BODY[2]).encode("utf-8"))
check("V12 frame size is independent of media size (§4's 1 MiB ceiling holds)",
      grew <= 8 and len(R.canonical(big_frame).encode("utf-8")) < (1 << 20),
      f"1 MiB of media grew the frame by {grew} bytes")
inline = reframe(BODY[2], {**sonic, "media": {"midi-dna": dict(ref, data_b64="TVRoZA==")}})
ok, step, _ = R.verify_dimension_payload(inline["payload"], ORG)
check("V12 media octets smuggled into the frame refused at §7.7.2", (not ok) and step == "§7.7.2")
foreign = reframe(BODY[2], {**sonic, "media": {"midi-dna": dict(ref, space="rapp/1:particle")}})
ok, step, _ = R.verify_dimension_payload(foreign["payload"], ORG)
check("V12 a media hash in a foreign address space refused at §7.7.2", (not ok) and step == "§7.7.2")
badmt = reframe(BODY[2], {**sonic, "media": {"midi-dna": dict(ref, media_type="Audio/MIDI")}})
ok, step, _ = R.verify_dimension_payload(badmt["payload"], ORG)
check("V12 a non-canonical media type refused at §7.7.2", (not ok) and step == "§7.7.2")

# V13 the trait snapshot and the fold are recomputed, never believed.
check("V13 traits_hash is the particle-space address of the traits",
      sonic["traits_hash"] == R.H("rapp/1:particle", sonic["traits"]))
lie = reframe(BODY[2], {**sonic, "traits": {"root_note": 61, "tempo_bpm": 96}})
ok, step, _ = R.verify_dimension_payload(lie["payload"], ORG)
check("V13 a traits/traits_hash mismatch refused at §7.7.3", (not ok) and step == "§7.7.3")
fold_lie = reframe(BODY[3], {**BODY[3]["payload"], "traits_hash": R.H("rapp/1:particle", {})})
ok, step, _, _ = R.fold_body_stream(BODY[:3] + [fold_lie], stream_id_of_record=ORG)
check("V13 an asserted fold that differs from the rebuilt one refused at §7.7.6",
      (not ok) and step == "§7.7.6")
unsorted_src = reframe(BODY[1], {**BODY[1]["payload"], "sources": list(reversed(SRC))})
ok, step, _ = R.verify_dimension_payload(unsorted_src["payload"], ORG)
check("V13 unordered source pointers refused at §7.7.4", (not ok) and step == "§7.7.4")

# V14 offspring: a fork mints a new rappid and points at its parent.
CHILD = R.mint_rappid("kody", "quill-two")
birth = R.build_growth_frame(CHILD, 0, "2026-08-02T07:00:00.000Z", BABY,
                             R.inherit(STATE, ["sonic"]),
                             parent={"rappid": ORG, "particle": STATE["particle"]}, prev=None)
ok, step, why, CHILD_STATE = R.fold_body_stream([birth], stream_id_of_record=CHILD, inherited=STATE)
check("V14 offspring verifies against the resolved parent fold", ok, f"{step}: {why}")
check("V14 offspring is a new identity carrying a parent pointer",
      ok and CHILD != ORG and birth["payload"]["parent"]["rappid"] == ORG
      and sorted(CHILD_STATE["dimensions"]) == ["sonic"])
ok, step, _, _ = R.fold_body_stream([birth], stream_id_of_record=CHILD)
check("V14 an unresolved parent fails closed at §7.7.5", (not ok) and step == "§7.7.5")
with tempfile.TemporaryDirectory() as unresolved_repo:
    frame_dir = os.path.join(unresolved_repo, "organism", "frames")
    os.makedirs(frame_dir)
    with open(os.path.join(frame_dir, "0.json"), "w", encoding="utf-8") as handle:
        json.dump(birth, handle)
    verdict, findings, _ = RC.check_repo(unresolved_repo)
check("V14 the repo gate reports unresolved lineage UNVERIFIED, never COMPLIANT",
      verdict == "UNVERIFIED" and findings[0].get("status") == "unverified")
selfp = reframe(birth, {**birth["payload"], "parent": {"rappid": CHILD,
                                                       "particle": STATE["particle"]}})
ok, step, _ = R.verify_growth_payload(selfp["payload"], CHILD)
check("V14 an organism claiming itself as parent refused at §7.7.1", (not ok) and step == "§7.7.1")
midlife = reframe(BODY[3], {**BODY[3]["payload"],
                            "parent": {"rappid": CHILD, "particle": STATE["particle"]}})
ok, step, _, _ = R.fold_body_stream(BODY[:3] + [midlife], stream_id_of_record=ORG, inherited=STATE)
check("V14 ancestry acquired mid-life refused at §7.7.5", (not ok) and step == "§7.7.5")
fabricated = reframe(birth, {**birth["payload"],
                             "dimensions": {"skill": {"version": 9, "particle": "c" * 64}}})
ok, step, _, _ = R.fold_body_stream([fabricated], stream_id_of_record=CHILD, inherited=STATE)
check("V14 an inheritance the parent never had refused at §7.7.5", (not ok) and step == "§7.7.5")

print()
print("=" * 70)
print("§7.8 — weight: a RAPPID's data size, in verified bytes")
print("=" * 70)

LEDGER = R.weigh(BODY)
DNA_REF = R.media_ref(DNA, "audio/midi")
STORE = {(R.MEDIA_SPACE, DNA_REF["hash"]): DNA}

# V15 the ledger itself: exact integers, canonical, and internally consistent.
check("V15 weight is exact integers only — no float ever reaches a payload",
      all(isinstance(LEDGER[k], int) and not isinstance(LEDGER[k], bool)
          for k in ("frame_weight_bytes", "asset_weight_bytes", "total_weight_bytes",
                    "resident_weight_bytes", "linked_weight_bytes")))
check("V15 the attested weight canonicalizes (it is a §4 value)",
      R.canonical(R.attested_weight(LEDGER)) ==
      R.canonical(dict(sorted(R.attested_weight(LEDGER).items()))))
check("V15 total = frames + assets",
      LEDGER["total_weight_bytes"] == LEDGER["frame_weight_bytes"] + LEDGER["asset_weight_bytes"])
check("V15 resident + linked = total",
      LEDGER["resident_weight_bytes"] + LEDGER["linked_weight_bytes"] == LEDGER["total_weight_bytes"])
check("V15 a frame weighs its canonical bytes",
      LEDGER["frame_weight_bytes"] == sum(len(R.canonical(f).encode("utf-8")) for f in BODY))
check("V15 an asset weighs its attested octet count",
      LEDGER["asset_weight_bytes"] == len(DNA))
check("V15 the fold's running weight equals a standalone weigh() of the same frames",
      STATE["weight"] == R.attested_weight(LEDGER))

# V16 de-duplication by content address: nothing is ever weighed twice.
check("V16 the same frames presented twice weigh once",
      R.weigh(BODY + BODY)["total_weight_bytes"] == LEDGER["total_weight_bytes"])
again = R.build_dimension_frame(ORG, 4, "2026-08-01T11:00:00.000Z", "visual", 1, RAPTOR,
                                traits={}, media={"midi-dna": DNA_REF},
                                prev=BODY[-1]["payload_hash"])
check("V16 one asset referenced by two dimensions weighs once",
      R.weigh(BODY + [again])["asset_weight_bytes"] == LEDGER["asset_weight_bytes"])
check("V16 …while the new frame's own bytes do count",
      R.weigh(BODY + [again])["frame_weight_bytes"] ==
      LEDGER["frame_weight_bytes"] + R.frame_weight(again))

# V17 residency is the reader's view; the attested weight is the organism's.
bare, held = R.weigh(BODY), R.weigh(BODY, store=STORE)
check("V17 with nothing hydrated, every asset is linked",
      bare["linked_weight_bytes"] == bare["asset_weight_bytes"] and
      bare["resident_weight_bytes"] == bare["frame_weight_bytes"])
check("V17 with the octets hydrated, the asset becomes resident",
      held["resident_weight_bytes"] == held["total_weight_bytes"] and
      held["linked_weight_bytes"] == 0)
check("V17 the attested weight is habitat-independent",
      R.attested_weight(bare) == R.attested_weight(held))

# V18 missing or unverifiable sizes are SURFACED, never estimated.
corrupt = {(R.MEDIA_SPACE, DNA_REF["hash"]): b"\x00" * len(DNA)}
cl = R.weigh(BODY, store=corrupt)
check("V18 a local copy that fails §5 is not counted as resident",
      (not cl["verified"]) and cl["resident_weight_bytes"] == cl["frame_weight_bytes"]
      and cl["unverified"][0]["reason"] == "store-mismatch")
check("V18 …its attested bytes stay linked, and the attested weight does not move",
      cl["linked_weight_bytes"] == cl["asset_weight_bytes"] and
      R.attested_weight(cl) == R.attested_weight(bare))
clash = R.build_dimension_frame(ORG, 4, "2026-08-01T11:00:00.000Z", "visual", 1, RAPTOR,
                                traits={}, media={"midi-dna": dict(DNA_REF, bytes=999999)},
                                prev=BODY[-1]["payload_hash"])
cf = R.weigh(BODY + [clash])
check("V18 two sizes for one address makes that size unknown, not averaged",
      (not cf["complete"]) and cf["incomplete"][0]["reason"] == "size-conflict"
      and cf["asset_weight_bytes"] == 0)
check("V18 an incomplete ledger says so in the frame's attestation too",
      R.attested_weight(cf)["complete"] is False)

# V19 weight rides the growth frame, is recomputed, and never touches identity.
ok, step, why, st3 = R.fold_body_stream(BODY[:3], stream_id_of_record=ORG)
check("V19 the growth frame attests the weight of everything before it",
      ok and BODY[3]["payload"]["weight"] == st3["weight"], f"{step}: {why}")
heavier = reframe(BODY[3], {**BODY[3]["payload"],
                            "weight": dict(BODY[3]["payload"]["weight"],
                                           asset_weight_bytes=10 ** 9,
                                           total_weight_bytes=10 ** 9 +
                                           BODY[3]["payload"]["weight"]["frame_weight_bytes"])})
ok, step, _, _ = R.fold_body_stream(BODY[:3] + [heavier], stream_id_of_record=ORG)
check("V19 an organism claiming more weight than its bytes refused at §7.8",
      (not ok) and step == "§7.8")
lopsided = reframe(BODY[3], {**BODY[3]["payload"],
                             "weight": dict(BODY[3]["payload"]["weight"], total_weight_bytes=1)})
ok, step, _ = R.verify_growth_payload(lopsided["payload"], ORG)
check("V19 a ledger whose total != frames + assets refused at §7.8", (not ok) and step == "§7.8")
weights = [f["payload"]["weight"]["total_weight_bytes"] for f in BODY
           if f["kind"] == R.BODY_RECONSTRUCTED]
growth2 = R.build_growth_frame(ORG, 4, "2026-08-01T12:00:00.000Z", RAPTOR, STATE,
                               prev=BODY[-1]["payload_hash"])
ok, step, why, _ = R.fold_body_stream(BODY + [growth2], stream_id_of_record=ORG)
check("V19 weight only grows as the chain appends", ok and
      growth2["payload"]["weight"]["total_weight_bytes"] > weights[-1], f"{step}: {why}")
check("V19 gaining weight changed no identity",
      growth2["stream_id"] == BODY[0]["stream_id"] == ORG
      and growth2["payload"]["rappid"] == ORG)
check("V19 an offspring is born owning its inherited assets and no frames of its own",
      birth["payload"]["weight"]["frame_weight_bytes"] == 0
      and birth["payload"]["weight"]["asset_weight_bytes"] == len(DNA))
child_ledger = R.weigh([birth], inherited=STATE)
child_card = R.stat_block(CHILD_STATE, ledger=child_ledger)
check("V19 an offspring habitat ledger includes inherited assets",
      child_ledger["asset_weight_bytes"] == len(DNA)
      and child_ledger["total_weight_bytes"] == CHILD_STATE["weight"]["total_weight_bytes"]
      and child_card["resident_weight_bytes"] + child_card["linked_weight_bytes"]
      == child_card["total_weight_bytes"])
try:
    R.weigh([birth])
    unresolved_weigh_refused = False
except ValueError:
    unresolved_weigh_refused = True
check("V19 weighing unresolved offspring assets fails closed instead of dropping them",
      unresolved_weigh_refused)

mass = b"x" * 4096
mass_ref = R.media_ref(mass, "application/octet-stream")
mass_org = R.mint_rappid("kody", "weight-floor")
mass_dimension = R.build_dimension_frame(
    mass_org, 0, "2026-08-03T00:00:00.000Z", "memory", 1, BABY,
    traits={}, media={"engram": mass_ref})
ok, step, why, mass_state = R.fold_body_stream([mass_dimension], stream_id_of_record=mass_org)
mass_growth = R.build_growth_frame(
    mass_org, 1, "2026-08-03T00:01:00.000Z", BABY, mass_state,
    prev=mass_dimension["payload_hash"])
ok, step, why, mass_state = R.fold_body_stream(
    [mass_dimension, mass_growth], stream_id_of_record=mass_org)
mass_conflict = R.build_dimension_frame(
    mass_org, 2, "2026-08-03T00:02:00.000Z", "visual", 1, BABY,
    traits={}, media={"same-address-wrong-size": dict(mass_ref, bytes=1)},
    prev=mass_growth["payload_hash"])
ok, step, why, conflicted_state = R.fold_body_stream(
    [mass_dimension, mass_growth, mass_conflict], stream_id_of_record=mass_org)
try:
    R.build_growth_frame(
        mass_org, 3, "2026-08-03T00:03:00.000Z", BABY, conflicted_state,
        prev=mass_conflict["payload_hash"])
    shrinking_producer_refused = False
except ValueError:
    shrinking_producer_refused = True
shrink_payload = {
    "rappid": mass_org,
    "species": conflicted_state["species"],
    "stage": dict(conflicted_state["stage"]),
    "dimensions": {name: dict(value)
                   for name, value in conflicted_state["dimensions"].items()},
    "traits_hash": conflicted_state["traits_hash"],
    "weight": dict(conflicted_state["weight"]),
    "sources": [],
    "parent": None,
}
shrinking_growth = R.build_frame(
    R.BODY_RECONSTRUCTED, mass_org, 3, "2026-08-03T00:03:00.000Z",
    shrink_payload, prev=mass_conflict["payload_hash"])
ok, step, _, _ = R.fold_body_stream(
    [mass_dimension, mass_growth, mass_conflict, shrinking_growth],
    stream_id_of_record=mass_org)
check("V19 a producer refuses to construct a decreasing weight attestation",
      shrinking_producer_refused)
check("V19 a consumer refuses a recomputed but decreasing weight at §7.8.5",
      (not ok) and step == "§7.8.5")
adult = R.build_dimension_frame(ORG, 1, "2026-08-01T09:00:00.000Z", "memory", 1,
                                {"name": "adult", "ordinal": 1}, traits={"engram_count": 2},
                                sources=SRC, prev=BODY[0]["payload_hash"])
elder = R.build_dimension_frame(ORG, 1, "2026-08-01T09:00:00.000Z", "memory", 1,
                                {"name": "elder", "ordinal": 2}, traits={"engram_count": 2},
                                sources=SRC, prev=BODY[0]["payload_hash"])
check("V19 equal weight, different stage — bytes are mass, never maturity",
      R.frame_weight(adult) == R.frame_weight(elder)
      and adult["payload"]["stage"] != elder["payload"]["stage"])

# V20 readable weight is presentation over the exact integer, never the weight itself.
check("V20 format_weight renders bytes for humans",
      (R.format_weight(0), R.format_weight(999), R.format_weight(2444),
       R.format_weight(1 << 20)) == ("0 B", "999 B", "2.4 KiB", "1.0 MiB"))
check("V20 the payload keeps the exact integer, never the rendered string",
      all(isinstance(v, int) and not isinstance(v, bool)
          for k, v in BODY[3]["payload"]["weight"].items() if k != "complete"))

print()
print("=" * 70)
print("§7.9 — the creature card: exact stats, presentation height, and proposals")
print("=" * 70)

SPECIES = "quill-strider"
CURVE = {"curve": "quill-atlas/1",
         "species": {SPECIES: {"base_mm": 70, "cap_mm": 260,
                               "points": [[0, 0], [4, 40], [16, 120], [64, 220]]}}}
CARD_BODY = BODY + [R.build_growth_frame(ORG, 4, "2026-08-01T12:00:00.000Z", RAPTOR, STATE,
                                         species=SPECIES, prev=BODY[-1]["payload_hash"])]
ok, step, why, CARD_STATE = R.fold_body_stream(CARD_BODY, stream_id_of_record=ORG)
CARD = R.stat_block(CARD_STATE, curve=CURVE)

# V21 frame height is exact, verified chain depth — and cannot be padded.
check("V21 a species may be declared and the stream folds", ok, f"{step}: {why}")
check("V21 frame_height == accepted frames == head seq + 1",
      CARD["frame_height"] == len(CARD_BODY) == CARD_BODY[-1]["seq"] + 1)
ok, step, _, _ = R.fold_body_stream(CARD_BODY + [CARD_BODY[-1]], stream_id_of_record=ORG)
check("V21 re-presenting a frame cannot inflate the height (refused at step 4)",
      (not ok) and step == "4")
dup = R.weigh(CARD_BODY + CARD_BODY)
check("V21 …nor can it inflate the weight",
      dup["total_weight_bytes"] == CARD["total_weight_bytes"])
twice = R.build_dimension_frame(ORG, 5, "2026-08-01T13:00:00.000Z", "device", 1, RAPTOR,
                                traits={}, media={"midi-dna": DNA_REF, "spare": DNA_REF},
                                prev=CARD_BODY[-1]["payload_hash"])
ok, _, _, twice_state = R.fold_body_stream(CARD_BODY + [twice], stream_id_of_record=ORG)
check("V21 one asset under two roles weighs once",
      ok and twice_state["weight"]["asset_weight_bytes"] == CARD["total_weight_bytes"] -
      CARD_STATE["weight"]["frame_weight_bytes"])

# V22 the card: every stat is derived from verified state.
check("V22 the stat block has exactly the §7.9.3 members", set(CARD.keys()) == R.STAT_KEYS)
check("V22 stats mirror the fold, not a claim",
      CARD["rappid"] == ORG and CARD["species"] == SPECIES
      and CARD["lifecycle_stage"] == RAPTOR
      and CARD["dimension_count"] == len(CARD_STATE["dimensions"])
      and CARD["capabilities"] == sorted(CARD_STATE["dimensions"])
      and CARD["traits_hash"] == CARD_STATE["traits_hash"])
check("V22 weight on the card is the exact ledger",
      CARD["total_weight_bytes"] == CARD_STATE["weight"]["total_weight_bytes"]
      and CARD["resident_weight_bytes"] + CARD["linked_weight_bytes"] == CARD["total_weight_bytes"])
check("V22 the card canonicalizes — it is a §4 value of exact integers",
      isinstance(R.canonical(CARD), str) and CARD["frame_height"] == 5)
check("V22 completeness is stated, never assumed",
      CARD["complete"] is True and set(CARD["completeness"]) ==
      {"weight_sizes_established", "local_copies_verified", "display_height_resolved"})
bare_card = R.stat_block(CARD_STATE)                      # the default curve knows no such species
check("V22 an unrenderable height is null and the card says it is incomplete",
      bare_card["display_height_mm"] is None and bare_card["height_curve"] is None
      and bare_card["complete"] is False
      and bare_card["completeness"]["display_height_resolved"] is False)
check("V22 …and the exact stats are unaffected by presentation",
      bare_card["frame_height"] == CARD["frame_height"]
      and bare_card["total_weight_bytes"] == CARD["total_weight_bytes"])

# V23 display height is a deterministic, versioned, presentational rendering.
check("V23 the same species, curve, and height render the same millimetres",
      R.display_height_mm(SPECIES, 5, CURVE) == R.display_height_mm(SPECIES, 5, CURVE)
      == CARD["display_height_mm"])
check("V23 the curve is versioned, and the card names the version it used",
      CARD["height_curve"] == CURVE["curve"] != R.HEIGHT_CURVE_V1["curve"])
other = {"curve": "quill-atlas/2",
         "species": {SPECIES: dict(CURVE["species"][SPECIES], base_mm=140)}}
check("V23 a different curve version renders differently and changes nothing else",
      R.stat_block(CARD_STATE, curve=other)["display_height_mm"] !=
      CARD["display_height_mm"] and
      R.stat_block(CARD_STATE, curve=other)["frame_height"] == CARD["frame_height"])
check("V23 display height is millimetres of exact integer, never a float",
      isinstance(CARD["display_height_mm"], int) and not isinstance(CARD["display_height_mm"], bool))
check("V23 it rises with the chain, never falls, and saturates at the species cap",
      R.display_height_mm(SPECIES, 0, CURVE) <= R.display_height_mm(SPECIES, 16, CURVE)
      <= R.display_height_mm(SPECIES, 64, CURVE) == R.display_height_mm(SPECIES, 10 ** 6, CURVE)
      == CURVE["species"][SPECIES]["cap_mm"])
check("V23 no display height appears in any frame (presentation never rides the chain)",
      all("display_height_mm" not in json.dumps(f["payload"]) for f in CARD_BODY))
respecies = reframe(CARD_BODY[4], {**CARD_BODY[4]["payload"], "species": "other-strider"})
ok, step, _, _ = R.fold_body_stream(BODY + [respecies], stream_id_of_record=ORG)
check("V23 declaring a species on a stream that had none is lawful", ok)
ok, step, _, _ = R.fold_body_stream(CARD_BODY + [
    R.build_growth_frame(ORG, 5, "2026-08-01T14:00:00.000Z", RAPTOR, CARD_STATE,
                         species="other-strider", prev=CARD_BODY[-1]["payload_hash"])],
    stream_id_of_record=ORG)
check("V23 …but changing a declared species refused at §7.9.2", (not ok) and step == "§7.9.2")
ok, step, _, _ = R.fold_body_stream(CARD_BODY + [
    R.build_growth_frame(ORG, 5, "2026-08-01T14:00:00.000Z", RAPTOR, CARD_STATE,
                         species=None, prev=CARD_BODY[-1]["payload_hash"])],
    stream_id_of_record=ORG)
check("V23 a null species after declaration is refused at §7.9.2",
      (not ok) and step == "§7.9.2")

# V24 a proposal reads; it never writes, and it never invents bytes.
SNAPSHOT = R.canonical(CARD_STATE)
PROP = R.propose_next(CARD_STATE, lineage=R.inherit(STATE), curve=CURVE)
check("V24 a proposal has exactly the §7.9.4 members and says it is not authoritative",
      set(PROP.keys()) == R.PROPOSAL_KEYS and PROP["proposal"] is True
      and PROP["authoritative"] is False)
check("V24 predicting mutated no canonical state", R.canonical(CARD_STATE) == SNAPSHOT)
check("V24 the proposal is anchored to the head it was computed from",
      PROP["basis"]["particle"] == CARD_STATE["particle"]
      and PROP["basis"]["frame_height"] == CARD["frame_height"])
check("V24 a proposal invents no bytes — a frame that does not exist has no weight",
      PROP["projected"]["total_weight_bytes"] is None
      and PROP["projected"]["weight_known"] is False)
ok, step, _ = R.verify_dimension_payload(PROP, ORG)
check("V24 a proposal is not a conformant payload", (not ok) and step == "§7.7.4")
ok, step, _, still = R.fold_body_stream(CARD_BODY, stream_id_of_record=ORG)
check("V24 the chain is untouched by the proposal",
      ok and R.stat_block(still, curve=CURVE) == CARD)
realized = R.build_dimension_frame(ORG, 5, "2026-08-01T13:00:00.000Z",
                                   PROP["next_dimension"]["dimension"],
                                   PROP["next_dimension"]["version"], RAPTOR, traits={},
                                   prev=CARD_BODY[-1]["payload_hash"])
ok, step, why, grown = R.fold_body_stream(CARD_BODY + [realized], stream_id_of_record=ORG)
GROWN = R.stat_block(grown, curve=CURVE)
check("V24 a proposal becomes authoritative only once appended and verified", ok, f"{step}: {why}")
check("V24 the realized frame matches what was projected",
      GROWN["frame_height"] == PROP["projected"]["frame_height"]
      and GROWN["capabilities"] == PROP["projected"]["capabilities"]
      and GROWN["display_height_mm"] == PROP["projected"]["display_height_mm"])
check("V24 …and only now is there a weight, measured rather than predicted",
      GROWN["total_weight_bytes"] == CARD["total_weight_bytes"] + R.frame_weight(realized))
check("V24 growing the card changed no identity",
      GROWN["rappid"] == CARD["rappid"] == ORG and GROWN["species"] == CARD["species"])

print()
print("=" * 70)
print("REAL-WORLD CHECK — RAPP vs a live estate artifact (kody-w/twin/frames/0.json)")
print("=" * 70)
try:
    raw = urllib.request.urlopen(
        "https://raw.githubusercontent.com/kody-w/twin/main/frames/0.json", timeout=20).read()
    real = json.loads(raw)
    payload = real["payload"]
    exact_envelope = set(real) == R.FRAME_KEYS and real.get("spec") == R.SPEC
    if exact_envelope:
        tagged = R.H("rapp/1:particle", payload)
        check("R1 live frame's particle is reproduced byte-for-byte",
              tagged == real["payload_hash"],
              f"computed {tagged[:16]} vs stored {str(real.get('payload_hash'))[:16]}")
        ok, step, why = R.verify_frame(
            real, stream_id_of_record=real.get("stream_id"))
        check("R2 live RAPP/1 frame passes the complete consumer checklist",
              ok, "" if ok else f"refused at step {step}: {why}")
        print(f"       current artifact: conformant {R.SPEC} frame · {real.get('kind')}")
    else:
        # Historical estates legitimately exercise the refusal path. The
        # remote artifact has since migrated to RAPP/1, so the conformance
        # check must classify what it fetched rather than assert that the live
        # estate remains frozen in its old drift forever.
        stored = real.get("sha256")
        untagged = hashlib.sha256(R.canonical(payload).encode()).hexdigest()
        check("R1 legacy frame's historical untagged payload address is reproduced",
              stored is not None and untagged == stored,
              f"computed {untagged[:16]} vs stored {str(stored)[:16]}")
        ok, step, why = R.verify_frame(real)
        check("R2 legacy frame is refused as non-conformant drift", not ok, "")
        print(f"       legacy artifact refused at step {step}: {why}")
        print(f"       real frame keys: {sorted(real.keys())}")
except Exception as ex:
    check("R1 real-world fetch", False, f"network: {ex}")

print()
n = len(results); ok = sum(results)
print("-" * 70)
print(f"{n} checks | {ok} PASS | {n - ok} FAIL")
import sys
sys.exit(0 if ok == n else 1)
