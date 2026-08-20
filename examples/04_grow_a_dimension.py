"""04 — Growth and weight. One organism, one rappid, many dimensions.

A RAPPID hatches small and grows by APPENDING dimension frames to its body-stream:
memory, skill, sonic, device, visual, capability. Growing does not re-mint anything.
The lifecycle stage it reaches is *state* it carries in a payload; the rappid minted
at hatch is the same rappid at every later stage (§6.2 mint-once, §7.7.1).

What it accumulates is its WEIGHT (§7.8): verified bytes, de-duplicated by content
address, split into the frames it has appended and the assets they reference, and split
again into what this habitat actually holds (resident) and what it merely knows the
address of (linked). Sizes that cannot be established or confirmed are surfaced, never
estimated.

All of it deals out as a creature card (§7.9): exact stats — frame height, weight,
dimensions, traits — beside a clearly-labelled presentation height rendered by a versioned
species growth curve. The card can even autocomplete its own next move, as a proposal that
is worth nothing until a real frame is appended and verified.

This program grows a sonic dimension — MIDI DNA and a wake-call — out of real engram
frames, folds it into a growth event, packs the media into a §9 egg, and then hatches
true offspring: a NEW rappid with a parent pointer, which is what a fork is.

Run: python3 examples/04_grow_a_dimension.py
"""
import sys, os, io, json, math, wave
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R

SPECIES = "quill-strider"
# A versioned species growth curve. Presentation data — it lives with the bestiary, not
# with the protocol — and it is evaluated in exact integers so every renderer agrees.
QUILL_ATLAS = {"curve": "quill-atlas/1",
               "species": {SPECIES: {"base_mm": 70, "cap_mm": 260,
                                     "points": [[0, 0], [4, 40], [16, 120], [64, 220]]}}}


def midi_dna():
    """A real Type-0 MIDI file: the organism's sonic DNA, four bytes of it audible."""
    track = bytes([0x00, 0x90, 0x3C, 0x64,      # note on  C4
                   0x60, 0x80, 0x3C, 0x40,      # note off C4
                   0x00, 0xFF, 0x2F, 0x00])     # end of track
    return (b"MThd" + (6).to_bytes(4, "big") + (0).to_bytes(2, "big")
            + (1).to_bytes(2, "big") + (96).to_bytes(2, "big")
            + b"MTrk" + len(track).to_bytes(4, "big") + track)


def wake_call():
    """A real WAV: 0.3 s of 440 Hz — the sound the organism answers to."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1); w.setsampwidth(1); w.setframerate(8000)
        w.writeframes(bytes((128 + int(96 * math.sin(2 * math.pi * 440 * t / 8000))) & 0xFF
                            for t in range(2400)))
    return buf.getvalue()


# ── 1. The mint. Exactly once, at hatch, and never again. ────────────────────────────
rid = R.mint_rappid("kody", "quill")
print("hatched rappid (minted once):", rid)

# ── 2. Engrams: the memory-stream this organism actually lived. ───────────────────────
mem_stream = rid + ":main"
engrams, head = [], None
for seq, (utc, p) in enumerate([("2026-08-01T09:00:00.000Z", {"heard": "a door closing"}),
                                ("2026-08-01T09:04:00.000Z", {"hummed": "three notes"})]):
    fr = R.build_frame("memory.save", mem_stream, seq, utc, p,
                       prev=head["payload_hash"] if head else None)
    engrams.append(fr); head = fr
print(f"engrams recorded on the memory-stream: {len(engrams)}")

# ── 3. The body-stream. Genesis is a breath, not a dimension. ─────────────────────────
body, head = [], None


def append(frame):
    ok, step, why = R.verify_frame(frame, head=body[-1] if body else None, stream_id_of_record=rid)
    assert ok, f"seq {frame['seq']} refused at {step}: {why}"
    body.append(frame)
    return frame


append(R.build_frame("body.pulse", rid, 0, "2026-08-01T08:00:00.000Z", {"hatched": True}, prev=None))

# ── 4. Grow the memory dimension (stage: baby). ──────────────────────────────────────
BABY, FLEDGLING, RAPTOR = ({"name": "baby", "ordinal": 0},
                           {"name": "fledgling", "ordinal": 1},
                           {"name": "raptor", "ordinal": 2})
sources = R.source_list([{"stream_id": mem_stream, "particle": e["payload_hash"]} for e in engrams])
append(R.build_dimension_frame(
    rid, 1, "2026-08-01T09:10:00.000Z", "memory", 1, BABY,
    traits={"engram_count": len(engrams), "recall_horizon_days": 30},
    sources=sources, prev=body[-1]["payload_hash"]))

# ── 5. Grow the sonic dimension (stage: fledgling) — media stays OUTSIDE the frame. ───
dna, call = midi_dna(), wake_call()
media = {"midi-dna": R.media_ref(dna, "audio/midi"),
         "wake-call": R.media_ref(call, "audio/wav")}
append(R.build_dimension_frame(
    rid, 2, "2026-08-01T09:30:00.000Z", "sonic", 1, FLEDGLING,
    traits={"root_note": 60, "tempo_bpm": 96, "scale": "dorian", "timbre": "glass"},
    media=media, sources=sources, prev=body[-1]["payload_hash"]))
print(f"\nsonic media held by reference: wake-call is {len(call)} bytes, "
      f"its frame is {len(R.canonical(body[-1]))} bytes")
print("  midi-dna  :", media["midi-dna"]["space"], media["midi-dna"]["hash"][:16], "…",
      media["midi-dna"]["media_type"], f'{media["midi-dna"]["bytes"]}B')
print("  wake-call :", media["wake-call"]["space"], media["wake-call"]["hash"][:16], "…",
      media["wake-call"]["media_type"], f'{media["wake-call"]["bytes"]}B')

# ── 6. The growth event: fold the dimensions, declare the stage reached. ─────────────
ok, step, why, state = R.fold_body_stream(body, stream_id_of_record=rid)
assert ok, f"fold refused at {step}: {why}"
append(R.build_growth_frame(rid, 3, "2026-08-01T10:00:00.000Z", RAPTOR, state,
                            species=SPECIES, sources=sources, prev=body[-1]["payload_hash"]))

ok, step, why, state = R.fold_body_stream(body, stream_id_of_record=rid)
assert ok, f"fold refused at {step}: {why}"
print(f"\nstream verified and reconstructed: {len(body)} frames")
print(f"  stage      : {state['stage']['name']} (ordinal {state['stage']['ordinal']})")
dims = ", ".join("%s v%d" % (k, v["version"]) for k, v in sorted(state["dimensions"].items()))
print(f"  dimensions : {dims}")
print(f"  traits     : {state['traits_hash'][:16]}…")
w = state["weight"]
print(f"  weight     : {R.format_weight(w['total_weight_bytes'])} "
      f"({w['total_weight_bytes']} bytes exactly) — "
      f"{w['frame_weight_bytes']} in frames + {w['asset_weight_bytes']} in assets"
      f"{'' if w['complete'] else '  [INCOMPLETE]'}")
# A frame cannot weigh itself — its size depends on the number it would contain — so the
# growth frame attests the weight of everything BEFORE it, and the fold recomputes that.
_, _, _, before = R.fold_body_stream(body[:3], stream_id_of_record=rid)
print("  the growth frame's attested weight is recomputed, not believed:",
      body[3]["payload"]["weight"] == before["weight"],
      f"({before['weight']['total_weight_bytes']} bytes at seq 3)")

# ── 7. The law: growth changed the stage, and changed nothing about identity. ────────
ids = {f["stream_id"] for f in body} | {f["payload"]["rappid"] for f in body[1:]}
print(f"\nidentity across every frame of the growth: {len(ids)} distinct rappid → {ids.pop() == rid}")
print(f"  baby stage → raptor stage, tail unchanged: {rid.rsplit(':', 1)[1][:16]}…")

# ── 8. Where the media actually lives: a §9 organism egg, same §5 address. ───────────
files = {"rappid.json": R.canonical({"schema": "rapp/1", "rappid": rid}).encode("utf-8"),
         "soul.md": b"# quill\nA small thing that learned a tune.\n",
         "organs/sonic/midi-dna.mid": dna,
         "organs/sonic/wake-call.wav": call}
egg = R.pack_egg("organism", rid, "2026-08-01T10:05:00.000Z", files=files)
ok, step, why = R.verify_egg(egg)
print(f"\norganism egg ({len(egg)} bytes) verifies: {ok}" + ("" if ok else f" — {step}: {why}"))
manifest, _ = R.read_egg(egg)
by_path = {c["path"]: c["hash"] for c in manifest["contents"]}
print("  frame's media hash == egg's content hash:",
      by_path["organs/sonic/midi-dna.mid"] == media["midi-dna"]["hash"]
      and by_path["organs/sonic/wake-call.wav"] == media["wake-call"]["hash"])

# ── 8b. Weight on a habitat: what is hydrated here, and what is merely linked. ───────
empty = R.weigh(body)
hydrated = R.weigh(body, store={(R.MEDIA_SPACE, R.Hb(R.MEDIA_SPACE, b)): b for b in (dna, call)})
print(f"\nweight on a habitat holding nothing : resident {R.format_weight(empty['resident_weight_bytes'])}"
      f" · linked {R.format_weight(empty['linked_weight_bytes'])}")
print(f"weight on a habitat holding the media: resident {R.format_weight(hydrated['resident_weight_bytes'])}"
      f" · linked {R.format_weight(hydrated['linked_weight_bytes'])}")
print("  the attested weight is the same on both — residency is the reader's view, never the organism's:",
      R.attested_weight(empty) == R.attested_weight(hydrated) == state["weight"])

# Same length, one flipped byte: the copy is the right size and the wrong bytes.
corrupt_call = bytes([call[0] ^ 0xFF]) + call[1:]
corrupt_store = {(R.MEDIA_SPACE, R.Hb(R.MEDIA_SPACE, dna)): dna,
                 (R.MEDIA_SPACE, media["wake-call"]["hash"]): corrupt_call}
bad = R.weigh(body, store=corrupt_store)
print(f"a habitat whose wake-call copy is corrupt: verified={bad['verified']}, surfaced as "
      f"{bad['unverified'][0]['reason']} — those {bad['unverified'][0]['bytes']} bytes go back to "
      "linked, never resident, and are never estimated")

# Two sizes claimed for one address means the size is UNKNOWN. It is reported, not guessed.
clash = R.build_dimension_frame(rid, 4, "2026-08-01T11:00:00.000Z", "visual", 1, RAPTOR,
                                traits={}, media={"wake-call": dict(media["wake-call"], bytes=1)},
                                prev=body[-1]["payload_hash"])
conflicted = R.weigh(body + [clash])
print(f"two sizes claimed for one wake-call    : complete={conflicted['complete']}, "
      f"{conflicted['incomplete'][0]['reason']} → that asset's size is unknown (bytes: null), "
      "so it weighs nothing at all rather than being averaged or guessed")

# ── 8c. The creature card: every stat derived, presentation clearly labelled. ────────
card = R.stat_block(state, ledger=hydrated, curve=QUILL_ATLAS)
print(f"\n┌ {card['species']} · {card['lifecycle_stage']['name']}")
print(f"│ frame height   {card['frame_height']} frames (exact, verified chain depth)")
print(f"│ display height {card['display_height_mm']} mm  [presentation, {card['height_curve']}]")
print(f"│ weight         {R.format_weight(card['total_weight_bytes'])} · "
      f"resident {R.format_weight(card['resident_weight_bytes'])} · "
      f"linked {R.format_weight(card['linked_weight_bytes'])}")
print(f"│ dimensions     {card['dimension_count']}: {', '.join(card['capabilities'])}")
print(f"│ traits         {card['traits_hash'][:16]}…")
print(f"└ complete       {card['complete']}  {card['completeness']}")
taller = {"curve": "quill-atlas/2",
          "species": {SPECIES: dict(QUILL_ATLAS["species"][SPECIES], base_mm=140)}}
redrawn = R.stat_block(state, ledger=hydrated, curve=taller)
print(f"  a later curve version redraws the picture ({redrawn['display_height_mm']} mm) and moves "
      f"no exact stat: {redrawn['frame_height'] == card['frame_height']} "
      f"{redrawn['total_weight_bytes'] == card['total_weight_bytes']}")

# ── 8d. Autocomplete the next dimension — a proposal, worth nothing until appended. ──
snapshot = R.canonical(state)
prop = R.propose_next(state, curve=QUILL_ATLAS)
print(f"\nproposed next: {prop['next_dimension']['dimension']} v{prop['next_dimension']['version']} "
      f"(from {prop['next_dimension']['derived_from']}) · authoritative={prop['authoritative']}")
print(f"  projected frame height {prop['projected']['frame_height']}, display "
      f"{prop['projected']['display_height_mm']} mm, weight "
      f"{prop['projected']['total_weight_bytes']} — a frame that does not exist has no bytes")
print("  predicting changed nothing about the organism:", R.canonical(state) == snapshot)
append(R.build_dimension_frame(rid, 4, "2026-08-02T09:00:00.000Z",
                               prop["next_dimension"]["dimension"],
                               prop["next_dimension"]["version"], RAPTOR,
                               traits={"grip": "four-toed"}, prev=body[-1]["payload_hash"]))
ok, step, why, state = R.fold_body_stream(body, stream_id_of_record=rid)
assert ok, f"fold refused at {step}: {why}"
grown = R.stat_block(state, curve=QUILL_ATLAS)
print(f"  appended and verified → frame height {grown['frame_height']}, display "
      f"{grown['display_height_mm']} mm, weight {grown['total_weight_bytes']} bytes measured")
print("  the prediction was right about height and silent about weight, which is the point:",
      grown["frame_height"] == prop["projected"]["frame_height"]
      and grown["capabilities"] == prop["projected"]["capabilities"])

# ── 9. Offspring is not a stage. It mints a NEW rappid and points at its parent. ─────
child = R.mint_rappid("kody", "quill-two")
inherited = R.inherit(state, ["sonic"])
birth = R.build_growth_frame(child, 0, "2026-08-02T07:00:00.000Z", BABY, inherited,
                             parent={"rappid": rid, "particle": state["particle"]}, prev=None)
ok, step, why, child_state = R.fold_body_stream([birth], stream_id_of_record=child, inherited=state)
print(f"\noffspring {child[:34]}… verifies: {ok}" + ("" if ok else f" — {step}: {why}"))
print(f"  new rappid, not the parent's : {child != rid}")
print(f"  inherited sonic from parent  : {sorted(child_state['dimensions'])}")
print(f"  starts at stage              : {child_state['stage']['name']}")
ok, step, why, _ = R.fold_body_stream([birth], stream_id_of_record=child)
print(f"  parent not resolvable → verdict fails closed: {not ok} ({step}: {why})")

# ── 10. Three refusals, so you can recognise them in the wild. ───────────────────────
print("\nrefusals:")
swap = R.build_dimension_frame(rid, 1, "2026-08-01T09:10:00.000Z", "skill", 1, BABY, traits={})
swap["payload"]["rappid"] = child                 # a stage change that re-identifies the organism
ok, step, why = R.verify_dimension_payload(swap["payload"], rid)
print(f"  identity swap dressed as growth → {step}: {why}")

regress = R.build_dimension_frame(rid, len(body), "2026-08-03T11:00:00.000Z", "device", 1, BABY,
                                  traits={}, prev=body[-1]["payload_hash"])
ok, step, why, _ = R.fold_body_stream(body + [regress], stream_id_of_record=rid)
print(f"  raptor regressing to baby       → {step}: {why}")

embed = R.build_dimension_frame(rid, 1, "2026-08-01T09:10:00.000Z", "sonic", 1, BABY, traits={},
                                media={"midi-dna": dict(media["midi-dna"], data_b64="TVRoZA==")})
ok, step, why = R.verify_dimension_payload(embed["payload"], rid)
print(f"  media octets smuggled inline    → {step}: {why}")