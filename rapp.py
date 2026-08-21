"""rapp.py — reference implementation of the RAPP protocol suite (rev-5).

Stdlib only. Implements the primitives that the
spec claims are byte-for-byte interoperable, so the conformance suite can PROVE the
standard is implementable and self-consistent — and so it can be run against real
estate artifacts to see where reality conforms and where reality is the drift RAPP fixes.

Scope note: §4 canonicalization here is JCS restricted to the string/int/bool/null/
array/object domain (no floats) — exactly the profile RAPP §4 allows for payloads.
Full IEEE-754 number serialization (RFC 8785) is the production requirement; the
reference vectors use exact-integer payloads so the hashes are reproducible anywhere.
"""
import base64
import datetime
import hashlib
import io
import json
import re
import urllib.parse
import uuid
import zipfile

SPEC = "rapp/1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_LCLABEL = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_RAPPID = re.compile(r"^rappid:@([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:-[a-z0-9]+)*):([0-9a-f]{64})$")

FRAME_KEYS = {"spec", "kind", "stream_id", "seq", "utc", "payload",
              "payload_hash", "frame_hash", "prev", "prev_wave", "sig"}


# ---------- §4 canonicalization ----------
def canonical(v):
    """RFC 8785 JCS over the exact-value domain (no floats). Returns UTF-8 str."""
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, int):
        return json.dumps(v)               # exact integers only in this profile
    if isinstance(v, float):
        raise ValueError("floats require full-JCS number serialization; use ints/strings")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys())
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate keys")
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v[k]) for k in keys) + "}"
    raise ValueError(f"non-I-JSON value: {type(v)}")


# ---------- §5 domain-separated content addressing ----------
def H(space, v):
    return hashlib.sha256(space.encode() + b"\x0a" + canonical(v).encode("utf-8")).hexdigest()

def Hb(space, b):
    return hashlib.sha256(space.encode() + b"\x0a" + b).hexdigest()


# ---------- §6 identity ----------
def mint_rappid(owner, slug, spki_der=None):
    """§6.2 mint-once. keyless = Hb(uuid4); keyed = Hb(SPKI). NEVER a name-hash."""
    if spki_der is not None:
        tail = Hb("rapp/1:rappid", spki_der)
    else:
        tail = Hb("rapp/1:rappid", uuid.uuid4().bytes)
    return f"rappid:@{owner}/{slug}:{tail}"

def rappid_valid(s):
    return isinstance(s, str) and bool(_RAPPID.match(s))


# ---------- §7 the frame ----------
def build_frame(kind, stream_id, seq, utc, payload, prev, prev_wave=None, sig=None):
    """Construct an 11-key frame, computing particle then wave (§7.3)."""
    payload_hash = H("rapp/1:particle", payload)
    frame = {
        "spec": SPEC, "kind": kind, "stream_id": stream_id, "seq": seq, "utc": utc,
        "payload": payload, "payload_hash": payload_hash,
        "prev": prev, "prev_wave": prev_wave, "sig": sig,
    }
    pre = {k: frame[k] for k in frame if k not in ("frame_hash", "sig")}
    frame["frame_hash"] = H("rapp/1:wave", pre)
    # canonical key set / ordering is by JCS at hash time; store all 11:
    frame = {**frame, "frame_hash": frame["frame_hash"]}
    return frame


def verify_frame(frame, head=None, stream_id_of_record=None):
    """§7.5 consumer checklist. Returns (ok, failing_step_or_None, reason)."""
    # 1 shape & types
    if set(frame.keys()) != FRAME_KEYS:
        return False, "1", f"key set != 11 ({sorted(frame.keys())})"
    if frame["spec"] != SPEC:
        return False, "1", "spec != rapp/1"
    if not (isinstance(frame["kind"], str) and re.match(r"^[a-z0-9]+(-[a-z0-9]+)*\.[a-z0-9]+(-[a-z0-9]+)*$", frame["kind"])):
        return False, "1", "kind grammar"
    if not isinstance(frame["stream_id"], str):
        return False, "1", "stream_id type"
    if not (isinstance(frame["seq"], int) and not isinstance(frame["seq"], bool) and 0 <= frame["seq"] <= 2**53 - 1):
        return False, "1", "seq not uint53"
    if not (isinstance(frame["utc"], str) and _UTC.match(frame["utc"])):
        return False, "1", "utc not fixed form"
    if not isinstance(frame["payload"], dict):
        return False, "1", "payload not object"
    for k in ("payload_hash", "frame_hash"):
        if not (isinstance(frame[k], str) and _HEX64.match(frame[k])):
            return False, "1", f"{k} not 64hex"
    for k in ("prev", "prev_wave"):
        if not (frame[k] is None or (isinstance(frame[k], str) and _HEX64.match(frame[k]))):
            return False, "1", f"{k} not null|64hex"
    # 1a stream binding
    if stream_id_of_record is not None and frame["stream_id"] != stream_id_of_record:
        return False, "1a", "stream_id mismatch (cross-stream replay)"
    # 2 particle
    if frame["payload_hash"] != H("rapp/1:particle", frame["payload"]):
        return False, "2", "payload_hash mismatch"
    # 3 wave
    pre = {k: frame[k] for k in frame if k not in ("frame_hash", "sig")}
    if frame["frame_hash"] != H("rapp/1:wave", pre):
        return False, "3", "frame_hash mismatch"
    # 4 chain
    if head is None:
        if not (frame["seq"] == 0 and frame["prev"] is None):
            return False, "4", "genesis must be seq=0 prev=null"
    else:
        if frame["seq"] != head["seq"] + 1:
            return False, "4", "seq not contiguous"
        if frame["prev"] != head["payload_hash"]:
            return False, "4", "prev != head payload_hash"
        if frame["utc"] < head["utc"]:
            return False, "4", "utc < head utc"
    # 5 wire
    is_swarm = frame["stream_id"].startswith("net:")
    if is_swarm and frame["seq"] > 0:
        if head is not None and frame["prev_wave"] != head["frame_hash"]:
            return False, "5", "prev_wave != head frame_hash"
    else:
        if frame["prev_wave"] is not None:
            return False, "5", "prev_wave must be null off swarm"
    # 6 signature: (crypto-dependent; verified elsewhere) — refuse unsigned swarm
    if is_swarm and frame["sig"] is None:
        return False, "6", "swarm frame must be signed"
    return True, None, "ok"


# ---------- §7.7 dimensional growth (body-family payload profiles) ----------
# One organism, one mint-once rappid (§6.2), grown by APPENDING dimension frames to
# its body-stream. A lifecycle stage is state carried in a payload — never part of an
# identifier — so growth never re-mints. True offspring mint their own rappid and carry
# a parent pointer (§7.7.5). Nothing here changes the §7.1 envelope, the wire tag, the
# canonicalization, the hashing, or the identity grammar: it is two registered body-family
# `kind`s and their payload profiles, built from the primitives above.

BODY_DIMENSION = "body.dimension"
BODY_RECONSTRUCTED = "body.reconstructed"

#: The estate's baseline dimension names (§7.7.4). The token space is open — any lclabel
#: is conformant — but these six are the ones the estate builds an organism out of.
DIMENSION_BASELINE = ("memory", "skill", "sonic", "device", "visual", "capability")

#: The §13.3 `kind` entries this profile needs; append them verbatim to the registry.
REGISTRY_KIND_ENTRIES = (
    {"type": "kind", "kind": BODY_DIMENSION, "family": "body", "deprecated": False},
    {"type": "kind", "kind": BODY_RECONSTRUCTED, "family": "body", "deprecated": False},
)

#: Media octets NEVER ride inside frame JSON; a frame carries only their §5 address, in
#: the existing octet space `rapp/1:egg` (§9.1) — no new domain tag is introduced.
MEDIA_SPACE = "rapp/1:egg"

#: The one refusal a reader may report as *unverified* rather than *drift*: an offspring
#: whose parent stream is not in hand. Unresolved is never "clean" (§13.1 staleness rule).
UNRESOLVED_PARENT = "parent lineage unresolved"

_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$")
_MEMORY_STREAM = re.compile(r"^rappid:@[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:-[a-z0-9]+)*"
                            r":[0-9a-f]{64}:[a-z0-9]+(?:-[a-z0-9]+)*$")
_SWARM_STREAM = re.compile(r"^net:[a-z0-9]+(?:-[a-z0-9]+)*$")

_MEDIA_REF_KEYS = {"space", "hash", "media_type", "bytes"}
_STAGE_KEYS = {"name", "ordinal"}
_SOURCE_KEYS = {"stream_id", "particle"}
_PARENT_KEYS = {"rappid", "particle"}
_DIM_ENTRY_KEYS = {"version", "particle"}
DIMENSION_PAYLOAD_KEYS = {"rappid", "dimension", "version", "stage", "traits",
                          "traits_hash", "media", "sources"}
GROWTH_PAYLOAD_KEYS = {"rappid", "species", "stage", "dimensions", "traits_hash", "weight",
                       "sources", "parent"}

#: §7.8 — a RAPPID's data size is its WEIGHT: verified bytes, de-duplicated by content
#: address, so the same frame or asset can never be weighed twice. The four members a
#: frame attests are habitat-independent; residency is a reader's view (§7.8.3).
WEIGHT_KEYS = {"frame_weight_bytes", "asset_weight_bytes", "total_weight_bytes", "complete"}
LEDGER_KEYS = WEIGHT_KEYS | {"resident_weight_bytes", "linked_weight_bytes",
                             "verified", "incomplete", "unverified"}
_INCOMPLETE_KEYS = {"object", "space", "hash", "reason", "bytes"}

#: A byte count that could not be *established* — the object weighs nothing and is listed
#: (`incomplete`). Habitat-independent, so a frame may attest `complete`.
WEIGHT_INCOMPLETE_REASONS = ("size-conflict",)
#: A byte count that is attested but could not be *confirmed* here — the object stays
#: linked, never resident, and is listed (`unverified`). This is a reader's view only.
WEIGHT_UNVERIFIED_REASONS = ("store-mismatch",)


def _uint53(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2**53 - 1


def _hex64(v):
    return isinstance(v, str) and bool(_HEX64.match(v))


def _lclabel(v):
    return isinstance(v, str) and bool(_LCLABEL.match(v))


def stream_family(stream_id):
    """§6.1.1/§7.2 — 'body' | 'memory' | 'swarm', or None if not a conformant stream_id."""
    if not isinstance(stream_id, str):
        return None
    if rappid_valid(stream_id):
        return "body"
    if _MEMORY_STREAM.match(stream_id):
        return "memory"
    if _SWARM_STREAM.match(stream_id):
        return "swarm"
    return None


def media_ref(octets, media_type):
    """§7.7.2 — the content-addressed reference to media held OUTSIDE the frame.

    The same address a §9 egg's `contents[].hash` carries for those octets, so a
    dimension's media resolves out of any store keyed by (`rapp/1:egg`, hash)."""
    if not isinstance(octets, (bytes, bytearray)):
        raise ValueError("media octets must be bytes — media never rides in frame JSON")
    if not (isinstance(media_type, str) and _MEDIA_TYPE.match(media_type)):
        raise ValueError(f"media_type not a lowercase type/subtype: {media_type!r}")
    return {"space": MEDIA_SPACE, "hash": Hb(MEDIA_SPACE, bytes(octets)),
            "media_type": media_type, "bytes": len(octets)}


def traits_snapshot(traits):
    """§7.7.3 — the trait snapshot address, in the existing particle space (no new tag)."""
    if not isinstance(traits, dict):
        raise ValueError("traits must be a JSON object")
    return H("rapp/1:particle", traits)


def source_list(pointers):
    """§7.7.4 — the deterministic source-pointer array: sorted by (stream_id, particle)
    UTF-8 bytes, de-duplicated, so two readers fold the same sources into the same bytes."""
    uniq = {(p["stream_id"], p["particle"]) for p in pointers}
    return [{"stream_id": s, "particle": h} for s, h in
            sorted(uniq, key=lambda t: (t[0].encode("utf-8"), t[1].encode("utf-8")))]


# ---------- §7.8 weight — a RAPPID's data size ----------
# WEIGHT is what an organism's data actually masses: verified bytes, de-duplicated by
# content address (§5), so one frame or one asset can never be counted twice however many
# times it is referenced. Weight is state — it grows by appending (§7.8.5) and never
# touches the mint-once identity. A byte count that cannot be established or confirmed is
# surfaced as *incomplete*; it is never estimated, rounded, or quietly dropped.

_WEIGHT_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def frame_weight(frame):
    """§7.8.1 — one accepted frame's weight: the length of its §4 canonical form."""
    return len(canonical(frame).encode("utf-8"))


def _asset_table(media_maps):
    """(space, hash) → attested bytes, plus the set of addresses attested two ways.

    De-duplication is by content address, so the same wake-call referenced by six
    dimensions weighs once. A second, *different* size for one address makes that asset's
    size unknown — it is reported, never guessed at."""
    attested, conflict = {}, set()
    for media in media_maps:
        for ref in media.values():
            key = (ref["space"], ref["hash"])
            if key in attested and attested[key] != ref["bytes"]:
                conflict.add(key)
            attested.setdefault(key, ref["bytes"])
    for key in conflict:
        attested.pop(key, None)
    return attested, conflict


def _store_octets(store, key):
    """A habitat store is keyed by (space, hash) per §5; `None` means not hydrated here."""
    if store is None:
        return None
    return store.get(key)


def _ledger(frame_bytes, attested, conflict, store=None):
    """§7.8.2/§7.8.3 — build the weight ledger from de-duplicated frame and asset tables."""
    incomplete = [{"object": "asset", "space": s, "hash": h,
                   "reason": "size-conflict", "bytes": None}
                  for s, h in sorted(conflict)]
    unverified = []
    resident_assets = 0
    for key in sorted(attested):
        octets = _store_octets(store, key)
        if octets is None:
            continue                                    # attested, not hydrated here → linked
        if Hb(key[0], octets) != key[1] or len(octets) != attested[key]:
            unverified.append({"object": "asset", "space": key[0], "hash": key[1],
                               "reason": "store-mismatch", "bytes": attested[key]})
            continue                                    # a local copy that fails §5 is not weight
        resident_assets += attested[key]
    fw, aw = sum(frame_bytes.values()), sum(attested.values())
    resident = fw + resident_assets                     # an accepted frame is resident by definition
    return {"frame_weight_bytes": fw, "asset_weight_bytes": aw, "total_weight_bytes": fw + aw,
            "resident_weight_bytes": resident, "linked_weight_bytes": fw + aw - resident,
            "complete": not incomplete, "verified": not unverified,
            "incomplete": incomplete, "unverified": unverified}


def weigh(frames, store=None, inherited=None):
    """§7.8 — weigh a set of accepted frames. Returns the §7.8.2 ledger.

    `frames` MUST already have passed §7.5 (weight counts *verified* bytes only). Assets
    are the §7.7.2 media references carried by `body.dimension` frames — a payload is never
    scanned for hash-shaped strings, because guessing is not weighing. `store` is this
    habitat's octet store keyed by `(space, hash)`; without one, nothing is hydrated and
    every asset is linked. For an offspring stream, `inherited` is the resolved parent fold;
    the child's genesis dimensions select the inherited media maps. Refusing to weigh an
    unresolved offspring is safer than silently dropping inherited mass. The attested members
    (§7.8.2) are identical on every habitat."""
    frame_bytes = {}
    for fr in frames:
        frame_bytes.setdefault(fr["frame_hash"], frame_weight(fr))
    media_maps = [fr["payload"]["media"] for fr in frames if fr.get("kind") == BODY_DIMENSION]
    births = [fr for fr in frames
              if fr.get("kind") == BODY_RECONSTRUCTED
              and fr.get("payload", {}).get("parent") is not None]
    if births:
        if inherited is None:
            raise ValueError("weighing an offspring requires its resolved parent fold")
        birth = births[0]
        try:
            media_maps = [inherited["media"][name]
                          for name in birth["payload"]["dimensions"]] + media_maps
        except (KeyError, TypeError) as ex:
            raise ValueError("offspring inheritance does not resolve every inherited asset") from ex
    attested, conflict = _asset_table(media_maps)
    return _ledger(frame_bytes, attested, conflict, store)


def attested_weight(ledger):
    """§7.8.2 — the habitat-independent members, the only ones a frame may carry.

    `complete` covers sizes that could not be *established* (habitat-independent); a local
    copy that could not be *confirmed* lands in the reader's `unverified` list (§7.8.3) and
    never moves these four numbers, or one habitat's bad disk would break every verifier."""
    return {k: ledger[k] for k in sorted(WEIGHT_KEYS)}


def format_weight(n):
    """§7.8.4 — presentation only. The exact integer IS the weight; this string is never
    hashed, canonicalized, put in a payload, parsed back, or compared."""
    if not _uint53(n):
        raise ValueError("weight is an exact uint53 count of bytes")
    if n < 1024:
        return f"{n} B"
    v, i = float(n), 0
    while v >= 1024 and i < len(_WEIGHT_UNITS) - 1:
        v /= 1024.0
        i += 1
    return f"{v:.1f} {_WEIGHT_UNITS[i]}"


# ---------- §7.9 stats — the creature card over verified state ----------
# Two different things, kept apart on purpose. FRAME HEIGHT is protocol: the verified depth
# of an append-only body-chain, an exact integer. DISPLAY HEIGHT is presentation: millimetres
# a species' versioned growth curve renders from that depth, for a card. A stat block is a
# derived VIEW — it is never a frame, never hashed, never identity. And a proposal is a
# guess about the next one: useful, and worth nothing until it is appended and verified.

STAT_KEYS = {"rappid", "species", "lifecycle_stage", "frame_height", "display_height_mm",
             "height_curve", "dimension_count", "capabilities", "traits", "traits_hash",
             "total_weight_bytes", "resident_weight_bytes", "linked_weight_bytes",
             "completeness", "complete"}
PROPOSAL_KEYS = {"proposal", "authoritative", "basis", "next_dimension", "projected"}

#: A versioned species growth curve (§7.9.2). Exact-integer piecewise-linear interpolation,
#: so two implementations render the same millimetres. Presentation data, not protocol: the
#: estate's own bestiary lives outside this file and passes its own curve.
HEIGHT_CURVE_V1 = {
    "curve": "rapp-height/1",
    "species": {"default": {"base_mm": 50, "cap_mm": 260,
                            "points": [[0, 0], [4, 30], [16, 90], [64, 170]]}},
}

_CARRY = object()          # "keep whatever the fold already established" (§7.9.2 species)


def display_height_mm(species, frame_height, curve=HEIGHT_CURVE_V1):
    """§7.9.2 — render a species' display height in millimetres from frame height.

    PRESENTATION ONLY. It is not identity, not protocol, and not a claim about any physical
    object. Returns None when the species is unknown to this curve — an unrenderable height
    is reported as unknown, never invented."""
    if not _uint53(frame_height):
        raise ValueError("frame_height is an exact uint53 chain depth")
    if species is None:
        return None
    entry = curve.get("species", {}).get(species)
    if entry is None:
        return None
    pts = entry["points"]
    if frame_height <= pts[0][0]:
        y = pts[0][1]
    else:
        y = pts[-1][1]
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            if frame_height <= x1:
                y = y0 + (frame_height - x0) * (y1 - y0) // (x1 - x0)   # exact integers only
                break
    return min(entry["cap_mm"], entry["base_mm"] + y)


def stat_block(state, ledger=None, curve=HEIGHT_CURVE_V1):
    """§7.9.3 — the creature card: a derived view over one verified fold.

    `state` comes from fold_body_stream (so every number below was verified, not claimed).
    `ledger` is a habitat weigh() when you want this machine's resident/linked split;
    without one the fold's own store-free ledger is used. The card is a view: it is never
    appended, hashed, or treated as identity."""
    led = state["ledger"] if ledger is None else ledger
    if attested_weight(led) != state["weight"]:
        raise ValueError("habitat ledger does not match the verified fold's attested weight")
    height = display_height_mm(state["species"], state["frame_height"], curve)
    completeness = {"weight_sizes_established": led["complete"],
                    "local_copies_verified": led["verified"],
                    "display_height_resolved": height is not None}
    return {
        "rappid": state["rappid"],
        "species": state["species"],
        "lifecycle_stage": None if state["stage"] is None else dict(state["stage"]),
        "frame_height": state["frame_height"],
        "display_height_mm": height,
        "height_curve": None if height is None else curve["curve"],
        "dimension_count": len(state["dimensions"]),
        "capabilities": sorted(state["dimensions"]),
        "traits": {n: state["traits"][n] for n in sorted(state["traits"])},
        "traits_hash": state["traits_hash"],
        "total_weight_bytes": led["total_weight_bytes"],
        "resident_weight_bytes": led["resident_weight_bytes"],
        "linked_weight_bytes": led["linked_weight_bytes"],
        "completeness": completeness,
        "complete": all(completeness.values()),
    }


def propose_next(state, lineage=None, curve=HEIGHT_CURVE_V1):
    """§7.9.4 — autocomplete the organism's next dimension from its traits and its lineage.

    This is a PROPOSAL, the way a continuation of a melody is a proposal: it reads, it never
    writes. It is not authoritative, it is not canonical state, and nothing in it counts
    until someone appends a real frame and a verifier accepts it. It cannot invent bytes
    either — a frame that does not exist has no weight, so the projection says so."""
    have = set(state["dimensions"])
    from_lineage = [] if lineage is None else [n for n in sorted(lineage["dimensions"])
                                               if n not in have]
    unfilled = [n for n in DIMENSION_BASELINE if n not in have]
    if from_lineage:
        nxt = {"dimension": from_lineage[0], "version": 1, "derived_from": "lineage"}
    elif unfilled:
        nxt = {"dimension": unfilled[0], "version": 1, "derived_from": "baseline"}
    else:
        name = min(have, key=lambda n: (state["dimensions"][n]["version"], n))
        nxt = {"dimension": name, "version": state["dimensions"][name]["version"] + 1,
               "derived_from": "traits"}
    height = state["frame_height"] + 1
    caps = sorted(have | {nxt["dimension"]})
    return {
        "proposal": True,
        "authoritative": False,
        "basis": {"rappid": state["rappid"], "particle": state["particle"],
                  "frame_height": state["frame_height"]},
        "next_dimension": nxt,
        "projected": {"frame_height": height,
                      "display_height_mm": display_height_mm(state["species"], height, curve),
                      "dimension_count": len(caps), "capabilities": caps,
                      "total_weight_bytes": None, "weight_known": False},
    }


def _bad_weight(weight):
    if not isinstance(weight, dict) or set(weight.keys()) != WEIGHT_KEYS:
        return f"weight must have exactly {sorted(WEIGHT_KEYS)}"
    for k in ("frame_weight_bytes", "asset_weight_bytes", "total_weight_bytes"):
        if not _uint53(weight[k]):
            return f"weight.{k} not a uint53 count of bytes (weight is exact, never estimated)"
    if not isinstance(weight["complete"], bool):
        return "weight.complete must be a boolean"
    if weight["total_weight_bytes"] != weight["frame_weight_bytes"] + weight["asset_weight_bytes"]:
        return "weight.total_weight_bytes != frame_weight_bytes + asset_weight_bytes"
    return None


def _bad_media(media):
    if not isinstance(media, dict):
        return "media must be an object of role → media-ref"
    for role, ref in media.items():
        if not _lclabel(role):
            return f"media role not an lclabel: {role!r}"
        if not isinstance(ref, dict) or set(ref.keys()) != _MEDIA_REF_KEYS:
            return (f"media[{role}] must have exactly {{space,hash,media_type,bytes}} — "
                    "raw media MUST NOT be embedded in frame JSON")
        if ref["space"] != MEDIA_SPACE:
            return f"media[{role}].space must be {MEDIA_SPACE!r} (§5: no cross-space deref)"
        if not _hex64(ref["hash"]):
            return f"media[{role}].hash not 64hex"
        if not (isinstance(ref["media_type"], str) and _MEDIA_TYPE.match(ref["media_type"])):
            return f"media[{role}].media_type not a lowercase type/subtype"
        if not _uint53(ref["bytes"]):
            return f"media[{role}].bytes not uint53"
    return None


def _bad_stage(stage):
    if not isinstance(stage, dict) or set(stage.keys()) != _STAGE_KEYS:
        return "stage must be exactly {name, ordinal}"
    if not _lclabel(stage["name"]):
        return "stage.name not an lclabel"
    if not _uint53(stage["ordinal"]):
        return "stage.ordinal not uint53"
    return None


def _bad_sources(sources):
    if not isinstance(sources, list):
        return "sources must be an array of {stream_id, particle}"
    seen = []
    for s in sources:
        if not isinstance(s, dict) or set(s.keys()) != _SOURCE_KEYS:
            return "source must be exactly {stream_id, particle}"
        if stream_family(s["stream_id"]) is None:
            return f"source.stream_id not a §6.1.1 stream: {s['stream_id']!r}"
        if not _hex64(s["particle"]):
            return "source.particle not 64hex"
        seen.append((s["stream_id"].encode("utf-8"), s["particle"].encode("utf-8")))
    if seen != sorted(seen):
        return "sources MUST be sorted ascending by (stream_id, particle) UTF-8 bytes"
    if len(set(seen)) != len(seen):
        return "duplicate source pointer"
    return None


def _stage_regression(prev_stage, stage):
    if prev_stage is not None and stage["ordinal"] < prev_stage["ordinal"]:
        return (f"stage {stage['name']} (ordinal {stage['ordinal']}) is below "
                f"{prev_stage['name']} (ordinal {prev_stage['ordinal']}) — a stage is state, and it grows")
    return None


def verify_dimension_payload(payload, stream_id):
    """§7.7.4 — the `body.dimension` payload profile. Returns (ok, step, reason)."""
    if not isinstance(payload, dict) or set(payload.keys()) != DIMENSION_PAYLOAD_KEYS:
        return False, "§7.7.4", f"payload key set != {sorted(DIMENSION_PAYLOAD_KEYS)}"
    if stream_family(stream_id) != "body":
        return False, "§7.2", "body.dimension rides a body-stream (the organism's biography)"
    if payload["rappid"] != stream_id:
        return False, "§7.7.1", ("payload.rappid != stream_id — growth MUST NOT re-identify "
                                 "the organism (§6.2 mint-once)")
    if not _lclabel(payload["dimension"]):
        return False, "§7.7.4", "dimension not an lclabel"
    if not (_uint53(payload["version"]) and payload["version"] >= 1):
        return False, "§7.7.4", "version not a uint53 >= 1"
    why = _bad_stage(payload["stage"])
    if why:
        return False, "§7.7.4", why
    why = _bad_media(payload["media"])
    if why:
        return False, "§7.7.2", why
    why = _bad_sources(payload["sources"])
    if why:
        return False, "§7.7.4", why
    if not isinstance(payload["traits"], dict):
        return False, "§7.7.3", "traits must be a JSON object"
    if payload["traits_hash"] != traits_snapshot(payload["traits"]):
        return False, "§7.7.3", "traits_hash != H('rapp/1:particle', traits)"
    return True, None, "ok"


def verify_growth_payload(payload, stream_id):
    """§7.7.5 — the `body.reconstructed` payload profile. Returns (ok, step, reason).

    Position-dependent rules (parent only at genesis, fold equality) are stream-level:
    see fold_body_stream()."""
    if not isinstance(payload, dict) or set(payload.keys()) != GROWTH_PAYLOAD_KEYS:
        return False, "§7.7.5", f"payload key set != {sorted(GROWTH_PAYLOAD_KEYS)}"
    if stream_family(stream_id) != "body":
        return False, "§7.2", "body.reconstructed rides a body-stream"
    if payload["rappid"] != stream_id:
        return False, "§7.7.1", ("payload.rappid != stream_id — a fold MUST NOT re-identify "
                                 "the organism (§6.2 mint-once)")
    if not (payload["species"] is None or _lclabel(payload["species"])):
        return False, "§7.9.2", "species must be null or an lclabel"
    why = _bad_stage(payload["stage"])
    if why:
        return False, "§7.7.5", why
    dims = payload["dimensions"]
    if not isinstance(dims, dict):
        return False, "§7.7.5", "dimensions must be an object of dimension → {version, particle}"
    for name, entry in dims.items():
        if not _lclabel(name):
            return False, "§7.7.5", f"dimension name not an lclabel: {name!r}"
        if not isinstance(entry, dict) or set(entry.keys()) != _DIM_ENTRY_KEYS:
            return False, "§7.7.5", f"dimensions[{name}] must be exactly {{version, particle}}"
        if not (_uint53(entry["version"]) and entry["version"] >= 1):
            return False, "§7.7.5", f"dimensions[{name}].version not a uint53 >= 1"
        if not _hex64(entry["particle"]):
            return False, "§7.7.5", f"dimensions[{name}].particle not 64hex"
    if not _hex64(payload["traits_hash"]):
        return False, "§7.7.5", "traits_hash not 64hex"
    why = _bad_weight(payload["weight"])
    if why:
        return False, "§7.8", why
    why = _bad_sources(payload["sources"])
    if why:
        return False, "§7.7.5", why
    parent = payload["parent"]
    if parent is not None:
        if not isinstance(parent, dict) or set(parent.keys()) != _PARENT_KEYS:
            return False, "§7.7.5", "parent must be null or exactly {rappid, particle}"
        if not rappid_valid(parent["rappid"]):
            return False, "§6.1", f"parent.rappid not a §6.1 rappid: {parent['rappid']!r}"
        if not _hex64(parent["particle"]):
            return False, "§7.7.5", "parent.particle not 64hex"
        if parent["rappid"] == payload["rappid"]:
            return False, "§7.7.1", ("an organism MUST NOT be its own parent — offspring mint a "
                                     "new rappid (§6.2), they do not re-point an existing one")
    return True, None, "ok"


def verify_body_payload(frame, stream_id_of_record=None):
    """§7.7 — profile check for one frame in isolation; a non-§7.7 kind passes through."""
    sid = stream_id_of_record or frame.get("stream_id")
    kind = frame.get("kind")
    if kind == BODY_DIMENSION:
        return verify_dimension_payload(frame.get("payload"), sid)
    if kind == BODY_RECONSTRUCTED:
        return verify_growth_payload(frame.get("payload"), sid)
    return True, None, "not a §7.7 kind"


def _check_inheritance(payload, parent, inherited):
    if parent["rappid"] != inherited["rappid"]:
        return f"parent.rappid != the resolved parent stream ({inherited['rappid']})"
    if parent["particle"] != inherited["particle"]:
        return "parent.particle != the parent state's particle (fold taken at a different frame)"
    for name, entry in payload["dimensions"].items():
        if inherited["dimensions"].get(name) != entry:
            return f"inherited dimension {name!r} is not the parent's — inheritance MUST NOT fabricate"
    missing = [n for n in payload["dimensions"] if n not in inherited.get("traits", {})]
    if missing:
        return f"the resolved parent fold carries no traits for dimension {missing[0]!r}"
    missing = [n for n in payload["dimensions"] if n not in inherited.get("media", {})]
    if missing:
        return f"the resolved parent fold carries no media map for dimension {missing[0]!r}"
    expect = {n: inherited["traits"][n] for n in payload["dimensions"]}
    if payload["traits_hash"] != traits_snapshot(expect):
        return "traits_hash != the trait snapshot of the inherited dimensions"
    return None


def _inherited_weight(payload, inherited):
    """§7.8.2 — an offspring is born owning the assets it inherited and no frames of its
    own; its genesis attests exactly that."""
    attested, conflict = _asset_table([inherited["media"][n] for n in payload["dimensions"]])
    return attested_weight(_ledger({}, attested, conflict))


def fold_body_stream(frames, stream_id_of_record=None, inherited=None):
    """§7.7.6 — verify a body-stream and deterministically reconstruct its state.

    Runs the full §7.5 checklist on every frame, then the §7.7 profile, folding
    `body.dimension` frames in ascending `seq` (per dimension, `version` strictly
    increases and the latest wins) and re-computing every `body.reconstructed` fold
    instead of believing it — including its §7.8 weight, which is recomputed from the
    frames that precede it and **never** from a habitat store, so every reader gets the
    same integers. `inherited` is the parent's state (a previous
    fold_body_stream result) when the genesis frame claims a parent; without it an
    offspring's lineage is *unresolved*, and unresolved fails closed.

    Returns (ok, step, reason, state); state is None when ok is False."""
    if not frames:
        return False, "§7.7.6", "empty stream", None
    sid = stream_id_of_record or frames[0].get("stream_id")
    state = {"rappid": sid, "particle": None, "stage": None, "species": None, "frame_height": 0,
             "dimensions": {}, "traits": {}, "traits_hash": traits_snapshot({}), "media": {},
             "weight": attested_weight(_ledger({}, {}, set())), "ledger": _ledger({}, {}, set()),
             "last_reconstructed_weight_bytes": None}
    frame_bytes, attested, conflict = {}, {}, set()      # the running §7.8 tables
    head = None
    for fr in frames:
        ok, step, why = verify_frame(fr, head=head, stream_id_of_record=sid)
        if not ok:
            return False, step, f"seq {fr.get('seq')}: {why}", None
        payload = fr["payload"]
        if fr["kind"] == BODY_DIMENSION:
            ok, step, why = verify_dimension_payload(payload, sid)
            if not ok:
                return False, step, f"seq {fr['seq']}: {why}", None
            prior = state["dimensions"].get(payload["dimension"])
            if prior is not None and payload["version"] <= prior["version"]:
                return False, "§7.7.4", (f"seq {fr['seq']}: dimension {payload['dimension']!r} version "
                                         f"{payload['version']} <= {prior['version']} — growth appends"), None
            why = _stage_regression(state["stage"], payload["stage"])
            if why:
                return False, "§7.7.1", f"seq {fr['seq']}: {why}", None
            state["stage"] = dict(payload["stage"])
            state["dimensions"][payload["dimension"]] = {"version": payload["version"],
                                                         "particle": fr["payload_hash"]}
            state["traits"][payload["dimension"]] = payload["traits"]
            state["media"][payload["dimension"]] = payload["media"]
            state["traits_hash"] = traits_snapshot(state["traits"])
        elif fr["kind"] == BODY_RECONSTRUCTED:
            ok, step, why = verify_growth_payload(payload, sid)
            if not ok:
                return False, step, f"seq {fr['seq']}: {why}", None
            if state["species"] is not None and payload["species"] != state["species"]:
                return False, "§7.9.2", (f"seq {fr['seq']}: species {payload['species']!r} != the "
                                         f"declared {state['species']!r} — a species is not a stage; "
                                         "a different species is a different organism (§7.7.1)"), None
            parent = payload["parent"]
            if parent is not None and fr["seq"] != 0:
                return False, "§7.7.5", (f"seq {fr['seq']}: a parent pointer is lawful only at the "
                                         "offspring's genesis — no organism acquires ancestry mid-life"), None
            if parent is None:
                if payload["dimensions"] != state["dimensions"]:
                    return False, "§7.7.6", (f"seq {fr['seq']}: asserted dimension fold != the fold "
                                             "reconstructed from this stream"), None
                if payload["traits_hash"] != state["traits_hash"]:
                    return False, "§7.7.6", (f"seq {fr['seq']}: asserted traits_hash != the trait "
                                             "snapshot reconstructed from this stream"), None
                expect_weight = attested_weight(_ledger(frame_bytes, attested, conflict))
            else:
                if inherited is None:
                    return False, "§7.7.5", (f"seq {fr['seq']}: {UNRESOLVED_PARENT} — resolve "
                                             "the parent stream and re-verify (fail closed)"), None
                why = _check_inheritance(payload, parent, inherited)
                if why:
                    return False, "§7.7.5", f"seq {fr['seq']}: {why}", None
                expect_weight = _inherited_weight(payload, inherited)
            if payload["weight"] != expect_weight:
                return False, "§7.8", (f"seq {fr['seq']}: asserted weight != the weight reweighed "
                                       f"from the verified bytes ({expect_weight})"), None
            prior_weight = state["last_reconstructed_weight_bytes"]
            current_weight = payload["weight"]["total_weight_bytes"]
            if prior_weight is not None and current_weight < prior_weight:
                return False, "§7.8.5", (
                    f"seq {fr['seq']}: reconstructed weight {current_weight} < the prior "
                    f"attestation {prior_weight} — weight on one stream MUST NOT decrease"), None
            why = _stage_regression(state["stage"], payload["stage"])
            if why:
                return False, "§7.7.1", f"seq {fr['seq']}: {why}", None
            state["stage"] = dict(payload["stage"])
            if payload["species"] is not None:
                state["species"] = payload["species"]
            state["last_reconstructed_weight_bytes"] = current_weight
            if parent is not None:
                # An offspring's genesis seeds its own fold with what it lawfully inherited.
                state["dimensions"] = {n: dict(e) for n, e in payload["dimensions"].items()}
                state["traits"] = {n: inherited["traits"][n] for n in payload["dimensions"]}
                state["media"] = {n: inherited["media"][n] for n in payload["dimensions"]}
                state["traits_hash"] = traits_snapshot(state["traits"])
                seeded, seed_conflict = _asset_table(list(state["media"].values()))
                attested.update(seeded)
                conflict |= seed_conflict
        # This frame's own bytes join the weight only after it has been accepted, so a
        # growth frame attests the weight of everything BEFORE it — never of itself.
        frame_bytes.setdefault(fr["frame_hash"], frame_weight(fr))
        if fr["kind"] == BODY_DIMENSION:
            added, added_conflict = _asset_table([payload["media"]])
            for key, n in added.items():
                if key in attested and attested[key] != n:
                    conflict.add(key)
                    attested.pop(key, None)
                elif key not in conflict:
                    attested[key] = n
            conflict |= added_conflict
            for key in added_conflict:
                attested.pop(key, None)
        state["weight"] = attested_weight(_ledger(frame_bytes, attested, conflict))
        state["ledger"] = _ledger(frame_bytes, attested, conflict)
        # §7.9.1 exact chain depth: accepted frames, which §7.5 step 4 makes identical to
        # the head's contiguous seq + 1. A re-presented frame is refused, never re-counted.
        state["frame_height"] = len(frame_bytes)
        head = fr
    state["particle"] = head["payload_hash"]
    if state["frame_height"] != head["seq"] + 1:
        return False, "§7.9.1", (f"frame height {state['frame_height']} != head seq + 1 "
                                 f"({head['seq'] + 1}) — the chain is not contiguous"), None
    return True, None, "ok", state


def inherit(state, dimensions=None):
    """§7.7.5 — narrow a parent fold to the dimensions an offspring inherits.

    Raises KeyError on a dimension the parent never had: inheritance cannot fabricate."""
    names = list(state["dimensions"]) if dimensions is None else list(dimensions)
    traits = {n: state["traits"][n] for n in names}
    media = {n: state["media"][n] for n in names}
    attested, conflict = _asset_table(list(media.values()))
    return {"rappid": state["rappid"], "particle": state["particle"], "stage": state["stage"],
            "species": state["species"],
            "dimensions": {n: dict(state["dimensions"][n]) for n in names},
            "traits": traits, "media": media, "traits_hash": traits_snapshot(traits),
            "weight": attested_weight(_ledger({}, attested, conflict))}


def build_dimension_frame(rappid, seq, utc, dimension, version, stage, traits,
                          media=None, sources=None, prev=None, sig=None):
    """§7.7.4 — append one dimension to an organism's biography; identity is untouched."""
    payload = {"rappid": rappid, "dimension": dimension, "version": version,
               "stage": dict(stage), "traits": traits, "traits_hash": traits_snapshot(traits),
               "media": {role: dict(ref) for role, ref in (media or {}).items()},
               "sources": source_list(sources or [])}
    return build_frame(BODY_DIMENSION, rappid, seq, utc, payload, prev=prev, sig=sig)


def build_growth_frame(rappid, seq, utc, stage, state, species=_CARRY, sources=None,
                       parent=None, prev=None, sig=None):
    """§7.7.5 — record a growth/reconstruct event over a fold (`state` from
    fold_body_stream, or inherit() at an offspring's genesis). The §7.8 weight is taken
    from the fold, never asserted by hand — a producer cannot make an organism heavier
    than its verified bytes. `species` defaults to whatever the fold already established
    (§7.9.2), so a routine growth frame cannot silently re-classify the organism."""
    prior_weight = state.get("last_reconstructed_weight_bytes")
    current_weight = state["weight"]["total_weight_bytes"]
    if parent is None and prior_weight is not None and current_weight < prior_weight:
        raise ValueError(
            f"cannot attest decreasing weight: {current_weight} < {prior_weight} (§7.8.5)")
    payload = {"rappid": rappid,
               "species": state.get("species") if species is _CARRY else species,
               "stage": dict(stage),
               "dimensions": {n: dict(e) for n, e in state["dimensions"].items()},
               "traits_hash": state["traits_hash"],
               "weight": dict(state["weight"]),
               "sources": source_list(sources or []),
               "parent": None if parent is None else dict(parent)}
    return build_frame(BODY_RECONSTRUCTED, rappid, seq, utc, payload, prev=prev, sig=sig)


# ---------- §7.10 RAPPID Calling Card and Debug Card profile ----------
# A card is not a second envelope. Its signed manifest is the payload of an ordinary
# eleven-key body frame, its address is that frame's particle, and its signature is the
# existing §10 `sig` member. The URI is only a compact, non-secret fetch instruction.

CARD_PROFILE = "rappid-card/1"
CARD_TEST_PROFILE = "rappid-card-test/1"
CARD_VIRTUAL_SUFFIX = ".rappid-card.json"
CARD_CALLING = "body.calling-card"
CARD_DEBUG = "body.debug-card"
CARD_REGISTRY_KIND_ENTRIES = (
    {"type": "kind", "kind": CARD_CALLING, "family": "body", "deprecated": False},
    {"type": "kind", "kind": CARD_DEBUG, "family": "body", "deprecated": False},
)

CARD_PAYLOAD_KEYS = {
    "profile", "rappid", "soul_hash", "parent", "engram_root",
    "reflex_capability_root", "compatibility", "classification",
    "requested_scope", "expires_utc", "revocation_url", "wake_challenge",
    "inventory", "key_id",
}
CARD_COMPATIBILITY_KEYS = {"protocol", "runtime", "features"}
CARD_INVENTORY_KEYS = {"part", "space", "hash", "bytes", "required"}
CARD_CONTINUITY_KEYS = {
    "rappid", "soul_hash", "parent", "engram_root",
    "reflex_capability_root", "nonce",
}
CARD_ENVIRONMENT_KEYS = {
    "protocol", "runtime", "features", "max_classification", "granted_scope",
}
CARD_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
CARD_REQUIRED_PARTS = ("engram", "reflex-capability", "soul")
CARD_VERIFY_STEPS = (
    "parse", "content-address", "schema", "signature", "expiry", "revocation",
    "compatibility", "classification-scope", "replay-nonce", "hydration",
    "continuity",
)

_CARD_PROFILE_TOKEN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*/[1-9][0-9]*$")
_CARD_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_CARD_CONNECTION = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_JWS_HEADER_KEYS = {"alg", "b64", "crit", "kid"}


# RFC 8032 Ed25519, expressed with Python integers so the reference remains stdlib-only.
# It is interoperable and vector-tested, but production signers should use constant-time
# platform crypto or an HSM rather than this clarity-first implementation.
_ED_Q = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)
_ED_IDENTITY = (0, 1, 1, 0)


def _ed_xrecover(y):
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_Q - 2, _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q:
        x = x * _ED_I % _ED_Q
    if x & 1:
        x = _ED_Q - x
    return x


_ED_BY = 4 * pow(5, _ED_Q - 2, _ED_Q) % _ED_Q
_ED_BX = _ed_xrecover(_ED_BY)
_ED_BASE = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _ED_Q)


def _ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _ED_Q
    b = (y1 + x1) * (y2 + x2) % _ED_Q
    c = 2 * _ED_D * t1 * t2 % _ED_Q
    d = 2 * z1 * z2 % _ED_Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_Q, h * g % _ED_Q, g * f % _ED_Q, e * h % _ED_Q)


def _ed_scalar_mult(point, scalar):
    result = _ED_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_encode(point):
    x, y, z, _ = point
    inv = pow(z, _ED_Q - 2, _ED_Q)
    x, y = x * inv % _ED_Q, y * inv % _ED_Q
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _ed_decode(encoded):
    if not isinstance(encoded, bytes) or len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 octets")
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _ED_Q:
        raise ValueError("non-canonical Ed25519 point")
    x = _ed_xrecover(y)
    if (x & 1) != (encoded[31] >> 7):
        x = _ED_Q - x
    if (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_Q:
        raise ValueError("point is not on Ed25519")
    point = (x, y, 1, x * y % _ED_Q)
    if _ed_encode(point) != encoded:
        raise ValueError("non-canonical Ed25519 encoding")
    if _ed_encode(_ed_scalar_mult(point, 8)) == _ed_encode(_ED_IDENTITY):
        raise ValueError("small-order Ed25519 point")
    if _ed_encode(_ed_scalar_mult(point, _ED_L)) != _ed_encode(_ED_IDENTITY):
        raise ValueError("Ed25519 point is outside the prime-order subgroup")
    return point


def _ed_equal(p, q):
    return ((p[0] * q[2] - q[0] * p[2]) % _ED_Q == 0
            and (p[1] * q[2] - q[1] * p[2]) % _ED_Q == 0)


def ed25519_public_key(seed):
    """Return the RFC 8032 Ed25519 public key for a 32-octet private seed."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("Ed25519 private seed must be exactly 32 octets")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(
        bytes([digest[0] & 248]) + digest[1:31] + bytes([(digest[31] & 63) | 64]),
        "little",
    )
    return _ed_encode(_ed_scalar_mult(_ED_BASE, scalar))


def ed25519_sign(seed, message):
    """RFC 8032 deterministic Ed25519 signature over `message`."""
    if not isinstance(message, bytes):
        raise ValueError("Ed25519 message must be bytes")
    public_key = ed25519_public_key(seed)
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(
        bytes([digest[0] & 248]) + digest[1:31] + bytes([(digest[31] & 63) | 64]),
        "little",
    )
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _ED_L
    encoded_r = _ed_encode(_ed_scalar_mult(_ED_BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little") % _ED_L
    return encoded_r + ((nonce + challenge * scalar) % _ED_L).to_bytes(32, "little")


def ed25519_verify(public_key, message, signature):
    """Verify an RFC 8032 Ed25519 signature. Invalid inputs return False."""
    if not (isinstance(public_key, bytes) and isinstance(message, bytes)
            and isinstance(signature, bytes)):
        return False
    if len(public_key) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ED_L:
        return False
    try:
        public_point = _ed_decode(public_key)
        r_point = _ed_decode(signature[:32])
    except ValueError:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _ED_L
    return _ed_equal(
        _ed_scalar_mult(_ED_BASE, scalar),
        _ed_add(r_point, _ed_scalar_mult(public_point, challenge)),
    )


def ed25519_spki(public_key):
    """The exact RFC 8410 SubjectPublicKeyInfo DER for a raw Ed25519 public key."""
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 octets")
    return _ED25519_SPKI_PREFIX + public_key


def ed25519_rappid(owner, slug, public_key):
    """Mint the §6.2 keyed RAPPID bound to an Ed25519 SPKI."""
    return mint_rappid(owner, slug, spki_der=ed25519_spki(public_key))


def _b64u_encode(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def _b64u_decode(text):
    if not isinstance(text, str) or not text or "=" in text:
        raise ValueError("base64url segment must be non-empty and unpadded")
    try:
        raw = base64.b64decode(
            text + "=" * ((4 - len(text) % 4) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as ex:
        raise ValueError("invalid base64url segment") from ex
    if _b64u_encode(raw) != text:
        raise ValueError("non-canonical base64url segment")
    return raw


def _json_object_no_duplicates(octets):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError(f"duplicate JSON member {key!r}")
            obj[key] = value
        return obj

    try:
        return json.loads(octets.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as ex:
        raise ValueError("invalid UTF-8 JSON") from ex


def sign_frame_eddsa(frame, kid, seed):
    """Attach a §10 detached, unencoded EdDSA JWS to an eleven-key frame."""
    if not isinstance(frame, dict) or set(frame.keys()) != FRAME_KEYS:
        raise ValueError("only an exact eleven-key frame can be signed")
    public_key = ed25519_public_key(seed)
    expected = ed25519_rappid(
        _RAPPID.match(kid).group(1), _RAPPID.match(kid).group(2), public_key
    ) if rappid_valid(kid) else None
    if expected != kid:
        raise ValueError("kid is not the keyed RAPPID of the signing seed")
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid}
    protected = _b64u_encode(canonical(header).encode("utf-8"))
    unsigned = {key: value for key, value in frame.items() if key != "sig"}
    signing_input = protected.encode("ascii") + b"." + canonical(unsigned).encode("utf-8")
    signed = dict(frame)
    signed["sig"] = protected + ".." + _b64u_encode(ed25519_sign(seed, signing_input))
    return signed


def _verify_frame_eddsa(frame, trust, mode):
    sig = frame.get("sig")
    if not isinstance(sig, str):
        return False, "card frame sig must be a detached JWS string"
    parts = sig.split(".")
    if len(parts) != 3 or parts[1] != "":
        return False, "sig must use detached compact serialization"
    try:
        header_octets = _b64u_decode(parts[0])
        signature = _b64u_decode(parts[2])
        header = _json_object_no_duplicates(header_octets)
    except ValueError as ex:
        return False, str(ex)
    if not isinstance(header, dict) or set(header.keys()) != _JWS_HEADER_KEYS:
        return False, "JWS protected header key set is not §10"
    if header != {"alg": "EdDSA", "b64": False, "crit": ["b64"],
                  "kid": frame["payload"]["key_id"]}:
        return False, "JWS protected header values do not match the card key_id"
    if header_octets != canonical(header).encode("utf-8"):
        return False, "JWS protected header is not canonical"
    entry = trust.get(header["kid"]) if isinstance(trust, dict) else None
    if not isinstance(entry, dict) or set(entry.keys()) != {"spki_der", "synthetic"}:
        return False, "unknown signing key"
    spki = entry["spki_der"]
    if not isinstance(spki, bytes) or not spki.startswith(_ED25519_SPKI_PREFIX) or len(spki) != 44:
        return False, "trusted key is not an Ed25519 SPKI"
    if not isinstance(entry["synthetic"], bool):
        return False, "trusted key synthetic marker is not boolean"
    if Hb("rapp/1:rappid", spki) != header["kid"].rsplit(":", 1)[1]:
        return False, "trusted SPKI does not bind the key_id"
    visibly_synthetic = header["kid"].startswith("rappid:@synthetic/")
    if mode == "production" and (entry["synthetic"] or visibly_synthetic):
        return False, "synthetic test key refused in production mode"
    if mode == "test" and (not entry["synthetic"] or not visibly_synthetic):
        return False, "test profile requires a visibly synthetic key"
    unsigned = {key: value for key, value in frame.items() if key != "sig"}
    signing_input = parts[0].encode("ascii") + b"." + canonical(unsigned).encode("utf-8")
    if not ed25519_verify(spki[len(_ED25519_SPKI_PREFIX):], signing_input, signature):
        return False, "Ed25519 signature verification failed"
    return True, "ok"


def card_inventory(parts, required_parts=CARD_REQUIRED_PARTS):
    """Build the signed, content-addressed hydration inventory from named octets."""
    if not isinstance(parts, dict):
        raise ValueError("card parts must be an object of part name to octets")
    required = set(required_parts)
    if not required <= set(parts):
        raise ValueError(f"missing required card part(s): {sorted(required - set(parts))}")
    inventory = []
    for part in sorted(parts, key=lambda value: value.encode("utf-8")):
        octets = parts[part]
        if not _lclabel(part):
            raise ValueError(f"card part is not an lclabel: {part!r}")
        if not isinstance(octets, bytes):
            raise ValueError(f"card part {part!r} must be bytes")
        inventory.append({
            "part": part, "space": MEDIA_SPACE, "hash": Hb(MEDIA_SPACE, octets),
            "bytes": len(octets), "required": part in required,
        })
    return inventory


def card_continuity(payload, nonce):
    """The exact continuity value challenged after hydration."""
    return {
        "rappid": payload["rappid"],
        "soul_hash": payload["soul_hash"],
        "parent": payload["parent"],
        "engram_root": payload["engram_root"],
        "reflex_capability_root": payload["reflex_capability_root"],
        "nonce": nonce,
    }


def card_wake_challenge(payload, nonce):
    """Bind the one-time URI nonce to the identity and every hydrated root."""
    if not isinstance(nonce, str) or not _CARD_NONCE.match(nonce):
        raise ValueError("card nonce must be 16-64 base64url characters")
    return H("rapp/1:particle", card_continuity(payload, nonce))


def build_card_manifest(profile, rappid, key_id, nonce, parts, compatibility,
                        classification, requested_scope, expires_utc, revocation_url,
                        parent=None, required_parts=CARD_REQUIRED_PARTS):
    """Build a §7.10 manifest payload; no secret or executable field exists."""
    if not set(CARD_REQUIRED_PARTS) <= set(required_parts):
        raise ValueError("soul, engram, and reflex-capability must all be required")
    inventory = card_inventory(parts, required_parts=required_parts)
    by_part = {entry["part"]: entry for entry in inventory}
    payload = {
        "profile": profile,
        "rappid": rappid,
        "soul_hash": by_part["soul"]["hash"],
        "parent": None if parent is None else dict(parent),
        "engram_root": by_part["engram"]["hash"],
        "reflex_capability_root": by_part["reflex-capability"]["hash"],
        "compatibility": {
            "protocol": compatibility["protocol"],
            "runtime": compatibility["runtime"],
            "features": sorted(set(compatibility["features"])),
        },
        "classification": classification,
        "requested_scope": sorted(set(requested_scope)),
        "expires_utc": expires_utc,
        "revocation_url": revocation_url,
        "wake_challenge": None,
        "inventory": inventory,
        "key_id": key_id,
    }
    payload["wake_challenge"] = card_wake_challenge(payload, nonce)
    return payload


def build_card_frame(rappid, seq, utc, manifest, seed, prev=None):
    """Build and sign a calling-card or synthetic debug-card body frame."""
    profile = manifest.get("profile")
    if profile == CARD_PROFILE:
        kind = CARD_CALLING
    elif profile == CARD_TEST_PROFILE:
        kind = CARD_DEBUG
    else:
        raise ValueError(f"unknown card profile: {profile!r}")
    frame = build_frame(kind, rappid, seq, utc, manifest, prev=prev)
    return sign_frame_eddsa(frame, manifest["key_id"], seed)


def _card_https_url(value, suffix=None):
    if not isinstance(value, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and port in (None, 443)
        and not parsed.query
        and not parsed.fragment
        and (suffix is None or parsed.path.endswith(suffix))
    )


def build_card_link(frame, endpoint, nonce):
    """Emit the canonical compact, non-secret `rappid://link/…` URI."""
    if not isinstance(frame, dict) or set(frame.keys()) != FRAME_KEYS:
        raise ValueError("card link requires an exact eleven-key frame")
    if not _card_https_url(endpoint, CARD_VIRTUAL_SUFFIX):
        raise ValueError(f"card endpoint must be an HTTPS *{CARD_VIRTUAL_SUFFIX} URL")
    if not isinstance(nonce, str) or not _CARD_NONCE.match(nonce):
        raise ValueError("card nonce must be 16-64 base64url characters")
    rappid = frame["payload"].get("rappid")
    if not rappid_valid(rappid):
        raise ValueError("card payload does not carry a canonical RAPPID")
    return (
        "rappid://link/" + urllib.parse.quote(rappid, safe="")
        + "?m=" + frame["payload_hash"]
        + "&e=" + urllib.parse.quote(endpoint, safe="")
        + "&n=" + nonce
    )


def parse_card_link(uri):
    """Parse an untrusted card URI and return its four non-secret values."""
    if not isinstance(uri, str):
        raise ValueError("card URI must be a string")
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme != "rappid" or parsed.netloc != "link" or parsed.fragment:
        raise ValueError("card URI must use rappid://link with no fragment")
    if not parsed.path.startswith("/") or parsed.path.count("/") != 1:
        raise ValueError("card URI path must contain one percent-encoded RAPPID")
    encoded_rappid = parsed.path[1:]
    try:
        rappid = urllib.parse.unquote(encoded_rappid, errors="strict")
        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True)
    except (UnicodeDecodeError, ValueError) as ex:
        raise ValueError("malformed card URI encoding") from ex
    if urllib.parse.quote(rappid, safe="") != encoded_rappid:
        raise ValueError("RAPPID path is not canonically percent-encoded")
    if not rappid_valid(rappid):
        raise ValueError("card URI path is not a canonical RAPPID")
    if [key for key, _ in pairs] != ["m", "e", "n"]:
        raise ValueError("card URI query must be exactly m, e, n in canonical order")
    manifest_hash, endpoint, nonce = (value for _, value in pairs)
    if not _hex64(manifest_hash):
        raise ValueError("card URI m is not lowercase 64hex")
    if not _card_https_url(endpoint, CARD_VIRTUAL_SUFFIX):
        raise ValueError(f"card URI e must be an HTTPS *{CARD_VIRTUAL_SUFFIX} URL")
    if not _CARD_NONCE.match(nonce):
        raise ValueError("card URI n must be 16-64 base64url characters")
    canonical_uri = (
        "rappid://link/" + urllib.parse.quote(rappid, safe="")
        + "?m=" + manifest_hash
        + "&e=" + urllib.parse.quote(endpoint, safe="")
        + "&n=" + nonce
    )
    if uri != canonical_uri:
        raise ValueError("card URI is not in canonical compact form")
    return {
        "rappid": rappid, "manifest_hash": manifest_hash,
        "endpoint": endpoint, "nonce": nonce,
    }


def read_card_resource(blob):
    """Parse canonical `.rappid-card.json` octets without duplicate-member ambiguity."""
    if not isinstance(blob, bytes):
        raise ValueError("card resource must be bytes")
    resource = _json_object_no_duplicates(blob)
    if not isinstance(resource, dict):
        raise ValueError("card resource must be a JSON object")
    if canonical(resource).encode("utf-8") != blob:
        raise ValueError("card resource bytes are not canonical")
    return resource


def _valid_utc(value):
    if not isinstance(value, str) or not _UTC.match(value):
        return None
    try:
        return datetime.datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _forbidden_card_material(value):
    forbidden_keys = {
        "password", "passwd", "api-key", "api_key", "apikey", "cookie",
        "set-cookie", "authorization", "bearer", "private-memory",
        "private_memory", "plaintext-memory", "auto-execute", "auto_execute",
        "instruction", "command",
    }
    forbidden_text = re.compile(
        r"(?i)(?:\bbearer\s+[A-Za-z0-9._~+/-]+=*|"
        r"\bapi[_ -]?key\s*[:=]|\bpassword\s*[:=]|\bcookie\s*[:=]|"
        r"\bauto[_ -]?execute\b)")
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower() if isinstance(key, str) else key
            if normalized in forbidden_keys or _forbidden_card_material(child):
                return True
        return False
    if isinstance(value, list):
        return any(_forbidden_card_material(child) for child in value)
    return isinstance(value, str) and bool(forbidden_text.search(value))


def _card_payload_error(payload, frame, link_rappid, mode):
    if not isinstance(payload, dict) or set(payload.keys()) != CARD_PAYLOAD_KEYS:
        return f"manifest payload must have exactly {sorted(CARD_PAYLOAD_KEYS)}"
    if _forbidden_card_material(payload):
        return "manifest contains secret, private-memory, or auto-execute material"
    profile = payload["profile"]
    if mode == "production":
        if profile != CARD_PROFILE or frame["kind"] != CARD_CALLING:
            return "production mode requires body.calling-card with profile rappid-card/1"
    elif mode == "test":
        if profile != CARD_TEST_PROFILE or frame["kind"] != CARD_DEBUG:
            return "test mode requires body.debug-card with profile rappid-card-test/1"
    else:
        return "mode must be production or test"
    if payload["rappid"] != frame["stream_id"] or payload["rappid"] != link_rappid:
        return "manifest rappid, frame stream_id, and URI RAPPID must byte-equal"
    if not rappid_valid(payload["rappid"]):
        return "manifest rappid is not canonical"
    if not rappid_valid(payload["key_id"]):
        return "manifest key_id is not a canonical keyed RAPPID"
    parent = payload["parent"]
    if parent is not None:
        if not isinstance(parent, dict) or set(parent.keys()) != _PARENT_KEYS:
            return "manifest parent must be null or exactly {rappid, particle}"
        if not rappid_valid(parent["rappid"]) or not _hex64(parent["particle"]):
            return "manifest parent is not a canonical RAPPID/particle pointer"
        if parent["rappid"] == payload["rappid"]:
            return "manifest rappid cannot be its own parent"
    for key in ("soul_hash", "engram_root", "reflex_capability_root", "wake_challenge"):
        if not _hex64(payload[key]):
            return f"manifest {key} is not lowercase 64hex"
    compatibility = payload["compatibility"]
    if not isinstance(compatibility, dict) or set(compatibility.keys()) != CARD_COMPATIBILITY_KEYS:
        return "compatibility must be exactly {protocol, runtime, features}"
    if not all(isinstance(compatibility[key], str)
               and _CARD_PROFILE_TOKEN.match(compatibility[key])
               for key in ("protocol", "runtime")):
        return "compatibility protocol/runtime is not a versioned token"
    features = compatibility["features"]
    if not isinstance(features, list) or not all(
            isinstance(feature, str) and _CARD_PROFILE_TOKEN.match(feature)
            for feature in features):
        return "compatibility features must be versioned tokens"
    if features != sorted(set(features)):
        return "compatibility features must be sorted and unique"
    if payload["classification"] not in CARD_CLASSIFICATIONS:
        return "classification is not a registered card classification"
    scopes = payload["requested_scope"]
    if not isinstance(scopes, list) or not all(_lclabel(scope) for scope in scopes):
        return "requested_scope must contain lclabels"
    if scopes != sorted(set(scopes)):
        return "requested_scope must be sorted and unique"
    expires = _valid_utc(payload["expires_utc"])
    issued = _valid_utc(frame["utc"])
    if expires is None or issued is None or expires <= issued:
        return "expires_utc must be calendar-valid and later than frame utc"
    if not _card_https_url(payload["revocation_url"]):
        return "revocation_url must be HTTPS with no credentials, query, or fragment"
    inventory = payload["inventory"]
    if not isinstance(inventory, list):
        return "inventory must be an array"
    seen = []
    by_part = {}
    for entry in inventory:
        if not isinstance(entry, dict) or set(entry.keys()) != CARD_INVENTORY_KEYS:
            return "inventory entries must be exactly {part, space, hash, bytes, required}"
        if not _lclabel(entry["part"]):
            return "inventory part is not an lclabel"
        if entry["space"] != MEDIA_SPACE or not _hex64(entry["hash"]):
            return "inventory address must be lowercase 64hex in rapp/1:egg"
        if not _uint53(entry["bytes"]) or not isinstance(entry["required"], bool):
            return "inventory bytes/required types are invalid"
        seen.append(entry["part"])
        by_part[entry["part"]] = entry
    if seen != sorted(seen, key=lambda value: value.encode("utf-8")):
        return "inventory must be sorted by part UTF-8 bytes"
    if len(seen) != len(set(seen)):
        return "inventory contains duplicate parts"
    if not set(CARD_REQUIRED_PARTS) <= set(by_part):
        return "inventory omits a required soul, engram, or reflex-capability root"
    if not all(by_part[part]["required"] for part in CARD_REQUIRED_PARTS):
        return "core card inventory parts must be required"
    roots = {
        "soul": payload["soul_hash"],
        "engram": payload["engram_root"],
        "reflex-capability": payload["reflex_capability_root"],
    }
    for part, root in roots.items():
        if by_part[part]["hash"] != root:
            return f"{part} inventory hash does not match its signed manifest root"
    if not isinstance(frame["sig"], str):
        return "card frame must carry a signature"
    return None


class CardReplayCache:
    """Atomic nonce claims: only the original connection may resume hydration."""

    def __init__(self, snapshot=None):
        self._claims = {}
        if snapshot is not None:
            if not isinstance(snapshot, dict):
                raise ValueError("card replay snapshot must be an object")
            for nonce, claim in snapshot.items():
                if not isinstance(claim, dict) or set(claim) != {"connection_id", "state"}:
                    raise ValueError("card replay snapshot claim has the wrong schema")
                self.seed(nonce, claim["connection_id"], claim["state"])

    def snapshot(self):
        """Return the canonicalizable state callers persist atomically between attempts."""
        return {
            nonce: dict(self._claims[nonce])
            for nonce in sorted(self._claims)
        }

    def seed(self, nonce, connection_id, state):
        """Seed deterministic persisted state (`hydrating` or `awake`) for recovery/tests."""
        if not _CARD_NONCE.match(nonce):
            raise ValueError("invalid card nonce")
        if not _CARD_CONNECTION.match(connection_id):
            raise ValueError("invalid card connection_id")
        if state not in ("hydrating", "awake"):
            raise ValueError("card replay state must be hydrating or awake")
        self._claims[nonce] = {"connection_id": connection_id, "state": state}

    def claim(self, nonce, connection_id):
        existing = self._claims.get(nonce)
        if existing is None:
            self._claims[nonce] = {"connection_id": connection_id, "state": "hydrating"}
            return True, "new"
        if existing == {"connection_id": connection_id, "state": "hydrating"}:
            return True, "resume"
        if existing["state"] == "hydrating":
            return False, "nonce is already hydrating on another connection"
        return False, "nonce has already awakened"

    def complete(self, nonce, connection_id):
        if self._claims.get(nonce) != {
                "connection_id": connection_id, "state": "hydrating"}:
            raise ValueError("cannot complete an unclaimed card nonce")
        self._claims[nonce] = {"connection_id": connection_id, "state": "awake"}


def _card_environment_error(environment):
    if not isinstance(environment, dict) or set(environment.keys()) != CARD_ENVIRONMENT_KEYS:
        return f"environment must have exactly {sorted(CARD_ENVIRONMENT_KEYS)}"
    if not all(isinstance(environment[key], str) for key in
               ("protocol", "runtime", "max_classification")):
        return "environment protocol/runtime/classification types are invalid"
    if environment["max_classification"] not in CARD_CLASSIFICATIONS:
        return "environment max_classification is not registered"
    for key, grammar in (("features", _CARD_PROFILE_TOKEN), ("granted_scope", _LCLABEL)):
        values = environment[key]
        if not isinstance(values, list) or not all(
                isinstance(value, str) and grammar.match(value) for value in values):
            return f"environment {key} has invalid tokens"
        if values != sorted(set(values)):
            return f"environment {key} must be sorted and unique"
    return None


def _verify_card_hydration(inventory, hydrated):
    if not isinstance(hydrated, dict):
        return False, "hydrated parts must be an object of part name to octets"
    if not all(_lclabel(part) for part in hydrated):
        return False, "hydrated part names must be lclabels"
    permitted = {entry["part"]: entry for entry in inventory}
    extra = sorted(set(hydrated) - set(permitted))
    if extra:
        return False, f"hydration attempted unpermitted part {extra[0]!r}"
    missing = sorted(
        entry["part"] for entry in inventory
        if entry["required"] and entry["part"] not in hydrated)
    if missing:
        return False, f"required hydration part missing: {missing[0]}"
    for part in sorted(hydrated):
        octets = hydrated[part]
        entry = permitted[part]
        if not isinstance(octets, bytes):
            return False, f"hydrated part {part!r} is not bytes"
        if len(octets) != entry["bytes"] or Hb(entry["space"], octets) != entry["hash"]:
            return False, f"hydrated part {part!r} does not match its permitted address"
    return True, "ok"


def verify_card_link(uri, frame, trust, now_utc, revocations, environment,
                     replay_cache, connection_id, hydrated, continuity,
                     mode="production", head=None):
    """Run the §7.10 verification order. Returns (ok, step, reason, result).

    `revocations` maps the signed manifest's revocation URL to an already-authenticated
    iterable of revoked manifest hashes, key ids, or RAPPIDs. Network retrieval and §13
    registry authentication are caller responsibilities; an unavailable location fails.
    The nonce is claimed atomically before hydration. A failed hydration may resume only
    on the same connection; reconnecting cannot race or replay a one-time wake.
    """
    try:
        link = parse_card_link(uri)
    except ValueError as ex:
        return False, "parse", str(ex), None

    if not isinstance(frame, dict) or not isinstance(frame.get("payload"), dict):
        return False, "content-address", "endpoint did not return a frame payload", None
    try:
        computed_manifest_hash = H("rapp/1:particle", frame["payload"])
    except (TypeError, ValueError) as ex:
        return False, "content-address", str(ex), None
    if (computed_manifest_hash != link["manifest_hash"]
            or frame.get("payload_hash") != link["manifest_hash"]):
        return False, "content-address", "URI m does not match the manifest particle", None

    if set(frame.keys()) != FRAME_KEYS:
        return False, "schema", "card resource is not the eleven-key frame", None
    ok, frame_step, reason = verify_frame(
        frame, head=head, stream_id_of_record=link["rappid"])
    if not ok:
        return False, "schema", f"frame §7.5 step {frame_step}: {reason}", None
    reason = _card_payload_error(frame["payload"], frame, link["rappid"], mode)
    if reason:
        return False, "schema", reason, None

    ok, reason = _verify_frame_eddsa(frame, trust, mode)
    if not ok:
        return False, "signature", reason, None

    now = _valid_utc(now_utc)
    expires = _valid_utc(frame["payload"]["expires_utc"])
    if now is None:
        return False, "expiry", "verifier now_utc is not calendar-valid", None
    if now >= expires:
        return False, "expiry", "card manifest is expired", None

    location = frame["payload"]["revocation_url"]
    if not isinstance(revocations, dict) or location not in revocations:
        return False, "revocation", "revocation location unavailable", None
    revoked = revocations[location]
    if not isinstance(revoked, (list, tuple, set, frozenset)):
        return False, "revocation", "revocation result is not an authenticated set", None
    if not all(isinstance(name, str) for name in revoked):
        return False, "revocation", "revocation set members must be strings", None
    revoked_names = {
        link["manifest_hash"], frame["payload"]["key_id"], frame["payload"]["rappid"]}
    if revoked_names & set(revoked):
        return False, "revocation", "card manifest, identity, or signing key is revoked", None

    reason = _card_environment_error(environment)
    if reason:
        return False, "compatibility", reason, None
    compatibility = frame["payload"]["compatibility"]
    if (compatibility["protocol"] != environment["protocol"]
            or compatibility["runtime"] != environment["runtime"]
            or not set(compatibility["features"]) <= set(environment["features"])):
        return False, "compatibility", "runtime/protocol requirements are not satisfied", None

    classification = CARD_CLASSIFICATIONS.index(frame["payload"]["classification"])
    maximum = CARD_CLASSIFICATIONS.index(environment["max_classification"])
    missing_scope = sorted(
        set(frame["payload"]["requested_scope"]) - set(environment["granted_scope"]))
    if classification > maximum:
        return False, "classification-scope", "classification exceeds local policy", None
    if missing_scope:
        return False, "classification-scope", f"requested scope not granted: {missing_scope[0]}", None

    if not isinstance(replay_cache, CardReplayCache):
        return False, "replay-nonce", "a persistent CardReplayCache is required", None
    if not isinstance(connection_id, str) or not _CARD_CONNECTION.match(connection_id):
        return False, "replay-nonce", "connection_id is invalid", None
    ok, reason = replay_cache.claim(link["nonce"], connection_id)
    if not ok:
        return False, "replay-nonce", reason, None

    ok, reason = _verify_card_hydration(frame["payload"]["inventory"], hydrated)
    if not ok:
        return False, "hydration", reason, None

    if not isinstance(continuity, dict) or set(continuity.keys()) != CARD_CONTINUITY_KEYS:
        return False, "continuity", "continuity response has the wrong schema", None
    expected_value = card_continuity(frame["payload"], link["nonce"])
    try:
        expected_challenge = H("rapp/1:particle", expected_value)
        actual_challenge = H("rapp/1:particle", continuity)
    except (TypeError, ValueError):
        return False, "continuity", "continuity response is not a canonical value", None
    if (frame["payload"]["wake_challenge"] != expected_challenge
            or actual_challenge != frame["payload"]["wake_challenge"]):
        return False, "continuity", "one-time continuity challenge failed", None

    replay_cache.complete(link["nonce"], connection_id)
    return True, None, "awake", {
        "status": "awake",
        "profile": frame["payload"]["profile"],
        "rappid": frame["payload"]["rappid"],
        "manifest_hash": link["manifest_hash"],
        "nonce": link["nonce"],
    }


# ---------- §9 the egg (L5) — the one egg spec of record ----------
EGG_VARIANTS = {"organism", "rapplication", "session", "invite", "neighborhood", "estate"}
_EGG_JSON_VARIANTS = {"session", "invite"}          # JSON object eggs (no packed files)
_EGG_MANIFEST_KEYS = {"schema", "variant", "rappid", "created_utc", "contents", "payload", "sig"}


def egg_address(manifest):
    """§9.1 the egg's one §5 address: H('rapp/1:egg-manifest', manifest \\ {sig})."""
    return H("rapp/1:egg-manifest", {k: v for k, v in manifest.items() if k != "sig"})


def _egg_contents(files):
    """§9.1 contents: {path: Hb('rapp/1:egg', octets)}, sorted ascending by UTF-8 bytes of path."""
    items = [{"path": p, "hash": Hb("rapp/1:egg", octets)} for p, octets in files.items()]
    items.sort(key=lambda c: c["path"].encode("utf-8"))
    return items


def pack_egg(variant, rappid, created_utc, files=None, payload=None, sig=None):
    """Build a byte-reproducible §9 `rapp/1-egg`. Returns bytes.

    files: {relative_posix_path: octets} for ZIP (tree) variants; MUST be empty for
    JSON variants (session/invite). Two conformant packers of the same manifest value
    emit byte-identical eggs (ZIP stored, manifest.json first, timestamps 1980-01-01)."""
    if variant not in EGG_VARIANTS:
        raise ValueError(f"unknown variant: {variant}")
    files = dict(files or {})
    payload = {} if payload is None else payload
    is_json = variant in _EGG_JSON_VARIANTS
    if is_json and files:
        raise ValueError(f"{variant} is a JSON variant — no packed files")
    manifest = {
        "schema": "rapp/1-egg", "variant": variant, "rappid": rappid,
        "created_utc": created_utc,
        "contents": [] if is_json else _egg_contents(files),
        "payload": payload, "sig": sig,
    }
    man_octets = canonical(manifest).encode("utf-8")
    if is_json:
        return man_octets                                  # JSON egg serialized == canonical(manifest)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        def _w(name, data):
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zi.flag_bits |= 0x800                          # UTF-8 filename flag
            z.writestr(zi, data)
        _w("manifest.json", man_octets)                    # manifest.json first
        for c in manifest["contents"]:                     # then contents order
            _w(c["path"], files[c["path"]])
    return buf.getvalue()


def read_egg(blob):
    """Parse a rapp/1-egg → (manifest_dict, files_dict). files={} for JSON variants."""
    if blob[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(blob))
        manifest = json.loads(z.read("manifest.json"))
        files = {n: z.read(n) for n in z.namelist() if n != "manifest.json"}
        return manifest, files
    return json.loads(blob), {}


def _egg_variant_ok(v, m, files):
    p = m["payload"]
    if v == "organism":
        if not {"rappid.json", "soul.md"} <= set(files):
            return "organism contents MUST include rappid.json + soul.md"
    elif v == "rapplication":
        if "rappid.json" not in files:
            return "rapplication MUST include rappid.json"
        root_py = [n for n in files if "/" not in n and n.endswith(".py")]
        if len(root_py) != 1:
            return "rapplication MUST have exactly one root agent.py"
    elif v == "session":
        if set(p.keys()) != {"runtime", "transcript"}:
            return "session payload MUST be {runtime, transcript}"
    elif v == "invite":
        if set(p.keys()) != {"target_rappid", "target_url", "target_kind"}:
            return "invite payload MUST be {target_rappid, target_url, target_kind}"
        if m["sig"] is None:
            return "invite sig is REQUIRED"
    elif v == "neighborhood":
        if set(p.keys()) != {"members"}:
            return "neighborhood payload MUST be {members}"
    elif v == "estate":
        if set(p.keys()) != {"neighborhoods"}:
            return "estate payload MUST be {neighborhoods}"
    return None


def verify_egg(blob):
    """§9.3 consumer verify — integrity then viability. Returns (ok, failing_step, reason)."""
    try:
        manifest, files = read_egg(blob)
    except Exception as e:
        return (False, "parse", str(e))
    if not isinstance(manifest, dict) or set(manifest.keys()) != _EGG_MANIFEST_KEYS:
        return (False, "§9.1", "manifest must have exactly the 7 members")
    if manifest["schema"] != "rapp/1-egg":
        return (False, "§9.1", f"schema != rapp/1-egg ({manifest.get('schema')})")
    v = manifest["variant"]
    if v not in EGG_VARIANTS:
        return (False, "§9.2", f"unknown variant {v}")
    if not rappid_valid(manifest["rappid"]):
        return (False, "§6.1", f"bad rappid {manifest['rappid']}")
    if not (isinstance(manifest["created_utc"], str) and _UTC.match(manifest["created_utc"])):
        return (False, "§7.4", "created_utc not the fixed millisecond form")
    contents = manifest["contents"]
    if not isinstance(contents, list):
        return (False, "§9.1", "contents not a list")
    paths = [c["path"] for c in contents]
    for p in paths:
        if p.startswith("/") or "\\" in p or any(seg in ("", ".", "..") for seg in p.split("/")):
            return (False, "§9.1", f"bad path grammar: {p}")
    if paths != sorted(paths, key=lambda x: x.encode("utf-8")):
        return (False, "§9.1", "contents not sorted by path bytes")
    if len(paths) != len(set(paths)):
        return (False, "§9.1", "duplicate path")
    if v in _EGG_JSON_VARIANTS:
        if contents != []:
            return (False, "§9.1", "JSON variant contents MUST be []")
        if blob != canonical(manifest).encode("utf-8"):
            return (False, "§9.1", "JSON egg serialized form != canonical(manifest)")
    else:
        if set(files.keys()) != set(paths):                # zip-slip defense
            return (False, "§9.1", "archive entry set != contents")
        for c in contents:
            if Hb("rapp/1:egg", files[c["path"]]) != c["hash"]:
                return (False, "§5", f"content hash mismatch: {c['path']}")
    why = _egg_variant_ok(v, manifest, files)
    if why:
        return (False, "§9.2", why)
    return (True, None, "ok")
