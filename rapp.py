"""rapp.py — reference implementation of the RAPP protocol suite (rev-5).

Stdlib only (json, hashlib, uuid, re, base64). Implements the primitives that the
spec claims are byte-for-byte interoperable, so the conformance suite can PROVE the
standard is implementable and self-consistent — and so it can be run against real
estate artifacts to see where reality conforms and where reality is the drift RAPP fixes.

Scope note: §4 canonicalization here is JCS restricted to the string/int/bool/null/
array/object domain (no floats) — exactly the profile RAPP §4 allows for payloads.
Full IEEE-754 number serialization (RFC 8785) is the production requirement; the
reference vectors use exact-integer payloads so the hashes are reproducible anywhere.
"""
import hashlib
import json
import re
import uuid
import io
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
        if abs(v) > 2**53 - 1:
            # I-JSON (RFC 7493) interoperable domain, which SPEC.md adopts: a
            # JS consumer's JSON.parse collapses larger ints (and >=1e21
            # re-serializes as exponent notation), so a producer-side hash
            # over such a value can NEVER be reproduced by a browser verifier.
            raise ValueError("int outside interoperable range (|n| > 2^53-1); carry it as a string")
        return json.dumps(v)               # exact integers only in this profile
    if isinstance(v, float):
        raise ValueError("floats require full-JCS number serialization; use ints/strings")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        # RFC 8785 orders member names by UTF-16 code units; plain sorted()
        # is code-POINT order and diverges for non-BMP keys.
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
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
    return bool(_RAPPID.match(s))


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
