"""rapp.py — reference implementation of the RAPP protocol suite (rev-14).

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
import base64
import hmac
import json
import re
import uuid
import struct
import urllib.parse
import unicodedata
import zlib
from datetime import datetime

SPEC = "rapp/1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_LCLABEL = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_RAPPID = re.compile(r"rappid:@([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:-[a-z0-9]+)*):([0-9a-f]{64})")
MAX_SEALED_PLAINTEXT_BYTES = 2**30
MAX_CANONICAL_BYTES = 1024 * 1024
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")

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


def sealed_plaintext_commitment(dek, plaintext):
    """Keyed plaintext commitment; reveals nothing useful without the DEK."""
    if not isinstance(dek, bytes) or len(dek) != 32:
        raise ValueError("sealed DEK MUST be 32 bytes")
    if not isinstance(plaintext, bytes):
        raise ValueError("sealed plaintext MUST be bytes")
    prk = hmac.new(b"\x00" * 32, dek, hashlib.sha256).digest()
    key = hmac.new(
        prk,
        b"rapp/1:sealed-commitment\x01",
        hashlib.sha256,
    ).digest()
    return hmac.new(key, plaintext, hashlib.sha256).hexdigest()


# ---------- §6 identity ----------
def mint_rappid(owner, slug, spki_der=None):
    """§6.2 mint-once. keyless = Hb(uuid4); keyed = Hb(SPKI). NEVER a name-hash."""
    if (
        not isinstance(owner, str)
        or not _LCLABEL.fullmatch(owner)
        or not 1 <= len(owner) <= 39
        or not isinstance(slug, str)
        or not _LCLABEL.fullmatch(slug)
        or not 1 <= len(slug) <= 100
    ):
        raise ValueError("owner or slug violates the RAPPID grammar")
    if spki_der is not None:
        tail = Hb("rapp/1:rappid", spki_der)
    else:
        tail = Hb("rapp/1:rappid", uuid.uuid4().bytes)
    return f"rappid:@{owner}/{slug}:{tail}"

def rappid_valid(s):
    if not isinstance(s, str):
        return False
    match = _RAPPID.fullmatch(s)
    return bool(
        match
        and 1 <= len(match.group(1)) <= 39
        and 1 <= len(match.group(2)) <= 100
    )


_KIND = re.compile(r"([a-z0-9]+(?:-[a-z0-9]+)*)\.([a-z0-9]+(?:-[a-z0-9]+)*)")


def kind_valid(kind):
    """§6.1.1 `kind = lclabel "." lclabel`, each label 1–64 characters."""
    match = _KIND.fullmatch(kind) if isinstance(kind, str) else None
    return bool(match and 1 <= len(match.group(1)) <= 64 and 1 <= len(match.group(2)) <= 64)


def stream_form(stream_id):
    """§6.1.1: "memory-stream", "body-stream" or "swarm-stream", or None if the string is none of them."""
    if not isinstance(stream_id, str):
        return None
    if stream_id.startswith("net:"):
        return "swarm-stream" if _LCLABEL.fullmatch(stream_id[4:]) else None
    if rappid_valid(stream_id):
        return "body-stream"
    head, sep, instance = stream_id.rpartition(":")
    if sep and rappid_valid(head) and _LCLABEL.fullmatch(instance) and 1 <= len(instance) <= 64:
        return "memory-stream"
    return None


def _names_ok(value):
    """§4 (rev-17 E-5, E-6): a producer treats every `payload` member name, at any depth, as a new string.

    It refuses (never normalizes) a name that is not NFC or that holds a code point unassigned
    (General_Category Cn) in the Unicode version this Python implements."""
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for name, item in current.items():
                if not isinstance(name, str):
                    raise ValueError("payload member names must be strings")
                if not unicodedata.is_normalized("NFC", name):
                    raise ValueError(f"payload member name is not NFC (§4): {name!r}")
                if any(unicodedata.category(char) == "Cn" for char in name):
                    raise ValueError(f"payload member name holds an unassigned code point (§4): {name!r}")
                stack.append(item)
        elif isinstance(current, list):
            stack.extend(current)


def utc_valid(value):
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def rappid_parts(value):
    match = _RAPPID.fullmatch(value or "")
    if not match:
        raise ValueError("invalid RAPPID")
    return {
        "owner": match.group(1),
        "slug": match.group(2),
        "hash": match.group(3),
    }


def _b64url_decode(value):
    if (
        not isinstance(value, str)
        or "=" in value
        or not _B64URL.fullmatch(value)
        or len(value) % 4 == 1
    ):
        raise ValueError("base64url value must be unpadded")
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("base64url value is not canonical")
    return decoded


def parse_detached_jws(sig):
    parts = sig.split(".") if isinstance(sig, str) else []
    if len(parts) != 3 or parts[1] != "":
        raise ValueError("JWS must use detached compact serialization")
    header_octets = _b64url_decode(parts[0])
    header = _strict_json(header_octets)
    if not isinstance(header, dict) or set(header) != {"alg", "b64", "crit", "kid"}:
        raise ValueError("JWS protected header must have exactly alg,b64,crit,kid")
    if header["alg"] not in {"EdDSA", "ES256"}:
        raise ValueError("JWS alg must be EdDSA or ES256")
    if header["b64"] is not False or header["crit"] != ["b64"]:
        raise ValueError("JWS must use b64=false with crit=['b64']")
    if not rappid_valid(header["kid"]):
        raise ValueError("JWS kid must be a valid keyed RAPPID")
    if header_octets != canonical(header).encode("utf-8"):
        raise ValueError("JWS protected header is not canonical")
    signature = _b64url_decode(parts[2])
    if len(signature) != 64:
        raise ValueError("JWS signature must be exactly 64 octets (§7.5 step 1, §10)")
    return header, parts[0], signature


def verify_detached_jws(value, sig, spki_der, expected_kid=None):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError:
        return False, "cryptography is required to verify signed RAPP artifacts"
    try:
        header, protected, signature = parse_detached_jws(sig)
        kid = header["kid"]
        if expected_kid is not None and kid != expected_kid:
            return False, "JWS kid does not match required signer"
        if Hb("rapp/1:rappid", spki_der) != rappid_parts(kid)["hash"]:
            return False, "JWS key does not match the kid RAPPID tail"
        signing_input = (
            protected.encode("ascii") + b"." + canonical(value).encode("utf-8")
        )
        public_key = serialization.load_der_public_key(spki_der)
        if header["alg"] == "EdDSA":
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False, "EdDSA JWS did not resolve to an Ed25519 key"
            public_key.verify(signature, signing_input)
        else:
            if not (
                isinstance(public_key, ec.EllipticCurvePublicKey)
                and isinstance(public_key.curve, ec.SECP256R1)
                and len(signature) == 64
            ):
                return False, "ES256 JWS requires a P-256 key and 64-byte raw signature"
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            public_key.verify(
                encode_dss_signature(r, s),
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
    except InvalidSignature:
        return False, "detached JWS signature is invalid"
    except (ValueError, TypeError) as exc:
        return False, str(exc)
    return True, "ok"


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


def verify_frame(
    frame,
    head=None,
    stream_id_of_record=None,
    signature_verifier=None,
):
    """§7.5 consumer checklist. Returns (ok, failing_step_or_None, reason)."""
    # 1 shape & types
    if set(frame.keys()) != FRAME_KEYS:
        return False, "1", f"key set != 11 ({sorted(frame.keys())})"
    if frame["spec"] != SPEC:
        return False, "1", "spec != rapp/1"
    if not (isinstance(frame["kind"], str) and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*\.[a-z0-9]+(-[a-z0-9]+)*", frame["kind"])):
        return False, "1", "kind grammar"
    if not isinstance(frame["stream_id"], str):
        return False, "1", "stream_id type"
    if not (isinstance(frame["seq"], int) and not isinstance(frame["seq"], bool) and 0 <= frame["seq"] <= 2**53 - 1):
        return False, "1", "seq not uint53"
    if not utc_valid(frame["utc"]):
        return False, "1", "utc not fixed form"
    if not isinstance(frame["payload"], dict):
        return False, "1", "payload not object"
    for k in ("payload_hash", "frame_hash"):
        if not (isinstance(frame[k], str) and _HEX64.fullmatch(frame[k])):
            return False, "1", f"{k} not 64hex"
    for k in ("prev", "prev_wave"):
        if not (frame[k] is None or (isinstance(frame[k], str) and _HEX64.fullmatch(frame[k]))):
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
    # 6 signature
    if is_swarm and frame["sig"] is None:
        return False, "6", "swarm frame must be signed"
    if frame["sig"] is not None:
        ok, why = _signature_ok(frame, signature_verifier)
        if not ok:
            return False, "6", why
    return True, None, "ok"


# ---------- §9 the egg (L5) — the one egg spec of record ----------
EGG_VARIANTS = {
    "organism",
    "rapplication",
    "session",
    "invite",
    "neighborhood",
    "estate",
    "sealed",
}
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


_ZIP_LOCAL = struct.Struct("<IHHHHHIIIHH")          # 30-octet local file header
_ZIP_CENTRAL = struct.Struct("<IHHHHHHIIIHHHHHII")  # 46-octet central directory header
_ZIP_END = struct.Struct("<IHHHHIIH")               # 22-octet end-of-central-directory record
_ZIP_VERSION = 0x0014                               # §9.1: version needed 20, version made by 0x0014
_ZIP_FLAGS = 0x0800                                 # §9.1: UTF-8 name; no data descriptor, no encryption
_ZIP_DOS_TIME, _ZIP_DOS_DATE = 0x0000, 0x0021       # §9.1: 1980-01-01 00:00:00
_ZIP_MAX_ENTRIES = 0xFFFE                           # 0xFFFF is the ZIP64 marker
_ZIP_MAX_FIELD = 0xFFFFFFFE                         # 0xFFFFFFFF is the ZIP64 marker


def _zip_pack(entries):
    """§9.1 container writer: [(name, octets)] in entry order -> bytes, every header field as pinned.

    Refuses (ValueError) an archive that would need ZIP64: more than 65,534 entries, or any
    size or offset above 0xFFFFFFFE."""
    if len(entries) > _ZIP_MAX_ENTRIES:
        raise ValueError("egg needs more than 65,534 ZIP entries; ZIP64 is not a §9.1 container")
    local, central, offset = [], [], 0
    for name, data in entries:
        encoded = name.encode("utf-8")
        if len(encoded) > 0xFFFF:
            raise ValueError(f"ZIP entry name exceeds 65,535 octets: {name!r}")
        if len(data) > _ZIP_MAX_FIELD or offset > _ZIP_MAX_FIELD:
            raise ValueError("egg needs a ZIP size or offset above 0xFFFFFFFE; ZIP64 is not a §9.1 container")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        fields = (_ZIP_FLAGS, 0, _ZIP_DOS_TIME, _ZIP_DOS_DATE, crc, len(data), len(data), len(encoded), 0)
        header = _ZIP_LOCAL.pack(0x04034B50, _ZIP_VERSION, *fields) + encoded
        central.append(_ZIP_CENTRAL.pack(0x02014B50, _ZIP_VERSION, _ZIP_VERSION, *fields, 0, 0, 0, 0, offset) + encoded)
        local += [header, data]
        offset += len(header) + len(data)
    directory = b"".join(central)
    if offset > _ZIP_MAX_FIELD or len(directory) > _ZIP_MAX_FIELD:
        raise ValueError("egg needs a ZIP size or offset above 0xFFFFFFFE; ZIP64 is not a §9.1 container")
    end = _ZIP_END.pack(0x06054B50, 0, 0, len(entries), len(entries), len(directory), offset, 0)
    return b"".join(local) + directory + end


def pack_egg(variant, rappid, created_utc, files=None, payload=None, sig=None):
    """§9.3 Producer: build a byte-reproducible `rapp/1-egg`, or refuse (ValueError). Returns bytes.

    files: {relative_posix_path: octets} for ZIP (tree) variants; MUST be empty for
    JSON variants (session/invite). Every §9.1 container field is written exactly as
    pinned, so two conformant packers of the same manifest value emit byte-identical
    eggs. The packed octets must then pass consumer steps (0)-(2), sub-eggs included
    (verify_egg_static); the §10 signature equation needs the signer's key context and
    is left to the consumer."""
    if not isinstance(variant, str) or variant not in EGG_VARIANTS:
        raise ValueError(f"unknown variant: {variant!r}")
    if not rappid_valid(rappid):
        raise ValueError(f"egg rappid is not a §6.1 rappid: {rappid!r}")
    if not utc_valid(created_utc):
        raise ValueError(f"created_utc is not the §7.4 millisecond UTC form: {created_utc!r}")
    payload = {} if payload is None else payload
    if not isinstance(payload, dict):
        raise ValueError("egg payload MUST be an object")
    _names_ok(payload)
    if sig is not None:
        if not isinstance(sig, str):
            raise ValueError("egg sig MUST be null or a §10 detached JWS string")
        try:
            parse_detached_jws(sig)
        except ValueError as exc:
            raise ValueError(f"egg sig is not a §10 detached JWS: {exc}") from None
    elif variant in {"invite", "sealed"}:
        raise ValueError(f"a {variant} egg's sig is REQUIRED (§9.1, §9.2)")
    try:
        files = dict(files or {})
    except (TypeError, ValueError):
        raise ValueError("egg files MUST be a {path: octets} mapping") from None
    is_json = variant in _EGG_JSON_VARIANTS
    if is_json and files:
        raise ValueError(f"{variant} is a JSON variant — no packed files")
    for path, octets in files.items():
        if not _path_valid(path):
            raise ValueError(f"egg path violates the §9.1 path grammar: {path!r}")
        if not isinstance(octets, bytes):
            raise ValueError(f"egg file octets MUST be bytes: {path!r}")
    if not _path_set_valid(list(files)):
        raise ValueError("egg contents MUST NOT hold the root path manifest.json")
    manifest = {
        "schema": "rapp/1-egg", "variant": variant, "rappid": rappid,
        "created_utc": created_utc,
        "contents": [] if is_json else _egg_contents(files),
        "payload": payload, "sig": sig,
    }
    man_octets = canonical(manifest).encode("utf-8")
    if is_json:
        blob = man_octets                                  # JSON egg serialized == canonical(manifest)
    else:
        blob = _zip_pack(                                  # manifest.json first, then contents order
            [("manifest.json", man_octets)]
            + [(c["path"], files[c["path"]]) for c in manifest["contents"]]
        )
    ok, step, why = verify_egg_static(blob)
    if not ok:
        raise ValueError(f"producer refuses to emit an egg a consumer refuses at {step}: {why}")
    return blob


def _strict_json(blob):
    raw = blob.encode("utf-8") if isinstance(blob, str) else blob
    if not isinstance(raw, bytes) or len(raw) > MAX_CANONICAL_BYTES:
        raise ValueError("JSON exceeds the 1 MiB input ceiling")

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs)
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > 64:
            raise ValueError("JSON nesting depth exceeds 64")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    if len(canonical(value).encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical JSON exceeds the 1 MiB input ceiling")
    return value


def _zip_unpack(blob):
    """§9.1 container reader: ZIP octets -> [(name, octets)] in archive order, or ValueError.

    Parses the end record, the central directory and the local records itself (never
    through zipfile) and refuses every violation of §9.1's container paragraph. It accepts
    any value of version made by, version needed (when the local and central headers
    agree) and the internal and external attributes, and never interprets them."""
    end_at = len(blob) - _ZIP_END.size
    if end_at < 0 or blob[end_at:end_at + 4] != b"PK\x05\x06":
        if blob.rfind(b"PK\x05\x06") >= 0:
            raise ValueError("ZIP end record has a comment or octets follow it")
        raise ValueError("ZIP end-of-central-directory record is missing")
    (_, disk, directory_disk, disk_entries, entries_total, directory_size, directory_offset,
     comment_length) = _ZIP_END.unpack_from(blob, end_at)
    if comment_length:
        raise ValueError("ZIP archive comment MUST be empty")
    if disk or directory_disk:
        raise ValueError("ZIP end record disk numbers MUST be 0")
    if disk_entries != entries_total:
        raise ValueError("ZIP end record entry counts MUST be equal")
    if entries_total == 0xFFFF or 0xFFFFFFFF in (directory_size, directory_offset):
        raise ValueError("ZIP64 records are not a §9.1 container")
    if directory_offset + directory_size != end_at:
        if end_at >= 20 and blob[end_at - 20:end_at - 16] == b"PK\x06\x07":
            raise ValueError("ZIP64 records are not a §9.1 container")
        raise ValueError("ZIP central directory MUST end at the end record")
    entries, cursor, at = [], 0, directory_offset
    for _ in range(entries_total):
        if at + _ZIP_CENTRAL.size > end_at or blob[at:at + 4] != b"PK\x01\x02":
            raise ValueError("ZIP central directory header is malformed")
        (_, _made_by, needed, flags, method, time, date, crc, compressed, size,
         name_length, extra_length, file_comment_length, disk_start, _internal, _external,
         offset) = _ZIP_CENTRAL.unpack_from(blob, at)
        name_octets = blob[at + _ZIP_CENTRAL.size:at + _ZIP_CENTRAL.size + name_length]
        at += _ZIP_CENTRAL.size + name_length + extra_length + file_comment_length
        if at > end_at:
            raise ValueError("ZIP central directory header overruns the directory")
        if flags != _ZIP_FLAGS:
            raise ValueError("ZIP flags MUST be exactly 0x0800 (UTF-8 name; no data descriptor, no encryption)")
        if method != 0:
            raise ValueError("ZIP entries MUST use stored compression (method 0)")
        if (time, date) != (_ZIP_DOS_TIME, _ZIP_DOS_DATE):
            raise ValueError("ZIP entry timestamp MUST be 1980-01-01 00:00:00 (time 0x0000, date 0x0021)")
        if extra_length:
            raise ValueError("ZIP entry extra fields MUST be empty")
        if file_comment_length:
            raise ValueError("ZIP file comments MUST be empty")
        if disk_start:
            raise ValueError("ZIP disk number start MUST be 0")
        if 0xFFFFFFFF in (compressed, size, offset):
            raise ValueError("ZIP64 records are not a §9.1 container")
        if compressed != size:
            raise ValueError("stored ZIP entry sizes differ")
        if offset != cursor:
            raise ValueError("ZIP local records MUST be contiguous, in entry order, from octet 0")
        local = blob[cursor:cursor + _ZIP_LOCAL.size]
        if len(local) != _ZIP_LOCAL.size or local[:4] != b"PK\x03\x04":
            raise ValueError("ZIP local file header is malformed")
        if _ZIP_LOCAL.unpack(local)[1:] != (
            needed, flags, method, time, date, crc, compressed, size, name_length, extra_length
        ):
            raise ValueError("ZIP local and central headers MUST hold the same values")
        start = cursor + _ZIP_LOCAL.size + name_length
        if blob[cursor + _ZIP_LOCAL.size:start] != name_octets:
            raise ValueError("ZIP local and central file names differ")
        data = blob[start:start + size]
        cursor = start + size
        if cursor > directory_offset:
            raise ValueError("ZIP local record overruns the central directory")
        if zlib.crc32(data) & 0xFFFFFFFF != crc:
            raise ValueError("ZIP entry CRC-32 mismatch")
        try:
            name = bytes(name_octets).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("ZIP entry name is not UTF-8") from None
        entries.append((name, bytes(data)))
    if at != end_at:
        raise ValueError("ZIP central directory holds octets beyond its entries")
    if cursor != directory_offset:
        raise ValueError("ZIP local records MUST end at the central directory")
    return entries


def read_egg(blob):
    """Parse a rapp/1-egg → (manifest_dict, files_dict). files={} for JSON variants."""
    if blob[:2] == b"PK":
        entries = _zip_unpack(blob)
        names = [name for name, _ in entries]
        if len(names) != len(set(names)):
            raise ValueError("duplicate ZIP entry")
        if not names or names[0] != "manifest.json":
            raise ValueError("manifest.json MUST be the first ZIP entry")
        manifest_octets = entries[0][1]
        manifest = _strict_json(manifest_octets)
        if manifest_octets != canonical(manifest).encode("utf-8"):
            raise ValueError("manifest.json bytes MUST equal canonical(manifest)")
        contents = manifest.get("contents") if isinstance(manifest, dict) else None
        if not isinstance(contents, list):
            raise ValueError("manifest contents MUST be a list")
        if not all(
            isinstance(item, dict)
            and set(item) == {"path", "hash"}
            and isinstance(item["path"], str)
            and isinstance(item["hash"], str)
            for item in contents
        ):
            raise ValueError("manifest content descriptors MUST be {path,hash} strings")
        expected = ["manifest.json"] + [item["path"] for item in contents]
        if names != expected:
            raise ValueError("ZIP entry order/set does not match manifest contents")
        return manifest, dict(entries[1:])
    manifest = _strict_json(blob)
    if blob != canonical(manifest).encode("utf-8"):
        raise ValueError("JSON egg bytes MUST equal canonical(manifest)")
    return manifest, {}


def _member_filename(rappid):
    parts = rappid_parts(rappid)
    return f"{parts['owner']}--{parts['slug']}.egg"


def _identity_matches_manifest(manifest, files):
    try:
        identity = _strict_json(files["rappid.json"])
    except Exception as exc:
        return f"rappid.json is invalid: {exc}"
    if not isinstance(identity, dict):
        return "rappid.json MUST be an object"
    if "schema" in identity and identity["schema"] != "rapp/1":
        return "rappid.json schema, when present, MUST be rapp/1"
    if identity.get("rappid") != manifest["rappid"]:
        return "rappid.json identity MUST equal manifest.rappid"
    return None


def _egg_variant_ok(
    v,
    m,
    files,
    signature_verifier=None,
    estate_owner_rappid=None,
    depth=0,
    *,
    verify_child=None,
):
    if verify_child is None:
        def verify_child(sub_blob, sub_depth):
            return verify_egg(
                sub_blob,
                signature_verifier=signature_verifier,
                estate_owner_rappid=estate_owner_rappid,
                _depth=sub_depth,
            )
    p = m["payload"]
    if v == "organism":
        if not {"rappid.json", "soul.md"} <= set(files):
            return "organism contents MUST include rappid.json + soul.md"
        why = _identity_matches_manifest(m, files)
        if why:
            return why
    elif v == "rapplication":
        if "rappid.json" not in files:
            return "rapplication MUST include rappid.json"
        why = _identity_matches_manifest(m, files)
        if why:
            return why
        root_py = [n for n in files if "/" not in n and n.endswith(".py")]
        if root_py != ["agent.py"]:
            return "rapplication MUST have exactly one root agent.py"
    elif v == "session":
        if set(p.keys()) != {"runtime", "transcript"}:
            return "session payload MUST be {runtime, transcript}"
        if not isinstance(p["runtime"], str) or not isinstance(p["transcript"], list):
            return "session runtime MUST be text and transcript MUST be an array"
        if not all(isinstance(turn, dict) for turn in p["transcript"]):
            return "session transcript entries MUST be objects"
    elif v == "invite":
        if set(p.keys()) != {"target_rappid", "target_url", "target_kind"}:
            return "invite payload MUST be {target_rappid, target_url, target_kind}"
        if m["sig"] is None:
            return "invite sig is REQUIRED"
        if not rappid_valid(p["target_rappid"]):
            return "invite target_rappid MUST be a rappid"
        if (
            not isinstance(p["target_kind"], str)
            or p["target_kind"] not in {"neighborhood", "estate"}
        ):
            return "invite target_kind MUST be neighborhood or estate"
        if not isinstance(p["target_url"], str):
            return "invite target_url MUST be text"
        try:
            target = urllib.parse.urlsplit(p["target_url"])
        except ValueError:
            return "invite target_url is invalid"
        if (
            target.scheme not in {"http", "https"}
            or not target.hostname
            or target.username is not None
            or target.password is not None
        ):
            return "invite target_url MUST be an absolute HTTP(S) URL without credentials"
    elif v == "neighborhood":
        if set(p.keys()) != {"members"}:
            return "neighborhood payload MUST be {members}"
        members = p["members"]
        if (
            not isinstance(members, list)
            or not all(
                isinstance(member, str) and rappid_valid(member)
                for member in members
            )
            or len(members) != len(set(members))
        ):
            return "neighborhood members MUST be unique rappids"
        member_filenames = [_member_filename(member) for member in members]
        if len(member_filenames) != len(set(member_filenames)):
            return "neighborhood members MUST have unique owner/slug filenames"
        expected_files = dict(zip(member_filenames, members))
        if set(files) != set(expected_files):
            return "neighborhood files MUST match members one-to-one"
        for filename, member in expected_files.items():
            ok, step, why = verify_child(files[filename], depth + 1)
            if not ok:
                return f"neighborhood member {filename} refused at {step}: {why}"
            child, _ = read_egg(files[filename])
            if child["variant"] != "organism" or child["rappid"] != member:
                return "neighborhood member egg identity or variant mismatch"
    elif v == "estate":
        if set(p.keys()) != {"neighborhoods"}:
            return "estate payload MUST be {neighborhoods}"
        neighborhoods = p["neighborhoods"]
        if (
            not isinstance(neighborhoods, list)
            or not all(
                isinstance(item, str) and rappid_valid(item)
                for item in neighborhoods
            )
            or len(neighborhoods) != len(set(neighborhoods))
        ):
            return "estate neighborhoods MUST be unique rappids"
        neighborhood_filenames = [
            _member_filename(neighborhood) for neighborhood in neighborhoods
        ]
        if len(neighborhood_filenames) != len(set(neighborhood_filenames)):
            return "estate neighborhoods MUST have unique owner/slug filenames"
        expected_files = dict(zip(neighborhood_filenames, neighborhoods))
        if set(files) != set(expected_files):
            return "estate files MUST match neighborhoods one-to-one"
        for filename, neighborhood in expected_files.items():
            ok, step, why = verify_child(files[filename], depth + 1)
            if not ok:
                return f"estate neighborhood {filename} refused at {step}: {why}"
            child, _ = read_egg(files[filename])
            if child["variant"] != "neighborhood" or child["rappid"] != neighborhood:
                return "estate neighborhood egg identity or variant mismatch"
    elif v == "sealed":
        expected = {
            "schema",
            "cipher",
            "nonce",
            "plaintext_commitment",
            "plaintext_bytes",
            "media_type",
            "key_id",
            "key_service_rappid",
            "key_service_url",
            "access",
            "aad_hash",
        }
        if set(p.keys()) != expected:
            return "sealed payload has missing or unknown members"
        if set(files.keys()) != {"ciphertext.bin"}:
            return "sealed contents MUST contain only ciphertext.bin"
        if m["sig"] is None:
            return "sealed sig is REQUIRED"
        if p["schema"] != "rapp-sealed-artifact/1":
            return "sealed schema MUST be rapp-sealed-artifact/1"
        if p["cipher"] != "A256GCM":
            return "sealed cipher MUST be A256GCM"
        if p["access"] != "scoped-key-release":
            return "sealed access MUST be scoped-key-release"
        if not (
            isinstance(p["nonce"], str)
            and re.fullmatch(r"[A-Za-z0-9_-]{16}", p["nonce"])
        ):
            return "sealed nonce MUST be 12-byte unpadded base64url"
        try:
            nonce = base64.urlsafe_b64decode(p["nonce"] + "==")
        except Exception:
            return "sealed nonce is not base64url"
        if len(nonce) != 12:
            return "sealed nonce MUST decode to 12 bytes"
        for key in ("plaintext_commitment", "key_id", "aad_hash"):
            if not isinstance(p[key], str) or not _HEX64.fullmatch(p[key]):
                return f"sealed {key} MUST be 64 lowercase hex"
        if not (
            isinstance(p["plaintext_bytes"], int)
            and not isinstance(p["plaintext_bytes"], bool)
            and 0 <= p["plaintext_bytes"] <= MAX_SEALED_PLAINTEXT_BYTES
        ):
            return "sealed plaintext_bytes exceeds the AES-GCM invocation limit"
        if not (
            isinstance(p["media_type"], str)
            and 1 <= len(p["media_type"]) <= 127
            and p["media_type"] == p["media_type"].strip()
        ):
            return "sealed media_type MUST be bounded text"
        if not rappid_valid(p["key_service_rappid"]):
            return "sealed key_service_rappid MUST be a rappid"
        if not _https_chat_url_valid(p["key_service_url"]):
            return "sealed key_service_url MUST be an absolute HTTPS /chat URL"
        aad = {
            "schema": p["schema"],
            "artifact_rappid": m["rappid"],
            "created_utc": m["created_utc"],
            "key_id": p["key_id"],
            "plaintext_commitment": p["plaintext_commitment"],
            "plaintext_bytes": p["plaintext_bytes"],
            "media_type": p["media_type"],
        }
        if p["aad_hash"] != H("rapp/1:sealed-aad", aad):
            return "sealed aad_hash mismatch"
        if len(files["ciphertext.bin"]) != p["plaintext_bytes"] + 16:
            return "sealed ciphertext length MUST equal plaintext_bytes + 16-byte tag"
    return None


def _https_chat_url_valid(value):
    if not isinstance(value, str) or "\\" in value or any(c.isspace() for c in value):
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
        and parsed.query == ""
        and parsed.fragment == ""
        and parsed.path.endswith("/chat")
        and (port is None or 1 <= port <= 65535)
    )


def _signature_ok(manifest, signature_verifier, expected_signer=None):
    if signature_verifier is None:
        return False, "trusted signature verifier is required"
    unsigned = {k: v for k, v in manifest.items() if k != "sig"}
    try:
        if expected_signer is None:
            result = signature_verifier(unsigned, manifest["sig"])
        else:
            result = signature_verifier(
                unsigned,
                manifest["sig"],
                expected_signer,
            )
    except Exception as exc:
        return False, f"signature verifier failed: {exc}"
    if isinstance(result, tuple):
        return bool(result[0]), str(result[1]) if len(result) > 1 else ""
    return bool(result), "signature refused"


def _egg_static(blob, depth, child):
    """§9.3 consumer steps (0)-(2) → (ok, failing_step, reason, manifest or None).

    child(sub_blob, sub_depth) -> (ok, step, why) verifies each packed sub-egg; no §10 equation here."""
    if depth > 8:
        return False, "§9.2", "nested egg depth exceeds eight", None
    try:
        manifest, files = read_egg(blob)
    except Exception as e:
        return False, "parse", str(e), None
    if not isinstance(manifest, dict) or set(manifest.keys()) != _EGG_MANIFEST_KEYS:
        return False, "§9.1", "manifest must have exactly the 7 members", None
    if not isinstance(manifest["schema"], str) or manifest["schema"] != "rapp/1-egg":
        return False, "§9.1", f"schema != rapp/1-egg ({manifest.get('schema')})", None
    v = manifest["variant"]
    if not isinstance(v, str) or v not in EGG_VARIANTS:
        return False, "§9.2", f"unknown variant {v}", None
    if not isinstance(manifest["rappid"], str) or not rappid_valid(manifest["rappid"]):
        return False, "§6.1", f"bad rappid {manifest['rappid']}", None
    if not utc_valid(manifest["created_utc"]):
        return False, "§7.4", "created_utc not the fixed millisecond form", None
    if not isinstance(manifest["payload"], dict):
        return False, "§9.1", "payload not an object", None
    if manifest["sig"] is not None:
        if not isinstance(manifest["sig"], str):
            return False, "§10", "sig MUST be null or detached JWS text", None
        try:
            parse_detached_jws(manifest["sig"])
        except Exception as exc:
            return False, "§10", f"sig is not a §10 detached JWS: {exc}", None
    contents = manifest["contents"]
    if not isinstance(contents, list):
        return False, "§9.1", "contents not a list", None
    for c in contents:
        if (
            not isinstance(c, dict)
            or set(c) != {"path", "hash"}
            or not isinstance(c["path"], str)
            or not isinstance(c["hash"], str)
            or not _HEX64.fullmatch(c["hash"])
        ):
            return False, "§9.1", "content descriptor MUST be exactly {path,hash}", None
    paths = [c["path"] for c in contents]
    for p in paths:
        if not _path_valid(p):
            return False, "§9.1", f"bad path grammar: {p}", None
    if paths != sorted(paths, key=lambda x: x.encode("utf-8")):
        return False, "§9.1", "contents not sorted by path bytes", None
    if len(paths) != len(set(paths)):
        return False, "§9.1", "duplicate path", None
    if not _path_set_valid(paths):
        return False, "§9.1", "contents MUST NOT list the root path manifest.json", None
    if v in _EGG_JSON_VARIANTS:
        if contents != []:
            return False, "§9.1", "JSON variant contents MUST be []", None
        if blob != canonical(manifest).encode("utf-8"):
            return False, "§9.1", "JSON egg serialized form != canonical(manifest)", None
    else:
        if blob[:2] != b"PK":
            return False, "§9.1", f"a {v} egg MUST be a ZIP container", None
        if set(files.keys()) != set(paths):                # zip-slip defense
            return False, "§9.1", "archive entry set != contents", None
        for c in contents:
            if Hb("rapp/1:egg", files[c["path"]]) != c["hash"]:
                return False, "§5", f"content hash mismatch: {c['path']}", None
    why = _egg_variant_ok(v, manifest, files, depth=depth, verify_child=child)
    if why:
        return False, "§9.2", why, None
    return True, None, "ok", manifest


def verify_egg_static(blob, _depth=0):
    """§9.3 consumer steps (0)-(2), sub-eggs included, without the §10 signature equation.

    The check a producer runs on the octets it is about to emit (it lacks the signer's key
    context): every §9.1 rule, a present `sig` in the §10 detached form and header profile,
    every contents hash, and the §9.2 variant rules. verify_egg adds §10. Returns
    (ok, failing_step, reason)."""
    return _egg_static(blob, _depth, verify_egg_static)[:3]


def verify_egg(
    blob,
    signature_verifier=None,
    estate_owner_rappid=None,
    _depth=0,
):
    """§9.3 consumer verify — integrity then viability. Returns (ok, failing_step, reason).

    Steps (0)-(2) are verify_egg_static's (a signed sub-egg also verifies per §10); then a
    present `sig` verifies per §10 through signature_verifier."""
    def child(sub_blob, sub_depth):
        return verify_egg(
            sub_blob,
            signature_verifier=signature_verifier,
            estate_owner_rappid=estate_owner_rappid,
            _depth=sub_depth,
        )

    ok, step, why, manifest = _egg_static(blob, _depth, child)
    if not ok:
        return (False, step, why)
    v = manifest["variant"]
    if manifest["sig"] is not None:
        if v == "invite" and not rappid_valid(estate_owner_rappid):
            return (False, "§10", "invite verification requires estate_owner_rappid")
        ok, why = _signature_ok(
            manifest,
            signature_verifier,
            (
                manifest["rappid"]
                if v == "sealed"
                else estate_owner_rappid
                if v == "invite"
                else None
            ),
        )
        if not ok:
            return (False, "§10", why)
    return (True, None, "ok")


def open_sealed_egg(blob, dek, signature_verifier, decryptor):
    """Verify and decrypt a sealed egg through a maintained AES-GCM adapter.

    decryptor(dek, nonce_bytes, aad_bytes, ciphertext_and_tag) -> plaintext bytes.
    """
    ok, step, why = verify_egg(blob, signature_verifier=signature_verifier)
    if not ok:
        raise ValueError(f"sealed egg refused at {step}: {why}")
    manifest, files = read_egg(blob)
    if manifest["variant"] != "sealed":
        raise ValueError("egg is not sealed")
    p = manifest["payload"]
    descriptor = {
        "schema": p["schema"],
        "artifact_rappid": manifest["rappid"],
        "created_utc": manifest["created_utc"],
        "key_id": p["key_id"],
        "plaintext_commitment": p["plaintext_commitment"],
        "plaintext_bytes": p["plaintext_bytes"],
        "media_type": p["media_type"],
    }
    nonce = base64.urlsafe_b64decode(p["nonce"] + "==")
    aad = canonical(descriptor).encode("utf-8")
    try:
        plaintext = decryptor(dek, nonce, aad, files["ciphertext.bin"])
    except Exception as exc:
        raise ValueError(f"sealed AES-GCM authentication failed: {exc}") from exc
    if not isinstance(plaintext, bytes):
        raise ValueError("sealed decryptor MUST return bytes")
    if len(plaintext) != p["plaintext_bytes"]:
        raise ValueError("sealed plaintext length mismatch")
    if not hmac.compare_digest(
        sealed_plaintext_commitment(dek, plaintext),
        p["plaintext_commitment"],
    ):
        raise ValueError("sealed plaintext commitment mismatch")
    return plaintext


_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}


def _path_valid(path):
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or path != unicodedata.normalize("NFC", path)
        or re.match(r"^[A-Za-z]:", path)
    ):
        return False
    parts = path.split("/")
    for part in parts:
        if (
            part in ("", ".", "..")
            or part.endswith((" ", "."))
            or ":" in part
            or any(ord(char) < 32 for char in part)
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED
        ):
            return False
    return True


def _path_set_valid(paths):
    """§9.1 (rev-17 E-14): a manifest's contents paths, as a set.

    Refuses only two paths equal as code-point sequences and the reserved root path
    `manifest.json`. Paths differing only in case or normalization, and a file beside a
    directory of the same name (`docs`, `docs/a.md`), are distinct and valid; whether they
    can be extracted together is the extractor's question (_path_set_extractable)."""
    paths = list(paths)
    return "manifest.json" not in paths and len(paths) == len(set(paths))


def _path_set_extractable(paths):
    """Extractor-side (§9.1): can these paths coexist on a case-insensitive, normalizing filesystem?

    False when two paths fold together (NFD + casefold per segment) or one is a directory
    prefix of another. An extractor refuses the extraction, never the egg; verify_egg does
    not call this."""
    keys = []
    for path in paths:
        key = tuple(
            unicodedata.normalize("NFD", part).casefold()
            for part in path.split("/")
        )
        keys.append(key)
    if len(keys) != len(set(keys)):
        return False
    ordered = sorted(keys)
    for index, key in enumerate(ordered[:-1]):
        following = ordered[index + 1]
        if len(key) < len(following) and following[:len(key)] == key:
            return False
    return True
