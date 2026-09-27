"""rapp.py — reference implementation of the RAPP protocol suite (rev-14).

Stdlib only (json, hashlib, uuid, re, base64). Implements the primitives that the
spec claims are byte-for-byte interoperable, so the conformance suite can PROVE the
standard is implementable and self-consistent — and so it can be run against real
estate artifacts to see where reality conforms and where reality is the drift RAPP fixes.

Scope note: §4 canonicalization here is full RFC 8785 JCS over the I-JSON domain:
numbers are binary64 and serialize with ECMA-262 Number::toString (0.1 -> "0.1",
1e21 -> "1e+21"), and integers up to 2^53-1 serialize as their digits. The
reference vectors use exact-integer payloads so the hashes are reproducible anywhere.
"""
import hashlib
import base64
import decimal
import hmac
import json
import re
import uuid
import io
import urllib.parse
import unicodedata
import zipfile
from datetime import datetime

SPEC = "rapp/1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_LCLABEL = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_RAPPID = re.compile(r"rappid:@([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:-[a-z0-9]+)*):([0-9a-f]{64})")
MAX_SEALED_PLAINTEXT_BYTES = 2**30
MAX_CANONICAL_BYTES = 1024 * 1024
MAX_JSON_INPUT_BYTES = 64 * 1024 * 1024   # a DoS guard on raw input only; §4 (d) bounds the canonical form
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")

FRAME_KEYS = {"spec", "kind", "stream_id", "seq", "utc", "payload",
              "payload_hash", "frame_hash", "prev", "prev_wave", "sig"}


# ---------- §4 canonicalization ----------
# §4 (b), RFC 7493 §2.1: surrogate code points and the 66 noncharacters are outside I-JSON.
_NOT_IJSON_CHAR = re.compile(
    "[\ud800-\udfff\ufdd0-\ufdef"
    + "".join(chr(plane << 16 | 0xFFFE) + chr(plane << 16 | 0xFFFF) for plane in range(17))
    + "]"
)


def _ijson_string(s):
    """A §4 string or member name in JCS form; refuses a surrogate or a noncharacter (§4 (b))."""
    bad = _NOT_IJSON_CHAR.search(s)
    if bad:
        raise ValueError(
            f"string holds U+{ord(bad.group()):04X}, a surrogate or noncharacter outside I-JSON (§4 (b))"
        )
    return json.dumps(s, ensure_ascii=False)


def _number_to_string(x):
    """ECMA-262 Number::toString of a finite binary64 value: the RFC 8785 §3.2.2.3 number form."""
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("NaN and infinities are outside the §4 domain")
    if x == 0:
        return "0"                          # both zeros; -0 serializes as 0
    # repr() is the shortest digit string that round-trips (nearest, ties to even), the
    # digits Number::toString picks; only the layout differs, so re-lay it out here.
    mantissa, _, exponent = repr(abs(x)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    n = len(whole) + int(exponent or 0) - (len(whole) + len(fraction) - len(digits))
    digits = digits.rstrip("0")
    k = len(digits)                         # value = 0.digits * 10**n
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * -n + digits
    else:
        text = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if n > 0 else "-") + str(abs(n - 1))
    return ("-" if x < 0 else "") + text


def canonical(v):
    """RFC 8785 JCS over the §4 I-JSON domain. Returns the canonical form as a str (encode as UTF-8)."""
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, int):
        if abs(v) <= 2**53 - 1:
            return json.dumps(v)
        # §4 (c): a number is a binary64 value; an int outside +/-(2^53-1) is admitted only
        # when it is one exactly (2**53 is, 2**53 + 1 is not), and then serializes as JCS does.
        try:
            as_binary64 = float(v)
        except OverflowError:
            as_binary64 = None
        if as_binary64 != v:
            raise ValueError("int is not exactly representable as binary64 (§4 (c)); carry it as a string")
        return _number_to_string(as_binary64)
    if isinstance(v, float):
        return _number_to_string(v)
    if isinstance(v, str):
        return _ijson_string(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise ValueError("member names must be strings")
        # RFC 8785 orders member names by UTF-16 code units; plain sorted()
        # is code-POINT order and diverges for non-BMP keys.
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate keys")
        return "{" + ",".join(_ijson_string(k) + ":" + canonical(v[k]) for k in keys) + "}"
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
        class _Utf8ZipInfo(zipfile.ZipInfo):
            def _encodeFilenameFlags(self):
                return self.filename.encode("utf-8"), self.flag_bits | 0x800

        def _w(name, data):
            zi = _Utf8ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zi.flag_bits |= 0x800                          # UTF-8 filename flag
            z.writestr(zi, data)
        _w("manifest.json", man_octets)                    # manifest.json first
        for c in manifest["contents"]:                     # then contents order
            _w(c["path"], files[c["path"]])
    return buf.getvalue()


def _json_number(token):
    """§4 (c): parse a number token as its nearest binary64 d; refuse unless d is finite and
    Number::toString(d) denotes exactly the token's value (so 0.1 passes, 0.10000000000000001 does not)."""
    d = float(token)                                   # correctly rounded, ties to even; overlong -> +/-inf
    if d != d or d in (float("inf"), float("-inf")):
        raise ValueError(f"number token {token[:40]} is not a finite binary64 value (§4 (c))")
    try:
        same = decimal.Decimal(token) == decimal.Decimal(_number_to_string(d))
    except ArithmeticError:
        # An exponent beyond decimal's range. d is finite, so it is a zero, and the token
        # denotes the same value iff every digit of its significand is zero.
        same = not any(c in "123456789" for c in token.lower().partition("e")[0])
    if not same:
        raise ValueError(f"number token {token[:40]} does not survive the binary64 round trip (§4 (c))")
    return d


def _json_int(token):
    if token == "-0":
        return -0.0          # E-9: -0 is not an integer token a field rule may take for 0; canonical(-0.0) is "0"
    d = _json_number(token)  # refuses 9007199254740993 and overlong tokens before int() runs
    value = int(token)
    # 10**23 passes §4 (c) (its d prints as "1e+23") but is not d; the value parsed is d itself.
    return value if value == d else int(d)


def _json_constant(token):
    raise ValueError(f"{token} is not a JSON number (§4 (c))")


def _strict_json(blob):
    """Parse one §4 JSON text (octets or str) and return its value, or raise ValueError."""
    if isinstance(blob, (bytes, bytearray)):
        if len(blob) > MAX_JSON_INPUT_BYTES:
            raise ValueError("JSON text exceeds the 64 MiB input guard")
        if blob.startswith(b"\xef\xbb\xbf"):
            raise ValueError("JSON text starts with a byte-order mark; §4 refuses it (never strips it)")
        try:
            text = bytes(blob).decode("utf-8")        # strict: UTF-16/UTF-32 text is never transcoded
        except UnicodeDecodeError as exc:
            raise ValueError(f"JSON text is not well-formed UTF-8 (§4): {exc}") from None
    elif isinstance(blob, str):
        if len(blob) > MAX_JSON_INPUT_BYTES:          # a str is bounded by its code points
            raise ValueError("JSON text exceeds the 64 MiB input guard")
        text = blob
    else:
        raise ValueError("JSON text must be octets or a str")
    if text.startswith("\ufeff"):
        raise ValueError("JSON text starts with a byte-order mark; §4 refuses it (never strips it)")

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=_json_number,
            parse_int=_json_int,
            parse_constant=_json_constant,
        )
    except RecursionError:
        raise ValueError("JSON nesting depth exceeds 64 (§4 (d))") from None
    # §4 (d): the root is depth 1 and only objects and arrays add a level; scalars never do.
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        children = current.values() if isinstance(current, dict) else current if isinstance(current, list) else ()
        for item in children:
            if isinstance(item, (dict, list)):
                if depth + 1 > 64:
                    raise ValueError("JSON nesting depth exceeds 64 (§4 (d))")
                stack.append((item, depth + 1))
    if len(canonical(value).encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical JSON exceeds the 1 MiB ceiling (§4 (d))")
    return value


def _validate_zip_layout(blob, archive, infos):
    if not blob.startswith(b"PK\x03\x04"):
        raise ValueError("ZIP MUST begin with a local file header")
    eocd = blob.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(blob):
        raise ValueError("ZIP end-of-central-directory record is missing")
    comment_length = int.from_bytes(blob[eocd + 20:eocd + 22], "little")
    if eocd + 22 + comment_length != len(blob):
        raise ValueError("ZIP has unauthenticated trailing bytes")
    if any(blob[eocd + offset:eocd + offset + 2] != b"\x00\x00" for offset in (4, 6)):
        raise ValueError("multi-disk ZIP is not supported")
    entries_on_disk = int.from_bytes(blob[eocd + 8:eocd + 10], "little")
    entries_total = int.from_bytes(blob[eocd + 10:eocd + 12], "little")
    central_size = int.from_bytes(blob[eocd + 12:eocd + 16], "little")
    central_offset = int.from_bytes(blob[eocd + 16:eocd + 20], "little")
    if entries_on_disk != len(infos) or entries_total != len(infos):
        raise ValueError("ZIP entry count mismatch")
    if central_offset != archive.start_dir or central_offset + central_size != eocd:
        raise ValueError("ZIP central directory is not canonical")

    cursor = 0
    for info in infos:
        if info.header_offset != cursor:
            raise ValueError("ZIP contains unreferenced local data")
        header = blob[cursor:cursor + 30]
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise ValueError("ZIP local header is malformed")
        flags = int.from_bytes(header[6:8], "little")
        method = int.from_bytes(header[8:10], "little")
        crc = int.from_bytes(header[14:18], "little")
        compressed_size = int.from_bytes(header[18:22], "little")
        file_size = int.from_bytes(header[22:26], "little")
        filename_length = int.from_bytes(header[26:28], "little")
        extra_length = int.from_bytes(header[28:30], "little")
        if flags != info.flag_bits or flags != 0x800:
            raise ValueError("ZIP local and central UTF-8 flags must match exactly")
        if method != zipfile.ZIP_STORED or method != info.compress_type:
            raise ValueError("ZIP local and central compression methods differ")
        if header[10:14] != b"\x00\x00\x21\x00":
            raise ValueError("ZIP local timestamp is not deterministic")
        if (
            crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
        ):
            raise ValueError("ZIP local and central CRC/size fields differ")
        if extra_length != 0:
            raise ValueError("ZIP local extra fields MUST be empty")
        filename_octets = blob[cursor + 30:cursor + 30 + filename_length]
        if filename_octets.decode("utf-8") != info.filename:
            raise ValueError("ZIP local filename bytes are not canonical UTF-8")
        cursor += 30 + filename_length + extra_length + info.compress_size
    if cursor != archive.start_dir:
        raise ValueError("ZIP local records do not end at the central directory")


def read_egg(blob):
    """Parse a rapp/1-egg → (manifest_dict, files_dict). files={} for JSON variants."""
    if blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            infos = z.infolist()
            _validate_zip_layout(blob, z, infos)
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ValueError("duplicate ZIP entry")
            if not names or names[0] != "manifest.json":
                raise ValueError("manifest.json MUST be the first ZIP entry")
            if z.comment:
                raise ValueError("ZIP archive comment MUST be empty")
            for info in infos:
                if info.compress_type != zipfile.ZIP_STORED:
                    raise ValueError("ZIP entries MUST use stored compression")
                if info.date_time != (1980, 1, 1, 0, 0, 0):
                    raise ValueError("ZIP entry timestamp is not deterministic")
                if info.extra or info.comment:
                    raise ValueError("ZIP entry extra fields/comments MUST be empty")
                if info.file_size != info.compress_size:
                    raise ValueError("stored ZIP entry size mismatch")
                if info.flag_bits != 0x800:
                    raise ValueError("ZIP entry flags MUST be exactly UTF-8")
            manifest_octets = z.read("manifest.json")
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
            files = {
                info.filename: z.read(info)
                for info in infos[1:]
            }
            return manifest, files
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
):
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
            ok, step, why = verify_egg(
                files[filename],
                signature_verifier=signature_verifier,
                estate_owner_rappid=estate_owner_rappid,
                _depth=depth + 1,
            )
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
            ok, step, why = verify_egg(
                files[filename],
                signature_verifier=signature_verifier,
                estate_owner_rappid=estate_owner_rappid,
                _depth=depth + 1,
            )
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


def verify_egg(
    blob,
    signature_verifier=None,
    estate_owner_rappid=None,
    _depth=0,
):
    """§9.3 consumer verify — integrity then viability. Returns (ok, failing_step, reason)."""
    if _depth > 8:
        return (False, "§9.2", "nested egg depth exceeds eight")
    try:
        manifest, files = read_egg(blob)
    except Exception as e:
        return (False, "parse", str(e))
    if not isinstance(manifest, dict) or set(manifest.keys()) != _EGG_MANIFEST_KEYS:
        return (False, "§9.1", "manifest must have exactly the 7 members")
    if not isinstance(manifest["schema"], str) or manifest["schema"] != "rapp/1-egg":
        return (False, "§9.1", f"schema != rapp/1-egg ({manifest.get('schema')})")
    v = manifest["variant"]
    if not isinstance(v, str) or v not in EGG_VARIANTS:
        return (False, "§9.2", f"unknown variant {v}")
    if not isinstance(manifest["rappid"], str) or not rappid_valid(manifest["rappid"]):
        return (False, "§6.1", f"bad rappid {manifest['rappid']}")
    if not utc_valid(manifest["created_utc"]):
        return (False, "§7.4", "created_utc not the fixed millisecond form")
    if not isinstance(manifest["payload"], dict):
        return (False, "§9.1", "payload not an object")
    if manifest["sig"] is not None and not isinstance(manifest["sig"], str):
        return (False, "§10", "sig MUST be null or detached JWS text")
    contents = manifest["contents"]
    if not isinstance(contents, list):
        return (False, "§9.1", "contents not a list")
    for c in contents:
        if (
            not isinstance(c, dict)
            or set(c) != {"path", "hash"}
            or not isinstance(c["path"], str)
            or not isinstance(c["hash"], str)
            or not _HEX64.fullmatch(c["hash"])
        ):
            return (False, "§9.1", "content descriptor MUST be exactly {path,hash}")
    paths = [c["path"] for c in contents]
    for p in paths:
        if not _path_valid(p):
            return (False, "§9.1", f"bad path grammar: {p}")
    if paths != sorted(paths, key=lambda x: x.encode("utf-8")):
        return (False, "§9.1", "contents not sorted by path bytes")
    if len(paths) != len(set(paths)):
        return (False, "§9.1", "duplicate path")
    if not _path_set_valid(["manifest.json", *paths]):
        return (False, "§9.1", "paths collide or conflict on common filesystems")
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
    why = _egg_variant_ok(
        v,
        manifest,
        files,
        signature_verifier=signature_verifier,
        estate_owner_rappid=estate_owner_rappid,
        depth=_depth,
    )
    if why:
        return (False, "§9.2", why)
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
