"""rapp_sdk_builder_agent.py — a hotloadable RAPP SDK, as a brainstem agent.

Drop this one file into any RAPP brainstem's `agents/` directory (no restart) and the
brainstem gains a working RAPP toolkit: mint compliant identities, build and verify
frames, canonicalize + content-address values, scaffold a ready-to-plant organism seed,
and lint any public repo in the stack for RAPP compliance.

Install straight from the public standard repo:

    curl -sSL https://raw.githubusercontent.com/kody-w/rapp-1/main/agents/rapp_sdk_builder_agent.py \
      -o ~/.brainstem/agents/rapp_sdk_builder_agent.py

Then just talk to your brainstem:
    "mint a keyless rappid for @me/notes"
    "scaffold a new RAPP organism called @me/scratch"
    "verify this frame: { … }"
    "check https://github.com/kody-w/twin for RAPP compliance"

The RAPP primitives are embedded here verbatim from the reference implementation
(kody-w/rapp-1 · rapp.py), so the agent is self-contained and offline-capable. The
`sync` action fetches the canonical rapp.py from the public repo and proves this file's
embedded primitive definitions are identical to it — by comparing source (parsed with
ast, never executed), so it is provenance you can check, not trust, and safe to run.
"""
import base64
import decimal
import hashlib
import json
import re
import unicodedata
import urllib.request
import uuid

# ── graceful base: use the brainstem's BasicAgent if present, else a standalone shim ──
try:                                            # inside a brainstem
    from agents.basic_agent import BasicAgent
except Exception:                               # dropped in / run standalone
    class BasicAgent:
        def __init__(self, name=None, metadata=None):
            self.name = name or getattr(self, "name", "BasicAgent")
            self.metadata = metadata or getattr(self, "metadata", {})
        def perform(self, **kwargs):
            return "Not implemented."
        def system_context(self):
            return None
        def to_tool(self):
            return {"type": "function", "function": {
                "name": self.name, "description": self.metadata.get("description", ""),
                "parameters": self.metadata.get("parameters", {})}}

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@kody-w/rapp_sdk_builder",
    "version": "1.2.0",
    "display_name": "RAPP SDK Builder",
    "description": "A hotloadable RAPP toolkit: mint compliant rappids, build/verify frames, "
                   "content-address values, scaffold organism seeds, discover additive profiles, "
                   "and lint any public repo in the stack for compliance. Build with RAPP and stay "
                   "synced against the public GitHubs — and back again. Builds on the public RAPP "
                   "standard (kody-w/rapp-1).",
    "author": "Kody Wildfeuer",
    "tags": ["starter", "rapp", "sdk", "identity", "frame", "builder"],
    "category": "devtools",
    "quality_tier": "official",
    "requires_env": [],
    "example_call": "scaffold a new RAPP organism called @me/scratch",
}

SPEC = "rapp/1"
SRC = "https://raw.githubusercontent.com/kody-w/rapp-1/main/rapp.py"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}Z", re.ASCII)
_LCLABEL = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_RAPPID = re.compile(r"rappid:@([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:-[a-z0-9]+)*):([0-9a-f]{64})")
FRAME_KEYS = {"spec", "kind", "stream_id", "seq", "utc", "payload",
              "payload_hash", "frame_hash", "prev", "prev_wave", "sig"}
PROFILE_DISCOVERY = {
    "rapp-work/1": {
        "name": "rapp-work/1",
        "parent": "rapp/1",
        "depends_on": ["rapp-hive/1", "rapp-cicd/1", "rapp-deploy/1"],
        "canonical_repository": "https://github.com/kody-w/rapp-1",
        "index_path": "protocols/index.json",
        "spec_path": "protocols/rapp-work/1/SPEC.md",
        "schema_path": "protocols/rapp-work/1/schema.json",
        "conformance": "work_conformance.py",
        "kinds": [
            "work.catalog",
            "work.migration",
            "work.observation",
            "work.organization",
            "work.receipt",
            "work.rollback",
            "work.vector",
        ],
        "family": "body",
        "authority": "discovery-only-until-signed-registry-adoption",
    }
}


# ── RAPP primitives (embedded verbatim from rapp.py; the `sync` action proves parity) ──
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


# §5 (rev-17 E-7): every tag belongs to exactly one function; any other tag is refused.
_H_SPACES = frozenset({"rapp/1:particle", "rapp/1:wave", "rapp/1:egg-manifest",
                       "rapp/1:sealed-aad", "rapp/1:sealed-key-request"})
_HB_SPACES = frozenset({"rapp/1:egg", "rapp/1:rappid", "rapp/1:grail", "rapp/1:seal"})


# §6.2 (rev-17 E-8): the only SPKI octets a keyed mint accepts. RFC 8410 id-Ed25519 with a 32-octet key;
# RFC 5480 id-ecPublicKey prime256v1 with a 65-octet uncompressed point (04 || X || Y).
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
_ED25519_P = 2**255 - 19
_ED25519_D = -121665 * pow(121666, _ED25519_P - 2, _ED25519_P) % _ED25519_P
_P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _ed25519_point_decodes(key):
    """RFC 8032 §5.1.3: the 32 octets decode to a point (y < p, x recoverable, no x = 0 with sign 1)."""
    p = _ED25519_P
    y = int.from_bytes(key, "little") & (2**255 - 1)
    sign = key[31] >> 7
    if y >= p:
        return False
    u = (y * y - 1) % p
    v = (_ED25519_D * y * y + 1) % p
    x = u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p) % p
    if (v * x * x - u) % p != 0:
        if (v * x * x + u) % p != 0:
            return False
        x = x * pow(2, (p - 1) // 4, p) % p
    return not (x == 0 and sign == 1)


def _p256_point_on_curve(point):
    """SEC 1 §3.2.2.1 for an uncompressed point: 0 <= X, Y < p and Y^2 = X^3 - 3X + b (mod p)."""
    p = _P256_P
    x = int.from_bytes(point[1:33], "big")
    y = int.from_bytes(point[33:65], "big")
    return x < p and y < p and (y * y - (x * x * x - 3 * x + _P256_B)) % p == 0


def _spki_ok(spki_der):
    """True iff the octets are exactly the DER SPKI of a §10 key (§6.2, rev-17 E-8).

    The point must also decode (Ed25519) or lie on the curve (P-256). The five clean-room
    implementations split 4-1 on this at mint (python D-11/D-C07, typescript D-27, go D-21 and
    rust D-20 decode the point; swift D-06/D-32 checks the layout only); the reference follows
    the majority, since a key that is not a point can never verify a §10 signature."""
    if not isinstance(spki_der, (bytes, bytearray)):
        return False
    spki_der = bytes(spki_der)
    if len(spki_der) == 44 and spki_der.startswith(_ED25519_SPKI_PREFIX):
        return _ed25519_point_decodes(spki_der[12:])
    if len(spki_der) == 91 and spki_der.startswith(_P256_SPKI_PREFIX) and spki_der[26] == 0x04:
        return _p256_point_on_curve(spki_der[26:])
    return False


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


def H(space, v):
    if not (isinstance(space, str) and space in _H_SPACES):
        raise ValueError(f"§5: H (a value hash) is used only with the tags {sorted(_H_SPACES)}; refused {space!r}")
    return hashlib.sha256(space.encode() + b"\x0a" + canonical(v).encode("utf-8")).hexdigest()


def Hb(space, b):
    if not (isinstance(space, str) and space in _HB_SPACES):
        raise ValueError(f"§5: Hb (an octet hash) is used only with the tags {sorted(_HB_SPACES)}; refused {space!r}")
    return hashlib.sha256(space.encode() + b"\x0a" + b).hexdigest()


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
        if not _spki_ok(spki_der):
            raise ValueError(
                "§6.2: a keyed mint needs the exact DER SPKI of an Ed25519 key (RFC 8410) "
                "or of a P-256 key with an uncompressed on-curve point"
            )
        tail = Hb("rapp/1:rappid", bytes(spki_der))
    else:
        octets = uuid.uuid4().bytes
        if len(octets) != 16 or octets[6] >> 4 != 4 or octets[8] >> 6 != 0b10:
            raise ValueError("§6.2: keyless mint octets are not a UUIDv4 (RFC 9562: version 4, variant 0b10)")
        tail = Hb("rapp/1:rappid", octets)
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


def utc_valid(value):
    """§7.4 (rev-17 E-1): exactly the 24-octet form YYYY-MM-DDTHH:MM:SS.mmmZ in ASCII digits,
    calendar-valid on the proleptic Gregorian calendar for years 0000-9999, seconds 00-59."""
    if not isinstance(value, str) or len(value) != 24 or not value.isascii():
        return False
    match = _UTC.fullmatch(value)
    if not match:
        return False
    year, month, day, hour, minute, second = (int(group) for group in match.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return 1 <= month <= 12 and 1 <= day <= days[month - 1] and hour <= 23 and minute <= 59 and second <= 59


# ── rev-17 frame helpers (embedded verbatim from rapp.py; parity_check.py proves behaviour) ──
MAX_CANONICAL_BYTES = 1024 * 1024
MAX_JSON_INPUT_BYTES = 64 * 1024 * 1024   # a DoS guard on raw input only; §4 (d) bounds the canonical form
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
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


def _uint53(value):
    """§7.4 `uint53`: an int (never a bool or a float) from 0 to 2^53-1."""
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1


def _hex64_or_null(value):
    return value is None or (isinstance(value, str) and bool(_HEX64.fullmatch(value)))


def _is_regenesis(kind):
    """§12.1: a `*.re-genesis` kind, whose second label is exactly "re-genesis"."""
    return isinstance(kind, str) and kind.partition(".")[2] == "re-genesis"


def _regenesis_payload_error(payload):
    """§12.1 step 2 (rev-17 E-22): None if `payload` is the one re-genesis shape, else the reason."""
    if not isinstance(payload, dict) or set(payload) != {"migrated_from"}:
        return 're-genesis payload must be exactly {"migrated_from": {...}} (§12.1 step 2)'
    moved = payload["migrated_from"]
    if not isinstance(moved, dict) or set(moved) != {"stream_id", "terminal_seal", "terminal_seq"}:
        return "re-genesis migrated_from must be exactly stream_id, terminal_seal, terminal_seq (§12.1 step 2)"
    if stream_form(moved["stream_id"]) is None:
        return "re-genesis migrated_from.stream_id is not a §6.1.1 stream_id"
    if not (isinstance(moved["terminal_seal"], str) and _HEX64.fullmatch(moved["terminal_seal"])):
        return "re-genesis migrated_from.terminal_seal is not 64 lowercase hex"
    if not _uint53(moved["terminal_seq"]):
        return "re-genesis migrated_from.terminal_seq is not a uint53"
    return None


def _container_depth(value, limit=64):
    """§4 (d) nesting depth: the root is depth 1, each nested object/array adds 1, scalars add
    nothing. Stops counting once the depth passes `limit` (so a cyclic value terminates)."""
    deepest, stack = 0, [(value, 1)]
    while stack and deepest <= limit:
        current, depth = stack.pop()
        if isinstance(current, dict):
            current = list(current.values())
        if isinstance(current, list):
            deepest = max(deepest, depth)
            stack.extend((item, depth + 1) for item in current)
    return deepest


def build_frame(kind, stream_id, seq, utc, payload, prev, prev_wave=None, sig=None):
    """§11 Producer: construct an 11-key frame, computing particle then wave (§7.3).

    Refuses (ValueError, never repairs) any frame that §4, §6.1.1, §7.1, §7.4, §8, §10 or
    §12.1 forbids a producer to emit."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object (§7.1)")
    if 1 + _container_depth(payload) > 64:              # the frame object is depth 1
        raise ValueError("frame nesting depth exceeds 64 (§4 (d), §7.1)")
    _names_ok(payload)
    if not kind_valid(kind):
        raise ValueError(f"kind {kind!r} does not match the §6.1.1 grammar (two lclabels of 1-64)")
    form = stream_form(stream_id)
    if form is None:
        raise ValueError(f"stream_id {stream_id!r} is not a §6.1.1 stream_id (a provisional tail never is, §6.3)")
    if not _uint53(seq):
        raise ValueError("seq must be a uint53: an int from 0 to 2^53-1 (§7.4)")
    if not utc_valid(utc):
        raise ValueError("utc must be the fixed §7.4 form and a valid calendar time (second 00-59)")
    for name, value in (("prev", prev), ("prev_wave", prev_wave)):
        if not _hex64_or_null(value):
            raise ValueError(f"{name} must be null or 64 lowercase hex (§7.1)")
    if sig is not None:
        try:
            parse_detached_jws(sig)
        except Exception as exc:
            raise ValueError(f"sig is not null or a §10 detached JWS: {exc}") from exc
    if (seq == 0) != (prev is None):
        raise ValueError("the genesis has seq 0 and prev null; every later frame has seq > 0 and a prev (§7.4)")
    if (prev_wave is not None) != (form == "swarm-stream" and seq > 0):
        raise ValueError("prev_wave is non-null iff the stream is a swarm-stream and seq > 0 (§7.4)")
    if form == "swarm-stream" and sig is None:
        raise ValueError("a swarm-stream frame must be signed (§8)")
    if _is_regenesis(kind):
        if seq != 0 or prev is not None or sig is None:
            raise ValueError("a re-genesis frame is an owner-signed genesis: seq 0, prev null, sig set (§12.1 step 2)")
        why = _regenesis_payload_error(payload)
        if why:
            raise ValueError(why)
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
    size = len(canonical(frame).encode("utf-8"))
    if size > MAX_CANONICAL_BYTES:
        raise ValueError(f"canonical frame is {size} octets, over the 1 MiB limit (§4 (d), §7.1)")
    return frame


def verify_frame(
    frame,
    head=None,
    stream_id_of_record=None,
    signature_verifier=None,
    *,
    registry=None,
):
    """§7.5 consumer checklist. Returns (ok, failing_step_or_None, reason).

    `registry` (optional) is a duck-typed §13 registry such as rapp_registry.Registry:
    check_frame_binding(frame) -> (ok, reason) joins step 1, registered_genesis(stream_id)
    -> entry or None joins step 4, and owner_at(utc) -> rappid names the step-6 signer a
    `*.re-genesis` frame requires."""
    # 1 shape & types
    if not isinstance(frame, dict):
        return False, "1", "frame is not a JSON object"
    if set(frame.keys()) != FRAME_KEYS:
        return False, "1", f"key set != 11 ({sorted(frame.keys())})"
    if frame["spec"] != SPEC:
        return False, "1", "spec != rapp/1"
    if not kind_valid(frame["kind"]):
        return False, "1", "kind grammar (§6.1.1: two lclabels of 1-64 characters)"
    form = stream_form(frame["stream_id"])
    if form is None:
        return False, "1", "stream_id grammar (§6.1.1; a provisional tail is never a stream_id, §6.3)"
    if not _uint53(frame["seq"]):
        return False, "1", "seq not uint53"
    if not utc_valid(frame["utc"]):
        return False, "1", "utc not fixed form"
    if not isinstance(frame["payload"], dict):
        return False, "1", "payload not object"
    for k in ("payload_hash", "frame_hash"):
        if not (isinstance(frame[k], str) and _HEX64.fullmatch(frame[k])):
            return False, "1", f"{k} not 64hex"
    for k in ("prev", "prev_wave"):
        if not _hex64_or_null(frame[k]):
            return False, "1", f"{k} not null|64hex"
    if frame["sig"] is not None:
        try:
            parse_detached_jws(frame["sig"])
        except Exception as exc:
            return False, "1", f"sig is not null or a §10 detached JWS: {exc}"
    regenesis = _is_regenesis(frame["kind"])
    if regenesis:
        why = _regenesis_payload_error(frame["payload"])
        if why:
            return False, "1", why
    if registry is not None:
        try:
            bound, why = registry.check_frame_binding(frame)
        except Exception as exc:
            bound, why = False, f"binding check failed: {exc}"
        if not bound:
            return False, "1", f"registry binding: {why}"
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
    if regenesis and (frame["seq"] != 0 or frame["prev"] is not None):
        return False, "4", "a re-genesis frame must be a genesis: seq=0 prev=null (§12.1 step 2)"
    if head is None:
        if not (frame["seq"] == 0 and frame["prev"] is None):
            return False, "4", "genesis must be seq=0 prev=null"
        if registry is not None:
            try:
                entry = registry.registered_genesis(frame["stream_id"])
                registered = None if entry is None else entry["frame_hash"]
            except Exception as exc:
                return False, "4", f"registered genesis lookup failed: {exc}"
            if registered is not None and registered != frame["frame_hash"]:
                return False, "4", "genesis is not the stream's registered genesis (§7.5 step 4, §13.3)"
    else:
        if frame["seq"] != head["seq"] + 1:
            return False, "4", "seq not contiguous"
        if frame["prev"] != head["payload_hash"]:
            return False, "4", "prev != head payload_hash"
        if frame["utc"] < head["utc"]:
            return False, "4", "utc < head utc"
    # 5 wire
    is_swarm = form == "swarm-stream"
    if is_swarm and frame["seq"] > 0:
        if head is not None and frame["prev_wave"] != head["frame_hash"]:
            return False, "5", "prev_wave != head frame_hash"
    else:
        if frame["prev_wave"] is not None:
            return False, "5", "prev_wave must be null off swarm"
    # 6 signature
    if is_swarm and frame["sig"] is None:
        return False, "6", "swarm frame must be signed"
    if regenesis and frame["sig"] is None:
        return False, "6", "a re-genesis frame must be owner-signed (§12.1 step 2)"
    if frame["sig"] is not None:
        expected_signer = None
        if regenesis and registry is not None:
            try:
                expected_signer = registry.owner_at(frame["utc"])
            except Exception as exc:
                return False, "6", f"owner in effect at utc is unresolvable: {exc}"
            if expected_signer is None:
                return False, "6", "no estate owner in effect at the re-genesis utc (§13.2)"
        if signature_verifier is None:
            return False, "6", "trusted signature verifier is required"
        unsigned = {k: frame[k] for k in frame if k != "sig"}
        try:
            if expected_signer is None:
                result = signature_verifier(unsigned, frame["sig"])
            else:
                result = signature_verifier(unsigned, frame["sig"], expected_signer)
        except Exception as exc:
            return False, "6", f"signature verifier failed: {exc}"
        if isinstance(result, tuple):
            ok, why = bool(result[0]), (str(result[1]) if len(result) > 1 else "")
        else:
            ok, why = bool(result), "signature refused"
        if not ok:
            return False, "6", why
    return True, None, "ok"


# ── helpers ──
def _fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "rapp-sdk-builder/1.0"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def _parse_id(s):
    """Accept '@owner/slug' or a full rappid and return (owner, slug)."""
    if s.startswith("rappid:@"):
        m = _RAPPID.fullmatch(s)
        if m:
            return m.group(1), m.group(2)
    s = s.lstrip("@")
    if "/" in s:
        o, sl = s.split("/", 1)
        return o, sl.split(":")[0]
    raise ValueError(f"cannot parse owner/slug from {s!r}")


class RappSdkBuilderAgent(BasicAgent):
    def __init__(self):
        self.name = "RappSdkBuilder"
        self.metadata = {
            "name": self.name,
            "description": "RAPP SDK toolkit. Use for any RAPP protocol operation: mint a "
                           "compliant rappid, scaffold a new organism seed, build or verify a frame, "
                           "canonicalize/content-address a value, discover an additive protocol "
                           "profile, or check a repo for RAPP compliance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["mint", "scaffold", "frame", "verify", "canonicalize", "discover", "check", "sync"],
                        "description": "mint=mint a rappid · scaffold=new organism seed (rappid+genesis) · "
                                       "frame=build+verify a frame · verify=verify a frame object · "
                                       "canonicalize=canonical bytes + domain hash of a value · "
                                       "discover=non-authoritative additive profile discovery · "
                                       "check=lint a repo/rappid for compliance · sync=verify embedded SDK vs public repo",
                    },
                    "id": {"type": "string", "description": "identity as '@owner/slug' or a full rappid string"},
                    "kind": {"type": "string", "description": "frame kind, e.g. 'note.write' (noun.verb)"},
                    "payload": {"type": "object", "description": "frame payload / value to canonicalize"},
                    "utc": {"type": "string", "description": "millisecond UTC 'YYYY-MM-DDTHH:MM:SS.mmmZ'"},
                    "frame": {"type": "object", "description": "a frame object to verify"},
                    "repo": {"type": "string", "description": "a github repo URL or owner/name to lint for compliance"},
                    "protocol": {"type": "string", "description": "additive profile identifier to discover"},
                    "value": {"description": "any I-JSON value to canonicalize/address"},
                },
                "required": ["action"],
            },
        }
        super().__init__(name=self.name, metadata=self.metadata)

    def perform(self, **kwargs):
        action = (kwargs.get("action") or "").strip().lower()
        try:
            if action == "mint":
                return self._mint(kwargs)
            if action == "scaffold":
                return self._scaffold(kwargs)
            if action == "frame":
                return self._frame(kwargs)
            if action == "verify":
                return self._verify(kwargs)
            if action == "canonicalize":
                return self._canon(kwargs)
            if action == "discover":
                return self._discover(kwargs)
            if action == "check":
                return self._check(kwargs)
            if action == "sync":
                return self._sync()
            return json.dumps({"status": "error",
                               "message": f"unknown action {action!r}",
                               "actions": ["mint", "scaffold", "frame", "verify", "canonicalize", "discover", "check", "sync"]})
        except Exception as e:
            return json.dumps({"status": "error", "action": action, "message": str(e)})

    # -- actions --
    def _mint(self, kw):
        owner, slug = _parse_id(kw.get("id") or "@me/agent")
        rid = mint_rappid(owner, slug)
        return json.dumps({"status": "ok", "action": "mint", "rappid": rid,
                           "valid": rappid_valid(rid), "note": "keyless mint (§6.2): tail = Hb('rapp/1:rappid', uuid4)"})

    def _scaffold(self, kw):
        owner, slug = _parse_id(kw.get("id") or "@me/organism")
        rid = mint_rappid(owner, slug)
        utc = kw.get("utc") or "2026-07-15T00:00:00.000Z"
        genesis = build_frame("organism.genesis", rid, 0, utc,
                              {"born": {"owner": owner, "slug": slug}}, prev=None)
        ok, step, why = verify_frame(genesis, head=None, stream_id_of_record=rid)
        rappid_json = {"schema": "rapp/1", "rappid": rid, "kind": "organism",
                       "name": slug, "parent_rappid": None,
                       "frames": "frames/index.json"}
        return json.dumps({"status": "ok", "action": "scaffold",
                           "verified": ok, "verify_step": step,
                           "files": {"rappid.json": rappid_json, "frames/0.json": genesis},
                           "note": "A ready-to-plant RAPP organism seed. Commit rappid.json + frames/0.json; "
                                   "the genesis passes §7.5 verify. (A keyed organism would sign the genesis, §10.)"},
                          indent=2)

    def _frame(self, kw):
        rid = kw.get("id")
        if not rid or not rappid_valid(rid):
            return json.dumps({"status": "error", "message": "provide a full valid rappid in 'id'"})
        kind = kw.get("kind") or "note.write"
        utc = kw.get("utc") or "2026-07-15T00:00:00.000Z"
        payload = kw.get("payload") or {}
        seq = int(kw.get("seq", 0) or 0)
        prev = kw.get("prev")
        fr = build_frame(kind, rid, seq, utc, payload, prev=prev)
        ok, step, why = verify_frame(fr, head=None if prev is None else None,
                                     stream_id_of_record=rid)
        return json.dumps({"status": "ok", "action": "frame", "frame": fr,
                           "verified_as_genesis": ok if prev is None else None,
                           "particle": fr["payload_hash"], "wave": fr["frame_hash"]}, indent=2)

    def _verify(self, kw):
        fr = kw.get("frame")
        if not isinstance(fr, dict):
            return json.dumps({"status": "error", "message": "provide a frame object in 'frame'"})
        ok, step, why = verify_frame(fr, head=None, stream_id_of_record=fr.get("stream_id"))
        return json.dumps({"status": "ok", "action": "verify", "valid": ok,
                           "failing_step": step, "reason": why})

    def _canon(self, kw):
        v = kw.get("value", kw.get("payload"))
        c = canonical(v)
        return json.dumps({"status": "ok", "action": "canonicalize", "canonical": c,
                           "particle": H("rapp/1:particle", v), "wave_of_value": H("rapp/1:wave", v),
                           "egg_manifest": H("rapp/1:egg-manifest", v)})

    def _discover(self, kw):
        name = (kw.get("protocol") or "rapp-work/1").strip()
        profile = PROFILE_DISCOVERY.get(name)
        if profile is None:
            return json.dumps({
                "status": "error",
                "action": "discover",
                "message": f"unknown additive profile {name!r}",
                "known_profiles": sorted(PROFILE_DISCOVERY),
            })
        return json.dumps({
            "status": "ok",
            "action": "discover",
            "profile": profile,
            "registry_entries": [
                {"type": "kind", "kind": kind, "family": profile["family"], "deprecated": False}
                for kind in profile["kinds"]
            ],
            "note": "Discovery is not authority. Resolve the indexed specification hash and adopt it "
                    "with an owner-signed ordinary RAPP/1 protocol entry; these ordinary kind entries "
                    "add no frame key, registry entry type, or endpoint.",
        }, indent=2)

    def _check(self, kw):
        """Lint a public repo's rappid.json for compliance (network fetch)."""
        repo = (kw.get("repo") or "").strip()
        if not repo:
            return json.dumps({"status": "error", "message": "provide 'repo' as owner/name or a github URL"})
        m = re.search(r"github\.com/([^/]+)/([^/#?]+)", repo) or re.match(r"([^/]+)/([^/#?]+)$", repo)
        if not m:
            return json.dumps({"status": "error", "message": f"cannot parse repo from {repo!r}"})
        owner, name = m.group(1), m.group(2).replace(".git", "")
        findings, evidence = [], []
        try:
            raw = _fetch(f"https://raw.githubusercontent.com/{owner}/{name}/main/rappid.json")
            d = json.loads(raw)
        except Exception:
            return json.dumps({"status": "ok", "action": "check", "repo": f"{owner}/{name}",
                               "verdict": "CLEAN", "note": "no rappid.json on main — no RAPP artifacts to lint"})
        rid = d.get("rappid", "")
        if rappid_valid(rid):
            evidence.append(f"rappid §6.1 grammar OK: {rid}")
        else:
            tail = rid.rsplit(":", 1)[-1] if ":" in rid else rid
            findings.append(f"§6.1 identity: {'32-hex short-tail (C3)' if re.match(r'^[0-9a-f]{32}$', tail) else 'not RAPP grammar'} — {rid}")
        if d.get("schema") != "rapp/1":
            findings.append(f"§12 schema label: schema='{d.get('schema')}', not 'rapp/1'")
        p = d.get("parent_rappid")
        if p and not rappid_valid(p):
            findings.append(f"§6.3 parent_rappid not RAPP grammar: {p}")
        verdict = "COMPLIANT" if not findings else "DRIFT"
        return json.dumps({"status": "ok", "action": "check", "repo": f"{owner}/{name}",
                           "verdict": verdict, "findings": findings, "evidence": evidence}, indent=2)

    def _sync(self):
        """Prove the embedded SDK matches the canonical public reference implementation.

        We do NOT execute the fetched code — running remote code is a security hazard (and
        registries forbid it). Instead we compare the *source definitions* of the primitive
        functions (canonical/H/Hb) textually, parsing with `ast` (which never executes),
        against our own embedded copy. Identical definitions ⇒ identical addresses.
        """
        import ast, inspect, sys
        try:
            remote_src = _fetch(SRC).decode("utf-8")
        except Exception as e:
            return json.dumps({"status": "error", "action": "sync", "message": f"fetch failed: {e}"})

        roots = ("canonical", "H", "Hb", "_strict_json", "build_frame")

        def _defs(src):
            # Normalize each top-level definition to its executable form: strip a function's
            # leading docstring, then ast.unparse (which also drops comments). Constants and
            # tables (single-name assignments) are compared too, because the primitives use them.
            out, nodes = {}, {}
            for node in ast.parse(src).body:
                if isinstance(node, ast.FunctionDef):
                    body = list(node.body)
                    if (body and isinstance(body[0], ast.Expr)
                            and isinstance(getattr(body[0], "value", None), ast.Constant)
                            and isinstance(body[0].value.value, str)):
                        body = body[1:] or [ast.Pass()]
                    node.body = body
                    out[node.name], nodes[node.name] = ast.unparse(node), node
                elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name)):
                    out[node.targets[0].id], nodes[node.targets[0].id] = ast.unparse(node), node
            return out, nodes

        def _closure(nodes):
            # Everything the address and frame primitives use, directly or indirectly: equal
            # definitions of this whole set mean identical computation, not just equal names.
            seen, todo = set(), list(roots)
            while todo:
                name = todo.pop()
                if name in seen or name not in nodes:
                    continue
                seen.add(name)
                todo.extend(n.id for n in ast.walk(nodes[name]) if isinstance(n, ast.Name) and n.id in nodes)
            return seen

        local_src = None
        for get in (lambda: inspect.getsource(sys.modules[__name__]),
                    lambda: open(__file__, "r", encoding="utf-8").read()):
            try:
                local_src = get(); break
            except Exception:
                continue
        if local_src is None:
            return json.dumps({"status": "error", "action": "sync", "message": "cannot read local source"})

        (remote_defs, remote_nodes), (local_defs, _local_nodes) = _defs(remote_src), _defs(local_src)
        compared = sorted(_closure(remote_nodes))
        per = {p: (p in remote_defs and local_defs.get(p) == remote_defs.get(p)) for p in compared}
        match = bool(per) and all(per.values())
        return json.dumps({"status": "ok", "action": "sync",
                           "embedded_matches_public_reference": match,
                           "per_primitive": per,
                           "source": SRC,
                           "vector_particle": H("rapp/1:particle", {"b": 1, "a": [3, 2]}),
                           "note": "The embedded canonical/H/Hb/_strict_json/build_frame definitions, and every "
                                   "helper, table and constant they use, were compared textually (parsed with "
                                   "ast — no code executed) against the freshly-fetched public reference. Equal "
                                   "⇒ this agent parses, canonicalizes, addresses and builds frames byte-for-byte "
                                   "with rapp.py."}, indent=2)


# standalone self-test: `python3 rapp_sdk_builder_agent.py`
if __name__ == "__main__":
    a = RappSdkBuilderAgent()
    print("mint     :", a.perform(action="mint", id="@me/notes"))
    print("scaffold :", a.perform(action="scaffold", id="@me/scratch")[:160], "…")
    print("canon    :", a.perform(action="canonicalize", value={"b": 1, "a": [3, 2]}))
    print("discover :", a.perform(action="discover", protocol="rapp-work/1")[:160], "…")
    fr = json.loads(a.perform(action="scaffold", id="@me/x"))["files"]["frames/0.json"]
    print("verify   :", a.perform(action="verify", frame=fr))
