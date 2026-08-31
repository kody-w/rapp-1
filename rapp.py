"""rapp.py — reference implementation of the RAPP protocol suite (rev-15).

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
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")

FRAME_KEYS = {"spec", "kind", "stream_id", "seq", "utc", "payload",
              "payload_hash", "frame_hash", "prev", "prev_wave", "sig"}

LENS_KIND = "body.lens"
TILE_KINDS = {
    "body.tile": "body",
    "memory.tile": "memory",
    "swarm.tile": "swarm",
}
REGENESIS_KINDS = {
    "body.re-genesis",
    "memory.re-genesis",
    "swarm.re-genesis",
}
LENS_SCHEMA = "rapp-lens/1"
TILE_SCHEMA = "rapp-tile/1"
LINEAGE_REF_KEYS = {"frame_hash", "era"}
LINEAGE_RESOLUTION_KEYS = {"frames", "persisted", "invocation_id"}
LENS_PAYLOAD_KEYS = {
    "schema",
    "runner",
    "mutation",
    "inputs",
    "stochastic_inputs",
    "facets",
}
TILE_PAYLOAD_KEYS = {
    "schema",
    "crack",
    "lens",
    "parents",
    "root_sources",
    "generation",
    "replay",
    "output",
}
CRACK_KEYS = {"crack_id", "facet", "tile_index", "tile_count"}
_LINEAGE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


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
        if not all(isinstance(k, str) for k in v):
            raise ValueError("object member names MUST be strings")
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
    return header, parts[0], _b64url_decode(parts[2])


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


# ---------- §7.7 lens cracking and tile lineage ----------
class _LensTileRefusal(ValueError):
    pass


def _json_copy(value):
    try:
        return json.loads(canonical(value))
    except (AttributeError, RecursionError, TypeError, ValueError) as exc:
        raise _LensTileRefusal(
            f"value is not canonical I-JSON: {exc}"
        ) from exc


def _uint53(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 2**53 - 1
    )


def _json_depth(value):
    if not isinstance(value, (dict, list)):
        return 1
    maximum = 1
    active = set()
    stack = [(value, 1, False)]
    while stack:
        current, depth, exiting = stack.pop()
        identity = id(current)
        if exiting:
            active.remove(identity)
            continue
        if identity in active:
            raise _LensTileRefusal(
                "cyclic Python object graph is not a JSON tree"
            )
        active.add(identity)
        maximum = max(maximum, depth)
        stack.append((current, depth, True))
        if isinstance(current, dict):
            stack.extend(
                (item, depth + 1, False)
                for item in current.values()
                if isinstance(item, (dict, list))
            )
        elif isinstance(current, list):
            stack.extend(
                (item, depth + 1, False)
                for item in current
                if isinstance(item, (dict, list))
            )
    return maximum


def _semantic_value_limits(value, label):
    depth = _json_depth(value)
    if depth > 64:
        raise _LensTileRefusal(f"{label} exceeds JSON nesting depth 64")
    try:
        octets = canonical(value).encode("utf-8")
    except RecursionError as exc:
        raise _LensTileRefusal(f"{label} exceeds safe canonical depth") from exc
    except (AttributeError, TypeError, ValueError) as exc:
        raise _LensTileRefusal(f"{label} is not canonical I-JSON: {exc}")
    if len(octets) > MAX_CANONICAL_BYTES:
        raise _LensTileRefusal(
            f"{label} exceeds the 1 MiB canonical-byte limit"
        )
    return octets


def _stream_family(stream_id):
    if rappid_valid(stream_id):
        return "body"
    if isinstance(stream_id, str) and stream_id.startswith("net:"):
        label = stream_id[4:]
        if 1 <= len(label) <= 64 and _LCLABEL.fullmatch(label):
            return "swarm"
        return None
    if isinstance(stream_id, str):
        body_stream, separator, instance = stream_id.rpartition(":")
        if (
            separator
            and rappid_valid(body_stream)
            and 1 <= len(instance) <= 64
            and _LCLABEL.fullmatch(instance)
        ):
            return "memory"
    return None


def _registered_kind_family(kind, expected_family, kind_family_resolver):
    if kind_family_resolver is None:
        raise _LensTileRefusal(
            "semantic verification requires an injected registered-kind resolver"
        )
    try:
        family = kind_family_resolver(kind)
    except Exception as exc:
        raise _LensTileRefusal(f"registered-kind resolver failed: {exc}")
    if family != expected_family:
        raise _LensTileRefusal(
            f"registered kind {kind} is not bound to family {expected_family}"
        )


def _signature_verifier_for(frame, signature_verifier):
    if frame.get("kind") != LENS_KIND or signature_verifier is None:
        return signature_verifier
    expected_signer = frame.get("stream_id")

    def bound(unsigned, sig):
        return signature_verifier(unsigned, sig, expected_signer)

    return bound


def _ordinary_frame_result(
    frame,
    *,
    head,
    stream_id_of_record,
    signature_verifier,
):
    try:
        return verify_frame(
            frame,
            head=head,
            stream_id_of_record=stream_id_of_record,
            signature_verifier=_signature_verifier_for(
                frame,
                signature_verifier,
            ),
        )
    except (
        AttributeError,
        IndexError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        return False, "1", f"invalid canonical frame value: {exc}"


def _validate_names(values, label, *, nonempty=False):
    if (
        not isinstance(values, list)
        or (nonempty and not values)
        or any(
            not isinstance(value, str)
            or not 1 <= len(value) <= 64
            or not _LINEAGE_NAME.fullmatch(value)
            for value in values
        )
        or len(values) != len(set(values))
    ):
        raise _LensTileRefusal(
            f"lens {label} MUST be an ordered "
            f"{'non-empty ' if nonempty else ''}duplicate-free lclabel array"
        )


def _validate_lens_payload(payload):
    if not isinstance(payload, dict) or set(payload) != LENS_PAYLOAD_KEYS:
        raise _LensTileRefusal(
            "lens payload MUST have exactly schema,runner,mutation,inputs,"
            "stochastic_inputs,facets"
        )
    if payload["schema"] != LENS_SCHEMA:
        raise _LensTileRefusal(f"lens schema MUST be {LENS_SCHEMA}")
    runner = payload["runner"]
    if (
        not isinstance(runner, str)
        or not 1 <= len(runner) <= 200
        or runner != runner.strip()
        or unicodedata.normalize("NFC", runner) != runner
    ):
        raise _LensTileRefusal("lens runner MUST be bounded NFC text")
    if not isinstance(payload["mutation"], dict):
        raise _LensTileRefusal("lens mutation MUST be an object")
    if payload["mutation"].get("parent_order") not in {
        "declared",
        "dream-catcher",
    }:
        raise _LensTileRefusal(
            "lens mutation.parent_order MUST be declared or dream-catcher"
        )
    _validate_names(payload["inputs"], "inputs")
    _validate_names(payload["stochastic_inputs"], "stochastic_inputs")
    _validate_names(payload["facets"], "facets", nonempty=True)
    if set(payload["inputs"]) & set(payload["stochastic_inputs"]):
        raise _LensTileRefusal(
            "lens inputs and stochastic_inputs MUST be disjoint"
        )
    _semantic_value_limits(payload, "lens payload")


def verify_lens_frame(
    frame,
    head=None,
    stream_id_of_record=None,
    signature_verifier=None,
    kind_family_resolver=None,
):
    """Verify one immutable signed body.lens frame.

    signature_verifier(unsigned_frame, sig, expected_signer) must bind the
    signature to the lens's body-stream RAPPID.
    """
    ok, step, why = _ordinary_frame_result(
        frame,
        head=head,
        stream_id_of_record=stream_id_of_record,
        signature_verifier=signature_verifier,
    )
    if not ok:
        return False, step, why
    try:
        if frame["kind"] != LENS_KIND:
            raise _LensTileRefusal("lens kind MUST be exactly body.lens")
        if _stream_family(frame["stream_id"]) != "body":
            raise _LensTileRefusal("body.lens MUST use a body stream")
        _registered_kind_family(
            frame["kind"],
            "body",
            kind_family_resolver,
        )
        if not isinstance(frame["sig"], str) or not frame["sig"]:
            raise _LensTileRefusal("body.lens MUST carry a signature")
        _validate_lens_payload(frame["payload"])
        _semantic_value_limits(frame, "lens frame")
    except _LensTileRefusal as exc:
        return False, "§7.7", str(exc)
    return True, None, "ok"


def build_lens_frame(
    stream_id,
    seq,
    utc,
    *,
    runner,
    mutation,
    inputs,
    stochastic_inputs,
    facets,
    prev,
    sig,
):
    """Build a closed body.lens frame; signature verification is separate."""
    try:
        if (
            not isinstance(inputs, list)
            or not isinstance(stochastic_inputs, list)
            or not isinstance(facets, list)
        ):
            raise _LensTileRefusal(
                "lens inputs, stochastic_inputs, and facets MUST be arrays"
            )
        payload = {
            "schema": LENS_SCHEMA,
            "runner": runner,
            "mutation": _json_copy(mutation),
            "inputs": _json_copy(inputs),
            "stochastic_inputs": _json_copy(stochastic_inputs),
            "facets": _json_copy(facets),
        }
        _validate_lens_payload(payload)
        if _stream_family(stream_id) != "body":
            raise _LensTileRefusal("body.lens MUST use a body stream")
        if not isinstance(sig, str) or not sig:
            raise _LensTileRefusal("body.lens MUST carry a signature")
        frame = build_frame(
            LENS_KIND,
            stream_id,
            seq,
            utc,
            payload,
            prev,
            sig=sig,
        )
        _semantic_value_limits(frame, "lens frame")
        return frame
    except (RecursionError, _LensTileRefusal) as exc:
        raise ValueError(str(exc)) from exc


def make_lineage_ref(frame, era):
    """Return the exact frame-hash/era reference used by §7.7."""
    ref = {"frame_hash": frame.get("frame_hash"), "era": era}
    _validate_lineage_ref(ref, "lineage reference")
    return ref


def _validate_lineage_ref(ref, label):
    if (
        not isinstance(ref, dict)
        or set(ref) != LINEAGE_REF_KEYS
        or not isinstance(ref.get("frame_hash"), str)
        or not _HEX64.fullmatch(ref["frame_hash"])
        or not isinstance(ref.get("era"), str)
        or not _HEX64.fullmatch(ref["era"])
    ):
        raise _LensTileRefusal(
            f"{label} MUST be exactly {{frame_hash,era}} with 64hex values"
        )
    return (ref["frame_hash"], ref["era"])


def _validate_ref_list(refs, label, *, nonempty):
    if not isinstance(refs, list) or (nonempty and not refs):
        qualifier = "non-empty " if nonempty else ""
        raise _LensTileRefusal(f"{label} MUST be a {qualifier}array")
    keys = [_validate_lineage_ref(ref, label) for ref in refs]
    if len(keys) != len(set(keys)):
        raise _LensTileRefusal(f"{label} MUST NOT contain duplicate references")
    return keys


def _resolve_lineage_ref(
    ref,
    resolver,
    signature_verifier,
    genesis_verifier,
    kind_family_resolver,
    *,
    require_persisted,
    invocation_id,
):
    key = _validate_lineage_ref(ref, "lineage reference")
    if resolver is None:
        raise _LensTileRefusal("lineage resolution requires an injected resolver")
    try:
        resolved = resolver(ref["frame_hash"], ref["era"])
    except Exception as exc:
        raise _LensTileRefusal(f"lineage resolver failed: {exc}")
    if not isinstance(resolved, dict) or set(resolved) != LINEAGE_RESOLUTION_KEYS:
        raise _LensTileRefusal(
            "lineage resolver result MUST be exactly "
            "{frames,persisted,invocation_id}"
        )
    frames = resolved["frames"]
    persisted = resolved["persisted"]
    resolved_invocation = resolved["invocation_id"]
    if not isinstance(frames, list) or not frames or not all(
        isinstance(item, dict) for item in frames
    ):
        raise _LensTileRefusal("resolved lineage MUST be a non-empty frame array")
    if not isinstance(persisted, bool):
        raise _LensTileRefusal("resolved persisted flag MUST be boolean")
    if persisted:
        if resolved_invocation is not None:
            raise _LensTileRefusal(
                "persisted lineage resolution MUST have invocation_id null"
            )
    elif (
        not isinstance(resolved_invocation, str)
        or not resolved_invocation
        or resolved_invocation != invocation_id
    ):
        raise _LensTileRefusal(
            "transient lineage is usable only in the same invocation"
        )
    if require_persisted and not persisted:
        raise _LensTileRefusal(
            "durable or actionable lineage requires every intermediate tile persisted"
        )
    stream_id = frames[0].get("stream_id")
    if kind_family_resolver is None:
        kind_family_resolver = getattr(
            resolver,
            "kind_family_resolver",
            None,
        )
    previous = None
    for candidate in frames:
        ok, step, why = _ordinary_frame_result(
            candidate,
            head=previous,
            stream_id_of_record=stream_id,
            signature_verifier=signature_verifier,
        )
        if not ok:
            raise _LensTileRefusal(
                f"resolved lineage frame refused at {step}: {why}"
            )
        family = _stream_family(candidate["stream_id"])
        if family is None:
            raise _LensTileRefusal(
                "resolved lineage frame has an invalid stream family"
            )
        _registered_kind_family(
            candidate["kind"],
            family,
            kind_family_resolver,
        )
        previous = candidate
    if frames[0]["frame_hash"] != ref["era"]:
        raise _LensTileRefusal("lineage era does not name the resolved genesis")
    if genesis_verifier is None:
        genesis_verifier = getattr(resolver, "genesis_verifier", None)
    if genesis_verifier is None:
        raise _LensTileRefusal(
            "lineage resolution requires registered genesis authority"
        )
    try:
        genesis_result = genesis_verifier(stream_id, ref["era"])
    except Exception as exc:
        raise _LensTileRefusal(f"registered genesis verifier failed: {exc}")
    genesis_ok = (
        bool(genesis_result[0])
        if isinstance(genesis_result, tuple) and genesis_result
        else genesis_result is True
    )
    if not genesis_ok:
        raise _LensTileRefusal(
            "lineage era is not the accepted registered genesis"
        )
    if frames[-1]["frame_hash"] != ref["frame_hash"]:
        raise _LensTileRefusal("lineage frame_hash resolved to the wrong frame")
    return frames[-1], (frames[-2] if len(frames) > 1 else None), persisted, key


def _validate_replay(replay, lens_payload):
    if not isinstance(replay, dict):
        raise _LensTileRefusal("tile replay MUST be an object")
    mode = replay.get("mode")
    if mode == "deterministic":
        if set(replay) != {"mode", "inputs"}:
            raise _LensTileRefusal(
                "deterministic replay MUST be exactly {mode,inputs}"
            )
        if lens_payload["stochastic_inputs"]:
            raise _LensTileRefusal(
                "a lens declaring stochastic inputs requires seeded replay"
            )
    elif mode == "seeded":
        if set(replay) != {"mode", "inputs", "stochastic_inputs"}:
            raise _LensTileRefusal(
                "seeded replay MUST be exactly "
                "{mode,inputs,stochastic_inputs}"
            )
        if not lens_payload["stochastic_inputs"]:
            raise _LensTileRefusal(
                "seeded replay requires declared stochastic inputs"
            )
        stochastic = replay["stochastic_inputs"]
        if not isinstance(stochastic, dict) or set(stochastic) != set(
            lens_payload["stochastic_inputs"]
        ):
            raise _LensTileRefusal(
                "seeded replay MUST record every declared stochastic input"
            )
    else:
        raise _LensTileRefusal(
            "persisted tile replay mode MUST be deterministic or seeded"
        )
    inputs = replay.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != set(lens_payload["inputs"]):
        raise _LensTileRefusal(
            "tile replay inputs MUST exactly match the lens declaration"
        )
    _semantic_value_limits(replay, "tile replay")


def crack_id(lens, parents, replay):
    """Identify one exact lens invocation in the existing particle space."""
    invocation = {
        "schema": "rapp-crack/1",
        "lens": lens,
        "parents": parents,
        "replay": replay,
    }
    _semantic_value_limits(invocation, "crack invocation")
    return H("rapp/1:particle", invocation)


def verify_clean_frame(
    frame,
    head=None,
    stream_id_of_record=None,
    signature_verifier=None,
    kind_family_resolver=None,
):
    """Verify a fresh/source frame that contributes lineage generation 0."""
    ok, step, why = _ordinary_frame_result(
        frame,
        head=head,
        stream_id_of_record=stream_id_of_record,
        signature_verifier=signature_verifier,
    )
    if not ok:
        return False, step, why
    try:
        _semantic_value_limits(frame, "source frame")
    except _LensTileRefusal as exc:
        return False, "§7.7", str(exc)
    if frame["payload"].get("schema") == TILE_SCHEMA:
        return (
            False,
            "§7.7",
            "rapp-tile/1 payload cannot be relabeled as a generation-0 source",
        )
    family = _stream_family(frame["stream_id"])
    if family is None:
        return False, "§7.7", "source frame stream family is invalid"
    try:
        _registered_kind_family(
            frame["kind"],
            family,
            kind_family_resolver,
        )
    except _LensTileRefusal as exc:
        return False, "§7.7", str(exc)
    if frame["kind"] == LENS_KIND:
        return False, "§7.7", "a lens is an operation, not a source frame"
    if frame["kind"] in TILE_KINDS:
        return (
            False,
            "§7.7",
            "a tile/worn frame is not a generation-0 fresh source",
        )
    if frame["kind"] in REGENESIS_KINDS:
        return False, "§7.7", "re-genesis is not a source frame"
    return True, None, "ok"


def _tile_shape(frame, kind_family_resolver):
    payload = frame["payload"]
    if not isinstance(payload, dict) or set(payload) != TILE_PAYLOAD_KEYS:
        raise _LensTileRefusal(
            "tile payload MUST have exactly schema,crack,lens,parents,"
            "root_sources,generation,replay,output"
        )
    if payload["schema"] != TILE_SCHEMA:
        raise _LensTileRefusal(f"tile schema MUST be {TILE_SCHEMA}")
    expected_family = TILE_KINDS.get(frame["kind"])
    if expected_family is None:
        raise _LensTileRefusal(
            "tile kind MUST be exactly body.tile, memory.tile, or swarm.tile"
        )
    if _stream_family(frame["stream_id"]) != expected_family:
        raise _LensTileRefusal("tile kind is incompatible with its stream family")
    _registered_kind_family(
        frame["kind"],
        expected_family,
        kind_family_resolver,
    )
    crack = payload["crack"]
    if (
        not isinstance(crack, dict)
        or set(crack) != CRACK_KEYS
        or not isinstance(crack.get("crack_id"), str)
        or not _HEX64.fullmatch(crack["crack_id"])
        or not isinstance(crack.get("facet"), str)
        or not _LINEAGE_NAME.fullmatch(crack["facet"])
        or not _uint53(crack.get("tile_index"))
        or not _uint53(crack.get("tile_count"))
        or crack["tile_count"] < 1
        or crack["tile_index"] >= crack["tile_count"]
    ):
        raise _LensTileRefusal(
            "tile crack MUST be exactly "
            "{crack_id,facet,tile_index,tile_count} with a valid facet slot"
        )
    _validate_lineage_ref(payload["lens"], "tile lens")
    _validate_ref_list(payload["parents"], "tile parents", nonempty=True)
    _validate_ref_list(
        payload["root_sources"],
        "tile root_sources",
        nonempty=True,
    )
    if not _uint53(payload["generation"]) or payload["generation"] < 1:
        raise _LensTileRefusal("tile generation MUST be a uint53 >= 1")
    if not isinstance(payload["output"], dict):
        raise _LensTileRefusal("tile output MUST be an object")
    _semantic_value_limits(payload["output"], "tile output")
    _semantic_value_limits(frame, "tile frame")
    lineage_hashes = {
        payload["lens"]["frame_hash"],
        *(ref["frame_hash"] for ref in payload["parents"]),
    }
    if frame["prev"] in lineage_hashes:
        raise _LensTileRefusal(
            "frame.prev is the stream predecessor payload hash, not a lineage pointer"
        )


def verify_lineage_dag(edges):
    """Iteratively refuse duplicate edges and cycles in a hash-addressed DAG."""
    try:
        if not isinstance(edges, dict):
            raise _LensTileRefusal("lineage edges MUST be an object")
        graph = {}
        for node, parents in edges.items():
            if not isinstance(node, str) or not _HEX64.fullmatch(node):
                raise _LensTileRefusal("lineage node MUST be 64hex")
            if (
                not isinstance(parents, list)
                or any(
                    not isinstance(parent, str)
                    or not _HEX64.fullmatch(parent)
                    for parent in parents
                )
                or len(parents) != len(set(parents))
            ):
                raise _LensTileRefusal(
                    "lineage parent edges MUST be duplicate-free 64hex arrays"
                )
            graph[node] = parents
        done = set()
        active = set()
        for start in graph:
            if start in done:
                continue
            stack = [(start, 0)]
            while stack:
                node, index = stack[-1]
                if index == 0:
                    if node in active:
                        raise _LensTileRefusal(
                            "lens/tile lineage DAG contains a cycle"
                        )
                    if node in done:
                        stack.pop()
                        continue
                    active.add(node)
                parents = graph.get(node, [])
                if index < len(parents):
                    parent = parents[index]
                    stack[-1] = (node, index + 1)
                    if parent in active:
                        raise _LensTileRefusal(
                            "lens/tile lineage DAG contains a cycle"
                        )
                    if parent not in done:
                        stack.append((parent, 0))
                    continue
                active.remove(node)
                done.add(node)
                stack.pop()
    except (RecursionError, _LensTileRefusal) as exc:
        return False, "§7.7", str(exc)
    return True, None, "ok"


def _prepare_tile_node(
    frame,
    *,
    resolver,
    runner,
    signature_verifier,
    genesis_verifier,
    kind_family_resolver,
    require_persisted,
    invocation_id,
):
    if kind_family_resolver is None:
        kind_family_resolver = getattr(
            resolver,
            "kind_family_resolver",
            None,
        )
    _tile_shape(frame, kind_family_resolver)
    payload = frame["payload"]
    lens, lens_head, _, _ = _resolve_lineage_ref(
        payload["lens"],
        resolver,
        signature_verifier,
        genesis_verifier,
        kind_family_resolver,
        require_persisted=True,
        invocation_id=invocation_id,
    )
    lens_ok, lens_step, lens_why = verify_lens_frame(
        lens,
        head=lens_head,
        stream_id_of_record=lens["stream_id"],
        signature_verifier=signature_verifier,
        kind_family_resolver=kind_family_resolver,
    )
    if not lens_ok:
        raise _LensTileRefusal(
            f"referenced lens refused at {lens_step}: {lens_why}"
        )
    _validate_replay(payload["replay"], lens["payload"])
    if payload["crack"]["crack_id"] != crack_id(
        payload["lens"],
        payload["parents"],
        payload["replay"],
    ):
        raise _LensTileRefusal(
            "tile crack.crack_id does not match the invocation"
        )
    parents = []
    for ref in payload["parents"]:
        target, target_head, _persisted, key = _resolve_lineage_ref(
            ref,
            resolver,
            signature_verifier,
            genesis_verifier,
            kind_family_resolver,
            require_persisted=require_persisted,
            invocation_id=invocation_id,
        )
        if target["kind"] == LENS_KIND:
            raise _LensTileRefusal("a lens frame cannot be a tile parent")
        if target["kind"] in TILE_KINDS:
            parents.append(
                {
                    "ref": _json_copy(ref),
                    "key": key,
                    "frame": target,
                    "head": target_head,
                }
            )
        else:
            ok, step, why = verify_clean_frame(
                target,
                head=target_head,
                stream_id_of_record=target["stream_id"],
                signature_verifier=signature_verifier,
                kind_family_resolver=kind_family_resolver,
            )
            if not ok:
                raise _LensTileRefusal(
                    f"fresh parent refused at {step}: {why}"
                )
            parents.append(
                {
                    "ref": _json_copy(ref),
                    "summary": (
                        0,
                        [_json_copy(ref)],
                        _json_copy(target),
                    ),
                }
            )
    return {"lens": lens, "parents": parents, "runner": runner}


def _finalize_tile_node(frame, prepared, memo):
    payload = frame["payload"]
    parent_generations = []
    expected_roots = []
    seen_roots = set()
    parent_frames = []
    for parent in prepared["parents"]:
        summary = (
            parent["summary"]
            if "summary" in parent
            else memo[parent["key"]]
        )
        generation, roots, parent_frame = summary
        parent_generations.append(generation)
        parent_frames.append(_json_copy(parent_frame))
        for root in roots:
            root_key = _validate_lineage_ref(root, "computed root source")
            if root_key not in seen_roots:
                seen_roots.add(root_key)
                expected_roots.append(_json_copy(root))
    lens = prepared["lens"]
    if lens["payload"]["mutation"]["parent_order"] == "dream-catcher":
        order = [
            (parent["utc"], parent["frame_hash"])
            for parent in parent_frames
        ]
        if order != sorted(order):
            raise _LensTileRefusal(
                "unordered crack inputs MUST use Dream-Catcher "
                "(utc,frame_hash) order"
            )
    expected_generation = 1 + max(parent_generations)
    if payload["generation"] != expected_generation:
        raise _LensTileRefusal(
            "tile generation MUST equal 1 + max(parent tile generation; "
            "non-tile parent = 0)"
        )
    if payload["root_sources"] != expected_roots:
        raise _LensTileRefusal(
            "tile root_sources do not exactly match ordered root closure"
        )
    if prepared["runner"] is None:
        raise _LensTileRefusal(
            "tile replay requires an injected deterministic runner"
        )
    try:
        replayed_outputs = prepared["runner"](
            _json_copy(lens["payload"]),
            parent_frames,
            _json_copy(payload["replay"]),
        )
    except RecursionError as exc:
        raise _LensTileRefusal("tile replay runner exceeded safe depth") from exc
    except Exception as exc:
        raise _LensTileRefusal(f"tile replay runner failed: {exc}")
    if (
        not isinstance(replayed_outputs, list)
        or not replayed_outputs
        or not all(isinstance(item, dict) for item in replayed_outputs)
    ):
        raise _LensTileRefusal(
            "tile replay runner MUST return a non-empty ordered object array"
        )
    _semantic_value_limits(replayed_outputs, "tile runner outputs")
    if len(replayed_outputs) != payload["crack"]["tile_count"]:
        raise _LensTileRefusal(
            "tile crack.tile_count does not match replayed outputs"
        )
    if len(lens["payload"]["facets"]) != payload["crack"]["tile_count"]:
        raise _LensTileRefusal(
            "tile crack.tile_count does not match lens facets"
        )
    tile_index = payload["crack"]["tile_index"]
    if payload["crack"]["facet"] != lens["payload"]["facets"][tile_index]:
        raise _LensTileRefusal(
            "tile crack.facet does not match the signed lens slot"
        )
    replayed_payload = {
        "schema": payload["schema"],
        "crack": _json_copy(payload["crack"]),
        "lens": _json_copy(payload["lens"]),
        "parents": _json_copy(payload["parents"]),
        "root_sources": _json_copy(payload["root_sources"]),
        "generation": payload["generation"],
        "replay": _json_copy(payload["replay"]),
        "output": replayed_outputs[tile_index],
    }
    replayed_bytes = _semantic_value_limits(
        replayed_payload,
        "replayed tile payload",
    )
    stored_bytes = _semantic_value_limits(payload, "stored tile payload")
    if replayed_bytes != stored_bytes:
        raise _LensTileRefusal(
            "tile replay did not reproduce byte-identical canonical payload"
        )
    return (
        payload["generation"],
        _json_copy(payload["root_sources"]),
        _json_copy(frame),
    )


def _verify_tile_graph(
    frame,
    *,
    head,
    stream_id_of_record,
    resolver,
    runner,
    signature_verifier,
    genesis_verifier,
    kind_family_resolver,
    require_persisted,
    invocation_id,
    root_key=None,
    memo=None,
):
    ok, step, why = _ordinary_frame_result(
        frame,
        head=head,
        stream_id_of_record=stream_id_of_record,
        signature_verifier=signature_verifier,
    )
    if not ok:
        return False, step, why, None, None, None
    memo = {} if memo is None else memo
    root_key = (
        (frame["frame_hash"], None)
        if root_key is None
        else root_key
    )
    if root_key in memo:
        generation, roots, output_frame = memo[root_key]
        return True, None, "ok", generation, roots, output_frame
    active = set()
    stack = [
        {
            "key": root_key,
            "frame": frame,
            "head": head,
            "prepared": None,
            "next_parent": 0,
        }
    ]
    try:
        while stack:
            node = stack[-1]
            node_hash = node["frame"]["frame_hash"]
            if node["prepared"] is None:
                if node_hash in active:
                    raise _LensTileRefusal(
                        "lens/tile lineage DAG contains a cycle"
                    )
                active.add(node_hash)
                node["prepared"] = _prepare_tile_node(
                    node["frame"],
                    resolver=resolver,
                    runner=runner,
                    signature_verifier=signature_verifier,
                    genesis_verifier=genesis_verifier,
                    kind_family_resolver=kind_family_resolver,
                    require_persisted=require_persisted,
                    invocation_id=invocation_id,
                )
            parents = node["prepared"]["parents"]
            pushed = False
            while node["next_parent"] < len(parents):
                parent = parents[node["next_parent"]]
                node["next_parent"] += 1
                if "key" not in parent or parent["key"] in memo:
                    continue
                parent_hash = parent["frame"]["frame_hash"]
                if parent_hash in active:
                    raise _LensTileRefusal(
                        "lens/tile lineage DAG contains a cycle"
                    )
                stack.append(
                    {
                        "key": parent["key"],
                        "frame": parent["frame"],
                        "head": parent["head"],
                        "prepared": None,
                        "next_parent": 0,
                    }
                )
                pushed = True
                break
            if pushed:
                continue
            summary = _finalize_tile_node(
                node["frame"],
                node["prepared"],
                memo,
            )
            memo[node["key"]] = summary
            active.remove(node_hash)
            stack.pop()
        generation, roots, output_frame = memo[root_key]
        return True, None, "ok", generation, roots, output_frame
    except (RecursionError, _LensTileRefusal) as exc:
        return False, "§7.7", str(exc), None, None, None


def _summarize_parent_refs(
    refs,
    *,
    resolver,
    runner,
    signature_verifier,
    genesis_verifier,
    kind_family_resolver,
    require_persisted,
    invocation_id,
):
    if kind_family_resolver is None:
        kind_family_resolver = getattr(
            resolver,
            "kind_family_resolver",
            None,
        )
    summaries = []
    memo = {}
    for ref in refs:
        target, target_head, _persisted, key = _resolve_lineage_ref(
            ref,
            resolver,
            signature_verifier,
            genesis_verifier,
            kind_family_resolver,
            require_persisted=require_persisted,
            invocation_id=invocation_id,
        )
        if target["kind"] == LENS_KIND:
            raise _LensTileRefusal("a lens frame cannot be a tile parent")
        if target["kind"] in TILE_KINDS:
            result = _verify_tile_graph(
                target,
                head=target_head,
                stream_id_of_record=target["stream_id"],
                resolver=resolver,
                runner=runner,
                signature_verifier=signature_verifier,
                genesis_verifier=genesis_verifier,
                kind_family_resolver=kind_family_resolver,
                require_persisted=require_persisted,
                invocation_id=invocation_id,
                root_key=key,
                memo=memo,
            )
            if not result[0]:
                raise _LensTileRefusal(
                    f"tile parent refused at {result[1]}: {result[2]}"
                )
            summary = (result[3], result[4], _json_copy(target))
        else:
            ok, step, why = verify_clean_frame(
                target,
                head=target_head,
                stream_id_of_record=target["stream_id"],
                signature_verifier=signature_verifier,
                kind_family_resolver=kind_family_resolver,
            )
            if not ok:
                raise _LensTileRefusal(
                    f"fresh parent refused at {step}: {why}"
                )
            summary = (0, [_json_copy(ref)], _json_copy(target))
        summaries.append({"ref": _json_copy(ref), "summary": summary})
    return summaries


def verify_tile_frame(
    frame,
    head=None,
    stream_id_of_record=None,
    *,
    resolver=None,
    runner=None,
    signature_verifier=None,
    genesis_verifier=None,
    kind_family_resolver=None,
    invocation_id=None,
):
    """Statelessly verify tile shape, lineage, ordering, limits, and replay.

    resolver(frame_hash, era) returns exactly
    {"frames": [genesis,...,target], "persisted": bool,
     "invocation_id": str|null}. genesis_verifier(stream_id, era) must prove
    the accepted registered genesis; kind_family_resolver(kind) returns the
    exact registered family. These callbacks may instead be attributes on the
    resolver. Stateless verification never reserves a persisted facet slot.
    """
    result = _verify_tile_graph(
        frame,
        head=head,
        stream_id_of_record=stream_id_of_record,
        resolver=resolver,
        runner=runner,
        signature_verifier=signature_verifier,
        genesis_verifier=genesis_verifier,
        kind_family_resolver=kind_family_resolver,
        require_persisted=False,
        invocation_id=invocation_id,
    )
    return result[:3]


def accept_tile_frame(
    frame,
    head=None,
    stream_id_of_record=None,
    *,
    resolver=None,
    runner=None,
    signature_verifier=None,
    genesis_verifier=None,
    kind_family_resolver=None,
    facet_claim=None,
):
    """Verify persisted ancestry, then atomically claim its crack facet slot.

    facet_claim(crack_id, tile_index, frame_hash) performs compare-and-set and
    returns the hash bound after the claim. Only the same hash is accepted.
    """
    result = _verify_tile_graph(
        frame,
        head=head,
        stream_id_of_record=stream_id_of_record,
        resolver=resolver,
        runner=runner,
        signature_verifier=signature_verifier,
        genesis_verifier=genesis_verifier,
        kind_family_resolver=kind_family_resolver,
        require_persisted=True,
        invocation_id=None,
    )
    if not result[0]:
        return result[:3]
    if facet_claim is None:
        return False, "§7.7", "persisted tile acceptance requires atomic facet claim"
    crack = frame["payload"]["crack"]
    try:
        bound = facet_claim(
            crack["crack_id"],
            crack["tile_index"],
            frame["frame_hash"],
        )
    except Exception as exc:
        return False, "§7.7", f"atomic facet claim failed: {exc}"
    if (
        not isinstance(bound, str)
        or not _HEX64.fullmatch(bound)
    ):
        return False, "§7.7", "atomic facet claim MUST return the bound 64hex"
    if bound != frame["frame_hash"]:
        return (
            False,
            "§7.7",
            "crack facet slot is already bound to another frame",
        )
    return True, None, "ok"


def build_tile_frame(
    kind,
    stream_id,
    seq,
    utc,
    *,
    lens,
    parents,
    replay,
    resolver,
    runner,
    prev,
    head=None,
    prev_wave=None,
    sig=None,
    signature_verifier=None,
    genesis_verifier=None,
    kind_family_resolver=None,
    persisted=True,
    invocation_id=None,
    actionable=False,
    tile_index=0,
):
    """Build one crack result, deriving generation, roots, facets, and output.

    Dream-Catcher input parents are normalized on copies before identity,
    lineage, and runner evaluation; caller inputs are never mutated.
    """
    try:
        if kind_family_resolver is None:
            kind_family_resolver = getattr(
                resolver,
                "kind_family_resolver",
                None,
            )
        if not isinstance(persisted, bool) or not isinstance(actionable, bool):
            raise _LensTileRefusal(
                "persisted and actionable flags MUST be boolean"
            )
        if not persisted and (
            not isinstance(invocation_id, str) or not invocation_id
        ):
            raise _LensTileRefusal(
                "a transient candidate requires its invocation_id"
            )
        if not persisted and actionable:
            raise _LensTileRefusal(
                "a transient candidate cannot authorize side effects"
            )
        _validate_lineage_ref(lens, "tile lens")
        _validate_ref_list(parents, "tile parents", nonempty=True)
        lens_frame, lens_head, _, _ = _resolve_lineage_ref(
            lens,
            resolver,
            signature_verifier,
            genesis_verifier,
            kind_family_resolver,
            require_persisted=True,
            invocation_id=invocation_id,
        )
        ok, step, why = verify_lens_frame(
            lens_frame,
            head=lens_head,
            stream_id_of_record=lens_frame["stream_id"],
            signature_verifier=signature_verifier,
            kind_family_resolver=kind_family_resolver,
        )
        if not ok:
            raise _LensTileRefusal(
                f"referenced lens refused at {step}: {why}"
            )
        _validate_replay(replay, lens_frame["payload"])
        parent_records = _summarize_parent_refs(
            _json_copy(parents),
            resolver=resolver,
            runner=runner,
            signature_verifier=signature_verifier,
            genesis_verifier=genesis_verifier,
            kind_family_resolver=kind_family_resolver,
            require_persisted=persisted,
            invocation_id=invocation_id,
        )
        if lens_frame["payload"]["mutation"]["parent_order"] == "dream-catcher":
            parent_records.sort(
                key=lambda record: (
                    record["summary"][2]["utc"],
                    record["summary"][2]["frame_hash"],
                )
            )
        ordered_parents = [record["ref"] for record in parent_records]
        generations = []
        roots = []
        seen_roots = set()
        parent_frames = []
        for record in parent_records:
            generation, parent_roots, parent_frame = record["summary"]
            generations.append(generation)
            parent_frames.append(_json_copy(parent_frame))
            for root in parent_roots:
                key = _validate_lineage_ref(root, "computed root source")
                if key not in seen_roots:
                    seen_roots.add(key)
                    roots.append(_json_copy(root))
        if runner is None:
            raise _LensTileRefusal(
                "tile construction requires an injected deterministic runner"
            )
        try:
            outputs = runner(
                _json_copy(lens_frame["payload"]),
                parent_frames,
                _json_copy(replay),
            )
        except RecursionError as exc:
            raise _LensTileRefusal(
                "tile construction runner exceeded safe depth"
            ) from exc
        except Exception as exc:
            raise _LensTileRefusal(f"tile construction runner failed: {exc}")
        if (
            not isinstance(outputs, list)
            or not outputs
            or not all(isinstance(item, dict) for item in outputs)
        ):
            raise _LensTileRefusal(
                "tile runner MUST return a non-empty ordered object array"
            )
        _semantic_value_limits(outputs, "tile runner outputs")
        if len(outputs) != len(lens_frame["payload"]["facets"]):
            raise _LensTileRefusal(
                "tile runner output count MUST match signed lens facets"
            )
        if not _uint53(tile_index) or tile_index >= len(outputs):
            raise _LensTileRefusal(
                "tile_index MUST select one replayed facet output"
            )
        payload = {
            "schema": TILE_SCHEMA,
            "crack": {
                "crack_id": crack_id(lens, ordered_parents, replay),
                "facet": lens_frame["payload"]["facets"][tile_index],
                "tile_index": tile_index,
                "tile_count": len(outputs),
            },
            "lens": _json_copy(lens),
            "parents": _json_copy(ordered_parents),
            "root_sources": roots,
            "generation": 1 + max(generations),
            "replay": _json_copy(replay),
            "output": _json_copy(outputs[tile_index]),
        }
        frame = build_frame(
            kind,
            stream_id,
            seq,
            utc,
            payload,
            prev,
            prev_wave=prev_wave,
            sig=sig,
        )
        _semantic_value_limits(frame, "tile frame")
        ok, step, why = verify_tile_frame(
            frame,
            head=head,
            stream_id_of_record=stream_id,
            resolver=resolver,
            runner=runner,
            signature_verifier=signature_verifier,
            genesis_verifier=genesis_verifier,
            kind_family_resolver=kind_family_resolver,
            invocation_id=invocation_id,
        )
        if not ok:
            raise _LensTileRefusal(f"built tile refused at {step}: {why}")
        return frame
    except (RecursionError, _LensTileRefusal) as exc:
        raise ValueError(str(exc)) from exc


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
    try:
        unsigned = _json_copy(
            {k: v for k, v in manifest.items() if k != "sig"}
        )
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
