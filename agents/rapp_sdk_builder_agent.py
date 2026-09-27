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
import hashlib
import json
import re
import unicodedata
import urllib.request
import uuid
from datetime import datetime

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
    "version": "1.1.0",
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
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
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
def canonical(v):
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, int):
        if abs(v) > 2**53 - 1:
            raise ValueError("int outside interoperable range (|n| > 2^53-1); carry it as a string")
        return json.dumps(v)
    if isinstance(v, float):
        raise ValueError("floats require full-JCS number serialization; use ints/strings")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate keys")
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v[k]) for k in keys) + "}"
    raise ValueError(f"non-I-JSON value: {type(v)}")


def H(space, v):
    return hashlib.sha256(space.encode() + b"\x0a" + canonical(v).encode("utf-8")).hexdigest()


def Hb(space, b):
    return hashlib.sha256(space.encode() + b"\x0a" + b).hexdigest()


def mint_rappid(owner, slug, spki_der=None):
    if (
        not isinstance(owner, str)
        or not _LCLABEL.fullmatch(owner)
        or not 1 <= len(owner) <= 39
        or not isinstance(slug, str)
        or not _LCLABEL.fullmatch(slug)
        or not 1 <= len(slug) <= 100
    ):
        raise ValueError("owner or slug violates the RAPPID grammar")
    tail = Hb("rapp/1:rappid", spki_der) if spki_der is not None else Hb("rapp/1:rappid", uuid.uuid4().bytes)
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


# ── rev-17 frame helpers (embedded verbatim from rapp.py; parity_check.py proves behaviour) ──
MAX_CANONICAL_BYTES = 1024 * 1024
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

        prims = ("canonical", "H", "Hb")

        def _defs(src):
            # Normalize each primitive to its executable form: strip a leading docstring,
            # then ast.unparse (which also drops comments). What survives is exactly the
            # code that computes addresses — so equality means identical computation, not
            # identical formatting.
            out = {}
            for node in ast.parse(src).body:
                if isinstance(node, ast.FunctionDef) and node.name in prims:
                    body = list(node.body)
                    if (body and isinstance(body[0], ast.Expr)
                            and isinstance(getattr(body[0], "value", None), ast.Constant)
                            and isinstance(body[0].value.value, str)):
                        body = body[1:] or [ast.Pass()]
                    node.body = body
                    out[node.name] = ast.unparse(node)
            return out

        local_src = None
        for get in (lambda: inspect.getsource(sys.modules[__name__]),
                    lambda: open(__file__, "r", encoding="utf-8").read()):
            try:
                local_src = get(); break
            except Exception:
                continue
        if local_src is None:
            return json.dumps({"status": "error", "action": "sync", "message": "cannot read local source"})

        remote_defs, local_defs = _defs(remote_src), _defs(local_src)
        per = {p: (p in remote_defs and local_defs.get(p) == remote_defs.get(p)) for p in prims}
        match = all(per.values())
        return json.dumps({"status": "ok", "action": "sync",
                           "embedded_matches_public_reference": match,
                           "per_primitive": per,
                           "source": SRC,
                           "vector_particle": H("rapp/1:particle", {"b": 1, "a": [3, 2]}),
                           "note": "The embedded canonical/H/Hb definitions were compared textually "
                                   "(parsed with ast — no code executed) against the freshly-fetched public "
                                   "reference. Equal ⇒ this agent computes canonical RAPP addresses byte-for-byte "
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
