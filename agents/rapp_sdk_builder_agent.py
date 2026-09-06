"""rapp_sdk_builder_agent.py — a hotloadable RAPP SDK, as a brainstem agent.

Drop this one file into any RAPP brainstem's `agents/` directory (no restart) and the
brainstem gains a working RAPP toolkit: mint compliant identities, build and verify
frames, canonicalize + content-address values, scaffold a ready-to-plant organism seed,
and inspect a public repository's main/rappid.json identity record.

Install straight from the public standard repo:

    curl -sSL https://raw.githubusercontent.com/kody-w/rapp-1/main/agents/rapp_sdk_builder_agent.py \
      -o ~/.brainstem/agents/rapp_sdk_builder_agent.py

Then just talk to your brainstem:
    "mint a keyless rappid for @me/notes"
    "scaffold a new RAPP organism called @me/scratch"
    "verify this frame: { … }"
    "check the main/rappid.json identity record in https://github.com/kody-w/twin"

The RAPP primitives are embedded here verbatim from the reference implementation
(kody-w/rapp-1 · rapp.py), so the agent is self-contained and offline-capable. The
`sync` action fetches the canonical rapp.py from the public repo and proves this file's
embedded primitive definitions are identical to it — by comparing source (parsed with
ast, never executed), so it is provenance you can check, not trust, and safe to run.
"""
import hashlib
import copy
import json
import math
import re
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

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
    "version": "1.0.1",
    "display_name": "RAPP SDK Builder",
    "description": "A hotloadable RAPP toolkit: mint compliant rappids, build/verify frames, "
                   "content-address values, scaffold organism seeds, and inspect a public repo's "
                   "main/rappid.json identity record. Build with RAPP and stay synced against the public "
                   "GitHubs — and back again. Builds on the public RAPP standard (kody-w/rapp-1).",
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
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
_LCLABEL = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_KIND = re.compile(r"([a-z0-9]+(?:-[a-z0-9]+)*)\.([a-z0-9]+(?:-[a-z0-9]+)*)")
_RAPPID = re.compile(r"rappid:@([a-z0-9]+(?:-[a-z0-9]+)*)/([a-z0-9]+(?:-[a-z0-9]+)*):([0-9a-f]{64})")
MAX_CANONICAL_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
FRAME_KEYS = {"spec", "kind", "stream_id", "seq", "utc", "payload",
              "payload_hash", "frame_hash", "prev", "prev_wave", "sig"}


# ── RAPP primitives (embedded verbatim from rapp.py; the `sync` action proves parity) ──
def _canonical_number(value):
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("number is outside finite binary64") from exc
    if not math.isfinite(number):
        raise ValueError("non-finite number is not I-JSON")
    if number == 0:
        return "0"

    # Python's binary64 repr supplies the shortest round-trip significand,
    # choosing the closest/even result. Apply ECMA-262's decimal placement
    # and exponent rules; json.dumps does not implement those rules.
    negative = number < 0
    significand, _, exponent = repr(abs(number)).partition("e")
    whole, _, fraction = significand.partition(".")
    digits = whole + fraction
    leading = len(digits) - len(digits.lstrip("0"))
    point = len(whole) + (int(exponent) if exponent else 0) - leading
    digits = digits.lstrip("0").rstrip("0")
    count = len(digits)
    if count <= point <= 21:
        text = digits + "0" * (point - count)
    elif 0 < point <= 21:
        text = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        text = "0." + "0" * (-point) + digits
    else:
        text = digits[0] + ("." + digits[1:] if count > 1 else "")
        power = point - 1
        text += "e" + ("+" if power >= 0 else "-") + str(abs(power))
    if negative:
        text = "-" + text
    if isinstance(value, int) and Decimal(value) != Decimal(text):
        raise ValueError("integer does not survive the binary64/JCS round-trip")
    return text


def canonical(v):
    """RFC 8785 JCS and the frozen §4 value-domain limits; returns UTF-8 str."""
    chunks = []
    byte_count = 0
    active = set()

    def emit(text):
        nonlocal byte_count
        try:
            byte_count += len(text.encode("utf-8"))
        except UnicodeError as exc:
            raise ValueError("string contains a surrogate code point") from exc
        if byte_count > MAX_CANONICAL_BYTES:
            raise ValueError("canonical JSON exceeds 1 MiB")
        chunks.append(text)

    def visit(value, depth):
        if value is None:
            emit("null")
        elif isinstance(value, bool):
            emit("true" if value else "false")
        elif isinstance(value, (int, float)):
            emit(_canonical_number(value))
        elif isinstance(value, str):
            emit(json.dumps(value, ensure_ascii=False))
        elif isinstance(value, (list, dict)):
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting depth exceeds 64")
            identity = id(value)
            if identity in active:
                raise ValueError("cyclic value is not a JSON tree")
            active.add(identity)
            try:
                if isinstance(value, list):
                    emit("[")
                    for index, item in enumerate(value):
                        if index:
                            emit(",")
                        visit(item, depth + 1)
                    emit("]")
                else:
                    if not all(isinstance(key, str) for key in value):
                        raise ValueError("object member names MUST be strings")
                    try:
                        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
                    except UnicodeError as exc:
                        raise ValueError("object member name contains a surrogate") from exc
                    emit("{")
                    for index, key in enumerate(keys):
                        if index:
                            emit(",")
                        emit(json.dumps(key, ensure_ascii=False))
                        emit(":")
                        visit(value[key], depth + 1)
                    emit("}")
            finally:
                active.remove(identity)
        else:
            raise ValueError(f"non-I-JSON value: {type(value).__name__}")

    visit(v, 1)
    return "".join(chunks)


def _parse_json_number(token):
    number = float(token)
    text = _canonical_number(number)
    if number == 0:
        mantissa = token.lower().split("e", 1)[0]
        if any(char in "123456789" for char in mantissa):
            raise ValueError("number token does not survive the binary64/JCS round-trip")
    else:
        try:
            if Decimal(token) != Decimal(text):
                raise ValueError("number token does not survive the binary64/JCS round-trip")
        except InvalidOperation as exc:
            raise ValueError("invalid JSON number token") from exc
    # Keep fraction/exponent syntax distinguishable for fields such as seq.
    return number if "." in token or "e" in token.lower() else int(token)


def _strict_json(blob):
    if not isinstance(blob, (str, bytes)):
        raise ValueError("JSON input MUST be UTF-8 bytes or text")
    try:
        text = blob.decode("utf-8") if isinstance(blob, bytes) else blob
    except UnicodeError as exc:
        raise ValueError("JSON input is not UTF-8") from exc

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    def constant(value):
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        value = json.loads(
            text, object_pairs_hook=pairs, parse_int=_parse_json_number,
            parse_float=_parse_json_number, parse_constant=constant,
        )
        canonical(value)
    except RecursionError as exc:
        raise ValueError("JSON nesting depth exceeds 64") from exc
    return value


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


def kind_valid(value):
    match = _KIND.fullmatch(value) if isinstance(value, str) else None
    return bool(match and all(1 <= len(label) <= 64 for label in match.groups()))


def stream_form(value):
    if not isinstance(value, str):
        return None
    if value.startswith("net:"):
        return "swarm-stream" if _LCLABEL.fullmatch(value[4:]) else None
    if rappid_valid(value):
        return "body-stream"
    body, separator, instance = value.rpartition(":")
    if separator and rappid_valid(body) and 1 <= len(instance) <= 64 and _LCLABEL.fullmatch(instance):
        return "memory-stream"
    return None


def utc_valid(value):
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _frame_shape(frame):
    if not isinstance(frame, dict):
        return "frame MUST be an object"
    if set(frame) != FRAME_KEYS:
        return "key set != 11"
    if frame["spec"] != SPEC:
        return "spec != rapp/1"
    if not kind_valid(frame["kind"]):
        return "kind grammar"
    if stream_form(frame["stream_id"]) is None:
        return "stream_id grammar"
    if not (isinstance(frame["seq"], int) and not isinstance(frame["seq"], bool)
            and 0 <= frame["seq"] <= 2**53 - 1):
        return "seq not uint53"
    if not utc_valid(frame["utc"]):
        return "utc not fixed form"
    if not isinstance(frame["payload"], dict):
        return "payload not object"
    for key in ("payload_hash", "frame_hash"):
        if not (isinstance(frame[key], str) and _HEX64.fullmatch(frame[key])):
            return f"{key} not 64hex"
    for key in ("prev", "prev_wave"):
        if not (frame[key] is None
                or isinstance(frame[key], str) and _HEX64.fullmatch(frame[key])):
            return f"{key} not null|64hex"
    if frame["sig"] is not None and not isinstance(frame["sig"], str):
        return "sig not null|JWS text"
    return None


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
    frame = {**frame, "frame_hash": frame["frame_hash"]}
    why = _frame_shape(frame)
    if why:
        raise ValueError(why)
    canonical(frame)
    return frame


def verify_frame(
    frame,
    head=None,
    stream_id_of_record=None,
    signature_verifier=None,
):
    """Verify frame shape/hashes/links; caller also supplies registry binding.

    Returns (ok, failing_step_or_None, reason), including malformed-value refusals.
    A stream-of-record must be supplied for an authoritative step-1a check.
    """
    try:
        return _verify_frame(frame, head, stream_id_of_record, signature_verifier)
    except (AttributeError, IndexError, KeyError, RecursionError, TypeError, ValueError) as exc:
        return False, "1", f"invalid frame value: {exc}"


def _verify_frame(frame, head, stream_id_of_record, signature_verifier):
    why = _frame_shape(frame)
    if why:
        return False, "1", why
    canonical(frame)
    if stream_id_of_record is not None and frame["stream_id"] != stream_id_of_record:
        return False, "1a", "stream_id mismatch (cross-stream replay)"
    if frame["payload_hash"] != H("rapp/1:particle", frame["payload"]):
        return False, "2", "payload_hash mismatch"
    pre = {k: frame[k] for k in frame if k not in ("frame_hash", "sig")}
    if frame["frame_hash"] != H("rapp/1:wave", pre):
        return False, "3", "frame_hash mismatch"
    if head is None:
        if not (frame["seq"] == 0 and frame["prev"] is None):
            return False, "4", "genesis must be seq=0 prev=null"
    else:
        if _frame_shape(head):
            return False, "4", "head MUST be a verified frame"
        try:
            canonical(head)
        except ValueError as exc:
            return False, "4", f"invalid head value: {exc}"
        if frame["seq"] != head["seq"] + 1:
            return False, "4", "seq not contiguous"
        if frame["prev"] != head["payload_hash"]:
            return False, "4", "prev != head payload_hash"
        if frame["utc"] < head["utc"]:
            return False, "4", "utc < head utc"
    is_swarm = frame["stream_id"].startswith("net:")
    if is_swarm and frame["seq"] > 0:
        if head is not None and frame["prev_wave"] != head["frame_hash"]:
            return False, "5", "prev_wave != head frame_hash"
    else:
        if frame["prev_wave"] is not None:
            return False, "5", "prev_wave must be null off swarm"
    if is_swarm and frame["sig"] is None:
        return False, "6", "swarm frame must be signed"
    if frame["sig"] is not None:
        ok, why = _signature_ok(frame, signature_verifier)
        if not ok:
            return False, "6", why
    return True, None, "ok"


def _signature_ok(manifest, signature_verifier, expected_signer=None):
    if signature_verifier is None:
        return False, "trusted signature verifier is required"
    try:
        unsigned = copy.deepcopy({k: v for k, v in manifest.items() if k != "sig"})
        if expected_signer is None:
            result = signature_verifier(unsigned, manifest["sig"])
        else:
            result = signature_verifier(
                unsigned,
                manifest["sig"],
                expected_signer,
            )
    except (ValueError, TypeError, RuntimeError, OSError) as exc:
        return False, f"signature verifier failed: {exc}"
    if isinstance(result, tuple):
        return bool(result[0]), str(result[1]) if len(result) > 1 else ""
    return bool(result), "signature refused"


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
                           "canonicalize/content-address a value, or inspect a repo's main/rappid.json identity record.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["mint", "scaffold", "frame", "verify", "canonicalize", "check", "sync"],
                        "description": "mint=mint a rappid · scaffold=new organism seed (rappid+genesis) · "
                                       "frame=build+verify a frame · verify=verify a frame object · "
                                       "canonicalize=canonical bytes + domain hash of a value · "
                                       "check=observe only main/rappid.json identity grammar · sync=verify embedded SDK vs public repo",
                    },
                    "id": {"type": "string", "description": "identity as '@owner/slug' or a full rappid string"},
                    "kind": {"type": "string", "description": "frame kind, e.g. 'note.write' (noun.verb)"},
                    "payload": {"type": "object", "description": "frame payload / value to canonicalize"},
                    "utc": {"type": "string", "description": "millisecond UTC 'YYYY-MM-DDTHH:MM:SS.mmmZ'"},
                    "frame": {"type": "object", "description": "a frame object to verify"},
                    "repo": {"type": "string", "description": "github repo URL or owner/name; check observes only main/rappid.json"},
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
            if action == "check":
                return self._check(kwargs)
            if action == "sync":
                return self._sync()
            return json.dumps({"status": "error",
                               "message": f"unknown action {action!r}",
                               "actions": ["mint", "scaffold", "frame", "verify", "canonicalize", "check", "sync"]})
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
        kind = kw.get("kind", "note.write")
        utc = kw.get("utc", "2026-07-15T00:00:00.000Z")
        payload = kw.get("payload", {})
        seq = kw.get("seq", 0)
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

    def _check(self, kw):
        """Observe only main/rappid.json; never certify unobserved repo artifacts."""
        repo = (kw.get("repo") or "").strip()
        if not repo:
            return json.dumps({"status": "error", "message": "provide 'repo' as owner/name or a github URL"})
        m = re.search(r"github\.com/([^/]+)/([^/#?]+)", repo) or re.match(r"([^/]+)/([^/#?]+)$", repo)
        if not m:
            return json.dumps({"status": "error", "message": f"cannot parse repo from {repo!r}"})
        owner, name = m.group(1), m.group(2)
        if name.endswith(".git"):
            name = name[:-4]
        if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", part) for part in (owner, name)):
            return json.dumps({"status": "error", "action": "check", "message": "unsafe repository identifier"})
        findings, evidence = [], []
        url = f"https://raw.githubusercontent.com/{owner}/{name}/main/rappid.json"
        observation = {
            "action": "check", "repo": f"{owner}/{name}", "inspected_url": url,
            "scope": "identity grammar/schema at main/rappid.json only",
            "repository_artifacts_checked": False, "authenticated_acceptance": False,
            "identity_records_parsed": 0,
        }
        try:
            raw = _fetch(url)
        except urllib.error.HTTPError as error:
            return json.dumps({
                **observation, "status": "error",
                "verdict": "NO_ARTIFACTS" if error.code == 404 else "INCOMPLETE",
                "reason": f"identity observation failed: HTTP {error.code}",
                "note": "No identity evidence at this path does not establish absence of other repository artifacts.",
            })
        except OSError as error:
            return json.dumps({**observation, "status": "error", "verdict": "INCOMPLETE",
                               "reason": f"identity observation failed: {error}"})
        try:
            original = raw.encode("utf-8") if isinstance(raw, str) else raw
            if not isinstance(original, bytes):
                raise ValueError("identity response is not bytes or text")
            d = _strict_json(original)
            if not isinstance(d, dict):
                raise ValueError("identity response is not a JSON object")
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as error:
            return json.dumps({**observation, "status": "error", "verdict": "DRIFT",
                               "findings": [f"original identity JSON refused: {error}"]})
        observation["identity_records_parsed"] = 1
        rid = d.get("rappid", "")
        if rappid_valid(rid):
            evidence.append(f"rappid §6.1 grammar OK: {rid}")
        else:
            tail = rid.rsplit(":", 1)[-1] if isinstance(rid, str) else ""
            findings.append(f"§6.1 identity: {'32-hex short-tail (C3)' if re.fullmatch(r'[0-9a-f]{32}', tail) else 'not RAPP grammar'}")
        if d.get("schema") != "rapp/1":
            findings.append(f"§12 schema label: schema='{d.get('schema')}', not 'rapp/1'")
        p = d.get("parent_rappid")
        if p is not None and not rappid_valid(p):
            findings.append(f"§6.3 parent_rappid not RAPP grammar: {p}")
        verdict = "COMPLIANT" if not findings else "DRIFT"
        return json.dumps({**observation, "status": "ok" if not findings else "error",
                           "verdict": verdict, "findings": findings, "evidence": evidence}, indent=2)

    def _sync(self):
        """Prove the embedded SDK matches the canonical public reference implementation.

        We do NOT execute the fetched code — running remote code is a security hazard (and
        registries forbid it). Instead we compare the *source definitions* of the primitive
        functions and their transitive helpers/constants textually, parsing with `ast`
        (which never executes), against our own embedded copy.
        """
        import ast, inspect, sys
        try:
            remote_src = _fetch(SRC).decode("utf-8")
        except Exception as e:
            return json.dumps({"status": "error", "action": "sync", "message": f"fetch failed: {e}"})

        prims = (
            "_canonical_number", "canonical", "_parse_json_number", "_strict_json",
            "H", "Hb", "mint_rappid", "rappid_valid", "kind_valid", "stream_form",
            "utc_valid", "_frame_shape", "build_frame", "verify_frame", "_verify_frame",
            "_signature_ok", "SPEC", "FRAME_KEYS", "MAX_CANONICAL_BYTES", "MAX_JSON_DEPTH",
            "_HEX64", "_UTC", "_LCLABEL", "_KIND", "_RAPPID",
        )

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
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id in prims:
                            out[target.id] = ast.unparse(node.value)
            return out

        local_src = None
        for get in (lambda: inspect.getsource(sys.modules[__name__]),
                    lambda: Path(__file__).read_text(encoding="utf-8")):
            try:
                local_src = get(); break
            except (OSError, TypeError, KeyError, UnicodeError):
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
                           "note": "The embedded primitives, transitive helpers, and constants were compared textually "
                                   "(parsed with ast — no code executed) against the freshly-fetched public "
                                   "reference. Equal ⇒ this agent computes canonical RAPP addresses byte-for-byte "
                                   "with rapp.py."}, indent=2)


# standalone self-test: `python3 rapp_sdk_builder_agent.py`
if __name__ == "__main__":
    a = RappSdkBuilderAgent()
    print("mint     :", a.perform(action="mint", id="@me/notes"))
    print("scaffold :", a.perform(action="scaffold", id="@me/scratch")[:160], "…")
    print("canon    :", a.perform(action="canonicalize", value={"b": 1, "a": [3, 2]}))
    fr = json.loads(a.perform(action="scaffold", id="@me/x"))["files"]["frames/0.json"]
    print("verify   :", a.perform(action="verify", frame=fr))
