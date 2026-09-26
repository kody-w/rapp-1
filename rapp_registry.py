"""rapp_registry.py — the §13 registry as executable checks. Stdlib only.

RAPP/1 grows by registration, never by fork (Constitution Art. 4). Every estate —
the reference estate, a vendor's factory, your laptop — publishes its own signed
`rapp/1-registry` document, and *that* document is what binds a `kind` to a family,
admits an egg variant or error code, discovers a signer's key, and retires a key by
tombstone. Extending RAPP therefore means writing registry entries, not patching
this repository. This module makes those entries checkable with the reference.

What is fully specified by §13 and enforced here:
  - the document container (§13.1): exactly `schema`, `registry_seq`,
    `canonical_source`, `entries`, and `sig` carry meaning; any other top-level
    member is covered by `sig` and carries none;
  - every entry type and its exact member set (§13.3), and an entry of a type this reference does not
    implement ignored unless it is marked critical, which refuses the registry (`unknown_entries`);
  - kind grammar and family binding; family ↔ stream_id-form compatibility (§6.1.1, §7.2);
  - owner succession by re-anchor records, owner-in-effect at a time (§13.2);
  - key discovery, superseded-key and tombstone refusal at a time (§10);
  - one non-deprecated genesis per stream (§7.6); one grail-kernel per grail_id (§11.1);
  - declared entries (§13.4): each entry-level owner signature at its own
    `activated_utc`, never blessed by the enclosing document signature, and
    retention of persisted entries, unchanged in canonical form (§4), once a caller has accepted them;
  - lifecycle notices (§13.5): one linear, owner-signed chain of `lifecycle` entries per
    subject — an organism's rappid, or the URI of a repository that has none — the state and
    successor in effect at a time, and no cycle among the successors in effect at any one time;
  - owner-signature verification over canonical(document \\ {sig}).

Structural accessors — chains, heads — read whatever registry you hold. Answers — the lifecycle in
effect, whether a copy is a declaration — come only from a registry `load_document` returned as
"verified"; a "draft" gives them only with `allow_draft=True`, as a rehearsal, and a Registry built
directly never.

What stays the caller's responsibility, because a snapshot cannot prove it:
  - freshness, trusted heads, registry high-water marks, first-seen times, and the
    append provenance of each entry (see `load_document`).

Nothing here can make an unsigned registry authoritative. `load_document` reports
"verified" only after a §10 signature by the estate owner verifies AND that owner is the
rappid the caller obtained out of band (the trust anchor); an unsigned document is at most
a "draft", and a registry that names any other owner is refused outright.
"""
import base64
import ipaddress
import re
from datetime import datetime, timezone

import rapp as R

FAMILIES = ("memory", "swarm", "body")
STREAM_FORMS = {"memory": "memory-stream", "swarm": "swarm-stream", "body": "body-stream"}
REANCHOR_CASES = ("upgrade", "rotation", "compromise", "tag-migrate")
LIFECYCLE_STATES = ("active", "deprecated", "superseded", "archived")  # §13.5

_LCLABEL = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_KIND = re.compile(rf"({_LCLABEL})\.({_LCLABEL})")
_LABEL = re.compile(_LCLABEL)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
# RFC 3986 pieces, applied by hand so the verdict never depends on the Python version's urllib.
_URI_SAFE = r"A-Za-z0-9\-._~!$&'()*+,;="  # unreserved and sub-delims
_PCT = r"%[0-9A-Fa-f]{2}"
_REG_NAME = re.compile(rf"(?:[{_URI_SAFE}]|{_PCT})+")
_PCHAR = rf"(?:[{_URI_SAFE}:@]|{_PCT})"
_PATH_ABEMPTY = re.compile(rf"(?:/{_PCHAR}*)*")
_QUERY = re.compile(rf"(?:{_PCHAR}|[/?])*")
_IPV_FUTURE = re.compile(rf"[vV][0-9A-Fa-f]+\.[{_URI_SAFE}:]+")  # RFC 3986 literals are case-insensitive
_PORT = re.compile(r"[0-9]{1,5}")
# RFC 8141 assigned-name: "urn:" NID ":" NSS, with no r-, q-, or f-component.
_URN = re.compile(rf"urn:[A-Za-z0-9][A-Za-z0-9-]{{0,30}}[A-Za-z0-9]:{_PCHAR}(?:{_PCHAR}|/)*")

# §13.1 — the registry document container (rev-17 closure).
DOCUMENT_SCHEMA = "rapp/1-registry"
ENTRIES_MEMBER = "entries"
DOCUMENT_MEMBERS = ("schema", "registry_seq", "canonical_source", ENTRIES_MEMBER, "sig")

# §13.4 — entry types that carry their own owner signature at `activated_utc`.
# Every declared entry is persisted: once accepted, it is retained with its canonical form unchanged.
DECLARED_TYPES = ("grail-kernel", "lifecycle")
PERSISTED_TYPES = DECLARED_TYPES
FIRST_SEEN_SKEW_SECONDS = 300

# §13.3 — exact members per entry type: (required, optional)
ENTRY_MEMBERS = {
    "protocol": ({"type", "name", "spec_repo", "spec_path", "spec_hash", "deprecated"}, set()),
    "kind": ({"type", "kind", "family", "deprecated"}, set()),
    "egg-variant": ({"type", "variant", "deprecated"}, set()),
    "error-code": ({"type", "code"}, set()),
    "genesis": ({"type", "stream_id", "frame_hash", "deprecated"}, {"old_stream_id", "new_stream_id"}),
    "spki": ({"type", "rappid", "spki_der_b64", "deprecated"}, set()),
    "tombstone": ({"type", "rappid", "revoked_utc", "sig"}, set()),
    "re-anchor": ({"type", "old_rappid", "new_rappid", "case", "utc", "sig"}, {"old_key_sig"}),
    "grail-kernel": ({"type", "release_scope", "grail_id", "repository", "immutable_ref",
                      "object_format", "commit", "path", "mode", "blob", "sha256", "size_bytes",
                      "activated_utc", "predecessor", "declared_by", "sig"}, set()),
    "lifecycle": ({"type", "subject", "state", "superseded_by", "since_utc", "previous",
                   "activated_utc", "declared_by", "sig"}, set()),
    "estate_owner": ({"type", "rappid"}, set()),
    "master-plan": ({"type", "repo", "path"}, set()),
}


class RegistryError(ValueError):
    """A registry that must be refused, whole (§7.5-style: never partial, never repaired)."""


def entry_hash(entry):
    """`H("rapp/1:particle", entry)` of one exact entry, signatures included.

    This is how a later entry names an earlier one, and how a caller keys
    persisted or first-seen state: any byte of difference is a different entry."""
    return R.H("rapp/1:particle", entry)


def _https_uri(value):
    """An absolute HTTPS URI (§3), by RFC 3986's grammar: `https://` authority path-abempty [`?` query]
    with no fragment, at most 2048 characters; the authority is a host and an optional port, with no
    user information; the host is a non-empty reg-name or an IP literal (an IPv6 address with no zone,
    or IPvFuture); a `:` after the host is followed by a port of 1-5 digits at most 65535 (so an empty
    port is refused). Parsed here, not by urllib, whose port and
    IP-literal rules differ between Python versions. (`rapp_profile.https_uri`, used by the
    operational profiles, is looser; registry members follow §3.)"""
    if not (isinstance(value, str) and len(value) <= 2048 and value.startswith("https://")):
        return False
    rest = value[len("https://"):]
    cut = min([i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i != -1], default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    path, question, query = tail.partition("?")
    if "#" in tail or not _PATH_ABEMPTY.fullmatch(path) or (question and not _QUERY.fullmatch(query)):
        return False
    if authority.startswith("["):
        close = authority.find("]")
        literal, port = authority[1:close], authority[close + 1:]
        if close == -1 or not (_IPV_FUTURE.fullmatch(literal) or _ipv6_address(literal)):
            return False
    else:
        host, colon, digits = authority.partition(":")
        if not _REG_NAME.fullmatch(host):
            return False
        port = colon + digits
    return port == "" or (port[0] == ":" and bool(_PORT.fullmatch(port[1:])) and int(port[1:]) <= 65535)


_DEC_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4_TAIL = re.compile(rf"{_DEC_OCTET}(?:\.{_DEC_OCTET}){{3}}")


def _ipv6_address(text):
    """An RFC 3986 IPv6address: what `ipaddress` accepts, with no zone identifier, and an embedded IPv4
    part checked here against RFC 3986's dec-octet (no leading zero), which CPython before 3.9.5
    did not refuse — so the verdict is the same on every Python 3.9 and later."""
    if "%" in text or ("." in text and not _IPV4_TAIL.fullmatch(text.rsplit(":", 1)[-1])):
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _canonical_source_ok(value):
    """§13.1: an absolute HTTPS URI (§3) for a registry published on the web, or a URN (RFC 8141,
    lowercase `urn:`, no r-, q-, or f-component, at most 2048 characters) for one kept in a private
    store, such as a private Hive's registry history."""
    return _https_uri(value) or (isinstance(value, str) and len(value) <= 2048 and bool(_URN.fullmatch(value)))


def _utc_form(value):
    """`rapp.utc_valid`, restricted to ASCII. Python's `\\d` also matches other scripts' digits, but the
    fixed §7.4 form is 24 ASCII octets, and only for those does bytewise order equal time order —
    which every time comparison in this module relies on."""
    return R.utc_valid(value) and value.isascii()


def _utc_seconds(value, where):
    if not _utc_form(value):
        raise RegistryError(f"{where}: not the fixed §7.4 UTC form")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def linear_chains(items, *, key, ident, link, where):
    """Group `items` (entries in append order) into linear chains.

    `key(entry)` names the chain, `ident(entry)` identifies an entry within it, and
    `link(entry)` is None for the chain's first entry or the ident of the entry it
    follows. A link must name an entry that appears EARLIER in the same chain (so no
    cycle can form), no two entries may follow the same entry (no fork), and every
    chain has exactly one first entry. Returns {chain_key: [entries in chain order]}.
    """
    chains = {}
    for entry in items:
        chains.setdefault(key(entry), []).append(entry)
    ordered = {}
    for chain_key, members in chains.items():
        seen, successor, roots = {}, {}, []
        for entry in members:
            own = ident(entry)
            if own in seen:
                raise RegistryError(f"{where} {chain_key!r}: duplicate entry {own!r}")
            parent = link(entry)
            if parent is None:
                roots.append(entry)
            elif parent not in seen:
                raise RegistryError(
                    f"{where} {chain_key!r}: {own!r} follows an entry that does not precede it"
                )
            elif parent in successor:
                raise RegistryError(f"{where} {chain_key!r}: two entries follow {parent!r} (fork)")
            else:
                successor[parent] = entry
            seen[own] = entry
        if len(roots) != 1:
            raise RegistryError(f"{where} {chain_key!r}: expected exactly one first entry, found {len(roots)}")
        chain, current = [], roots[0]
        while current is not None:
            chain.append(current)
            current = successor.get(ident(current))
        ordered[chain_key] = chain
    return ordered


def kind_valid(kind):
    """§6.1.1 `kind = lclabel "." lclabel`, each label 1–64."""
    m = _KIND.fullmatch(kind) if isinstance(kind, str) else None
    return bool(m and 1 <= len(m.group(1)) <= 64 and 1 <= len(m.group(2)) <= 64)


def stream_form(stream_id):
    """§6.1.1: which stream form a stream_id is, or None if it is none of them."""
    if not isinstance(stream_id, str):
        return None
    if stream_id.startswith("net:"):
        label = stream_id[4:]
        return "swarm-stream" if _LABEL.fullmatch(label) else None
    if R.rappid_valid(stream_id):
        return "body-stream"
    head, sep, instance = stream_id.rpartition(":")
    if sep and R.rappid_valid(head) and _LABEL.fullmatch(instance) and 1 <= len(instance) <= 64:
        return "memory-stream"
    return None


def _bool(entry, member, where):
    if not isinstance(entry.get(member), bool):
        raise RegistryError(f"{where}: `{member}` must be a JSON boolean")


def _str(entry, member, where):
    if not isinstance(entry.get(member), str) or not entry[member]:
        raise RegistryError(f"{where}: `{member}` must be a non-empty string")
    return entry[member]


def _rappid(entry, member, where):
    if not R.rappid_valid(entry.get(member)):
        raise RegistryError(f"{where}: `{member}` is not a §6.1 rappid")
    return entry[member]


def _utc(entry, member, where):
    if not _utc_form(entry.get(member)):
        raise RegistryError(f"{where}: `{member}` is not the fixed §7.4 UTC form")
    return entry[member]


def _hex64(entry, member, where):
    v = entry.get(member)
    if not (isinstance(v, str) and _HEX64.fullmatch(v)):
        raise RegistryError(f"{where}: `{member}` must be 64 lowercase hex")
    return v


def lifecycle_subject_valid(value):
    """§13.5: a lifecycle subject is a §6.1 rappid (an organism) or an absolute HTTPS URI naming a
    repository (one that carries no rappid of its own). The two forms never overlap."""
    return R.rappid_valid(value) or _https_uri(value)


def _validate_lifecycle(entry, where):
    """The §13.3 `lifecycle` members and the §13.5 rules one entry shows by itself.
    Its chain and the no-cycle rule span entries, so `Registry` checks those."""
    subject = entry.get("subject")
    if not lifecycle_subject_valid(subject):
        raise RegistryError(f"{where}: `subject` must be a §6.1 rappid or an absolute HTTPS repository URI")
    state = entry.get("state")
    if state not in LIFECYCLE_STATES:
        raise RegistryError(f"{where}: `state` must be one of {LIFECYCLE_STATES}")
    successor = entry.get("superseded_by")
    if successor is not None and not lifecycle_subject_valid(successor):
        raise RegistryError(
            f"{where}: `superseded_by` must be null, a §6.1 rappid, or an absolute HTTPS repository URI"
        )
    if successor == subject:
        raise RegistryError(f"{where}: `superseded_by` never equals `subject` (§13.5)")
    if state == "active" and successor is not None:
        raise RegistryError(f"{where}: an active notice names no successor; `superseded_by` must be null (§13.5)")
    if state == "superseded" and successor is None:
        raise RegistryError(f"{where}: a superseded notice names its successor in `superseded_by` (§13.5)")
    _utc(entry, "since_utc", where)
    previous = entry.get("previous")
    if previous is not None and not (isinstance(previous, str) and _HEX64.fullmatch(previous)):
        raise RegistryError(f"{where}: `previous` must be null or the 64-hex entry_hash of an earlier entry")
    _utc(entry, "activated_utc", where)
    _rappid(entry, "declared_by", where); _str(entry, "sig", where)


def validate_entry(entry, where="entry"):
    """Refuse an entry that is not exactly a §13.3 entry of its type. Returns the type."""
    if not isinstance(entry, dict):
        raise RegistryError(f"{where}: not an object")
    t = entry.get("type")
    if not isinstance(t, str) or t not in ENTRY_MEMBERS:
        raise RegistryError(f"{where}: unknown entry type {t!r}")
    required, optional = ENTRY_MEMBERS[t]
    keys = set(entry.keys())
    if not required <= keys or not keys <= (required | optional):
        raise RegistryError(
            f"{where} ({t}): member set {sorted(keys)} != exactly {sorted(required)}"
            + (f" plus optional {sorted(optional)}" if optional else "")
        )
    if t == "protocol":
        _str(entry, "name", where); _str(entry, "spec_path", where); _bool(entry, "deprecated", where)
        if not _https_uri(_str(entry, "spec_repo", where)):
            raise RegistryError(f"{where}: `spec_repo` must be an absolute HTTPS URI")
        _hex64(entry, "spec_hash", where)
        name = entry["name"]
        if name == "rapp/1" and not entry["deprecated"]:
            if entry["spec_repo"] != "https://github.com/kody-w/rapp-1" or entry["spec_path"] != "SPEC.md":
                raise RegistryError(f"{where}: a current `rapp/1` pin must point at kody-w/rapp-1 SPEC.md")
        elif name != "rapp/1" and (name.startswith("rapp/") or name.startswith("rapp-1")):
            raise RegistryError(f"{where}: another protocol may not claim the rapp/1 name or namespace")
    elif t == "kind":
        if not kind_valid(entry.get("kind")):
            raise RegistryError(f"{where}: `kind` fails the §6.1.1 grammar")
        if entry.get("family") not in FAMILIES:
            raise RegistryError(f"{where}: `family` must be one of {FAMILIES}")
        _bool(entry, "deprecated", where)
    elif t == "egg-variant":
        v = _str(entry, "variant", where)
        if not _LABEL.fullmatch(v):
            raise RegistryError(f"{where}: `variant` must be an lclabel")
        _bool(entry, "deprecated", where)
    elif t == "error-code":
        _str(entry, "code", where)
    elif t == "genesis":
        if stream_form(entry.get("stream_id")) is None:
            raise RegistryError(f"{where}: `stream_id` is not a §6.1.1 stream form")
        _hex64(entry, "frame_hash", where); _bool(entry, "deprecated", where)
        for m in ("old_stream_id", "new_stream_id"):
            if m in entry and stream_form(entry[m]) is None:
                raise RegistryError(f"{where}: `{m}` is not a §6.1.1 stream form")
    elif t == "spki":
        _rappid(entry, "rappid", where); _bool(entry, "deprecated", where)
        try:
            der = base64.b64decode(_str(entry, "spki_der_b64", where), validate=True)
        except Exception:
            raise RegistryError(f"{where}: `spki_der_b64` is not base64")
        if R.Hb("rapp/1:rappid", der) != R.rappid_parts(entry["rappid"])["hash"]:
            raise RegistryError(f"{where}: SPKI does not hash to the rappid tail (§10 key discovery)")
    elif t == "tombstone":
        _rappid(entry, "rappid", where); _utc(entry, "revoked_utc", where); _str(entry, "sig", where)
    elif t == "re-anchor":
        _rappid(entry, "old_rappid", where); _rappid(entry, "new_rappid", where)
        if entry.get("case") not in REANCHOR_CASES:
            raise RegistryError(f"{where}: `case` must be one of {REANCHOR_CASES}")
        _utc(entry, "utc", where); _str(entry, "sig", where)
        if entry["case"] == "rotation" and "old_key_sig" not in entry:
            raise RegistryError(f"{where}: case rotation REQUIRES `old_key_sig`")
        if "old_key_sig" in entry:
            _str(entry, "old_key_sig", where)
    elif t == "grail-kernel":
        for m in ("release_scope", "repository"):
            if not _https_uri(_str(entry, m, where)):
                raise RegistryError(f"{where}: `{m}` must be an absolute HTTPS URI")
        if not _str(entry, "immutable_ref", where).startswith("refs/tags/"):
            raise RegistryError(f"{where}: `immutable_ref` must be a full refs/tags/... name")
        fmt = entry.get("object_format")
        if fmt not in ("sha1", "sha256"):
            raise RegistryError(f"{where}: `object_format` must be sha1 or sha256")
        hexre = _HEX40 if fmt == "sha1" else _HEX64
        for m in ("commit", "blob"):
            if not (isinstance(entry.get(m), str) and hexre.fullmatch(entry[m])):
                raise RegistryError(f"{where}: `{m}` must be lowercase hex of the {fmt} length")
        gid = _str(entry, "grail_id", where)
        if not (gid.startswith("grail:") and _HEX64.fullmatch(gid[6:])):
            raise RegistryError(f"{where}: `grail_id` must be grail:<64hex>")
        if entry.get("mode") not in ("100644", "100755"):
            raise RegistryError(f"{where}: `mode` must be 100644 or 100755")
        path = _str(entry, "path", where)
        parts = path.split("/")
        if path.startswith("/") or any(p in ("", ".", "..") for p in parts):
            raise RegistryError(f"{where}: `path` must be a relative POSIX path with no empty/./.. component")
        _hex64(entry, "sha256", where)
        n = entry.get("size_bytes")
        if not (isinstance(n, int) and not isinstance(n, bool) and 0 < n <= 2**53 - 1):
            raise RegistryError(f"{where}: `size_bytes` must be a positive uint53")
        _utc(entry, "activated_utc", where)
        if entry.get("predecessor") is not None:
            p = entry["predecessor"]
            if not (isinstance(p, str) and p.startswith("grail:") and _HEX64.fullmatch(p[6:])):
                raise RegistryError(f"{where}: `predecessor` must be null or a grail_id")
        _rappid(entry, "declared_by", where); _str(entry, "sig", where)
    elif t == "lifecycle":
        _validate_lifecycle(entry, where)
    elif t == "estate_owner":
        _rappid(entry, "rappid", where)
    elif t == "master-plan":
        _str(entry, "repo", where); _str(entry, "path", where)
    return t


class Registry:
    """An estate's registry, loaded from its §13.3 entries and answering §7/§10 questions."""

    def __init__(self, entries):
        if not isinstance(entries, list):
            raise RegistryError("entries must be a JSON array")
        self.entries = entries
        self.kinds = {}          # kind -> entry
        self.egg_variants = {}   # variant -> entry
        self.error_codes = set()
        self.spki = {}           # rappid -> entry
        self.tombstones = {}     # rappid -> revoked_utc (earliest)
        self.reanchors = []      # entries, in order
        self.genesis = {}        # stream_id -> list of entries
        self.grail = {}          # grail_id -> entry
        self.lifecycle = {}      # subject -> [lifecycle entries, chain order] (§13.5)
        self.protocol_history = {}  # name -> [entries], append order
        self.master_plan = None
        self.unknown_entries = []  # indices of entries of types this reference does not implement (§13.3)
        self.canonical_source = None  # set by load_document from the §13.1 container
        self.status = None  # "verified" or "draft" when load_document returns it; None when built directly
        owners, reanchored = [], set()
        for i, e in enumerate(entries):
            where = f"entries[{i}]"
            unknown = e.get("type") if isinstance(e, dict) else None
            if isinstance(unknown, str) and unknown and unknown not in ENTRY_MEMBERS:
                # §13.3: an entry type this consumer does not implement is ignored — it grants, revokes,
                # binds, pins, and declares nothing here — unless it is marked critical.
                if "critical" in e and e["critical"] is not False:
                    raise RegistryError(
                        f"{where}: entry type {unknown!r} is marked critical and this consumer does not "
                        "implement it; the registry is refused whole (§13.3)"
                    )
                self.unknown_entries.append(i)
                continue
            t = validate_entry(e, where)
            if t == "kind":
                if e["kind"] in self.kinds:
                    raise RegistryError(f"{where}: kind {e['kind']!r} registered twice (append-only, closed)")
                self.kinds[e["kind"]] = e
            elif t == "egg-variant":
                if e["variant"] in self.egg_variants:
                    raise RegistryError(f"{where}: variant {e['variant']!r} registered twice")
                self.egg_variants[e["variant"]] = e
            elif t == "error-code":
                self.error_codes.add(e["code"])
            elif t == "spki":
                if e["rappid"] in self.spki:
                    raise RegistryError(f"{where}: spki for {e['rappid']} registered twice")
                self.spki[e["rappid"]] = e
            elif t == "tombstone":
                prior = self.tombstones.get(e["rappid"])
                self.tombstones[e["rappid"]] = min(prior, e["revoked_utc"]) if prior else e["revoked_utc"]
            elif t == "re-anchor":
                if R.rappid_parts(e["old_rappid"])["hash"] == R.rappid_parts(e["new_rappid"])["hash"]:
                    raise RegistryError(f"{where}: re-anchor requires a fresh identity tail")
                if e["new_rappid"] in reanchored:
                    raise RegistryError(f"{where}: more than one predecessor for a re-anchored identity")
                reanchored.add(e["new_rappid"])
                self.reanchors.append(e)
            elif t == "genesis":
                self.genesis.setdefault(e["stream_id"], []).append(e)
            elif t == "grail-kernel":
                if e["grail_id"] in self.grail:
                    raise RegistryError(f"{where}: second grail-kernel entry for {e['grail_id']} (kernel-drift)")
                if e["release_scope"] in {g["release_scope"] for g in self.grail.values()}:
                    raise RegistryError(f"{where}: release_scope {e['release_scope']!r} rebound")
                self.grail[e["grail_id"]] = e
            elif t == "lifecycle":
                self.lifecycle.setdefault(e["subject"], []).append(e)
            elif t == "protocol":
                self.protocol_history.setdefault(e["name"], []).append(e)
            elif t == "estate_owner":
                owners.append(e["rappid"])
            elif t == "master-plan":
                self.master_plan = e
        if len(owners) != 1:
            raise RegistryError(f"exactly one estate_owner entry is required, found {len(owners)}")
        self.estate_owner = owners[0]
        # name -> the sole non-deprecated pin. A name whose pins are all deprecated, or
        # that carries more than one non-deprecated pin, has no current pin here: the
        # first entry is never assumed current, and ambiguity is left to the adopting
        # profile to refuse (rapp-work/1 requires exactly one active pin per dependency).
        self.protocols = {}
        for name, history in self.protocol_history.items():
            current = [p for p in history if not p["deprecated"]]
            if len(current) == 1:
                self.protocols[name] = current[0]
        for sid, gs in self.genesis.items():
            if sum(1 for g in gs if not g["deprecated"]) > 1:
                raise RegistryError(f"stream {sid}: more than one non-deprecated genesis (§7.6)")
        for g in self.grail.values():
            if g["predecessor"] is not None and g["predecessor"] not in self.grail:
                raise RegistryError(f"grail-kernel {g['grail_id']}: predecessor is not an accepted entry")
        # predecessor cycles
        for gid in self.grail:
            seen, cur = set(), gid
            while cur is not None:
                if cur in seen:
                    raise RegistryError(f"grail-kernel predecessor cycle through {gid}")
                seen.add(cur)
                cur = self.grail[cur]["predecessor"]
        self._declared = {R.canonical(e) for e in entries if e["type"] in DECLARED_TYPES}
        self._succession = {r["new_rappid"]: r for r in self.reanchors}
        succession_by_tail = {}
        for record in self.reanchors:
            tail = R.rappid_parts(record["new_rappid"])["hash"]
            if tail in succession_by_tail:
                raise RegistryError("re-anchor must mint a fresh tail, not another name for one")
            succession_by_tail[tail] = record
        walked = set()  # tails whose walk back to a first identity already finished
        for successor in succession_by_tail:
            path, current = set(), successor
            while current not in walked:
                if current in path:
                    raise RegistryError("re-anchor succession reuses an ancestral identity tail")
                path.add(current)
                record = succession_by_tail.get(current)
                if record is None:
                    break
                current = R.rappid_parts(record["old_rappid"])["hash"]
            walked |= path
        # The §13.5 rules span entries, so they run once every entry is indexed.
        self._index_lifecycle()

    # ---- §7.2 / §6.1.1 kind binding ----
    def family(self, kind):
        e = self.kinds.get(kind)
        return None if e is None or e["deprecated"] else e["family"]

    def check_frame_binding(self, frame):
        """Registry-bound part of §7.5 step 1: kind registered here, family compatible with
        the stream form. Returns (ok, reason). Run alongside rapp.verify_frame."""
        kind = frame.get("kind")
        fam = self.family(kind)
        if fam is None:
            return False, f"kind {kind!r} is not a live registered kind of this estate"
        form = stream_form(frame.get("stream_id"))
        if form is None:
            return False, "stream_id is not a §6.1.1 stream form"
        if STREAM_FORMS[fam] != form:
            return False, f"kind family {fam!r} is incompatible with {form}"
        return True, "ok"

    # ---- §13.2 owner succession ----
    def owner_at(self, utc):
        """The estate-owner rappid in effect at `utc` (walks re-anchor records backwards). A `utc`
        that is not the fixed, ASCII §7.4 form raises RegistryError: tenure compares bytewise."""
        if not _utc_form(utc):
            raise RegistryError("owner_at: the time is not the fixed §7.4 UTC form")
        owner, seen = self.estate_owner, set()
        while True:
            if owner in seen:
                raise RegistryError("re-anchor succession cycle")
            seen.add(owner)
            rec = self._succession.get(owner)
            if rec is None or utc >= rec["utc"]:
                return owner
            owner = rec["old_rappid"]

    # ---- §10 signer acceptability at a time ----
    def signer_acceptable(self, kid, utc):
        """Is a `sig` by `kid` on an artifact at `utc` acceptable: key discoverable, not
        superseded by a re-anchor at or before utc, not tombstoned at or before utc."""
        return self._signer_acceptable(kid, utc)

    def _signer_acceptable(self, kid, utc, ignored_reanchor=None, match_key_aliases=False):
        if not _utc_form(utc):
            return False, "the artifact's time is not the fixed §7.4 UTC form"
        e = self.spki.get(kid)
        if e is None:
            return False, "no spki entry for kid (registry absence is refusal)"
        target = R.rappid_parts(kid)["hash"] if match_key_aliases else kid
        def matches(other):
            return (R.rappid_parts(other)["hash"] if match_key_aliases else other) == target
        for r in self.reanchors:
            if r is ignored_reanchor:
                continue
            if matches(r["old_rappid"]) and utc >= r["utc"]:
                return False, f"kid superseded by re-anchor ({r['case']}) at {r['utc']}"
        if e["deprecated"] and not any(matches(r["old_rappid"]) for r in self.reanchors):
            return False, "spki entry deprecated"
        revocations = [revoked for identity, revoked in self.tombstones.items() if matches(identity)]
        rv = min(revocations) if revocations else None
        if rv is not None and utc >= rv:
            return False, f"kid tombstoned at {rv}"
        return True, "ok"

    def spki_der(self, kid):
        e = self.spki.get(kid)
        return None if e is None else base64.b64decode(e["spki_der_b64"], validate=True)

    def signature_verifier(self):
        """A callable shaped for rapp.verify_frame(signature_verifier=...) that resolves
        keys from this registry and applies the time-scoped §10 rules."""
        def verify(unsigned, sig, expected_signer=None):
            try:
                header = R.parse_detached_jws(sig)[0]
            except ValueError as why:
                return False, str(why)
            kid = header["kid"]
            if expected_signer is not None and kid != expected_signer:
                return False, "kid is not the required signer"
            utc = unsigned.get("utc") or unsigned.get("created_utc") or unsigned.get("activated_utc")
            if utc is None:
                return False, "artifact carries no utc to scope the signer's authority"
            ok, why = self.signer_acceptable(kid, utc)
            if not ok:
                return False, why
            return R.verify_detached_jws(unsigned, sig, self.spki_der(kid), expected_kid=kid)
        return verify

    def registered_genesis(self, stream_id):
        for g in self.genesis.get(stream_id, []):
            if not g["deprecated"]:
                return g
        return None

    def current_protocol(self, name):
        """The estate's sole non-deprecated pin for protocol `name`; None when absent or ambiguous."""
        return self.protocols.get(name)

    # ---- §13.4 declared entries ----
    def _status_refusal(self, allow_draft, question):
        """None when this registry may answer `question` for the estate; else the refusal reason:
        "verified" always, "draft" only with allow_draft (a rehearsal), and a Registry built
        directly (status None) never."""
        accepted = ("verified", "draft") if allow_draft else ("verified",)
        if self.status in accepted:
            return None
        return (f"registry status is {self.status!r}; only a registry that load_document returned as "
                f"{' or '.join(accepted)} answers {question}")

    def declared_entry_ok(self, entry, *, verification_utc=None, allow_draft=False):
        """Is `entry` a declaration of this estate? (ok, why) — §13.4 items 1–3 for one entry.

        `entry` may be the registry's own entry or a copy found elsewhere (a Hive
        notice, a member file); a copy counts only when its canonical form (§4) equals an
        entry this registry carries — a declaration no accepted registry carries is not a
        declaration, however well signed. It answers only for a registry load_document
        returned as "verified" (a "draft" only with `allow_draft=True`, as a rehearsal; a
        Registry built directly never), since only an accepted registry makes a copy count.
        `verification_utc`, when given, is the verifier's first-seen time for the entry;
        `activated_utc` may not exceed it by more than 300 seconds. Without it this method
        does not apply that rule; the loader does (`check_declared_signatures` refuses when no
        first-seen context is supplied)."""
        refusal = self._status_refusal(allow_draft, "whether a copy is one of its declarations (§13.4)")
        if refusal:
            return False, refusal
        return self._declared_entry_check(entry, verification_utc)

    def _declared_entry_check(self, entry, verification_utc):
        """§13.4 items 1–3 against these entries, whatever this registry's status (the loader's step)."""
        try:
            kind = validate_entry(entry, "declared entry")
        except RegistryError as why:
            return False, str(why)
        if kind not in DECLARED_TYPES:
            return False, f"{kind} is not a declared entry type (§13.4)"
        try:
            carried = R.canonical(entry) in self._declared
        except ValueError as why:
            return False, str(why)
        if not carried:
            return False, f"{kind}: not an entry of this registry (§13.4 — a copy must have a carried entry's canonical form)"
        activated, signer = entry["activated_utc"], entry["declared_by"]
        try:
            owner = self.owner_at(activated)
        except RegistryError as why:
            return False, str(why)
        if signer != owner:
            return False, f"{kind}: declared_by is not the estate owner in effect at activated_utc (§13.2)"
        ok, why = self.signer_acceptable(signer, activated)
        if not ok:
            return False, f"{kind}: declared_by key refused at activated_utc: {why}"
        if verification_utc is not None:
            try:
                skew = _utc_seconds(activated, "activated_utc") - _utc_seconds(verification_utc, "first-seen time")
            except RegistryError as why:
                return False, str(why)
            if skew > FIRST_SEEN_SKEW_SECONDS:
                return False, f"{kind}: activated_utc is more than 300 s after first-seen (§13.4)"
        unsigned = {k: v for k, v in entry.items() if k != "sig"}
        ok, why = R.verify_detached_jws(unsigned, entry["sig"], self.spki_der(signer), expected_kid=signer)
        if not ok:
            return False, f"{kind} entry signature refused: {why}"
        return True, "ok"

    def check_declared_signatures(self, *, verification_utc=None, first_seen=None):
        """Every declared entry's own signature; the document signature never substitutes.

        The 300-second rule compares each entry with the verifier's first-seen time for
        THAT entry: pass `first_seen(entry_hash) -> utc` from persisted state (returning
        the current time for an entry never seen before), or `verification_utc` when every
        declared entry is being seen for the first time now. Never both."""
        if verification_utc is not None and first_seen is not None:
            return False, "pass either verification_utc or first_seen, not both"
        for entry in self.entries:
            if entry["type"] in DECLARED_TYPES:
                if verification_utc is None and first_seen is None:
                    return False, ("a declared entry needs first-seen context: pass first_seen= or "
                                   "verification_utc= (§13.4 item 3)")
                seen = verification_utc
                if first_seen is not None:
                    try:
                        seen = first_seen(entry_hash(entry))
                    except (KeyError, ValueError) as why:
                        return False, f"first-seen context refused: {why}"
                if not _utc_form(seen):
                    return False, "first-seen context did not supply a valid UTC (§13.4 item 3)"
                ok, why = self._declared_entry_check(entry, seen)
                if not ok:
                    return False, why
        return True, "ok"

    def check_retained(self, persisted_entries):
        """§13.4 retention: every previously accepted persisted entry is still here, canonical form unchanged."""
        present = {R.canonical(e) for e in self.entries if e["type"] in PERSISTED_TYPES}
        for i, entry in enumerate(persisted_entries):
            if not isinstance(entry, dict) or entry.get("type") not in PERSISTED_TYPES:
                return False, f"persisted_entries[{i}] is not a persisted entry type (§13.4)"
            if R.canonical(entry) not in present:
                return False, f"a persisted {entry['type']} entry was removed or mutated (§13.4)"
        return True, "ok"

    # ---- §10 / §13.3 key-lifecycle entries (tombstones and re-anchors) ----
    def check_lifecycle_signatures(self, *, tombstone_issued_at=None):
        """Check the signatures on key-lifecycle entries, not only their outer registry.

        Key-lifecycle entries are tombstones and re-anchors (§10); `lifecycle` notices
        (§13.5) are declared entries, checked by `check_declared_signatures`.
        This checks owner tenure and old-key continuity. A snapshot cannot prove
        which entries arrived in the same append; callers must retain append
        provenance for the additional §6.3 compromise requirement. Tombstones
        have a cutoff, not an issuance UTC: a trusted context resolver must
        supply the latter, keyed by the exact signed entry's particle hash.
        """
        owner, seen, owner_transitions = self.estate_owner, set(), set()
        while owner in self._succession:
            if owner in seen:
                raise RegistryError("re-anchor succession cycle")
            seen.add(owner)
            record = self._succession[owner]
            prior = self._succession.get(record["old_rappid"])
            if prior is not None and prior["utc"] >= record["utc"]:
                raise RegistryError("owner succession requires a nonempty, forward tenure")
            owner_transitions.add(record["new_rappid"])
            owner = record["old_rappid"]

        def verify(value, sig, expected_kid):
            der = self.spki_der(expected_kid)
            if der is None:
                return False, "lifecycle signer has no registered spki"
            return R.verify_detached_jws(value, sig, der, expected_kid=expected_kid)

        for entry in self.entries:
            kind = entry["type"]
            if kind not in ("tombstone", "re-anchor"):
                continue
            if kind == "tombstone":
                if not callable(tombstone_issued_at):
                    return False, "tombstone issuance time requires trusted append/issuance context"
                try:
                    utc = tombstone_issued_at(R.H("rapp/1:particle", entry))
                except (KeyError, ValueError) as why:
                    return False, f"tombstone issuance context refused: {why}"
                if not _utc_form(utc):
                    return False, "tombstone issuance context did not supply a valid UTC"
            else:
                utc = entry["utc"]
            if kind == "re-anchor" and entry["new_rappid"] in owner_transitions:
                # The outgoing owner signs its own transition at the tenure boundary.
                signer = entry["old_rappid"]
            else:
                signer = self.owner_at(utc)
            unsigned = {k: v for k, v in entry.items() if k != "sig"}
            ok, why = verify(unsigned, entry["sig"], signer)
            if not ok:
                return False, f"{kind} owner signature refused: {why}"
            if kind == "re-anchor":
                if "old_key_sig" in entry:
                    if entry["case"] == "rotation":
                        ok, why = self._signer_acceptable(
                            entry["old_rappid"], utc, ignored_reanchor=entry,
                            match_key_aliases=True,
                        )
                        if not ok:
                            return False, f"rotation old-key authority refused: {why}"
                    continuity = {k: v for k, v in entry.items()
                                  if k not in ("sig", "old_key_sig")}
                    ok, why = verify(continuity, entry["old_key_sig"], entry["old_rappid"])
                    if not ok:
                        return False, f"re-anchor old-key signature refused: {why}"
                if entry["case"] == "compromise" and entry["old_rappid"] not in self.tombstones:
                    return False, "compromise re-anchor requires a registered tombstone"
        return True, "ok"

    # ---- §13.5 lifecycle notices ----
    def _index_lifecycle(self):
        """Chain each subject's `lifecycle` entries and refuse what §13.5 forbids.

        One linear chain per `subject` (a rappid or a repository URI, compared byte for byte),
        every entry after the first naming the one it follows by `previous` = entry_hash (so a
        chain is its subject's entries in append order); neither `since_utc` nor
        `activated_utc` decreasing along it; and, at no time, a cycle among the successors named
        by the notices in effect then."""
        collected = [e for notices in self.lifecycle.values() for e in notices]
        self.lifecycle = linear_chains(
            collected, key=lambda e: e["subject"], ident=entry_hash,
            link=lambda e: e["previous"], where="lifecycle chain",
        )
        for subject, chain in self.lifecycle.items():
            for prior, notice in zip(chain, chain[1:]):
                for member in ("since_utc", "activated_utc"):
                    # The fixed §7.4 form orders bytewise exactly as it orders in time.
                    if notice[member] < prior[member]:
                        raise RegistryError(
                            f"lifecycle chain {subject!r}: `{member}` decreases along the chain (§13.5)"
                        )
        # The notices in effect change only at a since_utc, so the successor graph is checked at
        # each distinct since_utc in time order. A cycle there must pass through a subject whose
        # notice changed then (the graph before that instant had none), so only walks from those
        # subjects are needed.
        changes = {}  # since_utc -> [(subject, notice)], each chain's entries in chain order
        for subject, chain in self.lifecycle.items():
            for notice in chain:
                changes.setdefault(notice["since_utc"], []).append((subject, notice))
        successors = {}  # subject -> the successor named by its notice in effect
        for instant in sorted(changes):
            for subject, notice in changes[instant]:  # a later entry at the same instant wins
                if notice["superseded_by"] is None:
                    successors.pop(subject, None)
                else:
                    successors[subject] = notice["superseded_by"]
            settled = set()  # subjects whose walk along the successors in effect is known to end
            for start, _ in changes[instant]:
                walk, current = set(), start
                while current in successors and current not in settled:
                    if current in walk:
                        raise RegistryError(
                            f"lifecycle: the `superseded_by` of the notices in effect at {instant} form a "
                            f"cycle through {current!r} (§13.5)"
                        )
                    walk.add(current)
                    current = successors[current]
                settled |= walk

    def lifecycle_chain(self, subject):
        """The subject's `lifecycle` entries in chain order (first notice first); [] when none.
        `subject` is a rappid or a repository URI, spelled exactly as the notices spell it."""
        return list(self.lifecycle.get(subject, ())) if isinstance(subject, str) else []

    def lifecycle_head(self, subject):
        """The current notice — the last entry of the subject's chain — or None. A scheduled
        notice is current before its `since_utc` arrives; `lifecycle_at` and `successor_at`
        say what is in effect."""
        chain = self.lifecycle_chain(subject)
        return chain[-1] if chain else None

    def lifecycle_at(self, subject, utc, *, allow_draft=False):
        """The notice in effect at `utc`: the last chain entry whose `since_utc` <= `utc`
        (bytewise, §7.4). None means no declared lifecycle at `utc` — never deprecation.
        It is the estate's answer, so it is given only by a registry load_document returned as
        "verified" (a "draft" only with `allow_draft=True`, as a rehearsal; a Registry built
        directly never): otherwise, and for a `utc` that is not the fixed §7.4 form, it raises
        RegistryError (a ValueError) rather than return a None that could read as "no notice"."""
        refusal = self._status_refusal(allow_draft, "the lifecycle in effect (§13.5)")
        if refusal:
            raise RegistryError(refusal)
        if not _utc_form(utc):
            raise RegistryError("lifecycle query time is not the fixed §7.4 UTC form")
        in_effect = None
        for notice in self.lifecycle_chain(subject):
            if notice["since_utc"] > utc:
                break  # since_utc never decreases along a chain
            in_effect = notice
        return in_effect

    def lifecycle_state_at(self, subject, utc, *, allow_draft=False):
        """The subject's state in effect at `utc`; None when it has no declared lifecycle then.
        Gated like lifecycle_at."""
        notice = self.lifecycle_at(subject, utc, allow_draft=allow_draft)
        return None if notice is None else notice["state"]

    def successor_at(self, subject, utc, *, allow_draft=False):
        """The `superseded_by` of the notice in effect at `utc` — a rappid or a repository URI —
        or None when no notice is in effect then or it names no successor, so a scheduled notice
        names none before its `since_utc`. It names; it grants nothing. The successors in effect
        at any one time never form a cycle (§13.5), so a walk along them at one time always ends.
        Gated like lifecycle_at."""
        notice = self.lifecycle_at(subject, utc, allow_draft=allow_draft)
        return None if notice is None else notice["superseded_by"]


def validate_document(doc):
    """The §13.1 container, structurally: refuse, never repair. Entries are not checked here."""
    if not isinstance(doc, dict) or doc.get("schema") != DOCUMENT_SCHEMA:
        raise RegistryError('document schema must be "rapp/1-registry"')
    missing = [m for m in DOCUMENT_MEMBERS if m not in doc]
    if missing:
        raise RegistryError(f"registry document lacks {missing} (§13.1)")
    seq = doc["registry_seq"]
    if not (isinstance(seq, int) and not isinstance(seq, bool) and 0 <= seq <= 2**53 - 1):
        raise RegistryError("registry_seq must be uint53")
    source = doc["canonical_source"]
    if not _canonical_source_ok(source):
        raise RegistryError("canonical_source must be an absolute HTTPS URI or a URN (§13.1)")
    if not isinstance(doc[ENTRIES_MEMBER], list):
        raise RegistryError("entries must be a JSON array (§13.1)")
    sig = doc["sig"]
    if sig is not None and not (isinstance(sig, str) and sig):
        raise RegistryError("sig must be a detached JWS string or null (§13.1)")
    try:  # §4(d): a registry is one §4 value — at most 1 MiB canonical, nested at most 64 deep
        R._strict_json(R.canonical(doc).encode("utf-8"))
    except (ValueError, RecursionError) as why:
        raise RegistryError(f"registry document is not a §4 value: {why}")
    return doc


def load_document(doc, *, trust_anchor, entries_member=ENTRIES_MEMBER, allow_unsigned=False,
                  persisted_seq=None, tombstone_issued_at=None, verification_utc=None,
                  first_seen=None, canonical_source=None, persisted_entries=None):
    """Load a `rapp/1-registry` document. Returns (status, registry, reason) where status is
    "verified" (owner signature verified AGAINST THE TRUST ANCHOR), "draft" (unsigned and
    allow_unsigned), or "refused".

    `trust_anchor` is REQUIRED: the estate-owner rappid you obtained out of band (§13.1 — the
    one bootstrap axiom). A document whose `estate_owner` entry names any other rappid is
    refused before its signature is even checked; without this, a registry signed by a
    self-minted key would verify against itself. §13.1 names the container: the entries are
    always the `entries` member (`entries_member` is kept for compatibility and refuses any
    other name), and `canonical_source` is the document's own owner-selected location of
    record; pass `canonical_source=` when you obtained one out of band with the anchor and a
    document naming another is refused. `persisted_seq` implements §13.1 no-rollback: a lower
    `registry_seq` is refused. Signed documents also verify each key-lifecycle entry's owner
    signature and any old-key continuity signature, and every declared entry's own owner
    signature at its `activated_utc` (§13.4). The 300-second rule is per entry:
    `first_seen(entry_hash)` returns the caller's persisted first-seen time for an entry (and
    the current time for one never seen before); `verification_utc` is the shortcut when every
    declared entry is being seen for the first time now; a signed registry that carries a declared
    entry is refused when neither is supplied. `persisted_entries` are the canonical
    declared entries the caller accepted before; each must still be present byte for byte.
    Freshness, append provenance, and historical migration proofs remain caller
    responsibilities; a verified snapshot alone cannot establish them. A returned registry
    records its status in `registry.status` ("verified" or "draft"): `declared_entry_ok`,
    `lifecycle_at`, `lifecycle_state_at`, and `successor_at` check it, so only a "verified"
    registry's copy checks and lifecycle answers (§13.4, §13.5) are the estate's (a draft only
    with `allow_draft=True`, as a rehearsal); a Registry constructed directly has status None.
    `tombstone_issued_at(entry_hash)` must resolve authenticated issuance/append
    context to a fixed UTC string. It is trusted caller configuration, never a
    field read from the untrusted document. No resolver means tombstones are
    refused: revoked_utc cannot be silently reinterpreted as issuance time."""
    if entries_member != ENTRIES_MEMBER:
        return "refused", None, 'the §13.1 entries member is "entries"; no other name is a rapp/1-registry'
    if not R.rappid_valid(trust_anchor):
        return "refused", None, "trust_anchor must be the out-of-band estate-owner rappid"
    try:
        validate_document(doc)
    except RegistryError as why:
        return "refused", None, str(why)
    seq = doc["registry_seq"]
    if persisted_seq is not None and seq < persisted_seq:
        return "refused", None, f"registry_seq {seq} < persisted {persisted_seq} (rollback)"
    if canonical_source is not None and doc["canonical_source"] != canonical_source:
        return "refused", None, "canonical_source differs from the one obtained with the trust anchor (§13.1)"
    try:
        R.canonical(doc)  # §4 input-domain profile: refuse, never repair
        reg = Registry(doc[ENTRIES_MEMBER])
    except (RegistryError, ValueError) as why:
        return "refused", None, str(why)
    reg.canonical_source = doc["canonical_source"]
    if reg.estate_owner != trust_anchor:
        return "refused", None, "estate_owner does not match the out-of-band trust anchor (§13.1)"
    sig = doc["sig"]
    if sig is None:
        if allow_unsigned:
            reg.status = "draft"
            return "draft", reg, "unsigned: a draft, never authority (§13.1)"
        return "refused", None, "unsigned registry (§13.1 MUST refuse)"
    unsigned = {k: v for k, v in doc.items() if k != "sig"}
    der = reg.spki_der(reg.estate_owner)
    if der is None:
        return "refused", None, "no spki entry for the estate_owner; the tail check cannot run"
    ok, why = R.verify_detached_jws(unsigned, sig, der, expected_kid=reg.estate_owner)
    if not ok:
        return "refused", None, why
    try:
        ok, why = reg.check_lifecycle_signatures(tombstone_issued_at=tombstone_issued_at)
        if ok:
            ok, why = reg.check_declared_signatures(verification_utc=verification_utc,
                                                    first_seen=first_seen)
        if ok and persisted_entries is not None:
            ok, why = reg.check_retained(persisted_entries)
    except RegistryError as why:
        return "refused", None, str(why)
    if not ok:
        return "refused", None, why
    reg.status = "verified"
    return "verified", reg, "ok"
