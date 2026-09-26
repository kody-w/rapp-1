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
  - every entry type and its exact member set (§13.3);
  - kind grammar and family binding; family ↔ stream_id-form compatibility (§6.1.1, §7.2);
  - owner succession by re-anchor records, owner-in-effect at a time (§13.2);
  - key discovery, superseded-key and tombstone refusal at a time (§10);
  - one non-deprecated genesis per stream (§7.6); one grail-kernel per grail_id (§11.1);
  - declared entries (§13.4): each entry-level owner signature at its own
    `activated_utc`, never blessed by the enclosing document signature, and
    retention of persisted entries, unchanged in canonical form (§4), once a caller has accepted them;
  - stream signers (§13.5): each `stream-signer` grant's structure and cross-entry rules,
    and the authority check above §7.5 for a consumer that follows no profile-defined signer
    rule — a verified frame speaks for the estate only when its `kid` is the owner in effect
    or a signer granted its stream, kind, and time;
  - owner-signature verification over canonical(document \\ {sig}).

Structural accessors — grants, `authority_decision` — read whatever registry you hold. Answers —
whether a frame speaks for the estate, whether a copy is a declaration — come only from a registry
`load_document` returned as "verified"; a "draft" gives them only with `allow_draft=True`, as a
rehearsal, and a Registry built directly never.

What stays the caller's responsibility, because a snapshot cannot prove it:
  - freshness, trusted heads, registry high-water marks, first-seen times, and the
    append provenance of each entry (see `load_document`);
  - re-evaluating a cached authority refusal against a newer registry, which can add a
    grant that adopts earlier frames but never withdraw one (§13.5).

Nothing here can make an unsigned registry authoritative. `load_document` reports
"verified" only after a §10 signature by the estate owner verifies AND that owner is the
rappid the caller obtained out of band (the trust anchor); an unsigned document is at most
a "draft", and a registry that names any other owner is refused outright.
"""
import base64
import re
import urllib.parse
from datetime import datetime, timezone

import rapp as R

FAMILIES = ("memory", "swarm", "body")
STREAM_FORMS = {"memory": "memory-stream", "swarm": "swarm-stream", "body": "body-stream"}
REANCHOR_CASES = ("upgrade", "rotation", "compromise", "tag-migrate")
# §7.2 / §12.1 — the three re-genesis kinds; only the owner signs them, so no grant may list one.
REGENESIS_KINDS = ("memory.re-genesis", "swarm.re-genesis", "body.re-genesis")

_LCLABEL = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_KIND = re.compile(rf"({_LCLABEL})\.({_LCLABEL})")
_LABEL = re.compile(_LCLABEL)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HTTPS = re.compile(r"https://[\x21-\x7e]+")  # printable ASCII after the scheme: no space, no control

# §13.1 — the registry document container (rev-17 closure).
DOCUMENT_SCHEMA = "rapp/1-registry"
ENTRIES_MEMBER = "entries"
DOCUMENT_MEMBERS = ("schema", "registry_seq", "canonical_source", ENTRIES_MEMBER, "sig")

# §13.4 — entry types that carry their own owner signature at `activated_utc`.
# Every declared entry is persisted: once accepted, it is retained with its canonical form unchanged.
DECLARED_TYPES = ("grail-kernel", "stream-signer")
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
    "stream-signer": ({"type", "stream_id", "signer", "kinds", "since_utc", "until_utc",
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
    """An absolute HTTPS URI (§3): scheme `https`, a non-empty host, no user information, printable
    ASCII only, at most 2048 characters — the rule `rapp_profile.https_uri` also applies."""
    if not (isinstance(value, str) and len(value) <= 2048 and _HTTPS.fullmatch(value)):
        return False
    try:
        parts = urllib.parse.urlsplit(value)
        return bool(parts.hostname) and "@" not in parts.netloc
    except ValueError:  # e.g. an unterminated IPv6 literal
        return False


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


def _validate_stream_signer(entry, where):
    """The §13.3 stream-signer members, one entry at a time. That the signer has an spki
    entry and each kind a compatible registration spans entries (Registry)."""
    if stream_form(entry.get("stream_id")) is None:
        raise RegistryError(f"{where}: `stream_id` is not a §6.1.1 stream form")
    _rappid(entry, "signer", where)
    kinds = entry.get("kinds")
    if not isinstance(kinds, list) or not kinds:
        raise RegistryError(f"{where}: `kinds` must be a non-empty array")
    for position, kind in enumerate(kinds):
        if not kind_valid(kind):
            raise RegistryError(f"{where}: `kinds[{position}]` fails the §6.1.1 kind grammar")
        if kind in REGENESIS_KINDS:
            raise RegistryError(f"{where}: `kinds` lists {kind}, which §12.1 reserves for the owner")
    for prior, kind in zip(kinds, kinds[1:]):
        # Kinds are ASCII, so Python's code-point order is the bytewise order §13.3 requires.
        if kind == prior:
            raise RegistryError(f"{where}: `kinds` lists {kind!r} twice")
        if kind < prior:
            raise RegistryError(f"{where}: `kinds` must ascend bytewise ({kind!r} follows {prior!r})")
    since = _utc(entry, "since_utc", where)
    if entry.get("until_utc") is not None and _utc(entry, "until_utc", where) <= since:
        raise RegistryError(f"{where}: `until_utc` must be null or after `since_utc` (§13.5)")
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
    elif t == "stream-signer":
        _validate_stream_signer(entry, where)
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
        self.stream_signers = {}  # stream_id -> [stream-signer grants], append order (§13.5)
        self.protocol_history = {}  # name -> [entries], append order
        self.master_plan = None
        self.canonical_source = None  # set by load_document from the §13.1 container
        self.status = None  # "verified" or "draft" when load_document returns it; None when built directly
        owners, reanchored = [], set()
        for i, e in enumerate(entries):
            where = f"entries[{i}]"
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
            elif t == "stream-signer":
                self.stream_signers.setdefault(e["stream_id"], []).append(e)
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
        # The §13.5 rules span entries, so they run once every entry is indexed: grants look up
        # their spki and kinds.
        self._index_stream_signers()

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

    def check_lifecycle_signatures(self, *, tombstone_issued_at=None):
        """Check the signatures on lifecycle entries, not only their outer registry.

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

    # ---- §13.5 stream signers ----
    def _index_stream_signers(self):
        """Check every grant the constructor collected against the rules that span entries
        (§13.3): its signer has a §13 `spki` entry here — so it is keyed; a keyless rappid never
        signs — and each listed kind a `kind` entry here whose family's stream form is the
        grant's stream form (§7.2). Deprecated `spki` and `kind` entries still count: a grant is
        permanent, and retiring a key or a kind later never invalidates the registry."""
        for stream_id, grants in self.stream_signers.items():
            form = stream_form(stream_id)
            for grant in grants:
                where = f"stream-signer for {grant['signer']} on {stream_id}"
                if grant["signer"] not in self.spki:
                    raise RegistryError(f"{where}: the signer has no spki entry in this registry (§13.3)")
                for kind in grant["kinds"]:
                    registered = self.kinds.get(kind)
                    if registered is None:
                        raise RegistryError(f"{where}: kind {kind!r} is not registered in this registry")
                    if STREAM_FORMS[registered["family"]] != form:
                        raise RegistryError(
                            f"{where}: kind {kind!r} is family {registered['family']!r}, "
                            f"incompatible with a {form} (§7.2)"
                        )

    @staticmethod
    def _window_covers(grant, utc):
        """since_utc ≤ utc < until_utc, bytewise over the fixed §7.4 form; a null until never ends."""
        return grant["since_utc"] <= utc and (grant["until_utc"] is None or utc < grant["until_utc"])

    def stream_grants(self, stream_id):
        """The `stream-signer` grants for `stream_id` in append order (a new list; [] if none)."""
        return list(self.stream_signers.get(stream_id, ())) if isinstance(stream_id, str) else []

    def grant_covers(self, stream_id, kid, kind, utc):
        """Does a grant for `stream_id` name `kid` as signer, list `kind`, and cover `utc`?

        The grant window only; §10 key refusal and owner authority are authority_decision's."""
        if not _utc_form(utc):
            return False
        return any(grant["signer"] == kid and kind in grant["kinds"] and self._window_covers(grant, utc)
                   for grant in self.stream_grants(stream_id))

    def authority_decision(self, stream_id, kid, kind, utc):
        """The §13.5 rule over a frame summary: may `kid` speak for this estate on `stream_id`
        with `kind` at `utc`? Returns (ok, reason); `kid` None means the frame is unsigned.

        Authorized iff `kid` is the estate owner in effect at `utc` (§13.2), or a grant covers
        `stream_id`, `kid`, `kind`, and `utc` — and in both cases §10 does not refuse the key at
        `utc`. A grant's `activated_utc` plays no part: a grant may start before it, and then
        adopts frames the signer already published inside its window. It decides authority,
        never validity: the frame must already have passed §7.5 (see frame_authorized). Pure:
        it reads only this registry's entries and does not check `status` — it is the rule, not
        the estate's answer; frame_authorized and verify_authorized_frame give the answer only
        for a verified registry. A refusal holds only against this registry — a newer registry
        can add a grant that adopts the frame, and a cached refusal is re-evaluated against it
        (§13.5)."""
        if kid is None:
            return False, "an unsigned frame never speaks for the estate (§10, §13.5)"
        if not R.rappid_valid(kid):
            return False, "kid is not a §6.1 rappid"
        if not _utc_form(utc):
            return False, "utc is not the fixed §7.4 form"
        try:
            owner = self.owner_at(utc)
        except RegistryError as why:
            return False, str(why)
        if kid == owner:
            ok, why = self.signer_acceptable(kid, utc)
            if not ok:
                return False, f"the estate owner's key is refused at utc (§10): {why}"
            return True, "estate owner"
        named = [grant for grant in self.stream_grants(stream_id) if grant["signer"] == kid]
        if not named:
            return False, ("kid is neither the estate owner in effect at utc (§13.2) nor granted "
                           "this stream by a stream-signer entry (§13.5)")
        listing = [grant for grant in named if kind in grant["kinds"]]
        if not listing:
            return False, f"no stream-signer grant to kid on this stream lists kind {kind!r} (§13.5)"
        if not any(self._window_covers(grant, utc) for grant in listing):
            return False, "utc is outside every stream-signer window for kid, stream, and kind (§13.5)"
        ok, why = self.signer_acceptable(kid, utc)
        if not ok:
            return False, f"the granted signer's key is refused at utc (§10): {why}"
        return True, "stream-signer grant"

    def frame_authorized(self, frame, *, allow_draft=False):
        """The §13.5 authority rule ONLY — does this frame speak for the estate? (ok, reason).

        !! IT DOES NOT VERIFY THE FRAME. Call it only for a frame that has ALREADY passed §7.5
        !! — rapp.verify_frame(signature_verifier=self.signature_verifier()) plus
        !! check_frame_binding — or call verify_authorized_frame, which runs all three. It reads
        !! the signer from the protected `kid` without checking the signature, so its answer
        !! for an unverified frame means nothing.

        Answers only for a registry that load_document returned as "verified" (its `status`); a
        "draft" answers only with `allow_draft=True`, for rehearsal, and a Registry built
        directly (status None) never. Refuses an unsigned frame (it never speaks for the
        estate, §10) and a `sig` whose protected header does not parse; otherwise applies
        authority_decision to the frame's `stream_id`, `kid`, `kind`, and `utc`. A refusal
        leaves the frame a valid `rapp/1` frame."""
        refusal = self._status_refusal(allow_draft, "who speaks for the estate (§13.5)")
        if refusal:
            return False, refusal
        if not isinstance(frame, dict):
            return False, "frame is not a JSON object"
        sig = frame.get("sig")
        if sig is None:
            return False, "an unsigned frame never speaks for the estate (§10, §13.5)"
        try:
            kid = R.parse_detached_jws(sig)[0]["kid"]
        except (ValueError, TypeError) as why:
            return False, f"sig is not a §10 detached JWS: {why}"
        return self.authority_decision(frame.get("stream_id"), kid, frame.get("kind"), frame.get("utc"))

    def verify_authorized_frame(self, frame, *, head, stream_id_of_record, allow_draft=False):
        """§7.5 against this registry, then the §13.5 authority check. Returns (ok, step, why).

        An invalid frame fails at its §7.5 step, "1" through "6"; the registered-kind and
        family binding (check_frame_binding) is part of step 1. A valid `rapp/1` frame that does
        not speak for the estate fails at step "authority", which is deliberately not a §7.5
        step, so a caller can tell "not the estate's statement" from "not a frame". On success
        step is None and why names the authority: "estate owner" or "stream-signer grant".
        `head` is the stream's verified head (None at genesis); `stream_id_of_record` is the
        stream being read or extended (§7.5 step 1a) and is required. The authority step answers
        only for a registry load_document returned as "verified" (§13.1; see `status`), or a
        "draft" with `allow_draft=True` for rehearsal; any other registry is refused first, at step
        "authority", because its kinds and keys cannot judge the frame either."""
        refusal = self._status_refusal(allow_draft, "who speaks for the estate (§13.5)")
        if refusal:
            return False, "authority", refusal
        if not isinstance(frame, dict):
            return False, "1", "frame is not a JSON object"
        if not isinstance(stream_id_of_record, str):
            return False, "1a", "stream_id_of_record must name the stream being read or extended"
        ok, step, why = R.verify_frame(frame, head=head, stream_id_of_record=stream_id_of_record,
                                       signature_verifier=self.signature_verifier())
        if not ok and step == "1":
            return False, step, why
        bound, bound_why = self.check_frame_binding(frame)
        if not bound:
            return False, "1", bound_why
        if not ok:
            return False, step, why
        authorized, why = self.frame_authorized(frame, allow_draft=allow_draft)
        if not authorized:
            return False, "authority", why
        return True, None, why

    def authorization_verifier(self, *, allow_draft=False):
        """A callable `(frame, purpose=None) -> bool` for the `authorization_verifier` parameter of
        rapp_profile.authoritative_frame_payload: True only when frame_authorized(frame) holds,
        so never for a registry that is not "verified" (or a "draft" with `allow_draft=True`).
        That helper asks only after its own rapp.verify_frame — pass it
        signature_verifier=self.signature_verifier() — so the signature is verified first, as
        frame_authorized requires. `purpose` is accepted and never widens authority.

        §13.5 binds only a consumer that follows no profile-defined signer rule. A subordinate
        profile that defines its own signer authorization (rapp-work/1 §1, a rapp-cicd/1 stage
        approver) keeps it and MAY meet it with this verifier; nothing here replaces that rule."""
        def authorized(frame, purpose=None):
            return self.frame_authorized(frame, allow_draft=allow_draft)[0]
        return authorized


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
    if not _https_uri(source):
        raise RegistryError("canonical_source must be an absolute HTTPS URI (§13.1)")
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
    `registry_seq` is refused. Signed documents also verify each lifecycle entry's owner
    signature and any old-key continuity signature, and every declared entry's own owner
    signature at its `activated_utc` (§13.4). The 300-second rule is per entry:
    `first_seen(entry_hash)` returns the caller's persisted first-seen time for an entry (and
    the current time for one never seen before); `verification_utc` is the shortcut when every
    declared entry is being seen for the first time now; a signed registry that carries a declared
    entry is refused when neither is supplied. `persisted_entries` are the canonical
    declared entries the caller accepted before; each must still be present byte for byte.
    Freshness, append provenance, and historical migration proofs remain caller
    responsibilities; a verified snapshot alone cannot establish them. A returned registry
    records its status in `registry.status` ("verified" or "draft"): `frame_authorized`,
    `verify_authorized_frame`, `authorization_verifier`, and `declared_entry_ok` check it, so
    only a "verified" registry's authority answers and copy checks (§13.4, §13.5) are the
    estate's (a draft only with `allow_draft=True`, as a rehearsal); a Registry constructed
    directly has status None.
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
