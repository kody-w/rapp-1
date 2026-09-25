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
    byte-for-byte retention of persisted entries once a caller has accepted them;
  - release pins (§13.5): a release scope names a release family; each pinned release of it
    is one `release-pin` entry naming its manifest by a `manifest_hash` no other
    release-pin shares; a family lives in one channel, each channel is one linear chain of
    release pins whose head is current, and a family's `grail-kernel` precedes its first
    release-pin and, given the caller's persisted entries, is never added once a release of
    the family was accepted; the `rapp/1-release-manifest` structure and its `release`
    name, kernel coherence with the family's `grail-kernel`, and an all-or-nothing
    verified snapshot of one selected pinned release through a caller's fetch;
  - owner-signature verification over canonical(document \\ {sig}).

What stays the caller's responsibility, because a snapshot cannot prove it:
  - freshness, trusted heads, registry high-water marks, first-seen times, and the
    append provenance of each entry (see `load_document`).

Nothing here can make an unsigned registry authoritative. `load_document` reports
"verified" only after a §10 signature by the estate owner verifies AND that owner is the
rappid the caller obtained out of band (the trust anchor); an unsigned document is at most
a "draft", and a registry that names any other owner is refused outright.
"""
import base64
import hashlib
import re
import urllib.parse
from datetime import datetime, timezone

import rapp as R

FAMILIES = ("memory", "swarm", "body")
STREAM_FORMS = {"memory": "memory-stream", "swarm": "swarm-stream", "body": "body-stream"}
REANCHOR_CASES = ("upgrade", "rotation", "compromise", "tag-migrate")

_LCLABEL = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_KIND = re.compile(rf"({_LCLABEL})\.({_LCLABEL})")
_LABEL = re.compile(_LCLABEL)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HTTPS = re.compile(r"https://[^\s]+")
_OBJECT_ID = {"sha1": _HEX40, "sha256": _HEX64}  # object_format -> commit/blob grammar

# §13.1 — the registry document container (rev-17 closure).
DOCUMENT_SCHEMA = "rapp/1-registry"
ENTRIES_MEMBER = "entries"
DOCUMENT_MEMBERS = ("schema", "registry_seq", "canonical_source", ENTRIES_MEMBER, "sig")

# §13.4 — entry types that carry their own owner signature at `activated_utc`.
# Every declared entry is persisted: once accepted, it is retained byte-for-byte.
DECLARED_TYPES = ("grail-kernel", "release-pin")
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
    "release-pin": ({"type", "release_scope", "channel", "predecessor", "manifest_hash", "repository",
                     "object_format", "commit", "path", "activated_utc", "declared_by", "sig"}, set()),
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


def _utc_seconds(value, where):
    if not R.utc_valid(value):
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
    if not R.utc_valid(entry.get(member)):
        raise RegistryError(f"{where}: `{member}` is not the fixed §7.4 UTC form")
    return entry[member]


def _hex64(entry, member, where):
    v = entry.get(member)
    if not (isinstance(v, str) and _HEX64.fullmatch(v)):
        raise RegistryError(f"{where}: `{member}` must be 64 lowercase hex")
    return v


def _lclabel(value, maximum):
    return isinstance(value, str) and bool(_LABEL.fullmatch(value)) and len(value) <= maximum


def _object_id(object_format, value):
    """`object_format` fixes the lowercase-hex length of `value` (40 for sha1, 64 for sha256)."""
    pattern = _OBJECT_ID.get(object_format) if isinstance(object_format, str) else None
    return pattern is not None and isinstance(value, str) and bool(pattern.fullmatch(value))


def _validate_release_pin(entry, where):
    """The §13.3 release-pin members. Uniqueness, channels, families, and kernel order span
    entries, so `Registry` checks those."""
    for member in ("release_scope", "repository"):
        if not _HTTPS.fullmatch(_str(entry, member, where)):
            raise RegistryError(f"{where}: `{member}` must be an absolute HTTPS URI")
    if not _lclabel(entry.get("channel"), 64):
        raise RegistryError(f"{where}: `channel` must be an lclabel of 1-64 characters")
    named = entry.get("predecessor")
    if named is not None and not (isinstance(named, str) and _HEX64.fullmatch(named)):
        raise RegistryError(
            f"{where}: `predecessor` must be null or the manifest_hash of the release-pin it follows"
        )
    _hex64(entry, "manifest_hash", where)
    if entry.get("object_format") not in ("sha1", "sha256"):
        raise RegistryError(f"{where}: `object_format` must be sha1 or sha256")
    if not _object_id(entry["object_format"], entry.get("commit")):
        raise RegistryError(f"{where}: `commit` must be lowercase hex of the {entry['object_format']} length")
    # R._path_valid is the §9.1 path grammar: the grail-kernel path rule (relative NFC POSIX,
    # no empty/"."/".." component) plus the segment rules every file path of the manifest
    # obeys, so the manifest's own locator is as safe to fetch and store as what it pins.
    if not R._path_valid(entry.get("path")):
        raise RegistryError(f"{where}: `path` must be a relative NFC path obeying the §9.1 path grammar")
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
        if not _HTTPS.fullmatch(_str(entry, "spec_repo", where)):
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
            if not _HTTPS.fullmatch(_str(entry, m, where)):
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
    elif t == "release-pin":
        _validate_release_pin(entry, where)
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
        self.release_pins = {}   # manifest_hash -> release-pin entry, append order (§13.5)
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
            elif t == "release-pin":
                if e["manifest_hash"] in self.release_pins:
                    raise RegistryError(
                        f"{where}: a second release-pin for manifest_hash {e['manifest_hash']}; a release "
                        "manifest is pinned once and never rebound (§13.3)"
                    )
                self.release_pins[e["manifest_hash"]] = e
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
        # The §13.5 rules span entries, so they run once every entry is indexed: release pins
        # look up their predecessors and the kernels before them.
        self._index_release_pins()

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
        """The estate-owner rappid in effect at `utc` (walks re-anchor records backwards)."""
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
    def declared_entry_ok(self, entry, *, verification_utc=None):
        """Check one declared entry of this registry (§13.4 items 1–3).

        `entry` may be the registry's own entry or a copy found elsewhere (a Hive
        notice, a member file); a copy counts only when it is byte-for-byte an entry
        this registry carries — a declaration no accepted registry carries is not a
        declaration, however well signed. `verification_utc`, when given, is the
        verifier's first-seen time for the entry; `activated_utc` may not exceed it by
        more than 300 seconds. Without it this method does not apply that rule; the
        loader does (`check_declared_signatures` refuses when no first-seen context is
        supplied)."""
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
            return False, f"{kind}: not an entry of this registry (§13.4 — a copy must be byte-identical)"
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
                if not R.utc_valid(seen):
                    return False, "first-seen context did not supply a valid UTC (§13.4 item 3)"
                ok, why = self.declared_entry_ok(entry, verification_utc=seen)
                if not ok:
                    return False, why
        return True, "ok"

    def check_retained(self, persisted_entries):
        """§13.4 retention: every previously accepted persisted entry is still here, byte for byte;
        then the §13.5 release history against those same entries."""
        persisted_entries = list(persisted_entries)  # read twice: presence, then release history
        present = {R.canonical(e) for e in self.entries if e["type"] in PERSISTED_TYPES}
        for i, entry in enumerate(persisted_entries):
            if not isinstance(entry, dict) or entry.get("type") not in PERSISTED_TYPES:
                return False, f"persisted_entries[{i}] is not a persisted entry type (§13.4)"
            if R.canonical(entry) not in present:
                return False, f"a persisted {entry['type']} entry was removed or mutated (§13.4)"
        return self._check_release_history(persisted_entries)

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
                if not R.utc_valid(utc):
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

    # ---- §13.5 release pins ----
    def _index_release_pins(self):
        """Index the release-pin entries and refuse the registry when they break §13.5.

        A release scope names a release family, and every release pin of one family carries one
        channel. Each channel's release pins form one linear chain through `predecessor` — the
        `manifest_hash` of the pinned release each one follows in that channel — whose activation
        never regresses. A family's grail-kernel entry, if it has one, precedes the family's
        first release-pin in `entries`, so no kernel appended later can make a pinned release
        incoherent; `_check_release_history` refuses one inserted earlier, given the caller's
        persisted entries."""
        pins = [e for e in self.entries if e["type"] == "release-pin"]
        channel_of = {}
        for e in pins:
            channel = channel_of.setdefault(e["release_scope"], e["channel"])
            if channel != e["channel"]:
                raise RegistryError(
                    f"release_scope {e['release_scope']!r} has release pins in channels {channel!r} and "
                    f"{e['channel']!r}; a release family lives in exactly one channel (§13.5)"
                )
        for e in pins:
            named = e["predecessor"]
            if named is None:
                continue
            prior = self.release_pins.get(named)
            if prior is None:
                raise RegistryError(
                    f"release-pin {e['manifest_hash']}: predecessor {named} is not the manifest_hash of "
                    "any release-pin entry (§13.5)"
                )
            if prior["channel"] != e["channel"]:
                raise RegistryError(
                    f"release-pin {e['manifest_hash']} of channel {e['channel']!r}: predecessor {named} is a "
                    f"release-pin of channel {prior['channel']!r}; a release-pin follows a release-pin of "
                    "its own channel (§13.5)"
                )
        self.release_channels = linear_chains(
            pins, key=lambda e: e["channel"], ident=lambda e: e["manifest_hash"],
            link=lambda e: e["predecessor"], where="release-pin channel",
        )
        self.release_families = {}
        for channel, chain in self.release_channels.items():
            for prior, successor in zip(chain, chain[1:]):
                # The fixed §7.4 form orders bytewise, identically to chronological order.
                if successor["activated_utc"] < prior["activated_utc"]:
                    raise RegistryError(
                        f"release-pin channel {channel!r}: release-pin {successor['manifest_hash']} is "
                        f"activated before its predecessor {prior['manifest_hash']} (§13.5)"
                    )
            for e in chain:
                self.release_families.setdefault(e["release_scope"], []).append(e)
        first_release = {}
        for index, e in enumerate(self.entries):
            if e["type"] == "release-pin":
                first_release.setdefault(e["release_scope"], index)
            elif e["type"] == "grail-kernel" and e["release_scope"] in first_release:
                raise RegistryError(
                    f"entries[{index}]: the grail-kernel for release_scope {e['release_scope']!r} follows "
                    f"that family's first release-pin, entries[{first_release[e['release_scope']]}]; a "
                    "family's kernel is declared before its first release-pin (§13.5)"
                )

    def _check_release_history(self, persisted_entries):
        """§13.5 against what the caller accepted before: no grail-kernel joins a family after a
        release of that family was accepted.

        `check_retained` calls this once every persisted entry is known to be here byte for byte,
        so each is an entry of this registry. A grail-kernel that is not among them is new to the
        caller; when its family has a persisted release-pin, the kernel arrived after a release of
        the family was accepted — wherever it now sits in `entries`, which the in-document
        ordering rule alone cannot see. Pass every declared entry you accepted (§13.4): a kernel
        you accepted but did not pass back reads as new, and is refused."""
        known = {R.canonical(e) for e in persisted_entries}
        accepted = {}
        for e in persisted_entries:
            if e["type"] == "release-pin":
                accepted.setdefault(e["release_scope"], e["manifest_hash"])
        for index, e in enumerate(self.entries):
            if e["type"] != "grail-kernel" or e["release_scope"] not in accepted:
                continue
            if R.canonical(e) not in known:
                return False, (
                    f"entries[{index}]: a grail-kernel for release_scope {e['release_scope']!r} was added "
                    "after a release of that family was accepted (release-pin "
                    f"{accepted[e['release_scope']]}); a family's kernel is declared before its first "
                    "release-pin (§13.5)"
                )
        return True, "ok"

    def release_pin(self, manifest_hash):
        """The release-pin entry pinning `manifest_hash` — one exact pinned release — or None."""
        return self.release_pins.get(manifest_hash) if isinstance(manifest_hash, str) else None

    def scope_releases(self, release_scope):
        """The release pins of every release of the family `release_scope`, oldest first (chain
        order); [] when none."""
        releases = self.release_families.get(release_scope) if isinstance(release_scope, str) else None
        return list(releases or ())

    def scope_head(self, release_scope):
        """The release pin of the family's current release — its last in chain order — or None."""
        releases = self.scope_releases(release_scope)
        return releases[-1] if releases else None

    def channel_head(self, channel):
        """The release pin at the head of `channel` — the channel's current pinned release — or None."""
        chain = self.release_channels.get(channel) if isinstance(channel, str) else None
        return chain[-1] if chain else None


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
    if not (isinstance(source, str) and _HTTPS.fullmatch(source)):
        raise RegistryError("canonical_source must be an absolute HTTPS URI (§13.1)")
    if not isinstance(doc[ENTRIES_MEMBER], list):
        raise RegistryError("entries must be a JSON array (§13.1)")
    sig = doc["sig"]
    if sig is not None and not (isinstance(sig, str) and sig):
        raise RegistryError("sig must be a detached JWS string or null (§13.1)")
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
    declared entries the caller accepted before — all of them; each must still be present byte
    for byte, and a `grail-kernel` that is not among them is refused when its family has a
    persisted `release-pin` (§13.5: no kernel joins a family after a release of it was accepted).
    Freshness, append provenance, and historical migration proofs remain caller
    responsibilities; a verified registry snapshot alone cannot establish them. A returned
    registry records its status in `registry.status` ("verified" or "draft"), which
    `verify_snapshot` checks; a Registry constructed directly has status None.
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


# ---------------------------------------------------------------------------------------
# §13.5 release pins, release manifests, and verified snapshots. A release scope names a release
# family; a `release-pin` entry pins one immutable release of the family — one manifest by particle
# hash, which names the release for people in `release`; the manifest pins every component file by
# raw SHA-256 and length at an immutable commit; a verified snapshot of one pinned release is
# exactly those files.
MANIFEST_SCHEMA = "rapp/1-release-manifest"
MANIFEST_MEMBERS = ("schema", "release_scope", "release", "components")
COMPONENT_MEMBERS = ("id", "kind", "rappid", "identity_path", "repository", "object_format",
                     "commit", "immutable_ref", "files")
FILE_MEMBERS = ("path", "sha256", "size_bytes")
_RELEASE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # 1-64 characters, ASCII only
_TAG_PREFIX = "refs/tags/"
_GITHUB_REPOSITORY = re.compile(
    r"https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/([A-Za-z0-9._-]{1,100})"
)


def _validate_component(component, where):
    if not isinstance(component, dict) or set(component) != set(COMPONENT_MEMBERS):
        raise RegistryError(f"{where}: a component has exactly the members {list(COMPONENT_MEMBERS)}")
    if not _lclabel(component["id"], 100):
        raise RegistryError(f"{where}: `id` must be an lclabel of 1-100 characters")
    if not _lclabel(component["kind"], 64):
        raise RegistryError(f"{where}: `kind` must be an lclabel of 1-64 characters")
    repository = component["repository"]
    if not (isinstance(repository, str) and _HTTPS.fullmatch(repository)):
        raise RegistryError(f"{where}: `repository` must be an absolute HTTPS URI")
    if component["object_format"] not in ("sha1", "sha256"):
        raise RegistryError(f"{where}: `object_format` must be sha1 or sha256")
    if not _object_id(component["object_format"], component["commit"]):
        raise RegistryError(f"{where}: `commit` must be lowercase hex of the object_format's length")
    ref = component["immutable_ref"]
    if ref is not None and not (isinstance(ref, str) and ref.startswith(_TAG_PREFIX) and ref != _TAG_PREFIX):
        raise RegistryError(f"{where}: `immutable_ref` must be null or a full refs/tags/<name>")
    files = component["files"]
    if not isinstance(files, list):
        raise RegistryError(f"{where}: `files` must be an array")
    paths, previous = [], None
    for position, item in enumerate(files):
        at = f"{where}.files[{position}]"
        if not isinstance(item, dict) or set(item) != set(FILE_MEMBERS):
            raise RegistryError(f"{at}: a file has exactly the members {list(FILE_MEMBERS)}")
        path = item["path"]
        if not R._path_valid(path):
            raise RegistryError(f"{at}: `path` violates the §9.1 path grammar")
        try:
            key = path.encode("utf-8")
        except UnicodeEncodeError:
            raise RegistryError(f"{at}: `path` is not encodable as UTF-8")
        if previous is not None and not previous < key:
            raise RegistryError(f"{at}: `files` must ascend by the UTF-8 bytes of path, without duplicates")
        previous = key
        if not (isinstance(item["sha256"], str) and _HEX64.fullmatch(item["sha256"])):
            raise RegistryError(f"{at}: `sha256` must be 64 lowercase hex")
        size = item["size_bytes"]
        if not (isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= 2**53 - 1):
            raise RegistryError(f"{at}: `size_bytes` must be a uint53")
        paths.append(path)
    if not R._path_set_valid(paths):
        raise RegistryError(
            f"{where}: two file paths are equal case-insensitively, or one names a directory above another"
        )
    rappid, identity_path = component["rappid"], component["identity_path"]
    if (rappid is None) != (identity_path is None):
        raise RegistryError(f"{where}: `rappid` and `identity_path` must both be null or both be set")
    if rappid is not None:
        if not R.rappid_valid(rappid):
            raise RegistryError(f"{where}: `rappid` is not a §6.1 rappid")
        if identity_path not in paths:
            raise RegistryError(f"{where}: `identity_path` must be one of the component's files")


def validate_release_manifest(manifest):
    """The §13.5 release manifest, structurally: refuse (RegistryError), never repair.

    Checks exact members, the `release` name grammar, `id`/`kind` grammar and order, object
    ids, tag refs, the §9.1 path grammar and collision rules, digests and sizes,
    door-of-record pairing, one binding per rappid, and the §4 size limit (the exact structure
    bounds depth far below 64). Returns the manifest. The `release` name is for people: no rule
    here or elsewhere selects or trusts a release by it. Rules that need the registry are
    `verify_release_manifest`'s; rules that need the pinned bytes are `verify_snapshot`'s."""
    if not isinstance(manifest, dict) or set(manifest) != set(MANIFEST_MEMBERS):
        raise RegistryError(f"a release manifest has exactly the members {list(MANIFEST_MEMBERS)} (§13.5)")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise RegistryError(f'release manifest schema must be "{MANIFEST_SCHEMA}"')
    scope = manifest["release_scope"]
    if not (isinstance(scope, str) and _HTTPS.fullmatch(scope)):
        raise RegistryError("release manifest `release_scope` must be an absolute HTTPS URI")
    name = manifest["release"]
    if not (isinstance(name, str) and _RELEASE_NAME.fullmatch(name)):
        raise RegistryError(
            "release manifest `release` must be 1-64 characters of [A-Za-z0-9._-] beginning with a "
            "letter or digit (§13.5)"
        )
    components = manifest["components"]
    if not isinstance(components, list) or not components:
        raise RegistryError("release manifest `components` must be a non-empty array")
    previous, bound = None, {}
    for index, component in enumerate(components):
        where = f"components[{index}]"
        _validate_component(component, where)
        if previous is not None and not previous < component["id"]:
            raise RegistryError(f"{where}: components must be sorted ascending by `id`, without duplicates")
        previous = component["id"]
        rappid = component["rappid"]
        if rappid is not None:
            if rappid in bound:
                raise RegistryError(f"{where}: rappid already bound by component {bound[rappid]!r} (§13.5)")
            bound[rappid] = component["id"]
    try:
        size = len(R.canonical(manifest).encode("utf-8"))
    except ValueError as why:
        raise RegistryError(f"release manifest is not a §4 value: {why}")
    if size > R.MAX_CANONICAL_BYTES:
        raise RegistryError("release manifest canonical form exceeds 1 MiB (§4)")
    return manifest


def check_kernel_coherence(registry, manifest):
    """§13.5 kernel coherence of `manifest` against `registry`. Returns (ok, why).

    With a `grail-kernel` entry for the manifest's release_scope — its family's one kernel —
    exactly one `kernel` component must carry that entry's repository, object_format, commit,
    and immutable_ref and pin its path with its sha256 and size_bytes; without one, no
    component may be a `kernel`. Members compare byte for byte. A manifest that fails
    `validate_release_manifest` is not coherent."""
    try:
        validate_release_manifest(manifest)
    except RegistryError as why:
        return False, str(why)
    grails = [g for g in registry.grail.values() if g["release_scope"] == manifest["release_scope"]]
    kernels = [c for c in manifest["components"] if c["kind"] == "kernel"]
    if not grails:
        if kernels:
            return False, "a kernel component needs a grail-kernel entry for this release_scope (§13.5)"
        return True, "ok"
    grail = grails[0]
    if len(kernels) != 1:
        return False, f"a declared grail-kernel needs exactly one kernel component, not {len(kernels)} (§13.5)"
    kernel = kernels[0]
    for member in ("repository", "object_format", "commit", "immutable_ref"):
        if kernel[member] != grail[member]:
            return False, f"kernel component `{member}` differs from the family's grail-kernel entry (§13.5)"
    pinned = [f for f in kernel["files"] if f["path"] == grail["path"]]
    if not pinned:
        return False, "kernel component does not pin the grail-kernel path (§13.5)"
    if pinned[0]["sha256"] != grail["sha256"] or pinned[0]["size_bytes"] != grail["size_bytes"]:
        return False, "kernel component pins the grail-kernel path with other bytes (kernel-drift, §13.5)"
    return True, "ok"


def _registry_release_pin(registry, pin):
    """`pin` as one of `registry`'s own release-pin entries, byte for byte, or RegistryError."""
    try:
        own = registry.release_pin(pin.get("manifest_hash")) if isinstance(pin, dict) else None
        same = own is not None and R.canonical(own) == R.canonical(pin)
    except (ValueError, RecursionError):
        same = False
    if not same:
        raise RegistryError("the release-pin is not an entry of this registry, byte for byte (§13.5)")
    return own


def verify_release_manifest(registry, pin, manifest_octets):
    """§13.5 snapshot step 2 for one pinned release: the exact manifest `pin` pins, or RegistryError.

    `pin` is one of `registry`'s release-pin entries (an exact copy from elsewhere is the same
    entry; any other value is refused). `manifest_octets` are whatever bytes a transport
    returned for the pin's locator; the transport is never trusted. They must be exactly
    canonical(manifest), hash to the pin's `manifest_hash`, name the pin's `release_scope`,
    pass `validate_release_manifest`, and be coherent with that family's grail-kernel entry.
    The registry's own verification is `verify_snapshot`'s step 1, not this function's."""
    entry = _registry_release_pin(registry, pin)
    if not isinstance(manifest_octets, bytes):
        raise RegistryError("release manifest octets must be bytes")
    try:
        manifest = R._strict_json(manifest_octets)
        exact = manifest_octets == R.canonical(manifest).encode("utf-8")
    except (ValueError, RecursionError) as why:
        raise RegistryError(f"release manifest is not a §4 value: {why}")
    if not exact:
        raise RegistryError(
            "release manifest octets must be exactly canonical(manifest): UTF-8, no byte-order mark, "
            "no insignificant whitespace, no trailing line terminator (§13.5)"
        )
    if R.H("rapp/1:particle", manifest) != entry["manifest_hash"]:
        raise RegistryError("release manifest does not hash to the release-pin's manifest_hash (§13.5)")
    if not isinstance(manifest, dict) or manifest.get("release_scope") != entry["release_scope"]:
        raise RegistryError("release manifest names a release_scope other than its release-pin's (§13.5)")
    validate_release_manifest(manifest)
    ok, why = check_kernel_coherence(registry, manifest)
    if not ok:
        raise RegistryError(why)
    return manifest


def github_raw_url(repository, commit, path):
    """The commit-pinned raw URL of one file of a GitHub repository (§13.5 step 3), or None.

    Only `https://github.com/<owner>/<repository>` with plain name segments, a full
    lowercase-hex commit, and a §9.1 path qualify; another host, a branch or tag name, a `.git`
    suffix, extra path, a query, or a fragment returns None rather than a guess. Each path
    segment is percent-encoded. The URL is transport only: what it returns is verified by
    the pinned length and SHA-256, never by where it came from."""
    match = _GITHUB_REPOSITORY.fullmatch(repository) if isinstance(repository, str) else None
    if match is None:
        return None
    owner, name = match.groups()
    if name in (".", "..") or name.lower().endswith(".git"):
        return None
    if not (isinstance(commit, str) and (_HEX40.fullmatch(commit) or _HEX64.fullmatch(commit))):
        return None
    if not R._path_valid(path):
        return None
    try:
        encoded = "/".join(urllib.parse.quote(segment, safe="") for segment in path.split("/"))
    except UnicodeEncodeError:
        return None
    return f"https://raw.githubusercontent.com/{owner}/{name}/{commit}/{encoded}"


def _fetch_pinned(fetch, locator, path, where):
    try:
        octets = fetch(locator["repository"], locator["object_format"], locator["commit"], path)
    except Exception as why:  # any transport failure refuses the whole snapshot, never a part
        raise RegistryError(f"{where}: fetch failed: {why}") from why
    if not isinstance(octets, bytes):
        raise RegistryError(f"{where}: fetch must return bytes")
    return octets


def _door_of_record_mismatch(component, octets):
    try:
        identity = R._strict_json(octets)
    except (ValueError, RecursionError) as why:
        return f"identity file is not a §4 value: {why}"
    if not isinstance(identity, dict):
        return "identity file must be a JSON object"
    if identity.get("rappid") != component["rappid"]:
        return "identity file rappid differs from the component's rappid"
    if "schema" in identity and identity["schema"] != "rapp/1":
        return 'identity file schema, when present, must be "rapp/1"'
    return None


def _select_release(registry, release_scope, channel, manifest_hash):
    """§13.5 step 1's selection: the one release-pin named by exactly one selector."""
    given = [value for value in (release_scope, channel, manifest_hash) if value is not None]
    if len(given) != 1:
        raise RegistryError(
            "select exactly one pinned release: release_scope= (a family's current release), channel= "
            "(a channel's head), or manifest_hash= (one exact pinned release) (§13.5 step 1)"
        )
    if release_scope is not None:
        pin, named = registry.scope_head(release_scope), f"release_scope {release_scope!r}"
    elif channel is not None:
        pin, named = registry.channel_head(channel), f"channel {channel!r}"
    else:
        pin, named = registry.release_pin(manifest_hash), f"manifest_hash {manifest_hash!r}"
    if pin is None:
        raise RegistryError(f"no release-pin entry for {named} (§13.5)")
    return pin


def verify_snapshot(registry, fetch, *, release_scope=None, channel=None, manifest_hash=None,
                    allow_draft=False):
    """The §13.5 verified snapshot of one pinned release: {(component_id, path): octets}.

    Select the pinned release with exactly one of `release_scope=` (that family's current
    release), `channel=` (that channel's head), or `manifest_hash=` (that exact pinned release,
    current or not: every declared entry is persisted, so a successor supersedes a pinned
    release without retiring it, and every pinned release stays verifiable). A manifest's
    `release` name never selects. `registry` must be one `load_document` returned as
    "verified"; a "draft" is accepted only with `allow_draft=True`, for rehearsal, and a
    Registry built directly (status None) never.
    `fetch(repository, object_format, commit, path) -> bytes` is any transport (git, a mirror,
    `github_raw_url`) and is never trusted: it is called once for the release-pin's manifest
    locator and once per pinned file, and every returned byte is checked against the manifest.
    Refusal is whole: any failure raises RegistryError and returns nothing. What only git can
    prove — that an `immutable_ref` resolves to its `commit`, or the commit of a component
    whose `files` is empty — is left to a git-capable verifier."""
    accepted = ("verified", "draft") if allow_draft else ("verified",)
    status = getattr(registry, "status", None)
    if status not in accepted:
        raise RegistryError(
            f"registry status is {status!r}; a verified snapshot needs a registry that "
            f"load_document returned as {' or '.join(accepted)} (§13.5 step 1)"
        )
    entry = _select_release(registry, release_scope, channel, manifest_hash)
    manifest = verify_release_manifest(
        registry, entry, _fetch_pinned(fetch, entry, entry["path"], "release manifest")
    )
    snapshot = {}
    for component in manifest["components"]:
        for item in component["files"]:
            where = f"component {component['id']!r} file {item['path']!r}"
            octets = _fetch_pinned(fetch, component, item["path"], where)
            if len(octets) != item["size_bytes"]:
                raise RegistryError(f"{where}: {len(octets)} bytes, {item['size_bytes']} pinned (§13.5)")
            if hashlib.sha256(octets).hexdigest() != item["sha256"]:
                raise RegistryError(f"{where}: SHA-256 differs from the pinned digest (§13.5)")
            snapshot[(component["id"], item["path"])] = octets
    for component in manifest["components"]:
        if component["rappid"] is not None:
            why = _door_of_record_mismatch(component, snapshot[(component["id"], component["identity_path"])])
            if why:
                raise RegistryError(f"component {component['id']!r} door of record: {why} (§13.5)")
    return snapshot
