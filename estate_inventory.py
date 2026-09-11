"""Read-only, bounded inventory of a rapp-full-genome-index/1 capture.

    python3 estate_inventory.py --capture MATERIALIZED --scope SOURCE_SCOPE \
        --output NEW_REPORT.json --report-only

No captured code is imported, executed, installed, extracted, or rewritten.
Only the adjacent canonical rapp.py is used. A successful inventory is NOT an
ecosystem compatibility certificate. Exit 0 means an explicitly requested
--report-only collection completed; the default exits 1 even if every observed
artifact passes. Exit 2 means invalid capture bindings or an operational error.

The JSON report contains owner repository and dependency matrices, a deduplicated
blob ledger, artifact observations, bounded static evidence, and separate
container-local stream checks. Raw Git path bytes, not display strings, identify
entries. File/line references and location hints never confer authority, excuse a
refusal, or authorize migration. Frozen commits are not current live HEADs.
Numeric lexemes survive discovery; original JSON record octets must pass the
adjacent canonical strict parser before frame verification.
"""

import argparse
import ast
import base64
import collections
import contextlib
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import warnings
import zipfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import rapp as R


SCHEMA = "rapp-captured-estate-inventory/1"
ADAPTER = "materialized-rapp-full-genome-index/1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
REPO_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
MARKER = re.compile(
    r"(?i)(?<![a-z0-9])rapp(?:id\b|/[0-9]|-1\b|-frame\b|-protocol\b|\b)"
)
LABEL = re.compile(
    r"(?i)(?<![\w-])(?:rapp/[0-9]+(?:[.][0-9]+)*(?:-egg)?"
    r"|rapp-(?:frame|protocol|rappid-spec|rappid|egg)/[0-9]+(?:[.][0-9]+)*"
    r"|rev-[0-9]+)(?![\w.-])"
)
PIN = re.compile(
    r"https://(?:raw\.githubusercontent\.com|github\.com)/kody-w/rapp-1/"
    r"(?:blob/|tree/)?[^\s\"'<>`)\\]+"
)
PRODUCERS = {"build_frame", "pack_egg", "mint_rappid", "emit_frame", "write_frame",
             "append_frame"}
READERS = {"verify_frame", "verify_egg", "read_egg", "rappid_valid", "validate_frame"}
SOURCE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs",
                   ".go", ".sh", ".ps1", ".html"}
FRAME_DIR_NAME = re.compile(r"(?:[0-9]+|[0-9a-f]{64})[.]json\Z")
LOCATION_WORDS = {
    "fixture": {"fixture", "fixtures", "test", "tests", "conformance", "testdata"},
    "example": {"example", "examples", "tutorial", "tutorials", "sample", "samples"},
    "historical": {"archive", "archived", "archives", "legacy", "history", "attic"},
    "vendored_or_snapshot": {"vendor", "vendored", "repos", "snapshots", "snapshot"},
    "documentation": {"docs", "book", "guide", "guides"},
    "template": {"template", "templates", "seed", "seeds"},
}


class CaptureError(ValueError):
    """Capture binding or input safety failure; never a compatibility finding."""


class BoundExceeded(ValueError):
    """A declared measurement bound, rather than evidence of invalid content."""


@dataclass(frozen=True)
class JsonNumber:
    """A discovery token, never a binary-float or canonical-domain assertion."""

    lexeme: str


@dataclass(frozen=True)
class Limits:
    max_metadata_bytes: int = 128 * 1024 * 1024
    max_metadata_nodes: int = 2000000
    max_blob_bytes: int = 8 * 1024 * 1024
    max_hash_blob_bytes: int = 2 * 1024 * 1024 * 1024
    max_total_hash_bytes: int = 16 * 1024 * 1024 * 1024
    max_json_depth: int = 96
    max_json_nodes: int = 200000
    max_records_per_blob: int = 10000
    max_evidence_per_blob: int = 80
    max_python_ast_bytes: int = 512 * 1024
    max_chain_cache_bytes: int = 64 * 1024 * 1024
    max_zip_members: int = 10000


@contextlib.contextmanager
def safe_directory(path):
    """Walk each directory component with openat/O_NOFOLLOW, including root."""
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise CaptureError("this platform lacks the required no-follow directory API")
    path = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = None
    try:
        fd = os.open(path.anchor, flags)
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError as exc:
        raise CaptureError("unsafe or unreadable directory %s: %s" % (path, exc)) from exc
    finally:
        if fd is not None:
            os.close(fd)


@contextlib.contextmanager
def safe_file(path):
    path = Path(os.path.abspath(os.fspath(path)))
    with safe_directory(path.parent) as parent:
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise CaptureError("not a regular file: %s" % path)
            with os.fdopen(fd, "rb") as stream:
                fd = None
                yield stream
        except OSError as exc:
            raise CaptureError("unsafe or unreadable file %s: %s" % (path, exc)) from exc
        finally:
            if fd is not None:
                os.close(fd)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member: %s" % key)
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError("non-finite JSON number: %s" % value)


def discovery_decoder():
    return json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_nonfinite,
                            parse_int=JsonNumber, parse_float=JsonNumber)


def strict_json(body, limits, preserve_numbers=True):
    """Bounded discovery JSON; only capture metadata opts out of numeric tokens."""
    # Check nesting before json.loads, which otherwise reaches Python's recursion
    # limit before an iterative, post-parse budget check could run.
    depth = 0
    quoted = escaped = False
    for byte in body:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > limits.max_json_depth:
                raise BoundExceeded("max_json_depth")
        elif byte in (93, 125):
            depth -= 1
    text = body.decode("utf-8")
    if preserve_numbers:
        value = discovery_decoder().decode(text)
    else:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    stack = [value]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > limits.max_json_nodes:
            raise BoundExceeded("max_json_nodes")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("non-finite JSON number")
    return value


def array_record_octets(body, max_records):
    """Extract original value spans using stdlib JSON decoding, not reserialization.

    The caller has already checked the complete array's syntax and resource
    bounds. UTF-8 decode/encode preserves its original octets, including number
    spellings, escapes, nested values, and whitespace inside each record.
    """
    text = body.decode("utf-8")
    decoder = discovery_decoder()
    cursor = len(text) - len(text.lstrip(" \t\r\n"))
    if text[cursor:cursor + 1] != "[":
        raise ValueError("array record extraction requires an array")
    cursor += 1
    for _ in range(max_records):
        while text[cursor:cursor + 1] in (" ", "\t", "\r", "\n"):
            cursor += 1
        if text[cursor:cursor + 1] == "]":
            return
        row, end = decoder.raw_decode(text, cursor)
        yield row, text[cursor:end].encode("utf-8")
        cursor = end
        while text[cursor:cursor + 1] in (" ", "\t", "\r", "\n"):
            cursor += 1
        if text[cursor:cursor + 1] == "]":
            return
        if text[cursor:cursor + 1] != ",":
            raise ValueError("array record separator missing")
        cursor += 1


def read_metadata(path, limits, hashes):
    try:
        with safe_file(path) as stream:
            if os.fstat(stream.fileno()).st_size > limits.max_metadata_bytes:
                raise CaptureError("metadata exceeds max_metadata_bytes: %s" % path)
            body = stream.read(limits.max_metadata_bytes + 1)
        if len(body) > limits.max_metadata_bytes:
            raise CaptureError("metadata exceeds max_metadata_bytes: %s" % path)
        value = strict_json(body, replace(limits, max_json_nodes=limits.max_metadata_nodes),
                            preserve_numbers=False)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CaptureError("invalid metadata %s: %s" % (path, exc)) from exc
    hashes[str(path)] = {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
    return value


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def raw_path(entry):
    encoded = entry.get("path_bytes_base64")
    require(isinstance(encoded, str), "entry missing path_bytes_base64")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise CaptureError("invalid raw path base64") from exc
    require(base64.b64encode(raw).decode("ascii") == encoded, "noncanonical path base64")
    require(raw and b"\0" not in raw and not raw.startswith(b"/")
            and all(part not in (b"", b".", b"..") for part in raw.split(b"/")),
            "unsafe raw Git path: %r" % raw)
    require(entry.get("path") == raw.decode("utf-8", "surrogateescape"),
            "path display/raw-byte binding mismatch")
    return raw


def path_fields(entry):
    raw = raw_path(entry)
    try:
        utf8 = raw.decode("utf-8")
    except UnicodeError:
        utf8 = None
    return {
        "path_bytes_base64": entry["path_bytes_base64"],
        "path_utf8": utf8,
        "path_display": raw.decode("utf-8", "backslashreplace"),
        "mode": entry["mode"],
        "git_object": entry["git_object"],
    }


def validate_entries(entries, label):
    require(isinstance(entries, list), "%s entries is not an array" % label)
    paths = set()
    for entry in entries:
        require(isinstance(entry, dict), "%s entry is not an object" % label)
        raw = raw_path(entry)
        require(raw not in paths, "%s duplicate raw path: %r" % (label, raw))
        paths.add(raw)
        require((entry.get("mode"), entry.get("type")) in {
            ("100644", "blob"), ("100755", "blob"), ("120000", "blob"),
            ("160000", "commit")}, "%s invalid Git mode/type binding" % label)
        require(isinstance(entry.get("git_object"), str)
                and HEX40.fullmatch(entry["git_object"]),
                "%s invalid SHA-1 Git object id" % label)
    for raw in paths:
        parts = raw.split(b"/")
        require(not any(b"/".join(parts[:n]) in paths for n in range(1, len(parts))),
                "%s file/directory path conflict: %r" % (label, raw))


def entry_binding_digest(entries):
    digest = hashlib.sha256()
    for entry in sorted(entries, key=raw_path):
        raw = raw_path(entry)
        digest.update(entry["mode"].encode("ascii") + b" " + entry["type"].encode("ascii")
                      + b" " + entry["git_object"].encode("ascii") + b" "
                      + str(len(raw)).encode("ascii") + b":" + raw + b"\0")
    return digest.hexdigest()


def load_capture(capture, scope_path, limits):
    capture = Path(os.path.abspath(os.fspath(capture)))
    scope_path = Path(os.path.abspath(os.fspath(scope_path)))
    hashes = {}
    scope = read_metadata(scope_path, limits, hashes)
    index = read_metadata(capture / "genome-index.json", limits, hashes)
    inner_scope = read_metadata(capture / "genome/source-scope.json", limits, hashes)
    genome = read_metadata(capture / "genome/genome.json", limits, hashes)
    dependencies = read_metadata(capture / "dependency-index.json", limits, hashes)
    for document, schema in [
        (scope, "rapp-public-source-scope/1"),
        (index, "rapp-full-genome-index/1"),
        (genome, "rapp-full-public-genome/1"),
        (dependencies, "rapp-public-gitlink-bodies/1"),
    ]:
        require(isinstance(document, dict) and document.get("schema") == schema,
                "unsupported capture schema: expected %s" % schema)
    require(scope == inner_scope == index.get("source_scope"),
            "external, indexed, and materialized source scopes differ")
    owner = scope.get("owner")
    require(isinstance(owner, str) and REPO_NAME.fullmatch(owner), "invalid scope owner")
    rows = scope.get("repositories")
    require(isinstance(rows, list), "scope repositories is not an array")
    by_id, by_name = {}, {}
    for row in rows:
        require(isinstance(row, dict), "scope repository is not an object")
        rid, name = row.get("repository_id"), row.get("name")
        require(is_count(rid) and rid > 0 and rid not in by_id,
                "duplicate or invalid repository_id in scope")
        require(isinstance(name, str) and REPO_NAME.fullmatch(name)
                and name.casefold() not in by_name, "duplicate or invalid repository name")
        require(row.get("public_url") == "https://github.com/%s/%s" % (owner, name),
                "scope repository/public URL mismatch")
        require(isinstance(row.get("fork"), bool) and isinstance(row.get("archived"), bool),
                "scope fork/archived flags must be explicit booleans")
        commit = row.get("captured_commit")
        require(commit is None or isinstance(commit, str) and HEX40.fullmatch(commit),
                "invalid captured commit")
        branch = row.get("captured_default_branch")
        require(branch is None if commit is None else isinstance(branch, str) and bool(branch),
                "invalid captured default branch")
        by_id[rid], by_name[name.casefold()] = row, row
    require(is_count(scope.get("public_repositories"))
            and scope["public_repositories"] == len(rows), "scope repository count mismatch")
    repos = index.get("repositories")
    require(isinstance(repos, list), "index repositories is not an array")
    seen = set()
    owner_blobs = set()
    links = []
    entries_count = empty_count = 0
    for repo in repos:
        require(isinstance(repo, dict), "repository index row is not an object")
        rid = repo.get("repository_id")
        require(is_count(rid) and rid in by_id and rid not in seen,
                "extra, duplicate, or unknown indexed repository")
        seen.add(rid)
        scoped = by_id[rid]
        require(repo.get("schema") == "rapp-source-genome-repository/1",
                "unsupported repository metadata schema")
        for indexed_key, scope_key in [
            ("repo", "name"), ("public_url", "public_url"),
            ("source_snapshot_commit", "captured_commit"),
            ("default_branch", "captured_default_branch"),
            ("rapp_metadata_match", "rapp_metadata_match"),
            ("license_detection", "license_detection"),
        ]:
            require(indexed_key in repo and scope_key in scoped
                    and repo[indexed_key] == scoped[scope_key],
                    "%s scope/%s binding mismatch" % (scoped["name"], indexed_key))
        validate_entries(repo.get("entries"), repo["repo"])
        require(isinstance(repo.get("empty"), bool), "missing empty-repository flag")
        require(not repo["empty"] or not repo["entries"], "empty repository has entries")
        require((repo["source_snapshot_commit"] is None) == repo["empty"],
                "empty repository/commit mismatch")
        require(repo.get("lfs_objects") == [],
                "this adapter has no LFS-body validator; nonempty LFS inventory unsupported")
        materialized = read_metadata(capture / ("genome/repositories/%s.json" % rid),
                                     limits, hashes)
        require(materialized == repo, "%s repository metadata/index mismatch" % repo["repo"])
        entries_count += len(repo["entries"])
        empty_count += int(repo["empty"])
        for entry in repo["entries"]:
            if entry["type"] == "blob":
                owner_blobs.add(entry["git_object"])
            else:
                links.append({"repository_id": rid, "repo": repo["repo"],
                              "path": entry["path"], "commit": entry["git_object"]})
    require(seen == set(by_id), "missing indexed repository from scope")
    expected_metadata_names = {"%s.json" % rid for rid in seen}
    with safe_directory(capture / "genome/repositories") as directory:
        require(set(os.listdir(directory)) == expected_metadata_names,
                "extra or missing per-repository metadata files")
    expected_counts = {"repositories": len(repos), "tracked_entries": entries_count,
                       "unique_blobs": len(owner_blobs), "lfs_objects": 0,
                       "packed_files": len(owner_blobs) + len(repos) + 2}
    counts = index.get("counts")
    require(isinstance(counts, dict), "missing index counts")
    for key, count in expected_counts.items():
        require(is_count(counts.get(key)) and counts[key] == count,
                "index %s count mismatch" % key)
    for key, count in [("repositories", len(repos)), ("tracked_entries", entries_count),
                       ("unique_current_state_blobs", len(owner_blobs)),
                       ("empty_repositories", empty_count)]:
        require(is_count(genome.get(key)) and genome[key] == count,
                "genome %s count mismatch" % key)
    link_key = lambda item: (item["repository_id"], item["path"], item["commit"])
    try:
        require(sorted(links, key=link_key) == sorted(index.get("gitlinks", []), key=link_key)
                == sorted(genome.get("gitlinks", []), key=link_key),
                "Gitlink entry/index/genome binding mismatch")
    except (KeyError, TypeError) as exc:
        raise CaptureError("invalid Gitlink metadata") from exc
    dep_rows, dep_links = dependencies.get("dependencies"), dependencies.get("links")
    require(isinstance(dep_rows, list) and isinstance(dep_links, list),
            "invalid dependency index")
    dep_map, dep_blobs = {}, set()
    for dep in dep_rows:
        require(isinstance(dep, dict), "invalid dependency row")
        commit, url = dep.get("commit"), dep.get("source_url")
        require(isinstance(commit, str) and HEX40.fullmatch(commit)
                and isinstance(url, str) and url.startswith("https://github.com/"),
                "invalid dependency commit/source URL")
        key = (commit, url)
        require(key not in dep_map, "duplicate dependency body")
        validate_entries(dep.get("entries"), "dependency %s" % commit)
        dep_map[key] = dep
        dep_blobs.update(e["git_object"] for e in dep["entries"] if e["type"] == "blob")
    link_set = {(link["repo"], link["path"], link["commit"]) for link in links}
    seen_links, used_dependencies = set(), set()
    unavailable = 0
    for link in dep_links:
        require(isinstance(link, dict), "invalid dependency link")
        key = (link.get("parent_repo"), link.get("path"), link.get("commit"))
        require(key in link_set and key not in seen_links,
                "extra, duplicate, or mismatched dependency link")
        seen_links.add(key)
        status = link.get("status")
        if status == "hydrated":
            dep_key = (link["commit"], link.get("url"))
            require(dep_key in dep_map, "hydrated Gitlink has no bound dependency body")
            used_dependencies.add(dep_key)
        else:
            require(status == "pre-existing-unavailable",
                    "unsupported dependency availability status")
            require((link["commit"], link.get("url")) not in dep_map,
                    "unavailable Gitlink unexpectedly has a supplied body")
            unavailable += 1
    require(seen_links == link_set, "missing dependency link coverage")
    require(used_dependencies == set(dep_map), "unbound dependency body")
    require(is_count(dependencies.get("unavailable_count"))
            and dependencies["unavailable_count"] == unavailable,
            "dependency unavailable count mismatch")
    require(is_count(dependencies.get("extra_blob_count"))
            and dependencies["extra_blob_count"] == len(dep_blobs - owner_blobs),
            "dependency extra blob count mismatch")
    return {
        "root": capture, "scope": scope, "index": index, "genome": genome,
        "repositories": sorted(repos, key=lambda row: row["repository_id"]),
        "dependencies": sorted(dep_rows, key=lambda row: (row["source_url"], row["commit"])),
        "dependency_links": dep_links, "scope_by_id": by_id,
        "owner_blobs": owner_blobs, "all_blobs": owner_blobs | dep_blobs,
        "metadata_hashes": hashes, "expected_counts": expected_counts,
    }


def canonical_authority(limits):
    root = Path(__file__).absolute().parent
    hashes = {}
    orient = read_metadata(root / "anchor/orient.json", limits, hashes)
    with safe_file(root / "SPEC.md") as stream:
        spec = stream.read(limits.max_metadata_bytes + 1)
    require(len(spec) <= limits.max_metadata_bytes, "local SPEC.md exceeds metadata bound")
    spec_hash = hashlib.sha256(spec).hexdigest()
    require(spec_hash == orient["spec"]["normative_sha256"]
            and len(spec) == orient["spec"]["normative_bytes"],
            "local SPEC.md does not match selected anchor/orient.json")
    result = {
        "revision": orient["spec"]["revision"], "spec_sha256": spec_hash,
        "spec_bytes": len(spec), "anchor_head": orient["head"],
        "anchor_selected_commit": orient["spec"].get("commit"),
        "authority_selection": "local anchor/orient.json; no live HEAD resolution",
        "api": ["rapp._strict_json", "rapp.verify_frame", "rapp.rappid_valid", "rapp.verify_egg"],
    }
    for name in ("rapp.py", "estate_inventory.py"):
        with safe_file(root / name) as stream:
            body = stream.read(limits.max_metadata_bytes + 1)
        require(len(body) <= limits.max_metadata_bytes, "local validator exceeds bound")
        result[name.replace(".", "_") + "_sha256"] = hashlib.sha256(body).hexdigest()
    return result


def location_hints(path):
    words = set(re.split(r"[/_.-]+", path.lower()))
    result = [label for label, matches in LOCATION_WORDS.items() if words & matches]
    if path.lower().endswith((".md", ".rst", ".txt")):
        result.append("text_document")
    return sorted(set(result))


def artifact_hint(path):
    name = path.rsplit("/", 1)[-1].lower()
    if name == "rappid.json":
        return "identity"
    if name.endswith(".egg"):
        return "egg"
    parts = path.lower().split("/")
    if len(parts) > 1 and parts[-2] == "frames" and name.endswith(".json"):
        return "frame"
    return None


def short(value, maximum=220):
    value = str(value)
    return value if len(value) <= maximum else value[:maximum] + "..."


def observed_value(value):
    """JSON-safe diagnostic projection; never an input to protocol verification."""
    if isinstance(value, JsonNumber):
        if len(value.lexeme) <= 64 and re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value.lexeme):
            return int(value.lexeme)
        return {"json_number_lexeme": short(value.lexeme)}
    if isinstance(value, dict):
        return {key: observed_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [observed_value(item) for item in value]
    return value


def note_nested_boundary(analysis, value):
    nested = isinstance(value, list) or (
        isinstance(value, dict) and any(isinstance(item, (dict, list)) for item in value.values()))
    if nested:
        boundary = ("nested record containers are unmeasured; their original numeric domains "
                    "are not promoted to accepted standalone frames")
        if boundary not in analysis["boundaries"]:
            analysis["boundaries"].append(boundary)


def _evidence(text, limits, python_source):
    result = {"rapp_marker_occurrences": 0, "references": [], "static_roles": [],
              "reference_records_omitted": 0, "static_role_records_omitted": 0}
    result["rapp_marker_occurrences"] = sum(1 for _ in MARKER.finditer(text))
    if not result["rapp_marker_occurrences"]:
        return result
    references = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for pattern, kind in [(LABEL, "version_label_mention"), (PIN, "authority_url_mention")]:
            for match in pattern.finditer(line):
                if len(references) < limits.max_evidence_per_blob:
                    references.append({"line": line_no, "kind": kind,
                                       "value": short(match.group(0)),
                                       "context": short(line.strip())})
                else:
                    result["reference_records_omitted"] += 1
    result["references"] = references
    if not python_source:
        result["source_analysis"] = "not_python_ast; text references are not executable evidence"
        return result
    if len(text.encode("utf-8")) > limits.max_python_ast_bytes:
        result["source_analysis"] = "python_ast_unmeasured: max_python_ast_bytes"
        return result
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        result["source_analysis"] = "python_ast_unmeasured: %s" % type(exc).__name__
        return result
    roles = []
    for node in ast.walk(tree):
        role, name, form = None, None, None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name, form = node.name, "definition_name"
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            form = "call_name"
        elif isinstance(node, ast.Import):
            if any(alias.name == "rapp" for alias in node.names):
                name, form, role = "rapp", "import", "canonical_module_name"
        elif isinstance(node, ast.ImportFrom) and node.module == "rapp":
            name, form, role = "rapp", "import_from", "canonical_module_name"
        if name in PRODUCERS:
            role = "producer_name_hint"
        elif name in READERS:
            role = "reader_name_hint"
        if role:
            if len(roles) < limits.max_evidence_per_blob:
                roles.append({"line": node.lineno, "name": name, "form": form, "role": role})
            else:
                result["static_role_records_omitted"] += 1
    result["static_roles"] = sorted(roles, key=lambda item: (item["line"], item["name"]))
    result["source_analysis"] = "python_ast_names_only; reachability and behavior unmeasured"
    return result


def candidate_kind(value):
    if not isinstance(value, dict):
        return None
    schema = value.get("schema")
    if isinstance(schema, str) and (
        schema.startswith("rapp/") and "-egg" in schema or schema.startswith("rapp-egg/")
    ):
        return "egg"
    if (value.get("spec") == "rapp/1" and (
            {"seq", "payload"} <= set(value)
            or set(value) & {"payload_hash", "frame_hash", "prev", "prev_wave"}
            and set(value) & {"payload", "seq"})
        or isinstance(schema, str) and schema.startswith("rapp-frame/")
        or {"frame_hash", "payload"} <= set(value)
        or {"seq", "payload"} <= set(value) and set(value) & {"sha256", "hash", "payload_hash"}):
        return "frame"
    if ("rappid" in value and (schema == "rapp/1"
                              or isinstance(schema, str) and "rappid" in schema.lower())):
        return "identity"
    return None


def protocol_declaration(value, kind):
    """A field declaration, not the presence of 'RAPP' in an arbitrary payload."""
    if not isinstance(value, dict):
        return {"classification": "filename_only_or_unidentified",
                "original_protocol_validity": "not_determined"}
    for field in ("spec", "schema"):
        label = value.get(field)
        if not isinstance(label, str):
            continue
        if label in ("rapp/1", "rapp/1-egg"):
            return {"classification": "declared_rapp1", "field": field, "value": label,
                    "original_protocol_validity": "see bounded canonical API outcome"}
        if label.startswith(("rapp-frame/", "rapp-protocol/", "rapp-rappid-spec/",
                             "rapp-rappid/", "rapp-egg/")):
            return {"classification": "declared_legacy_rapp", "field": field, "value": short(label),
                    "original_protocol_validity": "not_determined; no legacy validator run"}
        if label.lower().startswith(("rapp/", "rapp-")):
            return {"classification": "other_rapp_namespace", "field": field, "value": short(label),
                    "original_protocol_validity": "not_determined; may be a distinct protocol"}
    if kind == "identity" and isinstance(value.get("rappid"), str) and value["rappid"].startswith("rappid:"):
        return {"classification": "rappid_field_only",
                "original_protocol_validity": "grammar measured, provenance not determined"}
    return {"classification": "unclaimed_or_other_protocol",
            "original_protocol_validity": "not_determined; filename/shape is not a RAPP declaration"}


def root_declarations(value):
    if not isinstance(value, dict):
        return []
    keys = {"schema", "spec", "spec_revision", "rapp_revision", "revision", "spec_sha256",
            "normative_sha256", "canonical_repo", "canonical_repository", "spec_url"}
    declarations = []
    for key, item in value.items():
        if key.lower() in keys and isinstance(item, (str, int, JsonNumber)) and not isinstance(item, bool):
            declarations.append({"field": key,
                                 "value": short(item.lexeme if isinstance(item, JsonNumber) else item),
                                 "meaning": "document field observed; authority not established"})
    spec = value.get("spec")
    if isinstance(spec, dict):
        for key in ("revision", "normative_sha256", "canonical_repo", "commit"):
            if isinstance(spec.get(key), str):
                declarations.append({"field": "spec." + key, "value": short(spec[key]),
                                     "meaning": "document field observed; authority not established"})
    return declarations


def outcome(ok, step, reason, api, missing_head=False):
    status = "accepted" if ok else "refused"
    missing = []
    if not ok and ("trusted signature verifier is required" in reason
                   or "invite verification requires estate_owner_rappid" in reason):
        status = "unverified_trust"
        missing = ["trusted_signature_verifier"]
        if "estate_owner_rappid" in reason:
            missing.append("estate_owner_rappid")
    elif not ok and step == "4" and missing_head:
        status = "unverified_history"
        missing = ["predecessor_or_genesis"]
    return {"status": status, "api": api, "canonical_called": True, "ok": bool(ok),
            "verifier_source_ref": "canonical.rapp_py_sha256",
            "step": step, "reason": short(reason), "missing_requirements": missing}


def _verify_frame_input(body, head=None, stream=None):
    if not isinstance(body, bytes):
        return ({
            "status": "unmeasured_original_domain", "api": None, "canonical_called": False,
            "frame_api_called": False, "reason": "original JSON record octets unavailable",
            "missing_requirements": ["original_json_record_octets"],
        }, None)
    domain = {
        "api": "rapp._strict_json", "input": "original_json_record_octets",
        "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
        "verifier_source_ref": "canonical.rapp_py_sha256",
    }
    try:
        value = R._strict_json(body)
    except ValueError as exc:
        domain["status"] = "refused"
        return ({
            "status": "refused", "api": "rapp._strict_json", "canonical_called": True,
            "frame_api_called": False, "exception": type(exc).__name__, "reason": short(exc),
            "original_domain": domain, "verifier_source_ref": "canonical.rapp_py_sha256",
            "missing_requirements": [],
        }, None)
    except (RuntimeError, OverflowError) as exc:
        domain["status"] = "unverified_validator_exception"
        return ({
            "status": "unverified_validator_exception", "api": "rapp._strict_json",
            "canonical_called": True, "frame_api_called": False,
            "exception": type(exc).__name__, "reason": short(exc), "original_domain": domain,
            "verifier_source_ref": "canonical.rapp_py_sha256",
            "missing_requirements": ["successful_original_domain_validation"],
        }, None)
    domain["status"] = "accepted"
    if not isinstance(value, dict):
        return ({
            "status": "refused", "api": "strict_json_shape", "canonical_called": True,
            "frame_api_called": False, "original_domain": domain,
            "reason": "candidate frame is not a JSON object", "missing_requirements": [],
        }, None)
    try:
        ok, step, reason = R.verify_frame(value, head=head, stream_id_of_record=stream)
        result = outcome(ok, step, reason, "rapp.verify_frame",
                         missing_head=head is None and isinstance(value.get("seq"), int)
                         and not isinstance(value["seq"], bool) and value["seq"] > 0)
    except (ValueError, RuntimeError, OverflowError) as exc:
        result = {"status": "unverified_validator_exception", "api": "rapp.verify_frame",
                  "canonical_called": True, "exception": type(exc).__name__,
                  "reason": short(exc), "missing_requirements": ["completed_canonical_frame_check"],
                  "verifier_source_ref": "canonical.rapp_py_sha256"}
    result["frame_api_called"] = True
    result["original_domain"] = domain
    return result, value


def verify_frame(body, head=None, stream=None):
    """Validate original JSON octets; a normalized dictionary is not raw evidence."""
    return _verify_frame_input(body, head, stream)[0]


def verify_identity(value):
    if not isinstance(value, dict):
        return {"status": "refused", "api": "strict_json_shape", "canonical_called": False,
                "reason": "candidate identity is not a JSON object", "missing_requirements": []}
    fields = ["rappid"] + (["parent_rappid"] if value.get("parent_rappid") is not None else [])
    checks = {field: R.rappid_valid(value.get(field)) for field in fields}
    return {
        "status": "accepted_grammar_only" if all(checks.values()) else "refused",
        "api": "rapp.rappid_valid", "canonical_called": True, "field_checks": checks,
        "declared_schema": observed_value(value.get("schema")),
        "rappid": short(value.get("rappid")),
        "reason": "grammar only; schema labels do not establish identity provenance",
        "missing_requirements": ["minting_provenance", "identity_ownership_and_trust"],
        "verifier_source_ref": "canonical.rapp_py_sha256",
    }


def egg_preflight(body, limits):
    if not body.startswith(b"PK"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_zip_members:
                raise BoundExceeded("max_zip_members")
            if sum(info.file_size for info in infos) > limits.max_blob_bytes:
                raise BoundExceeded("max_blob_bytes (expanded ZIP)")
    except zipfile.BadZipFile:
        pass  # The canonical API supplies the actual parse refusal.
    return None


def zip_manifest(body, limits):
    """Bounded classification only; never substitutes for canonical ZIP checks."""
    try:
        egg_preflight(body, limits)
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = [info for info in archive.infolist() if info.filename == "manifest.json"]
            if len(infos) != 1 or infos[0].file_size > R.MAX_CANONICAL_BYTES:
                return None
            # ZIP_STORED/DEFLATED reads are bounded by the preflight size budget.
            # No member is materialized in a filesystem.
            return strict_json(archive.read(infos[0]), limits, preserve_numbers=True)
    except (ValueError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
        return None


def verify_egg(body, limits):
    try:
        egg_preflight(body, limits)
    except BoundExceeded as exc:
        return {"status": "unmeasured_bound", "api": None, "canonical_called": False,
                "reason": str(exc), "missing_requirements": ["bounded_egg_container"]}
    try:
        ok, step, why = R.verify_egg(body)
        return outcome(ok, step, why, "rapp.verify_egg")
    except (ValueError, RuntimeError, OverflowError) as exc:
        return {"status": "unverified_validator_exception", "api": "rapp.verify_egg",
                "canonical_called": True, "exception": type(exc).__name__,
                "reason": short(exc), "missing_requirements": ["completed_canonical_egg_check"],
                "verifier_source_ref": "canonical.rapp_py_sha256"}


class Inventory:
    def __init__(self, captured, limits=Limits(), progress=None):
        self.capture, self.limits, self.progress = captured, limits, progress
        self.blobs = {}
        self.analyses = {}
        self.frame_inputs = {}
        self.frame_cache_bytes = 0
        self.chain_cache = {}
        self.hash_bytes = 0
        self.errors = []
        self.references = collections.defaultdict(list)
        self.units = []
        for repo in captured["repositories"]:
            scoped = captured["scope_by_id"][repo["repository_id"]]
            self.units.append({
                "unit_id": "repository:%s" % repo["repository_id"], "kind": "owner_repository",
                "repository_id": repo["repository_id"], "repository": repo["repo"],
                "public_url": repo["public_url"], "captured_commit": repo["source_snapshot_commit"],
                "captured_default_branch": repo["default_branch"], "fork": scoped["fork"],
                "archived": scoped["archived"], "empty": repo["empty"],
                "scope_metadata_rapp_match": scoped["rapp_metadata_match"],
                "_entries": repo["entries"],
            })
        for dep in captured["dependencies"]:
            self.units.append({
                "unit_id": "dependency:%s@%s" % (dep["source_url"], dep["commit"]),
                "kind": "gitlink_dependency", "source_url": dep["source_url"],
                "captured_commit": dep["commit"], "_entries": dep["entries"],
                "parent_links": [link for link in captured["dependency_links"]
                                 if link.get("url") == dep["source_url"]
                                 and link["commit"] == dep["commit"]],
            })
        for unit in self.units:
            for entry in unit["_entries"]:
                if entry["type"] == "blob":
                    self.references[entry["git_object"]].append((unit["unit_id"], entry))

    def enumerate_store(self):
        root = self.capture["root"] / "genome/objects"
        actual = set()
        with safe_directory(root) as directory:
            prefixes = sorted(os.listdir(directory))
        for prefix in prefixes:
            require(re.fullmatch("[0-9a-f]{2}", prefix), "unexpected object-store directory")
            with safe_directory(root / prefix) as directory:
                for suffix in os.listdir(directory):
                    require(re.fullmatch("[0-9a-f]{38}", suffix),
                            "unexpected object-store filename")
                    actual.add(prefix + suffix)
        extra = actual - self.capture["all_blobs"]
        if extra:
            self.errors.append({"kind": "unbound_objects", "git_objects": sorted(extra)})
        # Missing objects are handled per reference below, not silently discarded.
        return actual

    def read_blob(self, oid):
        record = {"git_object": oid, "references": len(self.references[oid]),
                  "integrity": "unverified", "content_status": "unverified_integrity"}
        path = self.capture["root"] / "genome/objects" / oid[:2] / oid[2:]
        try:
            with safe_file(path) as stream:
                initial = os.fstat(stream.fileno())
                size = initial.st_size
                record["bytes"] = size
                if size > self.limits.max_hash_blob_bytes:
                    record["integrity"] = "unmeasured_hash_bound"
                    record["reason"] = "max_hash_blob_bytes"
                    return record, None
                if self.hash_bytes + size > self.limits.max_total_hash_bytes:
                    record["integrity"] = "unmeasured_hash_bound"
                    record["reason"] = "max_total_hash_bytes"
                    return record, None
                sha1 = hashlib.sha1(("blob %s\0" % size).encode("ascii"))
                sha256 = hashlib.sha256()
                retain = size <= self.limits.max_blob_bytes
                chunks, read = [], 0
                while True:
                    chunk = stream.read(min(1024 * 1024, max(size - read + 1, 1)))
                    if not chunk:
                        break
                    read += len(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    if retain:
                        chunks.append(chunk)
                    if read > size:
                        break
                final = os.fstat(stream.fileno())
                self.hash_bytes += read
                record["bytes_hashed"] = read
                record["sha256"] = sha256.hexdigest()
                if read != size or (initial.st_size, initial.st_mtime_ns) != (
                    final.st_size, final.st_mtime_ns
                ):
                    record["integrity"] = "changed_during_read"
                elif sha1.hexdigest() != oid:
                    record["integrity"] = "git_blob_hash_mismatch"
                    record["observed_git_object"] = sha1.hexdigest()
                else:
                    record["integrity"] = "verified_git_blob"
                    if not retain:
                        record["content_status"] = "unmeasured_size_bound"
                        record["reason"] = "max_blob_bytes"
                    return record, b"".join(chunks) if retain else None
        except CaptureError as exc:
            record["integrity"] = "missing_or_unsafe_blob"
            record["reason"] = short(exc)
        self.errors.append({"kind": record["integrity"], "git_object": oid})
        return record, None

    def add_candidate(self, oid, analysis, kind, selector, value, body, origin):
        key = (kind, selector)
        if key in analysis["_candidate_keys"]:
            return
        analysis["_candidate_keys"].add(key)
        summary_value = value
        if kind == "frame":
            result, parsed = _verify_frame_input(body)
            if parsed is not None:
                summary_value = parsed
        elif kind == "identity":
            result = verify_identity(value)
        else:
            result = verify_egg(body, self.limits)
        candidate = {"kind": kind, "selector": selector, "origin": origin,
                     "validation": result, "protocol_declaration": protocol_declaration(value, kind),
                     "validation_scope": ("candidate bytes interpreted as RAPP/1; a refusal is not "
                                          "a retroactive invalidation of another protocol")}
        if isinstance(value, dict):
            if kind == "frame":
                candidate["frame_summary"] = {
                    k: observed_value(summary_value.get(k))
                    for k in ("spec", "schema", "stream_id", "seq", "utc",
                              "payload_hash", "frame_hash", "prev", "prev_wave")
                }
            if value.get("sig") is not None:
                candidate["signature"] = "present_unverified; no trust provider configured"
            else:
                candidate["signature"] = "not_present"
            if kind == "egg" and value.get("variant") == "sealed":
                candidate["sealed_plaintext"] = "not_opened_or_measured"
        if kind == "egg":
            candidate["embedded_application_behavior"] = "not_executed"
        analysis["candidates"].append(candidate)
        if kind == "frame" and isinstance(value, dict) and isinstance(body, bytes):
            cost = len(body)
            if self.frame_cache_bytes + cost <= self.limits.max_chain_cache_bytes:
                self.frame_inputs[(oid, selector)] = body
                self.frame_cache_bytes += cost
            else:
                candidate["stream_check_boundary"] = "max_chain_cache_bytes"

    def scan(self, oid, body, record):
        entries = [entry for _, entry in self.references[oid] if entry["mode"] != "120000"]
        analysis = {"candidates": [], "_candidate_keys": set(), "container": None,
                    "boundaries": []}
        self.analyses[oid] = analysis
        if not entries:
            record["content_status"] = "symlink_target_not_dereferenced"
            return
        paths = [entry["path"] for entry in entries]
        hints = {artifact_hint(path) for path in paths} - {None}
        analysis["_hints"] = hints
        if body.startswith(b"PK"):
            record["content_status"] = "opaque_archive"
            analysis["boundaries"].append("archive members are not inventoried as source files")
            manifest = zip_manifest(body, self.limits)
            declared_egg = candidate_kind(manifest) == "egg"
            if "egg" in hints or declared_egg:
                self.add_candidate(oid, analysis, "egg", "$", manifest, body,
                                   "zip_manifest_declaration" if declared_egg else "filename_hint")
            return
        try:
            text = body.decode("utf-8")
            if "\0" in text:
                raise UnicodeError("NUL-bearing content")
        except UnicodeError:
            record["content_status"] = "opaque_non_utf8_or_nul"
            if "egg" in hints:
                self.add_candidate(oid, analysis, "egg", "$", None, body, "filename_hint")
            for hint in sorted(hints - {"egg"}):
                analysis["candidates"].append({
                    "kind": hint, "selector": "$", "origin": "filename_hint",
                    "protocol_declaration": protocol_declaration(None, hint),
                    "validation": {"status": "refused", "api": "strict_utf8_json",
                                   "canonical_called": False,
                                   "reason": "named JSON artifact is not UTF-8 JSON",
                                   "missing_requirements": []}})
            return
        record["content_status"] = "scanned_utf8"
        evidence = _evidence(text, self.limits, any(path.endswith(".py") for path in paths))
        if evidence["rapp_marker_occurrences"]:
            analysis["static_evidence"] = evidence
        stripped = body.lstrip()
        json_named = any(path.lower().endswith((".json", ".jsonl", ".ndjson")) for path in paths)
        if not (stripped.startswith((b"{", b"[")) or hints or json_named):
            return
        value = None
        error = None
        try:
            value = strict_json(body, self.limits, preserve_numbers=True)
        except (ValueError, UnicodeError, RecursionError) as exc:
            error = exc
        if error is None:
            if evidence["rapp_marker_occurrences"]:
                analysis["root_declarations"] = root_declarations(value)
            kind = candidate_kind(value)
            kinds = {kind} if kind else set()
            kinds |= hints
            for item in sorted(kinds):
                self.add_candidate(oid, analysis, item, "$", value, body,
                                   "structured_root" if item == kind else "filename_hint")
            if not kinds and isinstance(value, dict):
                note_nested_boundary(analysis, value)
            if kind == "frame" and any(path.lower().endswith((".jsonl", ".ndjson")) for path in paths):
                nonempty = [line for line in body.splitlines() if line.strip()]
                if len(nonempty) == 1:
                    analysis["container"] = {"form": "json_lines", "records": 1,
                                             "nonframe_records": 0, "omitted_records": 0,
                                             "applicable_suffixes": [".jsonl", ".ndjson"]}
                else:
                    analysis["boundaries"].append(
                        "multiline JSON value in a JSON-lines-named blob; line stream not established")
            if isinstance(value, list):
                analysis["container"] = {"form": "json_array", "records": len(value),
                                         "nonframe_records": 0,
                                         "omitted_records": max(
                                             0, len(value) - self.limits.max_records_per_blob)}
                for index, (row, original) in enumerate(
                    array_record_octets(body, self.limits.max_records_per_blob)
                ):
                    row_kind = candidate_kind(row)
                    if row_kind != "frame":
                        analysis["container"]["nonframe_records"] += 1
                    if row_kind:
                        self.add_candidate(oid, analysis, row_kind, "$[%s]" % index, row,
                                           original, "structured_array_record")
                    else:
                        note_nested_boundary(analysis, row)
            return
        is_lines = any(path.lower().endswith((".jsonl", ".ndjson")) for path in paths)
        if is_lines:
            lines = [(number, line) for number, line in enumerate(body.splitlines(), 1)
                     if line.strip()]
            container = {"form": "json_lines", "records": len(lines), "nonframe_records": 0,
                         "omitted_records": 0, "parse_errors": [], "parse_error_count": 0,
                         "parse_error_records_omitted": 0}
            analysis["container"] = container
            for index, (number, line) in enumerate(lines):
                if index >= self.limits.max_records_per_blob:
                    container["omitted_records"] = len(lines) - index
                    break
                try:
                    row = strict_json(line, self.limits, preserve_numbers=True)
                except (ValueError, UnicodeError, RecursionError) as exc:
                    container["nonframe_records"] += 1
                    container["parse_error_count"] += 1
                    if len(container["parse_errors"]) < self.limits.max_evidence_per_blob:
                        container["parse_errors"].append({"line": number, "reason": short(exc)})
                    else:
                        container["parse_error_records_omitted"] += 1
                    continue
                kind = candidate_kind(row)
                if kind != "frame":
                    container["nonframe_records"] += 1
                if kind:
                    self.add_candidate(oid, analysis, kind, "line:%s" % number, row, line,
                                       "structured_json_line")
                else:
                    note_nested_boundary(analysis, row)
            return
        if isinstance(error, BoundExceeded):
            analysis["boundaries"].append(str(error))
        for hint in sorted(hints):
            if hint == "egg":
                self.add_candidate(oid, analysis, hint, "$", None, body, "filename_hint")
            else:
                analysis["candidates"].append({
                    "kind": hint, "selector": "$", "origin": "filename_hint",
                    "protocol_declaration": protocol_declaration(None, hint),
                    "validation": {
                        "status": "unmeasured_bound" if isinstance(error, BoundExceeded) else "refused",
                        "api": "strict_json", "canonical_called": False,
                        "reason": short(error), "missing_requirements": []}})
        if json_named:
            analysis["json_parse_boundary"] = short(error)

    def selected_candidates(self, entry):
        analysis = self.analyses.get(entry["git_object"], {})
        hint = artifact_hint(entry["path"])
        return [candidate for candidate in analysis.get("candidates", [])
                if candidate["origin"] != "filename_hint" or candidate["kind"] == hint]

    def chain_check(self, group, entries, form, ordering, incomplete):
        summaries = [candidate.get("frame_summary", {}) for _, candidate in entries]
        streams = {item.get("stream_id") for item in summaries
                   if isinstance(item.get("stream_id"), str)}
        seqs = [item.get("seq") for item in summaries]
        check = {"container": group, "form": form, "ordering": ordering,
                 "frames_observed": len(entries), "status": "unverified",
                 "authority": "observed container and self-declared stream only; not authenticated",
                 "incomplete": incomplete, "checks": []}
        if len(streams) != 1 or len(summaries) != len(
            [s for s in summaries if isinstance(s.get("stream_id"), str)]
        ):
            check["reason"] = "missing or mixed stream IDs; not combined"
            return check
        stream = next(iter(streams))
        check["stream_id"] = stream
        if any(not is_count(seq) for seq in seqs) or len(seqs) != len(set(seqs)):
            check["reason"] = "invalid or repeated sequence numbers; ambiguous container"
            return check
        check["starts_at_genesis"] = bool(seqs and seqs[0] == 0)
        head, statuses = None, []
        for entry, candidate in entries:
            key = (entry["git_object"], candidate["selector"])
            body = self.frame_inputs.get(key)
            source = dict(path_fields(entry), selector=candidate["selector"])
            if body is None:
                result = {"status": "unmeasured_bound", "api": None, "canonical_called": False,
                          "reason": "frame unavailable under max_chain_cache_bytes",
                          "missing_requirements": ["frame_body_for_stream_check"]}
            else:
                head_key = (
                    hashlib.sha256(R.canonical(head).encode("utf-8")).hexdigest()
                    if head is not None else None
                )
                cache_key = (key, head_key, stream)
                if cache_key not in self.chain_cache:
                    self.chain_cache[cache_key] = verify_frame(body, head=head, stream=stream)
                result = self.chain_cache[cache_key]
            statuses.append(result["status"])
            check["checks"].append(dict(source, validation=result))
            # A digest summary is not the verified predecessor frame required by
            # the canonical API. Unverified history never supplies a synthetic head.
            if result["status"] == "accepted" and body is not None:
                head = R._strict_json(body)
            else:
                head = None
        if "refused" in statuses:
            check["status"] = "refused"
        elif (statuses and set(statuses) == {"accepted"} and not incomplete
              and check["starts_at_genesis"]):
            check["status"] = "accepted_observed_chain"
        check["reason"] = ("container-local API outcomes only; application behavior, authoritative "
                           "stream selection, and cross-container completeness remain unmeasured")
        return check

    def unit_matrix(self, unit):
        row = {key: value for key, value in unit.items() if not key.startswith("_")}
        entries = unit["_entries"]
        row["entry_binding_sha256"] = entry_binding_digest(entries)
        row["tracked_entries"] = len(entries)
        row["entry_modes"] = dict(collections.Counter(e["mode"] for e in entries))
        coverage = collections.Counter()
        row["evidence"] = []
        row["unmeasured"] = []
        row["stream_checks"] = []
        row["compatibility"] = "not_established"
        artifact_counts = collections.Counter()
        declaration_counts = collections.Counter()
        rapp_observed = False
        directories = collections.defaultdict(list)
        dir_incomplete = collections.Counter()
        for entry in sorted(entries, key=raw_path):
            source = path_fields(entry)
            source["location_hints"] = location_hints(entry["path"])
            if entry["type"] == "commit":
                coverage["gitlink_not_an_owner_blob"] += 1
                link = next((item for item in self.capture["dependency_links"]
                             if item["parent_repo"] == unit.get("repository")
                             and item["path"] == entry["path"]
                             and item["commit"] == entry["git_object"]), None)
                row["unmeasured"].append(dict(
                    source, reason="gitlink is not an owner tracked body",
                    dependency_status=link["status"] if link else "nested_gitlink_unmeasured"))
                continue
            if entry["mode"] == "120000":
                coverage["symlink_target_not_dereferenced"] += 1
                row["unmeasured"].append(dict(source, reason="Git symlink target is inert data"))
                continue
            blob = self.blobs[entry["git_object"]]
            status = blob["content_status"]
            coverage[status] += 1
            parent, _, name = entry["path"].rpartition("/")
            is_frame_dir = parent.rsplit("/", 1)[-1].lower() == "frames" and name.endswith(".json")
            if status != "scanned_utf8":
                row["unmeasured"].append(dict(
                    source, reason=status, integrity=blob["integrity"], bytes=blob.get("bytes")))
                if is_frame_dir:
                    dir_incomplete[parent] += 1
            analysis = self.analyses.get(entry["git_object"], {})
            candidates = self.selected_candidates(entry)
            static = analysis.get("static_evidence")
            if static or candidates or artifact_hint(entry["path"]):
                evidence = dict(source, blob_evidence_ref=entry["git_object"])
                if static:
                    rapp_observed = True
                    evidence["has_textual_rapp_evidence"] = True
                    evidence["source_suffix_hint"] = Path(entry["path"]).suffix in SOURCE_SUFFIXES
                if candidates:
                    evidence["artifacts"] = candidates
                    for candidate in candidates:
                        artifact_counts[candidate["kind"] + ":" + candidate["validation"]["status"]] += 1
                        claim = candidate["protocol_declaration"]["classification"]
                        declaration_counts[claim + ":" + candidate["kind"] + ":"
                                           + candidate["validation"]["status"]] += 1
                        if claim in {"declared_rapp1", "declared_legacy_rapp",
                                     "other_rapp_namespace", "rappid_field_only"}:
                            rapp_observed = True
                row["evidence"].append(evidence)
            for boundary in analysis.get("boundaries", []):
                row["unmeasured"].append(dict(source, reason=boundary))
            if analysis.get("json_parse_boundary"):
                row["unmeasured"].append(dict(source, reason="JSON structure not parsed",
                                               detail=analysis["json_parse_boundary"]))
            if static:
                for key in ("reference_records_omitted", "static_role_records_omitted"):
                    if static[key]:
                        row["unmeasured"].append(dict(source, reason=key, count=static[key]))
                if static.get("source_analysis", "").startswith("python_ast_unmeasured"):
                    row["unmeasured"].append(dict(source, reason=static["source_analysis"]))
            frames = [candidate for candidate in candidates if candidate["kind"] == "frame"]
            container = analysis.get("container")
            if (container and frames and
                (not container.get("applicable_suffixes")
                 or Path(entry["path"]).suffix.lower() in container["applicable_suffixes"])):
                incomplete = (container["nonframe_records"] + container["omitted_records"])
                row["stream_checks"].append(self.chain_check(
                    source, [(entry, candidate) for candidate in frames],
                    container["form"], "original record order", incomplete))
            if container and container["omitted_records"]:
                row["unmeasured"].append(dict(source, reason="max_records_per_blob",
                                               count=container["omitted_records"]))
            if container and container.get("parse_error_count"):
                row["unmeasured"].append(dict(source, reason="JSON-lines record parse errors",
                                               count=container["parse_error_count"]))
            if is_frame_dir:
                roots = [candidate for candidate in frames if candidate["selector"] == "$"]
                if len(roots) != 1:
                    dir_incomplete[parent] += 1
                else:
                    directories[parent].append((entry, roots[0]))
        for directory, frames in sorted(directories.items()):
            names = [entry["path"].rsplit("/", 1)[-1] for entry, _ in frames]
            if all(re.fullmatch(r"[0-9]+[.]json", name) for name in names):
                frames.sort(key=lambda pair: int(pair[0]["path"].rsplit("/", 1)[-1][:-5]))
                ordering = "numeric filenames in this exact directory"
            elif all(FRAME_DIR_NAME.fullmatch(name) for name in names):
                frames.sort(key=lambda pair: (
                    pair[1].get("frame_summary", {}).get("seq")
                    if is_count(pair[1].get("frame_summary", {}).get("seq")) else -1,
                    raw_path(pair[0])))
                ordering = "self-declared sequence in this exact frame store"
            else:
                row["stream_checks"].append({
                    "container_path_bytes_base64": base64.b64encode(
                        directory.encode("utf-8", "surrogateescape")).decode("ascii"),
                    "status": "unverified", "reason": "unknown directory ordering; not guessed",
                    "frames_observed": len(frames)})
                continue
            row["stream_checks"].append(self.chain_check(
                {"path_bytes_base64": base64.b64encode(
                    directory.encode("utf-8", "surrogateescape")).decode("ascii"),
                 "path_display": directory}, frames, "frame_directory", ordering,
                dir_incomplete[directory]))
        row["entry_coverage"] = dict(sorted(coverage.items()))
        require(sum(coverage.values()) == len(entries), "internal tracked-entry accounting failure")
        row["artifact_outcomes"] = dict(sorted(artifact_counts.items()))
        row["artifact_declaration_outcomes"] = dict(sorted(declaration_counts.items()))
        row["observed_rapp_evidence"] = rapp_observed
        row["observation"] = ("rapp_evidence_observed" if rapp_observed else
                              "no_rapp_evidence_observed_in_measured_content")
        return row

    def run(self):
        store = self.enumerate_store()
        for index, oid in enumerate(sorted(self.capture["all_blobs"]), 1):
            record, body = self.read_blob(oid)
            self.blobs[oid] = record
            if body is not None:
                self.scan(oid, body, record)
            if self.progress and index % 10000 == 0:
                self.progress("hashed/accounted %s/%s unique blobs" %
                              (index, len(self.capture["all_blobs"])))
        owner_size = sum(self.blobs[oid].get("bytes", 0) for oid in self.capture["owner_blobs"])
        if all("bytes" in self.blobs[oid] for oid in self.capture["owner_blobs"]):
            for document, key in [(self.capture["index"]["counts"], "source_blob_bytes"),
                                  (self.capture["genome"], "blob_bytes")]:
                if not is_count(document.get(key)) or document[key] != owner_size:
                    self.errors.append({"kind": "source_blob_byte_count_mismatch",
                                        "field": key, "observed": owner_size,
                                        "declared": document.get(key)})
        matrices = [self.unit_matrix(unit) for unit in self.units]
        repositories = [row for row in matrices if row["kind"] == "owner_repository"]
        dependencies = [row for row in matrices if row["kind"] == "gitlink_dependency"]
        unique_outcomes = collections.Counter()
        for oid, analysis in self.analyses.items():
            public = {key: value for key, value in analysis.items()
                      if not key.startswith("_") and value}
            if public:
                self.blobs[oid]["analysis"] = public
            for candidate in analysis["candidates"]:
                unique_outcomes[candidate["kind"] + ":" + candidate["validation"]["status"]] += 1
        coverage = {
            "owner_repositories_expected": len(self.capture["scope"]["repositories"]),
            "owner_repositories_accounted": len(repositories),
            "owner_tracked_entries_expected": self.capture["expected_counts"]["tracked_entries"],
            "owner_tracked_entries_accounted": sum(row["tracked_entries"] for row in repositories),
            "empty_owner_repositories": sum(row["empty"] for row in repositories),
            "owner_repositories_with_observed_rapp_evidence": sum(
                row["observed_rapp_evidence"] for row in repositories),
            "owner_repositories_without_observed_rapp_evidence": sum(
                not row["observed_rapp_evidence"] for row in repositories),
            "owner_entry_coverage": dict(sum(
                (collections.Counter(row["entry_coverage"]) for row in repositories),
                collections.Counter())),
            "dependency_bodies_accounted": len(dependencies),
            "dependency_tracked_entries_accounted": sum(row["tracked_entries"] for row in dependencies),
            "dependency_entry_coverage": dict(sum(
                (collections.Counter(row["entry_coverage"]) for row in dependencies),
                collections.Counter())),
            "owner_unique_blobs": len(self.capture["owner_blobs"]),
            "owner_and_dependency_unique_blobs": len(self.blobs),
            "object_store_file_names": len(store),
            "blob_integrity": dict(collections.Counter(
                item["integrity"] for item in self.blobs.values())),
            "unique_blob_content_coverage": dict(collections.Counter(
                item["content_status"] for item in self.blobs.values())),
            "bytes_hashed": self.hash_bytes,
            "owner_unique_blob_bytes_stat": owner_size,
            "gitlinks": len(self.capture["dependency_links"]),
            "gitlinks_hydrated": sum(link["status"] == "hydrated"
                                    for link in self.capture["dependency_links"]),
            "gitlinks_unavailable": sum(link["status"] == "pre-existing-unavailable"
                                       for link in self.capture["dependency_links"]),
            "unique_artifact_outcomes": dict(sorted(unique_outcomes.items())),
            "owner_artifact_occurrence_outcomes": dict(sorted(sum(
                (collections.Counter(row["artifact_outcomes"]) for row in repositories),
                collections.Counter()).items())),
            "owner_artifact_declaration_outcomes": dict(sorted(sum(
                (collections.Counter(row["artifact_declaration_outcomes"]) for row in repositories),
                collections.Counter()).items())),
            "owner_stream_check_outcomes": dict(collections.Counter(
                check["status"] for row in repositories for check in row["stream_checks"])),
            "unique_stream_api_calls": len(self.chain_cache),
        }
        return {
            "schema": SCHEMA,
            "report_status": "capture_invalid" if self.errors else "complete",
            "compatibility_verdict": "not_established",
            "capture": {
                "adapter": ADAPTER, "root": str(self.capture["root"]),
                "owner": self.capture["scope"]["owner"],
                "created_at": self.capture["scope"].get("created_at"),
                "scope": "frozen public owner default-branch snapshots plus supplied Gitlink bodies",
                "metadata_hashes": self.capture["metadata_hashes"],
                "claimed_archive": self.capture["index"].get("archive"),
                "archive_and_git_history_verification": "not measured by this adapter",
                "commit_provenance": ("recorded commits cross-bound to scope and repository metadata; "
                                      "Git commit/tree objects and live HEADs not authenticated here"),
                "success_flags_used_as_evidence": False,
            },
            "canonical": canonical_authority(self.limits),
            "measurement_policy": {
                "limits": asdict(self.limits),
                "static_evidence": "mentions and AST names only; not producer/reader conformance",
                "labels": "older or newer pins alone are neither a refusal nor compatibility proof",
                "candidate_declarations": ("filename/shape candidates, other namespaces, legacy "
                                           "declarations and declared RAPP/1 are counted separately"),
                "paths": "raw bytes and modes authoritative; no normalization or symlink traversal",
                "location_hints": "descriptive only; never exempt an artifact or establish authority",
                "frames": ("canonical verify_frame with no invented predecessor; non-genesis "
                           "standalone failures at step 4 mean unverified history"),
                "frame_original_domain": (
                    "discovery preserves numeric lexemes; original root, JSON-line and array-record "
                    "octets must pass adjacent rapp._strict_json before rapp.verify_frame. "
                    "Normalized dictionaries without original octets are unmeasured, never accepted"),
                "metadata_json": "capture metadata discovery uses its own bounded parser, not RAPP limits",
                "verifier_provenance": "canonical.rapp_py_sha256 binds every canonical_called observation",
                "streams": ("only original JSON record order or exact frame-directory containers; "
                            "never combined across directories, repositories, or forks"),
                "signatures": "no trust provider; signed artifacts remain unverified, not counterfeit",
                "identity": "rappid_valid grammar only, not a complete identity-provenance verifier",
                "eggs": "canonical verify_egg on bounded original bytes; never execute or decrypt",
                "unmeasured_everywhere": [
                    "live HEAD freshness and uncaptured history",
                    "deployed behavior, producer reachability, reader interoperability and services",
                    "private/unpublished state and external trust registries",
                    "nested artifacts in prose, source literals, payloads and arbitrary containers",
                    "archive member inventories and sealed plaintext",
                    "dependency application execution and dependency installation",
                ],
            },
            "coverage": coverage, "capture_errors": self.errors,
            "repositories": repositories, "dependencies": dependencies,
            "dependency_links": self.capture["dependency_links"],
            "blobs": [self.blobs[oid] for oid in sorted(self.blobs)],
        }


def collect(capture, scope, limits=Limits(), progress=None):
    return Inventory(load_capture(capture, scope, limits), limits, progress).run()


def write_report(path, report, capture, scope):
    path = Path(os.path.abspath(os.fspath(path)))
    capture = Path(os.path.abspath(os.fspath(capture)))
    scope = Path(os.path.abspath(os.fspath(scope)))
    require(path != scope and path != capture and capture not in path.parents,
            "output may not overwrite any captured material or scope")
    # Exclusive creation prevents overwriting an earlier report, source, or a
    # symlink. Streaming JSON avoids another full in-memory copy of the ledger.
    with safe_directory(path.parent) as directory:
        fd = None
        created = False
        completed = False
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o644, dir_fd=directory)
            created = True
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = None
                json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=True,
                          allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            completed = True
        finally:
            if fd is not None:
                os.close(fd)
            if created and not completed:
                os.unlink(path.name, dir_fd=directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="new report file; existing files are never overwritten")
    parser.add_argument("--report-only", action="store_true",
                        help="exit 0 for a complete collection, NOT ecosystem compatibility")
    parser.add_argument("--quiet", action="store_true")
    for key, default in asdict(Limits()).items():
        parser.add_argument("--" + key.replace("_", "-"), type=int, default=default)
    args = parser.parse_args(argv)
    bounds = {key: getattr(args, key) for key in asdict(Limits())}
    if any(value <= 0 for value in bounds.values()):
        parser.error("all measurement bounds must be positive")
    progress = None if args.quiet else lambda line: print(line, file=sys.stderr, flush=True)
    try:
        report = collect(args.capture, args.scope, Limits(**bounds), progress)
        code = 2 if report["report_status"] != "complete" else 0 if args.report_only else 1
    except (CaptureError, OSError) as exc:
        report = {"schema": SCHEMA, "report_status": "capture_invalid",
                  "compatibility_verdict": "not_established",
                  "capture_errors": [{"kind": type(exc).__name__, "reason": short(exc, 2000)}],
                  "coverage": {"accounting_completed": False}}
        code = 2
    except (AttributeError, AssertionError, ArithmeticError, LookupError, TypeError,
            RuntimeError, MemoryError, ValueError) as exc:
        report = {"schema": SCHEMA, "report_status": "operational_failure",
                  "compatibility_verdict": "not_established",
                  "operational_errors": [{"kind": type(exc).__name__, "reason": short(exc, 2000)}],
                  "coverage": {"accounting_completed": False}}
        code = 2
    report["exit_semantics"] = {
        "report_only_requested": args.report_only, "exit_code": code,
        "0": "explicit report-only collection succeeded; findings may be refused or unmeasured",
        "1": "inventory is not an ecosystem compatibility gate",
        "2": "capture binding, integrity, or operational failure",
    }
    try:
        write_report(args.output, report, args.capture, args.scope)
    except (CaptureError, OSError, ValueError, TypeError, AttributeError, AssertionError,
            ArithmeticError, LookupError, RuntimeError, MemoryError) as exc:
        print("inventory report not written: %s" % exc, file=sys.stderr)
        return 2
    print("%s; compatibility not established; report=%s; exit=%s" %
          (report["report_status"], args.output, code), file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
