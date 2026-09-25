"""rapp_check.py — the RAPP compliance linter.

Point it at any repo checkout and it verdicts every RAPP artifact (rappid.json,
frame chains, egg/schema labels, §13 registry documents) against the RAPP standard,
using the reference implementation. A registry document is checked for structure only:
its owner signature needs the out-of-band trust anchor (§13.1), so it is reported as
unverified evidence, never as authority. It classifies a repo as:

  CLEAN     — no RAPP artifacts found by a complete bounded scan
  COMPLIANT — has artifacts, all pass RAPP
  DRIFT     — has violations or cannot establish signed conformance

Usage:  python3 rapp_check.py <repo_path> [--json]
Exit:   0 CLEAN/COMPLIANT · 1 DRIFT · 2 error
"""
from collections import defaultdict
import hashlib
import json
import os
import re
import stat
import sys

import rapp as R
import rapp_registry as REG

_32HEX = re.compile(r"^[0-9a-f]{32}$")
_64HEX = re.compile(r"^[0-9a-f]{64}$")
_NUMERIC_FRAME = re.compile(r"^\d+\.json$")
_INDEX_NAME = "rapp-frame-index.json"
_INDEX_SCHEMA = "rapp-frame-index/1"
_INDEX_KEYS = {"schema", "stream_id", "frames", "head"}
_HEAD_KEYS = {"seq", "frame_hash"}
_MAX_WALK_ENTRIES = 100_000
_MAX_WALK_DIRS = 10_000
_MAX_WALK_DEPTH = 32
_MAX_JSON_FILES = 10_000
_MAX_JSON_BYTES = 64 * 1024 * 1024
_REGISTRY_SCHEMA_TEXT = re.compile(rb'"schema"\s*:\s*"rapp/1-registry"')


def _untagged(payload):
    return hashlib.sha256(R.canonical(payload).encode("utf-8")).hexdigest()


def _walk_files(root):
    """Bounded regular-file discovery; never follows symlinks or .git."""
    root = os.path.abspath(root)
    if os.path.islink(root) or not os.path.isdir(root):
        raise OSError(f"not a regular repository directory: {root}")
    found, issues, walk_errors = [], [], []
    entries_seen = dirs_seen = 0
    walker = os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=lambda exc: walk_errors.append(str(exc)),
    )
    for base, dirs, files in walker:
        dirs_seen += 1
        relative = os.path.relpath(base, root)
        depth = 0 if relative == "." else relative.count(os.sep) + 1
        dirs[:] = sorted(
            name
            for name in dirs
            if name != ".git" and not os.path.islink(os.path.join(base, name))
        )
        if depth >= _MAX_WALK_DEPTH and dirs:
            issues.append(f"depth limit reached at {relative}")
            dirs.clear()
        entries_seen += len(dirs) + len(files)
        if dirs_seen > _MAX_WALK_DIRS or entries_seen > _MAX_WALK_ENTRIES:
            issues.append("repository tree limit reached; tail not scanned")
            dirs.clear()
            break
        for name in sorted(files):
            if not (name.endswith(".json") or name.endswith(".egg")):
                continue
            path = os.path.join(base, name)
            try:
                info = os.lstat(path)
            except OSError as exc:
                issues.append(f"cannot inspect {os.path.relpath(path, root)}: {exc}")
                continue
            if stat.S_ISREG(info.st_mode):
                found.append(path)
    issues.extend(f"cannot scan repository path: {error}" for error in walk_errors)
    return sorted(found), issues


def _read_blob(path, maximum=None):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("not a regular file")
    if maximum is not None and info.st_size > maximum:
        raise ValueError(f"file exceeds {maximum}-byte limit")
    with open(path, "rb") as source:
        blob = source.read(-1 if maximum is None else maximum + 1)
    if maximum is not None and len(blob) > maximum:
        raise ValueError(f"file exceeds {maximum}-byte limit")
    return blob


def _strict_json(path):
    return R._strict_json(_read_blob(path, R.MAX_CANONICAL_BYTES))


def _looks_like_frame(blob):
    """Recognize ambiguous exact Frames without accepting ordinary lookalikes."""
    try:
        value = json.loads(blob)
    except Exception:
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return bool(
            re.search(r'"spec"\s*:\s*"rapp/1"', text)
            and all(
                re.search(rf'"{re.escape(key)}"\s*:', text)
                for key in R.FRAME_KEYS
            )
        )
    return (
        isinstance(value, dict)
        and set(value) == R.FRAME_KEYS
        and value.get("spec") == R.SPEC
    )


def _safe_index_path(root, index_path, member):
    if (
        not isinstance(member, str)
        or not member
        or member.startswith("/")
        or "\\" in member
        or not member.endswith(".json")
        or any(part in ("", ".", "..") for part in member.split("/"))
    ):
        raise ValueError("frame path must be a safe relative .json path")
    candidate = os.path.abspath(os.path.join(os.path.dirname(index_path), member))
    if os.path.commonpath((root, candidate)) != root:
        raise ValueError("frame path escapes repository")
    cursor = root
    parts = os.path.relpath(candidate, root).split(os.sep)
    for position, part in enumerate(parts):
        cursor = os.path.join(cursor, part)
        info = os.lstat(cursor)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("frame path crosses a symlink")
        if position < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("frame path crosses a non-directory")
    if not stat.S_ISREG(os.lstat(candidate).st_mode):
        raise ValueError("frame path is not a regular file")
    return candidate


def _assess_frame(frame, head, signature_verifier):
    if frame.get("sig") is not None:
        try:
            R.parse_detached_jws(frame["sig"])
        except (TypeError, ValueError) as exc:
            return "invalid", "6", str(exc)
    try:
        ok, step, why = R.verify_frame(
            frame,
            head=head,
            stream_id_of_record=frame.get("stream_id"),
            signature_verifier=signature_verifier,
        )
    except (TypeError, ValueError) as exc:
        return "invalid", "1", str(exc)
    if ok:
        return "verified", None, "ok"
    if (
        step == "6"
        and frame.get("sig") is not None
        and signature_verifier is None
        and why == "trusted signature verifier is required"
    ):
        return "unverified", step, why
    return "invalid", step, why


def check_repo(root, signature_verifier=None):
    """Return (verdict, findings[], evidence[])."""
    root = os.path.abspath(root)
    findings, evidence, finding_keys = [], [], set()
    has_artifact = False

    def finding(artifact, rule, detail, status=None):
        key = (artifact, rule, detail, status)
        if key not in finding_keys:
            item = {"artifact": artifact, "rule": rule, "detail": detail}
            if status is not None:
                item["status"] = status
            findings.append(item)
            finding_keys.add(key)

    def unknown(artifact, detail):
        finding(
            artifact,
            "verification unavailable",
            detail,
            status="unverified",
        )

    files, scan_issues = _walk_files(root)
    for issue in scan_issues:
        unknown(".", f"bounded discovery incomplete: {issue}")
    json_paths = [path for path in files if path.endswith(".json")]
    egg_paths = [path for path in files if path.endswith(".egg")]

    # Identity records retain their existing checks, now under strict JSON.
    for path in (p for p in json_paths if os.path.basename(p) == "rappid.json"):
        has_artifact = True
        rel = os.path.relpath(path, root)
        try:
            record = _strict_json(path)
        except Exception as exc:
            finding(rel, "unreadable", str(exc))
            continue
        if not isinstance(record, dict):
            finding(rel, "§6 identity record", "rappid.json must be an object")
            continue
        rid, schema = record.get("rappid", ""), record.get("schema", "?")
        tail = rid.rsplit(":", 1)[-1] if isinstance(rid, str) else rid
        template = isinstance(tail, str) and bool(
            re.fullmatch(r"__[A-Z0-9_]+__", tail)
        )
        if template:
            evidence.append(
                {"artifact": rel, "ok": f"plant-template, exempt from §6.1: {rid}"}
            )
        elif R.rappid_valid(rid):
            match = R._RAPPID.match(rid)
            owner, slug, tail = match.group(1), match.group(2), match.group(3)
            if tail == hashlib.sha256(f"{owner}/{slug}".encode()).hexdigest():
                finding(rel, "§6.2 name-hash mint", f"tail == sha256('{owner}/{slug}')")
            else:
                evidence.append(
                    {"artifact": rel, "ok": f"rappid §6.1 grammar OK: {rid}"}
                )
        elif isinstance(tail, str) and _32HEX.fullmatch(tail):
            finding(rel, "§6.1 short-tail (C3)", f"32-hex tail, not 64-hex: {rid}")
        else:
            finding(
                rel,
                "§6.1 grammar (C2)",
                f"not rappid:@owner/slug:64hex — {rid}",
            )
        if schema != "rapp/1":
            finding(rel, "§12 schema label", f"schema='{schema}', not 'rapp/1'")
        parent = record.get("parent_rappid")
        if parent and not R.rappid_valid(parent):
            finding(
                rel,
                "§6.3 parent_rappid",
                f"parent_rappid not RAPP grammar: {parent}",
            )

    # Numeric frame directories remain explicit candidates.
    numeric_dirs = defaultdict(list)
    for path in json_paths:
        if (
            os.path.basename(os.path.dirname(path)) == "frames"
            and _NUMERIC_FRAME.fullmatch(os.path.basename(path))
        ):
            numeric_dirs[os.path.dirname(path)].append(path)
    for directory in numeric_dirs:
        numeric_dirs[directory].sort(
            key=lambda path: int(os.path.basename(path)[:-5])
        )
    required, numeric_paths, indexes = set(), set(), []
    for paths in numeric_dirs.values():
        required.update(paths)
        numeric_paths.update(paths)
        has_artifact = True

    # Optional exact discovery indexes identify malformed/nonstandard candidates
    # and publish a head for rollback checks. They confer no trust.
    for path in (p for p in json_paths if os.path.basename(p) == _INDEX_NAME):
        has_artifact = True
        rel = os.path.relpath(path, root)
        try:
            index = _strict_json(path)
            if not isinstance(index, dict) or set(index) != _INDEX_KEYS:
                raise ValueError("index must have exactly schema,stream_id,frames,head")
            if index["schema"] != _INDEX_SCHEMA or not isinstance(
                index["stream_id"], str
            ):
                raise ValueError(f"schema must be {_INDEX_SCHEMA}; stream_id must be text")
            members, head = index["frames"], index["head"]
            if (
                not isinstance(members, list)
                or not members
                or any(not isinstance(member, str) for member in members)
                or len(members) != len(set(members))
            ):
                raise ValueError("frames must be a non-empty list of unique paths")
            if (
                not isinstance(head, dict)
                or set(head) != _HEAD_KEYS
                or not isinstance(head["seq"], int)
                or isinstance(head["seq"], bool)
                or not 0 <= head["seq"] <= 2**53 - 1
                or not isinstance(head["frame_hash"], str)
                or not _64HEX.fullmatch(head["frame_hash"])
            ):
                raise ValueError("head must be exactly {seq:uint53,frame_hash:64hex}")
            targets = []
            for member in members:
                try:
                    target = _safe_index_path(root, path, member)
                except (OSError, ValueError) as exc:
                    finding(rel, "frame discovery index", f"{member}: {exc}")
                    continue
                targets.append(target)
                required.add(target)
            indexes.append((rel, index, targets))
        except Exception as exc:
            finding(rel, "frame discovery index", str(exc))

    records = {}

    def registry_document(rel, document):
        try:
            REG.validate_document(document)
            registry = REG.Registry(document[REG.ENTRIES_MEMBER])
        except (REG.RegistryError, ValueError) as exc:
            finding(rel, "§13 registry document", str(exc))
            return
        state = (
            "unsigned draft"
            if document["sig"] is None
            else "owner signature needs the out-of-band trust anchor"
        )
        evidence.append(
            {
                "artifact": rel,
                "ok": (
                    f"§13.1 registry structure OK (registry_seq "
                    f"{document['registry_seq']}, {len(registry.entries)} entries; {state})"
                ),
                "status": "unverified",
            }
        )

    def consider(path, is_required):
        nonlocal has_artifact
        rel = os.path.relpath(path, root)
        blob = None
        try:
            blob = _read_blob(path, R.MAX_CANONICAL_BYTES)
            value = R._strict_json(blob)
        except Exception as exc:
            if (
                not is_required
                and blob is not None
                and _REGISTRY_SCHEMA_TEXT.search(blob)
            ):
                has_artifact = True
                finding(rel, "§13 registry document", f"not strict I-JSON (§4): {exc}")
                return
            candidate = is_required or (
                blob is not None and _looks_like_frame(blob)
            )
            if candidate:
                has_artifact = True
                finding(rel, "RAPP/1 frame candidate", str(exc))
            return
        if (
            not is_required
            and isinstance(value, dict)
            and value.get("schema") == REG.DOCUMENT_SCHEMA
        ):
            has_artifact = True
            registry_document(rel, value)
            return
        candidate = is_required or (
            isinstance(value, dict)
            and set(value) == R.FRAME_KEYS
            and value.get("spec") == R.SPEC
        )
        if not candidate:
            return
        has_artifact = True
        if not isinstance(value, dict):
            finding(rel, "§7 frame envelope (C1)", "candidate must be an object")
            return
        records[path] = (rel, value)

    for path in sorted(required):
        consider(path, True)

    # Bounded exact-shape discovery finds Frames regardless of filename/layout.
    count = total = 0
    for path in (
        p
        for p in json_paths
        if p not in required
        and os.path.basename(p) not in ("rappid.json", _INDEX_NAME)
    ):
        try:
            size = os.lstat(path).st_size
        except OSError as exc:
            unknown(os.path.relpath(path, root), f"cannot stat JSON: {exc}")
            continue
        if size > R.MAX_CANONICAL_BYTES:
            continue
        if count >= _MAX_JSON_FILES or total + size > _MAX_JSON_BYTES:
            unknown(".", "bounded frame discovery JSON budget exhausted")
            break
        count, total = count + 1, total + size
        consider(path, False)

    # Preserve legacy canonicalization evidence and controlled-directory rules.
    for directory, paths in sorted(numeric_dirs.items()):
        canon = 0
        directory_records = [records[path][1] for path in paths if path in records]
        for frame in directory_records:
            payload, stored = frame.get("payload"), frame.get("sha256") or frame.get("hash")
            try:
                canon += bool(
                    payload is not None and stored is not None and _untagged(payload) == stored
                )
            except (TypeError, ValueError):
                pass
        if canon:
            evidence.append(
                {
                    "artifact": os.path.relpath(directory, root),
                    "ok": f"§4 canonicalization reproduces {canon}/{len(paths)} real payload hashes",
                }
            )
        streams = {
            frame.get("stream_id")
            for frame in directory_records
            if isinstance(frame.get("stream_id"), str)
        }
        if len(streams) > 1:
            finding(
                os.path.relpath(directory, root),
                "§7.5.1a mixed streams",
                f"numeric frame directory contains {len(streams)} stream_ids",
            )
        seqs = [
            frame.get("seq")
            for frame in directory_records
            if isinstance(frame.get("seq"), int)
            and not isinstance(frame.get("seq"), bool)
        ]
        if seqs and len(seqs) == len(directory_records) and seqs != list(
            range(len(seqs))
        ):
            rollback = seqs[-1] < max(seqs)
            finding(
                os.path.relpath(directory, root),
                "§7.6 rollback-shaped head" if rollback else "§7.4 numeric chain order",
                f"numeric path order carries sequence {seqs}, expected contiguous from 0",
            )

    # Thread globally by stream/seq; containers are checked separately above.
    streams = defaultdict(lambda: defaultdict(list))
    for path, (rel, frame) in records.items():
        stream_id, seq = frame.get("stream_id"), frame.get("seq")
        if isinstance(stream_id, str) and isinstance(seq, int) and not isinstance(seq, bool):
            streams[stream_id][seq].append((path, rel, frame))
        else:
            _, step, why = _assess_frame(frame, None, signature_verifier)
            finding(rel, f"§7 frame verification step {step or '?'}", why)

    fully_verified = set()
    for stream_id, positions in sorted(streams.items()):
        head, expected = None, 0
        for seq in sorted(positions):
            position = sorted(positions[seq], key=lambda item: item[1])
            if len(position) > 1:
                hashes = {item[2].get("frame_hash") for item in position}
                rule = "§7.6 duplicate position" if len(hashes) == 1 else "§7.6 fork"
                finding(
                    ", ".join(item[1] for item in position),
                    rule,
                    f"stream {stream_id} has {len(position)} frames at seq {seq}",
                )
                break
            path, rel, frame = position[0]
            if seq != expected:
                _, step, why = _assess_frame(frame, None, signature_verifier)
                if step not in ("4", None):
                    finding(rel, f"§7 frame verification step {step}", why)
                finding(
                    rel,
                    "§7.4 chain gap",
                    f"stream {stream_id} expected seq {expected}, found {seq}",
                )
                break
            status, step, why = _assess_frame(frame, head, signature_verifier)
            if status == "invalid":
                finding(rel, f"§7 frame verification step {step or '?'}", why)
                break
            if status == "unverified":
                evidence.append(
                    {
                        "artifact": rel,
                        "ok": "RAPP/1 frame passes §7 steps 1–5",
                        "status": "unverified",
                    }
                )
                finding(
                    rel,
                    "§10 signature verification unavailable",
                    "detached signature was not checked because no trusted "
                    "verifier/anchor was supplied",
                    status="unverified",
                )
            else:
                fully_verified.add(path)
                if path not in numeric_paths:
                    evidence.append(
                        {
                            "artifact": rel,
                            "ok": "RAPP/1 frame passes §7 envelope, hashes, and chain",
                        }
                    )
            head, expected = frame, expected + 1

    for directory, paths in sorted(numeric_dirs.items()):
        if paths and all(path in fully_verified for path in paths):
            evidence.append(
                {
                    "artifact": os.path.relpath(directory, root),
                    "ok": f"{len(paths)} frames conform to §7 envelope",
                }
            )

    # An index must bind one stream and its greatest discovered position.
    for rel, index, targets in indexes:
        listed = [records[path][1] for path in targets if path in records]
        declared = index["stream_id"]
        listed_streams = {
            frame.get("stream_id")
            for frame in listed
            if isinstance(frame.get("stream_id"), str)
        }
        if listed_streams - {declared}:
            finding(
                rel,
                "§7.5.1a mixed streams",
                "frame index lists stream_ids other than its declared stream",
            )
        declared_frames = [
            frame
            for frame in listed
            if frame.get("stream_id") == declared
            and isinstance(frame.get("seq"), int)
            and not isinstance(frame.get("seq"), bool)
        ]
        if not declared_frames:
            finding(rel, "frame discovery index", "no readable declared-stream frame")
            continue
        maximum = max(frame["seq"] for frame in declared_frames)
        head = index["head"]
        if head["seq"] < maximum:
            finding(
                rel,
                "§7.6 rollback-shaped head",
                f"index head seq {head['seq']} is below discovered seq {maximum}",
            )
        elif head["seq"] > maximum:
            finding(
                rel,
                "§7.4 chain gap",
                f"index head seq {head['seq']} exceeds discovered seq {maximum}",
            )
        match = any(
            frame["seq"] == head["seq"]
            and frame.get("frame_hash") == head["frame_hash"]
            for frame in declared_frames
        )
        if not match:
            finding(
                rel,
                "§7.6 head mismatch",
                "index head does not name the discovered frame at that position",
            )
        elif head["seq"] == maximum:
            evidence.append(
                {
                    "artifact": rel,
                    "ok": "discovery index head matches its greatest listed position",
                }
            )

    # Eggs retain existing behavior, but only regular, non-symlink files reach here.
    for path in egg_paths:
        has_artifact = True
        rel = os.path.relpath(path, root)
        try:
            blob = _read_blob(path)
            ok, step, why = R.verify_egg(blob)
            if ok:
                evidence.append({"artifact": rel, "ok": "egg conforms to §9 (rapp/1-egg)"})
            else:
                try:
                    manifest, _ = R.read_egg(blob)
                    schema = manifest.get("schema", "?")
                except Exception:
                    schema = "?"
                finding(
                    rel,
                    "§9 egg",
                    f"not a conformant rapp/1-egg (schema={schema}; {step}: {why})",
                )
        except Exception as exc:
            finding(rel, "§9 egg", f"unreadable egg: {exc}")

    if findings:
        return "DRIFT", findings, evidence
    if not has_artifact:
        return "CLEAN", [], []
    return "COMPLIANT", findings, evidence


def main():
    args = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__.strip().splitlines()[-2])
        sys.exit(2)
    root = args[0]
    try:
        verdict, findings, evidence = check_repo(root)
    except OSError as exc:
        if as_json:
            print(json.dumps({"repo": root, "error": str(exc)}, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    if as_json:
        print(
            json.dumps(
                {
                    "repo": root,
                    "verdict": verdict,
                    "findings": findings,
                    "evidence": evidence,
                },
                indent=2,
            )
        )
    else:
        name = os.path.basename(os.path.abspath(root))
        dot = {"CLEAN": "○", "COMPLIANT": "✅", "DRIFT": "🔧"}
        print(f"{dot[verdict]} {name}: {verdict}")
        for item in evidence:
            mark = "?" if item.get("status") == "unverified" else "✓"
            print(f"    {mark} {item['artifact']}: {item['ok']}")
        for item in findings:
            print(
                f"    ✗ {item['artifact']}  [{item['rule']}]  {item['detail']}"
            )
    sys.exit(1 if verdict == "DRIFT" else 0)


if __name__ == "__main__":
    main()
