"""Bounded, read-only RAPP artifact linting (stdlib, Python >= 3.9).

Usage: python3 rapp_check.py <repo_path> [--json]

COMPLIANT means only that the discovered artifacts pass the measured local
structure/hash checks. It is NOT authenticated Consumer conformance: this tool
has no trusted stream-of-record, signed registry, signature verifier, or persisted
head. Kind families are never inferred from kind names.

DRIFT is a refused artifact; INCOMPLETE is missing context or unread coverage;
NO_ARTIFACTS is no measured artifact evidence; ERROR is an unusable input root.
Exit: 0 scoped COMPLIANT, 1 DRIFT/INCOMPLETE, 2 NO_ARTIFACTS/ERROR.
The JSON report describes discovery, exclusions, counts, and the unmeasured gates.
"""
import argparse
from collections import defaultdict
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat

import rapp as R


_32HEX = re.compile(r"[0-9a-f]{32}")
_NUMBERED = re.compile(r"[0-9]+\.json", re.IGNORECASE)
# These are local scan budgets, not changes to the frozen §4 input domain.
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_JSONL_BYTES = 64 * 1024 * 1024
MAX_EGG_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILES = 20000
MAX_DOCUMENTS = 20000
MAX_JSONL_LINES = 20000
EXIT_CODES = {"COMPLIANT": 0, "DRIFT": 1, "INCOMPLETE": 1,
              "NO_ARTIFACTS": 2, "ERROR": 2}


def _declared_type(path):
    if path.name == "rappid.json":
        return "identity"
    if path.suffix.lower() == ".egg":
        return "egg"
    if path.suffix.lower() == ".jsonl":
        return ("frame-stream" if path.name.lower() in ("chain.jsonl", "frames.jsonl")
                or any(p in ("frames", "events") for p in path.parts[:-1]) else None)
    if "frames" in path.parts[:-1]:
        return "frame"
    return None


def _document_type(value):
    if not isinstance(value, dict):
        return None
    keys = set(value)
    if (value.get("spec") == R.SPEC
            or {"kind", "payload", "stream_id"} <= keys
            or {"payload", "payload_hash", "frame_hash"} <= keys):
        return "frame"
    if value.get("schema") == "rapp/1-egg":
        return "egg"
    if value.get("schema") == R.SPEC and "rappid" in value:
        return "identity"
    return None


def _verify_frame(frame, head=None, stream_id=None):
    if not isinstance(frame, dict):
        return False, "1", "frame MUST be an object"
    try:
        return R.verify_frame(frame, head=head, stream_id_of_record=stream_id)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        return False, "input-domain", f"{type(exc).__name__}: {exc}"


class _Scan:
    def __init__(self, root):
        self.root = Path(os.path.abspath(root))
        self.repo = os.fspath(root)
        self.findings = []
        self.evidence = []
        self.records = []
        self.chains = []
        self.containers = []
        self.root_error = False
        self.counts = dict.fromkeys((
            "files_seen", "json_files", "jsonl_files", "jsonl_records",
            "blank_jsonl_lines", "documents_attempted", "documents_parsed", "bytes_read",
            "identities", "frames", "unique_frames", "duplicate_frame_copies",
            "eggs", "verified_identities", "verified_frames", "verified_eggs",
        ), 0)
        self.coverage = {
            "complete_within_supported_forms": True,
            "supported": [
                "rappid.json identity records",
                "*.json under frames/ (declared frames, including named/hash files)",
                "top-level frame, rapp/1 identity, and rapp/1-egg objects in *.json",
                "one top-level frame per nonblank *.jsonl line; one stream per log",
                "*.egg via the shared verifier, without extraction or execution",
            ],
            "not_measured": [
                "nested fixture/configuration containers and source/documentation strings",
                "registry, anchor selection/beacon/index authority, and subordinate profiles",
                "other file formats, archive discovery, remote paths, and followed symlinks",
            ],
            "limits": {
                "json_file_or_line_bytes": MAX_JSON_BYTES,
                "jsonl_file_bytes": MAX_JSONL_BYTES,
                "egg_file_bytes": MAX_EGG_BYTES,
                "total_read_bytes": MAX_TOTAL_BYTES,
                "files": MAX_FILES,
                "json_documents": MAX_DOCUMENTS,
                "jsonl_lines_per_file": MAX_JSONL_LINES,
            },
            "counting": (
                "frames counts declared/recognized occurrences, including refusals; "
                "unique_frames deduplicates strict-parsed complete values (including sig "
                "and the seq integer-versus-fraction/exponent distinction), "
                "not just claimed hashes; verified_frames counts unique local checks passed. "
                "Counts stop at disclosed resource exclusions; reads use one overflow sentinel byte."
            ),
            "exclusions": [],
            "ignored_extensions": {},
        }

    def source(self, path, raw=None, line=None, offset=0):
        rel = os.path.relpath(path, self.root)
        source = {"artifact": rel if line is None else f"{rel}:{line}",
                  "path": os.fspath(path), "line": line, "byte_offset": offset,
                  "size_bytes": None, "sha256": None}
        if raw is not None:
            source.update(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        return source

    def record(self, kind, source, value=None, container=None):
        rec = {"type": kind, "source": source, "status": "pending",
               "value": value, "container": container}
        self.records.append(rec)
        key = {"identity": "identities", "frame": "frames", "egg": "eggs"}.get(kind)
        if key:
            self.counts[key] += 1
        return rec

    def refuse(self, rec, rule, detail, disposition="drift", step=None):
        if rec["status"] != "refused":
            rec["status"] = "refused" if disposition == "drift" else "incomplete"
        finding = {**rec["source"], "type": rec["type"], "rule": rule,
                   "detail": str(detail), "disposition": disposition}
        if step is not None:
            finding["step"] = step
        self.findings.append(finding)

    def exclude(self, source, reason, incomplete=False):
        self.coverage["exclusions"].append({
            **source, "reason": reason, "affects_gate": incomplete,
        })
        if incomplete:
            self.coverage["complete_within_supported_forms"] = False

    def unread(self, kind, source, reason):
        rec = self.record(kind or "unclassified-json", source)
        self.refuse(rec, "unread-coverage", reason, "incomplete")
        self.exclude(source, reason, incomplete=True)

    def passed(self, rec, detail, checks):
        rec["checks"] = checks
        if rec["status"] in ("refused", "incomplete"):
            return
        rec["status"] = "verified"
        self.evidence.append({**rec["source"], "ok": detail,
                              "scope": "local-structural-hash", "checks": checks})

    def read(self, path, kind, limit):
        source = self.source(path)
        try:
            before = path.lstat()
            source["size_bytes"] = before.st_size
            if not stat.S_ISREG(before.st_mode):
                self.unread(kind, source, "not a regular file; symlinks/devices are not read")
                return None, source
            budget = min(limit, MAX_TOTAL_BYTES - self.counts["bytes_read"])
            if before.st_size > budget:
                self.unread(kind, source, f"local resource limit: file bytes {before.st_size}, "
                            f"remaining per-file/total budget {budget}; no bytes parsed")
                return None, source
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(path, flags), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    self.unread(kind, source, "opened input is not a regular file")
                    return None, source
                raw = stream.read(budget + 1)
                after = os.fstat(stream.fileno())
            self.counts["bytes_read"] += len(raw)
            if len(raw) > budget:
                self.unread(kind, source, "local read budget exceeded while reading changing input")
                return None, source
            source = self.source(path, raw)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or len(raw) != after.st_size):
                self.unread(kind, source, "input changed during read; no stable snapshot")
                return None, source
            return raw, source
        except OSError as exc:
            self.unread(kind, source, f"{type(exc).__name__}: {exc}")
            return None, source

    def parse(self, raw, source, declared):
        if self.counts["documents_attempted"] >= MAX_DOCUMENTS or len(raw) > MAX_JSON_BYTES:
            self.unread(declared, source, "local JSON document/line resource limit exceeded")
            return False, None
        self.counts["documents_attempted"] += 1
        try:
            value = R._strict_json(raw)
            self.counts["documents_parsed"] += 1
            return True, value
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
            rec = self.record(declared or "unclassified-json", source)
            self.refuse(rec, "§4 strict JSON", f"{type(exc).__name__}: {exc}",
                        "drift" if declared else "incomplete", step="parse")
            if not declared:
                self.exclude(source, "strict parse refused; artifact type cannot be determined",
                             incomplete=True)
            return False, None

    def identity(self, rec):
        value = rec["value"]
        if not isinstance(value, dict):
            self.refuse(rec, "§6 identity", "identity record MUST be an object")
            return
        rid = value.get("rappid")
        tail = rid.rsplit(":", 1)[-1] if isinstance(rid, str) else ""
        template = bool(re.fullmatch(r"__[A-Z0-9_]+__", tail))
        if template:
            rec["status"] = "template"
            self.evidence.append({**rec["source"],
                                  "ok": "plant-template; no deployed identity verified",
                                  "scope": "scaffolding-only"})
        elif R.rappid_valid(rid):
            parts = R.rappid_parts(rid)
            name_hash = hashlib.sha256(
                f"{parts['owner']}/{parts['slug']}".encode("utf-8")).hexdigest()
            if tail == name_hash:
                self.refuse(rec, "§6.2 name-hash mint", "identity tail equals sha256(owner/slug)")
        else:
            rule = "§6.1 short-tail (C3)" if _32HEX.fullmatch(tail) else "§6.1 grammar (C2)"
            self.refuse(rec, rule, "not rappid:@owner/slug:64hex")
        if value.get("schema") != R.SPEC:
            self.refuse(rec, "§12 schema label", "identity schema MUST be rapp/1")
        parent = value.get("parent_rappid")
        if parent is not None and not R.rappid_valid(parent):
            self.refuse(rec, "§6.3 parent_rappid", "parent_rappid is not RAPP grammar")
        if not template:
            self.passed(rec, "identity grammar/schema and name-hash exclusion pass",
                        ["strict JSON", "identity grammar", "schema", "name-hash exclusion"])

    def egg(self, rec, raw):
        try:
            ok, step, why = R.verify_egg(raw)
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
            ok, step, why = False, "verification-error", f"{type(exc).__name__}: {exc}"
        if ok:
            self.passed(rec, "shared egg integrity/viability checks pass; no extraction or execution",
                        ["shared egg verifier", "archive/path checks", "integrity", "viability"])
        else:
            self.refuse(rec, "§9 egg", why, step=step)

    def document(self, raw, source, declared=None, container=None):
        parsed, value = self.parse(raw, source, declared)
        if not parsed:
            return None
        kind = declared or _document_type(value)
        if kind is None:
            self.exclude(source, "not a declared top-level artifact; nested/config/source "
                         "values are not interpreted as frames")
            return None
        rec = self.record(kind, source, value, container)
        if kind == "identity":
            self.identity(rec)
        elif kind == "egg":
            self.egg(rec, raw)
        return rec

    def jsonl(self, path, raw):
        relative = path.relative_to(self.root)
        declared = (path.name.lower() in ("chain.jsonl", "frames.jsonl")
                    or "frames" in relative.parts[:-1] or "events" in relative.parts[:-1])
        items, offset = [], 0
        for line, octets in enumerate(io.BytesIO(raw), 1):
            source = self.source(path, octets, line, offset)
            if (line > MAX_JSONL_LINES
                    or self.counts["documents_attempted"] >= MAX_DOCUMENTS):
                source["remaining_bytes"] = len(raw) - offset
                self.unread("frame-stream" if declared else "jsonl", source,
                            "local JSONL line/document limit; this and remaining records unmeasured")
                break
            offset += len(octets)
            if not octets.strip():
                self.counts["blank_jsonl_lines"] += 1
                continue
            self.counts["jsonl_records"] += 1
            parsed, value = self.parse(octets, source, "frame" if declared else None)
            if parsed:
                items.append((octets, source, value))
        is_stream = declared or any(_document_type(value) == "frame" for _, _, value in items)
        if is_stream and not items and not raw.strip():
            self.unread("frame-stream", self.source(path, raw), "declared stream contains no frames")
        for octets, source, value in items:
            if is_stream:
                self.record("frame", source, value, os.fspath(relative))
            elif _document_type(value) is not None:
                self.unread(_document_type(value), source,
                            "unsupported declared artifact in JSONL; only frame streams are supported")
            else:
                self.exclude(source, "JSONL record is not a top-level frame; "
                             "non-frame logs/containers are not interpreted as streams")

    def walk(self):
        try:
            if not stat.S_ISDIR(self.root.lstat().st_mode):
                raise OSError("input root MUST be a real directory, not a file or symlink")
        except OSError as exc:
            self.root_error = True
            self.unread("root", self.source(self.root), str(exc))
            return

        def onerror(exc):
            path = Path(exc.filename) if exc.filename else self.root
            if path == self.root:
                self.root_error = True
            self.unread("directory", self.source(path), f"{type(exc).__name__}: {exc}")

        for directory, dirs, files in os.walk(self.root, onerror=onerror, followlinks=False):
            dirs.sort()
            for name in list(dirs):
                path = Path(directory) / name
                if name == ".git":
                    dirs.remove(name)
                    self.exclude(self.source(path), "VCS metadata is outside discovery")
                elif path.is_symlink():
                    dirs.remove(name)
                    self.unread("directory", self.source(path), "symlink directory not traversed")
            for name in sorted(files):
                self.counts["files_seen"] += 1
                path = Path(directory) / name
                if self.counts["files_seen"] > MAX_FILES:
                    self.unread("directory", self.source(path), "local file-count limit exceeded; "
                                "remaining tree not scanned")
                    return
                suffix = path.suffix.lower()
                if suffix not in (".json", ".jsonl", ".egg"):
                    counts = self.coverage["ignored_extensions"]
                    counts[suffix or "(none)"] = counts.get(suffix or "(none)", 0) + 1
                    continue
                relative = path.relative_to(self.root)
                declared = _declared_type(relative)
                limit = {".json": MAX_JSON_BYTES, ".jsonl": MAX_JSONL_BYTES,
                         ".egg": MAX_EGG_BYTES}[suffix]
                if suffix in (".json", ".jsonl"):
                    self.counts["json_files" if suffix == ".json" else "jsonl_files"] += 1
                raw, source = self.read(path, declared, limit)
                if raw is None:
                    continue
                if suffix == ".egg":
                    self.egg(self.record("egg", source), raw)
                elif suffix == ".jsonl":
                    self.jsonl(path, raw)
                else:
                    container = os.fspath(relative.parent) if declared == "frame" else None
                    self.document(raw, source, declared, container)

    def frames(self):
        records = [r for r in self.records if r["type"] == "frame" and r["status"] == "pending"]
        nodes, containers = {}, defaultdict(list)
        for rec in records:
            value = rec["value"]
            sequence_type = type(value.get("seq")).__name__ if isinstance(value, dict) else None
            # JCS maps 0, 0.0 and 0e0 to the same bytes, but §7.4 admits only
            # integer seq syntax. A valid copy cannot certify a forbidden one.
            key = (R.canonical(value), sequence_type)
            nodes.setdefault(key, []).append(rec)
            rec["canonical_key"] = key
            if rec["container"] is not None:
                containers[rec["container"]].append(rec)
        self.counts["unique_frames"] = len(nodes)
        self.counts["duplicate_frame_copies"] = len(records) - len(nodes)

        def seq(rec):
            value = rec["value"]
            number = value.get("seq") if isinstance(value, dict) else None
            return number if isinstance(number, int) and not isinstance(number, bool) else -1

        for name, group in sorted(containers.items()):
            jsonl = group[0]["source"]["line"] is not None
            numbered = not jsonl and all(
                _NUMBERED.fullmatch(Path(r["source"]["path"]).name) for r in group)
            group.sort(key=lambda r: (
                r["source"]["line"] if jsonl else
                int(Path(r["source"]["path"]).stem) if numbered else seq(r),
                r["source"]["artifact"]))
            first = next((r for r in group if isinstance(r["value"], dict)
                          and isinstance(r["value"].get("stream_id"), str)), None)
            sid = first["value"]["stream_id"] if first is not None else None
            self.containers.append({
                "artifact": name, "stream_id": sid, "binding": "inferred-not-authenticated",
                "inferred_from": first["source"]["artifact"] if first else None,
                "ordering": "line" if jsonl else "numeric-filename" if numbered else "frame-seq",
            })
            seen, prior = set(), None
            for rec in group:
                value = rec["value"]
                if first is not None and isinstance(value, dict) and value.get("stream_id") != sid:
                    self.refuse(rec, "§7.5 stream binding", "stream_id differs from the fixed "
                                f"local container identity inferred at {first['source']['artifact']}",
                                step="1a")
                if rec["canonical_key"] in seen:
                    continue
                seen.add(rec["canonical_key"])
                if (jsonl or numbered) and prior is not None and seq(rec) < seq(prior):
                    self.refuse(rec, "§7.6 source order", "distinct frame moves backwards in "
                                "the declared source order; history was not reordered")
                prior = rec

        streams = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for copies in nodes.values():
            frame = copies[0]["value"]
            ok, step, why = _verify_frame(frame)
            if not ok and step not in ("4", "5", "6"):
                for rec in copies:
                    self.refuse(rec, "§7.5 frame", why, step=step)
                continue
            streams[frame["stream_id"]][frame["seq"]][frame["frame_hash"]].append(copies)

        for sid, positions in sorted(streams.items()):
            head, fork_at, state = None, None, "complete-local"
            for number, waves in sorted(positions.items()):
                if len(waves) > 1 and fork_at is None:
                    fork_at = number
                structural_head = None
                for variants in waves.values():
                    for copies in variants:
                        frame = copies[0]["value"]
                        if fork_at is not None:
                            state = "refused"
                            for rec in copies:
                                self.refuse(rec, "§7.6 fork", f"conflicting same-stream frames "
                                            f"at seq {fork_at}; neither branch nor descendants selected")
                            continue
                        if not any(rec["status"] == "pending" for rec in copies):
                            state = "refused"
                            continue
                        ok, step, why = _verify_frame(frame, head, sid)
                        if (step == "4" and number > (head["seq"] + 1 if head else 0)):
                            state = "partial" if state != "refused" else state
                            for rec in copies:
                                rec["checks"] = ["strict JSON", "shape/hash prefix (steps 1-3 only)"]
                                self.refuse(rec, "§7.5 missing chain context",
                                            "no verified local predecessor/genesis; only shape and "
                                            "particle/wave hashes measured, not full chain/wire",
                                            "incomplete", step="4")
                        elif ok:
                            structural_head = frame
                            for rec in copies:
                                self.passed(rec, "frame structure/hashes and local chain pass; "
                                            "kind registry and authenticated stream binding unmeasured",
                                            ["strict JSON", "shape", "particle", "wave",
                                             "local chain", "wire", "unsigned signature policy"])
                        elif step == "6":
                            structural_head = frame
                            missing_signature = frame["sig"] is None
                            if missing_signature:
                                state = "refused"
                            elif state == "complete-local":
                                state = "unverified-signature"
                            for rec in copies:
                                self.refuse(rec, "§7.5 signature", why,
                                            "drift" if missing_signature else "incomplete", step=step)
                        else:
                            state = "refused"
                            for rec in copies:
                                self.refuse(rec, "§7.5 frame", why, step=step)
                # No synthetic predecessor, overwrite, re-parent, or fork selection.
                if structural_head is not None and fork_at is None:
                    head = structural_head
            self.chains.append({
                "stream_id": sid, "status": state, "binding": "inferred-not-authenticated",
                "genesis_registration": "not-measured",
                "locally_verified_through_seq": head["seq"] if head is not None else None,
                "fork_at_seq": fork_at,
            })
        self.counts["verified_frames"] = sum(
            any(r["status"] == "verified" for r in copies) for copies in nodes.values())

    def report(self):
        self.walk()
        self.frames()
        for kind in ("identities", "eggs"):
            name = "identity" if kind == "identities" else "egg"
            self.counts["verified_" + kind] = sum(
                r["type"] == name and r["status"] == "verified" for r in self.records)
        measured = sum(self.counts["verified_" + name] for name in ("identities", "frames", "eggs"))
        if self.root_error:
            verdict = "ERROR"
        elif any(f["disposition"] == "drift" for f in self.findings):
            verdict = "DRIFT"
        elif self.findings:
            verdict = "INCOMPLETE"
        else:
            verdict = "COMPLIANT" if measured else "NO_ARTIFACTS"
        return {
            "repo": self.repo, "verdict": verdict, "exit_code": EXIT_CODES[verdict],
            "scope": {
                "name": "local-structural-hash",
                "consumer_conformance": "not-measured", "authenticated_acceptance": False,
                "chain_context": "union of strict local artifacts, not a persisted/trusted head",
                "unmeasured": [
                    "authenticated stream-of-record binding",
                    "signed/fresh registry adoption, kind-family and genesis registration",
                    "signature authority, owner tenure and tombstones",
                    "identity mint/ownership and lineage authority",
                    "persisted monotonic heads, trusted head freshness and owner fork resolution",
                ],
            },
            "gates": {
                "discovery": "pass" if self.coverage["complete_within_supported_forms"] else "incomplete",
                "local_artifacts": ("pass" if verdict == "COMPLIANT" else
                                    "unmeasured" if verdict in ("NO_ARTIFACTS", "ERROR") else
                                    "fail" if verdict == "DRIFT" else "incomplete"),
                "consumer_authority": "unmeasured",
            },
            "counts": self.counts, "coverage": self.coverage,
            "containers": self.containers, "chains": self.chains,
            "findings": self.findings, "evidence": self.evidence,
            "artifacts": [{**r["source"], "type": r["type"], "status": r["status"],
                           "checks": r.get("checks", [])} for r in self.records],
        }


def scan_repo(root):
    """Return a counted, scoped report. No registry authentication is performed."""
    return _Scan(root).report()


def check_repo(root):
    """Compatibility tuple: (scoped verdict, findings, evidence); see scan_repo for scope."""
    report = scan_repo(root)
    return report["verdict"], report["findings"], report["evidence"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = scan_repo(args.repo_path)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{args.repo_path}: {report['verdict']} (local structure/hash scope only)")
        counts = report["counts"]
        print(f"    {counts['identities']} identities, {counts['frames']} frame occurrences "
              f"({counts['unique_frames']} unique, {counts['duplicate_frame_copies']} copies), "
              f"{counts['eggs']} eggs; Consumer authority NOT measured")
        for item in report["findings"]:
            print(f"    ! {item['artifact']} [{item['rule']}] {item['detail']}")
        print(f"    Coverage: {report['gates']['discovery']}; "
              f"{len(report['coverage']['exclusions'])} exclusions (details with --json)")
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
