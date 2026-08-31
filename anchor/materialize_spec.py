#!/usr/bin/env python3
"""Verify the RAPP/1 specification chain and materialize a normative revision."""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import sys
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Sequence


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rapp as R
from anchor import bootstrap_verify as B


CHAIN_PATH = ROOT / "anchor" / "chain.jsonl"
ORIENT_PATH = ROOT / "anchor" / "orient.json"
INDEX_PATH = ROOT / "anchor" / "index.json"
BOOTSTRAP_INDEX_PATH = ROOT / "anchor" / "bootstrap" / "index.json"
CHAIN_URL = "https://raw.githubusercontent.com/kody-w/rapp-1/main/anchor/chain.jsonl"
ORIENT_URL = "https://raw.githubusercontent.com/kody-w/rapp-1/main/anchor/orient.json"
INDEX_URL = "https://raw.githubusercontent.com/kody-w/rapp-1/main/anchor/index.json"
REPOSITORY_RAW_URL = "https://raw.githubusercontent.com/kody-w/rapp-1/main/"
REVISION_SCHEMA = "rapp-spec-revision/1"
NORMATIVE_MEDIA_TYPE = "text/markdown; charset=utf-8"
MAX_FETCH_BYTES = 64 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
REVISION = re.compile(r"rev-[1-9][0-9]*")
GITHUB_REPOSITORY = re.compile(
    r"https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"([A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?)"
)
Fetcher = Callable[[str], bytes]
AUTHORITY_POLICY = {
    "canonical_repository": "https://github.com/kody-w/rapp-1",
    "protected_ref": "refs/heads/main",
    "selection": "owner-ratified acceptance of the chain snapshot onto protected canonical main",
    "linearization": "the accepted canonical-main commit containing the new frame",
    "history_replacement": "prohibited",
    "competing_append": "must rebase onto the accepted head and regenerate",
    "transition": "rev-14-ratified-under-rev-13-article-14",
    "chain_append_process": "governs-rev-15-and-later",
    "authenticated_registry_checkpoint": None,
}


class ChainError(ValueError):
    """The chain, beacon, or revision payload is invalid."""


class ResolutionError(ValueError):
    """A requested revision cannot be resolved safely."""


def sha256(octets: bytes) -> str:
    return hashlib.sha256(octets).hexdigest()


def _hex(value: object, length: int, label: str) -> str:
    pattern = HEX40 if length == 40 else HEX64
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ChainError(f"{label} must be {length} lowercase hex")
    return value


def _byte_length(value: object, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise ChainError(f"{label} must be a canonical decimal string")
    result = int(value)
    if result > R.MAX_CANONICAL_BYTES:
        raise ChainError(f"{label} exceeds the RAPP/1 canonical-byte limit")
    return result


def _safe_normative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith(("/", "./"))
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or "%" in value
    ):
        raise ChainError("normative_path must be a relative POSIX path")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ChainError("normative_path is not valid UTF-8 text") from error
    raw_parts = value.split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        raise ChainError("normative_path contains an unsafe raw component")
    candidate = pathlib.PurePosixPath(value)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or list(candidate.parts) != raw_parts
        or candidate.as_posix() != value
    ):
        raise ChainError("normative_path changes under POSIX reconstruction")
    return value


def _legacy_metadata(payload: object) -> Dict[str, object]:
    if not isinstance(payload, dict):
        raise ChainError("revision payload must be an object")
    required = {
        "revision",
        "canonical_repo",
        "commit",
        "normative_path",
        "normative_sha256",
        "normative_bytes",
    }
    missing = required - set(payload)
    if missing:
        raise ChainError(f"revision payload is missing legacy fields: {sorted(missing)}")
    revision = payload["revision"]
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ChainError("revision must match rev-N")
    repository = payload["canonical_repo"]
    if not isinstance(repository, str) or not GITHUB_REPOSITORY.fullmatch(repository):
        raise ChainError("canonical_repo must be an immutable-fetchable GitHub HTTPS repository")
    return {
        "revision": revision,
        "canonical_repo": repository,
        "commit": _hex(payload["commit"], 40, "commit"),
        "normative_path": _safe_normative_path(payload["normative_path"]),
        "normative_sha256": _hex(
            payload["normative_sha256"], 64, "normative_sha256"
        ),
        "normative_bytes": _byte_length(
            payload["normative_bytes"], "normative_bytes"
        ),
    }


def _inline_normative(payload: Dict[str, object]) -> bytes:
    if payload.get("schema") != REVISION_SCHEMA:
        raise ChainError(f"unsupported specification revision schema: {payload.get('schema')!r}")
    normative = payload.get("normative")
    if not isinstance(normative, dict) or set(normative) != {
        "media_type",
        "text",
        "sha256",
        "bytes",
    }:
        raise ChainError("inline normative object must have exactly media_type,text,sha256,bytes")
    if normative["media_type"] != NORMATIVE_MEDIA_TYPE:
        raise ChainError("inline normative media_type is unsupported")
    if not isinstance(normative["text"], str):
        raise ChainError("inline normative text must be Unicode text")
    try:
        octets = normative["text"].encode("utf-8")
    except UnicodeEncodeError as error:
        raise ChainError("inline normative text is malformed UTF-8") from error
    if octets.startswith(b"\xef\xbb\xbf"):
        raise ChainError("inline normative text must not carry a UTF-8 BOM")
    if (
        not isinstance(normative["bytes"], int)
        or isinstance(normative["bytes"], bool)
        or normative["bytes"] < 0
        or normative["bytes"] > R.MAX_CANONICAL_BYTES
    ):
        raise ChainError("inline normative bytes must be a bounded uint53")
    expected_hash = _hex(normative["sha256"], 64, "inline normative sha256")
    if len(octets) != normative["bytes"]:
        raise ChainError("inline normative byte length mismatch")
    if sha256(octets) != expected_hash:
        raise ChainError("inline normative SHA-256 mismatch")
    legacy = _legacy_metadata(payload)
    if legacy["normative_sha256"] != expected_hash:
        raise ChainError("legacy and inline normative SHA-256 values disagree")
    if legacy["normative_bytes"] != len(octets):
        raise ChainError("legacy and inline normative byte lengths disagree")
    return octets


def load_bootstrap(
    *,
    index_octets: Optional[bytes] = None,
    profile_octets: Optional[bytes] = None,
    verifier_octets: Optional[bytes] = None,
) -> tuple[dict, dict]:
    verifier_octets = (
        (ROOT / "anchor" / "bootstrap_verify.py").read_bytes()
        if verifier_octets is None
        else verifier_octets
    )
    index_octets = (
        BOOTSTRAP_INDEX_PATH.read_bytes()
        if index_octets is None
        else index_octets
    )
    try:
        index = B.strict_json(index_octets)
    except B.BootstrapError as error:
        raise ChainError(f"invalid bootstrap index: {error}") from error
    if not isinstance(index, dict):
        raise ChainError("bootstrap index must be an object")
    if profile_octets is None:
        profile_path = index.get("profile_path")
        if not isinstance(profile_path, str):
            raise ChainError("bootstrap index has no profile_path")
        candidate = (ROOT / profile_path).resolve()
        bootstrap_root = (ROOT / "anchor" / "bootstrap").resolve()
        if candidate.parent != bootstrap_root:
            raise ChainError("bootstrap profile path escapes anchor/bootstrap")
        profile_octets = candidate.read_bytes()
    try:
        B.verify_bootstrap_index(index_octets, profile_octets, verifier_octets)
        profile = B.verify_profile(profile_octets, verifier_octets)
    except B.BootstrapError as error:
        raise ChainError(f"bootstrap verification failed: {error}") from error
    return profile, index


def parse_chain(chain_octets: bytes) -> List[dict]:
    if not isinstance(chain_octets, bytes):
        raise ChainError("chain input must be bytes")
    if not chain_octets or not chain_octets.endswith(b"\n"):
        raise ChainError("chain must be non-empty JSONL ending in LF")
    if b"\r" in chain_octets:
        raise ChainError("chain JSONL must use LF line endings")
    try:
        chain_octets.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ChainError("chain is not valid UTF-8") from error
    frames = []
    for line_number, line in enumerate(chain_octets.splitlines(), 1):
        if not line:
            raise ChainError(f"blank chain line at {line_number}")
        try:
            frame = R._strict_json(line)
        except (UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise ChainError(f"invalid chain JSON at line {line_number}: {error}") from error
        if not isinstance(frame, dict):
            raise ChainError(f"chain line {line_number} is not a frame object")
        frames.append(frame)
    return frames


def verify_chain(
    chain_octets: bytes,
    *,
    bootstrap_profile: Optional[dict] = None,
    allow_unpublished_rev14_draft: bool = False,
) -> List[dict]:
    if bootstrap_profile is None:
        bootstrap_profile, _ = load_bootstrap()
    try:
        bootstrap_frames = B.verify_chain(chain_octets, bootstrap_profile)
    except B.BootstrapError as error:
        raise ChainError(f"bootstrap chain verification failed: {error}") from error
    frames = parse_chain(chain_octets)
    if frames != bootstrap_frames:
        raise ChainError("bootstrap and reference parsers disagree")
    stream_id = frames[0].get("stream_id")
    if not R.rappid_valid(stream_id):
        raise ChainError("anchor stream_id must be a body-stream RAPPID")
    seen_seq = {}
    seen_frame_hash = set()
    seen_payload_hash = set()
    children = {}
    revision_frames: Dict[str, List[dict]] = {}
    schema_seen = False
    head = None
    for line_number, frame in enumerate(frames, 1):
        seq = frame.get("seq")
        frame_hash_value = frame.get("frame_hash")
        payload_hash_value = frame.get("payload_hash")
        parent = frame.get("prev")
        if (
            not isinstance(seq, int)
            or isinstance(seq, bool)
            or not 0 <= seq <= 2**53 - 1
        ):
            raise ChainError(f"frame at line {line_number} has invalid scalar seq")
        for label, value in (
            ("frame_hash", frame_hash_value),
            ("payload_hash", payload_hash_value),
        ):
            if not isinstance(value, str) or not HEX64.fullmatch(value):
                raise ChainError(
                    f"frame at line {line_number} has invalid scalar {label}"
                )
        if parent is not None and (
            not isinstance(parent, str) or not HEX64.fullmatch(parent)
        ):
            raise ChainError(f"frame at line {line_number} has invalid scalar prev")
        if seq in seen_seq:
            raise ChainError(
                f"duplicate seq/fork at {seq}: lines {seen_seq[seq]} and {line_number}"
            )
        if frame_hash_value in seen_frame_hash:
            raise ChainError(f"duplicate frame_hash at line {line_number}")
        if payload_hash_value in seen_payload_hash:
            raise ChainError(f"duplicate payload_hash at line {line_number}")
        if parent is not None and parent in children:
            raise ChainError(
                f"fork: payload {parent} has children at lines "
                f"{children[parent]} and {line_number}"
            )
        ok, step, reason = R.verify_frame(
            frame,
            head=head,
            stream_id_of_record=stream_id,
        )
        if not ok:
            raise ChainError(
                f"frame at line {line_number} refused at RAPP/1 step {step}: {reason}"
            )
        if frame["kind"] != "body.pulse":
            raise ChainError("specification revisions must use registered kind body.pulse")
        if len(R.canonical(frame).encode("utf-8")) > R.MAX_CANONICAL_BYTES:
            raise ChainError(f"frame at line {line_number} exceeds 1 MiB")
        payload = frame["payload"]
        legacy = _legacy_metadata(payload)
        revision = legacy["revision"]
        schema = payload.get("schema")
        if schema is not None:
            schema_seen = True
            if schema != REVISION_SCHEMA:
                raise ChainError(f"unsupported specification revision schema: {schema!r}")
            if revision in revision_frames:
                raise ChainError(f"duplicate specification revision: {revision}")
            if head is None:
                raise ChainError("inline specification revision cannot be genesis")
            previous = head["payload"]
            if payload.get("previous_revision") != previous.get("revision"):
                raise ChainError("previous_revision does not name the predecessor")
            if (
                payload.get("previous_normative_sha256")
                != previous.get("normative_sha256")
            ):
                raise ChainError("previous_normative_sha256 does not match the predecessor")
            _inline_normative(payload)
            if payload.get("publication") != AUTHORITY_POLICY and not (
                allow_unpublished_rev14_draft
                and revision == "rev-14"
                and line_number == len(frames)
            ):
                raise ChainError("revision publication/ratification metadata drift")
        elif schema_seen:
            raise ChainError("legacy pointer frame cannot follow an inline revision frame")
        elif revision in revision_frames and not (
            revision == "rev-5"
            and frame["seq"] <= 5
            and all(existing["seq"] <= 5 for existing in revision_frames[revision])
        ):
            raise ChainError(f"duplicate specification revision: {revision}")
        revision_frames.setdefault(revision, []).append(frame)
        seen_seq[seq] = line_number
        seen_frame_hash.add(frame_hash_value)
        seen_payload_hash.add(payload_hash_value)
        if parent is not None:
            children[parent] = line_number
        head = frame
    return frames


def resolve_frame(
    frames: Sequence[dict],
    *,
    revision: Optional[str] = None,
    seq: Optional[int] = None,
    frame_hash: Optional[str] = None,
    payload_hash: Optional[str] = None,
) -> dict:
    selectors = [
        revision is not None,
        seq is not None,
        frame_hash is not None,
        payload_hash is not None,
    ]
    if sum(selectors) > 1:
        raise ResolutionError("choose exactly one revision selector")
    if not any(selectors):
        return frames[-1]
    if revision is not None:
        matches = [frame for frame in frames if frame["payload"]["revision"] == revision]
        if not matches:
            raise ResolutionError(f"unknown revision: {revision}")
        return max(matches, key=lambda frame: frame["seq"])
    if seq is not None:
        matches = [frame for frame in frames if frame["seq"] == seq]
    elif frame_hash is not None:
        _hex(frame_hash, 64, "frame_hash selector")
        matches = [frame for frame in frames if frame["frame_hash"] == frame_hash]
    else:
        _hex(payload_hash, 64, "payload_hash selector")
        matches = [frame for frame in frames if frame["payload_hash"] == payload_hash]
    if len(matches) != 1:
        raise ResolutionError("revision selector did not resolve exactly one frame")
    return matches[0]


def _frame_entry(frame: dict) -> dict:
    return {
        "seq": frame["seq"],
        "revision": frame["payload"]["revision"],
        "frame_hash": frame["frame_hash"],
        "payload_hash": frame["payload_hash"],
        "object_path": f"anchor/frames/{frame['frame_hash']}.json",
        "payload_profile": (
            REVISION_SCHEMA
            if frame["payload"].get("schema") == REVISION_SCHEMA
            else "legacy-immutable-pointer"
        ),
    }


def _local_object_loader(path: str) -> bytes:
    candidate = (ROOT / path).resolve()
    frame_root = (ROOT / "anchor" / "frames").resolve()
    if candidate.parent != frame_root:
        raise ChainError("frame object path escapes anchor/frames")
    return candidate.read_bytes()


def verify_revision_index(
    index_octets: bytes,
    frames: Sequence[dict],
    *,
    object_loader: Optional[Fetcher] = None,
    bootstrap_index: Optional[dict] = None,
    bootstrap_profile: Optional[dict] = None,
) -> dict:
    try:
        index = R._strict_json(index_octets)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ChainError(f"invalid anchor/index.json: {error}") from error
    if not isinstance(index, dict) or set(index) != {
        "schema",
        "generated_utc",
        "canonical_repository",
        "canonical_ref",
        "chain_path",
        "checkpoint_url_template",
        "frame_discovery_url_template",
        "authority",
        "bootstrap",
        "head",
        "entries",
    }:
        raise ChainError("anchor/index.json has an unexpected shape")
    if index["schema"] != "rapp-spec-chain-index/1":
        raise ChainError("anchor/index.json has the wrong schema")
    if index["canonical_repository"] != AUTHORITY_POLICY["canonical_repository"]:
        raise ChainError("anchor/index.json names the wrong canonical repository")
    if index["canonical_ref"] != AUTHORITY_POLICY["protected_ref"]:
        raise ChainError("anchor/index.json names the wrong canonical ref")
    if index["chain_path"] != "anchor/chain.jsonl":
        raise ChainError("anchor/index.json names the wrong chain path")
    if index["authority"] != AUTHORITY_POLICY:
        raise ChainError("anchor/index.json authority/ratification metadata drift")
    head = frames[-1]
    expected_head = {
        "seq": head["seq"],
        "revision": head["payload"]["revision"],
        "frame_hash": head["frame_hash"],
        "payload_hash": head["payload_hash"],
        "normative_sha256": head["payload"]["normative_sha256"],
        "normative_bytes": int(head["payload"]["normative_bytes"]),
    }
    if index["generated_utc"] != head["utc"] or index["head"] != expected_head:
        raise ChainError("anchor/index.json head metadata drift")
    if index["checkpoint_url_template"] != (
        "https://raw.githubusercontent.com/kody-w/rapp-1/"
        "{accepted_commit}/anchor/chain.jsonl"
    ):
        raise ChainError("anchor/index.json checkpoint URL template drift")
    if index["frame_discovery_url_template"] != (
        "https://raw.githubusercontent.com/kody-w/rapp-1/"
        "{ref}/anchor/frames/{frame_hash}.json"
    ):
        raise ChainError("anchor/index.json frame URL template drift")
    if bootstrap_index is None or bootstrap_profile is None:
        bootstrap_profile, bootstrap_index = load_bootstrap()
    expected_bootstrap = {
        "index_path": "anchor/bootstrap/index.json",
        "profile_path": bootstrap_index["profile_path"],
        "profile_sha256": bootstrap_index["profile_sha256"],
        "verifier_path": bootstrap_index["verifier_path"],
        "verifier_sha256": bootstrap_index["verifier_sha256"],
    }
    if index["bootstrap"] != expected_bootstrap:
        raise ChainError("anchor/index.json bootstrap pin drift")
    expected_entries = [_frame_entry(frame) for frame in frames]
    if index["entries"] != expected_entries:
        raise ChainError("anchor/index.json sequence/payload index drift")
    loader = object_loader or _local_object_loader
    for expected_frame, entry in zip(frames, expected_entries):
        try:
            object_frame = B.verify_frame_object(
                loader(entry["object_path"]),
                entry["frame_hash"],
                bootstrap_profile,
            )
        except (B.BootstrapError, ResolutionError, OSError) as error:
            raise ChainError(
                f"invalid content-addressed frame object {entry['object_path']}: {error}"
            ) from error
        if object_frame != expected_frame:
            raise ChainError(
                f"frame object {entry['object_path']} does not match the selected chain"
            )
    return index


def resolve_frame_object(
    frames: Sequence[dict],
    index: dict,
    *,
    revision: Optional[str] = None,
    seq: Optional[int] = None,
    frame_hash: Optional[str] = None,
    payload_hash: Optional[str] = None,
    object_loader: Optional[Fetcher] = None,
    bootstrap_profile: Optional[dict] = None,
) -> dict:
    selected = resolve_frame(
        frames,
        revision=revision,
        seq=seq,
        frame_hash=frame_hash,
        payload_hash=payload_hash,
    )
    entry = next(
        (
            candidate
            for candidate in index["entries"]
            if candidate["frame_hash"] == selected["frame_hash"]
        ),
        None,
    )
    if entry is None:
        raise ResolutionError("selected frame is absent from anchor/index.json")
    if bootstrap_profile is None:
        bootstrap_profile, _ = load_bootstrap()
    loader = object_loader or _local_object_loader
    try:
        object_frame = B.verify_frame_object(
            loader(entry["object_path"]),
            selected["frame_hash"],
            bootstrap_profile,
        )
    except (B.BootstrapError, ResolutionError, OSError) as error:
        raise ResolutionError(f"content-addressed frame object refused: {error}") from error
    if object_frame != selected:
        raise ResolutionError("content-addressed frame object is not in the selected chain")
    return object_frame


def legacy_url(payload: Dict[str, object]) -> str:
    metadata = _legacy_metadata(payload)
    match = GITHUB_REPOSITORY.fullmatch(str(metadata["canonical_repo"]))
    if match is None:
        raise ResolutionError("unsupported canonical repository")
    owner, repository = match.groups()
    path = "/".join(
        urllib.parse.quote(part, safe="")
        for part in pathlib.PurePosixPath(str(metadata["normative_path"])).parts
    )
    return (
        f"https://raw.githubusercontent.com/{owner}/{repository}/"
        f"{metadata['commit']}/{path}"
    )


def fetch_https(url: str, timeout: int = 30) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "raw.githubusercontent.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ResolutionError("only credential-free raw.githubusercontent.com HTTPS URLs are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "rapp-1-spec-resolver/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "raw.githubusercontent.com":
                raise ResolutionError("unsafe HTTPS redirect while resolving specification bytes")
            octets = response.read(MAX_FETCH_BYTES + 1)
            if len(octets) > MAX_FETCH_BYTES:
                raise ResolutionError("remote authority input exceeds 64 MiB")
            return octets
    except ResolutionError:
        raise
    except Exception as error:
        raise ResolutionError(f"cannot fetch specification bytes: {error}") from error


def _verify_normative_bytes(octets: bytes, payload: Dict[str, object]) -> bytes:
    metadata = _legacy_metadata(payload)
    if len(octets) != metadata["normative_bytes"]:
        raise ResolutionError("resolved normative byte length mismatch")
    if sha256(octets) != metadata["normative_sha256"]:
        raise ResolutionError("resolved normative SHA-256 mismatch")
    try:
        text = octets.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResolutionError("resolved normative bytes are malformed UTF-8") from error
    if text.encode("utf-8") != octets or octets.startswith(b"\xef\xbb\xbf"):
        raise ResolutionError("resolved normative bytes are not canonical UTF-8 text")
    return octets


def _absolute_path(path: pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(path)
    if ".." in path.parts:
        raise ResolutionError("unsafe parent traversal in destination path")
    return pathlib.Path(os.path.abspath(os.fspath(path)))


@contextlib.contextmanager
def _open_safe_directory(path: pathlib.Path):
    absolute = _absolute_path(path)
    if os.name == "nt" or os.open not in os.supports_dir_fd:
        current = pathlib.Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            try:
                details = os.lstat(current)
            except FileNotFoundError as error:
                raise ResolutionError(f"directory does not exist: {current}") from error
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
                raise ResolutionError(f"unsafe or non-directory path component: {current}")
        yield None, absolute
        return

    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ResolutionError(
                        f"unsafe or non-directory path component: {part}"
                    ) from error
                raise
            os.close(descriptor)
            descriptor = child
        yield descriptor, absolute
    finally:
        os.close(descriptor)


def _open_leaf(
    parent_descriptor: Optional[int],
    parent: pathlib.Path,
    name: str,
    flags: int,
    mode: int = 0o600,
) -> int:
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        if parent_descriptor is None:
            return os.open(parent / name, flags, mode)
        return os.open(name, flags, mode, dir_fd=parent_descriptor)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise ResolutionError(f"refusing symlink leaf: {parent / name}") from error
        raise


def _read_descriptor(
    descriptor: int,
    *,
    maximum_bytes: int,
    expected_size: Optional[int],
) -> bytes:
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode):
        raise ResolutionError("refusing non-regular file")
    if expected_size is not None and details.st_size != expected_size:
        raise ResolutionError("file byte length does not match the expected size")
    if details.st_size > maximum_bytes:
        raise ResolutionError("file exceeds the bounded read limit")
    chunks = []
    remaining = maximum_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    octets = b"".join(chunks)
    if len(octets) > maximum_bytes:
        raise ResolutionError("file exceeds the bounded read limit")
    final = os.fstat(descriptor)
    if (
        final.st_dev != details.st_dev
        or final.st_ino != details.st_ino
        or final.st_size != details.st_size
    ):
        raise ResolutionError("file changed during bounded read")
    if expected_size is not None and len(octets) != expected_size:
        raise ResolutionError("file byte length changed during bounded read")
    return octets


def read_bounded_file(
    path: pathlib.Path,
    *,
    maximum_bytes: int,
    expected_size: Optional[int] = None,
) -> bytes:
    path = _absolute_path(path)
    if path.name in ("", ".", ".."):
        raise ResolutionError("unsafe file leaf")
    with _open_safe_directory(path.parent) as (parent_descriptor, parent):
        descriptor = _open_leaf(
            parent_descriptor,
            parent,
            path.name,
            os.O_RDONLY,
        )
        try:
            return _read_descriptor(
                descriptor,
                maximum_bytes=maximum_bytes,
                expected_size=expected_size,
            )
        finally:
            os.close(descriptor)


def _leaf_details(
    parent_descriptor: Optional[int],
    parent: pathlib.Path,
    name: str,
):
    try:
        if parent_descriptor is None:
            return os.lstat(parent / name)
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _fsync_directory(descriptor: Optional[int], path: pathlib.Path) -> None:
    if descriptor is None:
        if os.name == "nt":
            return
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return
    try:
        os.fsync(descriptor)
    except OSError:
        if os.name != "nt":
            raise


def atomic_write(
    path: pathlib.Path,
    octets: bytes,
    *,
    expected: Optional[bytes] = None,
) -> None:
    if not isinstance(octets, bytes):
        raise ResolutionError("atomic write requires bytes")
    path = _absolute_path(path)
    if path.name in ("", ".", ".."):
        raise ResolutionError("unsafe destination leaf")
    with _open_safe_directory(path.parent) as (parent_descriptor, parent):
        initial = _leaf_details(parent_descriptor, parent, path.name)
        if initial is not None:
            if stat.S_ISLNK(initial.st_mode):
                raise ResolutionError(f"refusing symlink leaf: {path}")
            if not stat.S_ISREG(initial.st_mode):
                raise ResolutionError(f"refusing non-regular destination: {path}")
        if expected is not None:
            if initial is None:
                raise ResolutionError("compare-and-swap destination is missing")
            try:
                current = read_bounded_file(
                    path,
                    maximum_bytes=max(len(expected), 1),
                    expected_size=len(expected),
                )
            except ResolutionError as error:
                raise ResolutionError(
                    "compare-and-swap destination changed"
                ) from error
            if current != expected:
                raise ResolutionError("compare-and-swap destination changed")

        temporary_name = f".{path.name}.{secrets.token_hex(12)}.tmp"
        descriptor = _open_leaf(
            parent_descriptor,
            parent,
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        )
        try:
            view = memoryview(octets)
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            os.fsync(descriptor)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o644)
        finally:
            os.close(descriptor)
        try:
            current_details = _leaf_details(parent_descriptor, parent, path.name)
            if current_details is not None and stat.S_ISLNK(current_details.st_mode):
                raise ResolutionError(f"refusing raced symlink leaf: {path}")
            if expected is not None:
                try:
                    current = read_bounded_file(
                        path,
                        maximum_bytes=max(len(expected), 1),
                        expected_size=len(expected),
                    )
                except ResolutionError as error:
                    raise ResolutionError(
                        "compare-and-swap destination changed"
                    ) from error
                if current != expected:
                    raise ResolutionError("compare-and-swap destination changed")
            with _open_safe_directory(path.parent) as (
                check_descriptor,
                _check_parent,
            ):
                if (
                    parent_descriptor is not None
                    and check_descriptor is not None
                    and (
                        os.fstat(parent_descriptor).st_dev,
                        os.fstat(parent_descriptor).st_ino,
                    )
                    != (
                        os.fstat(check_descriptor).st_dev,
                        os.fstat(check_descriptor).st_ino,
                    )
                ):
                    raise ResolutionError("destination directory changed during write")
            if parent_descriptor is None:
                os.replace(parent / temporary_name, path)
            else:
                os.replace(
                    temporary_name,
                    path.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
            _fsync_directory(parent_descriptor, parent)
        finally:
            try:
                if parent_descriptor is None:
                    os.unlink(parent / temporary_name)
                else:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass


def safe_unlink(path: pathlib.Path) -> None:
    path = _absolute_path(path)
    with _open_safe_directory(path.parent) as (parent_descriptor, parent):
        details = _leaf_details(parent_descriptor, parent, path.name)
        if details is None:
            return
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise ResolutionError(f"refusing unsafe unlink target: {path}")
        if parent_descriptor is None:
            os.unlink(path)
        else:
            os.unlink(path.name, dir_fd=parent_descriptor)
        _fsync_directory(parent_descriptor, parent)


def resolve_spec_bytes(
    frame: dict,
    *,
    fetcher: Optional[Fetcher] = None,
    cache_dir: Optional[pathlib.Path] = None,
    offline: bool = False,
) -> bytes:
    payload = frame["payload"]
    if payload.get("schema") is not None:
        return _inline_normative(payload)
    metadata = _legacy_metadata(payload)
    cache_path = None
    if cache_dir is not None:
        cache_dir = _absolute_path(cache_dir)
        with _open_safe_directory(cache_dir):
            pass
        cache_path = cache_dir / f"{metadata['normative_sha256']}.md"
        try:
            cached = read_bounded_file(
                cache_path,
                maximum_bytes=metadata["normative_bytes"],
                expected_size=metadata["normative_bytes"],
            )
        except FileNotFoundError:
            cached = None
        if cached is not None:
            return _verify_normative_bytes(cached, payload)
    if offline:
        raise ResolutionError("legacy revision is not cached and offline mode forbids fetching")
    source = fetcher or fetch_https
    octets = _verify_normative_bytes(source(legacy_url(payload)), payload)
    if cache_path is not None:
        atomic_write(cache_path, octets)
    return octets


def verify_orient(
    orient_octets: bytes,
    frames: Sequence[dict],
    *,
    index_octets: Optional[bytes] = None,
    bootstrap_index: Optional[dict] = None,
    allow_unpublished_rev14_draft: bool = False,
) -> dict:
    try:
        orient = R._strict_json(orient_octets)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ChainError(f"invalid orient.json: {error}") from error
    if not isinstance(orient, dict) or orient.get("schema") != "rapp/1-anchor":
        raise ChainError("orient.json has the wrong schema")
    head = frames[-1]
    payload = head["payload"]
    expected_keys = {
        "schema",
        "generated_utc",
        "stream_id",
        "head",
        "spec",
        "registered_kinds",
        "vocabulary",
        "operational_profiles",
        "philosophy",
        "foundation",
        "constitution",
    }
    if payload.get("schema") == REVISION_SCHEMA:
        expected_keys |= {"authority", "bootstrap", "index"}
    if set(orient) != expected_keys:
        raise ChainError("orient.json has unexpected or missing top-level fields")
    expected_head = {
        "seq": head["seq"],
        "frame_hash": head["frame_hash"],
        "payload_hash": head["payload_hash"],
    }
    if orient.get("stream_id") != head["stream_id"] or orient.get("head") != expected_head:
        raise ChainError("orient.json does not point to the verified chain head")
    spec = orient.get("spec")
    if not isinstance(spec, dict):
        raise ChainError("orient.json has no spec view")
    legacy = _legacy_metadata(payload)
    for key in (
        "revision",
        "canonical_repo",
        "commit",
        "normative_sha256",
    ):
        if spec.get(key) != legacy[key]:
            raise ChainError(f"orient.json spec.{key} does not match the chain head")
    path_value = spec.get("materialized_path", spec.get("normative_path"))
    if path_value != legacy["normative_path"]:
        raise ChainError("orient.json materialized path does not match the chain head")
    for key in (
        "registered_kinds",
        "vocabulary",
        "operational_profiles",
        "philosophy",
        "foundation",
        "constitution",
    ):
        if orient.get(key) != payload.get(key):
            raise ChainError(f"orient.json {key} mirror does not match the chain head")
    if payload.get("schema") == REVISION_SCHEMA:
        expected = {
            "revision": legacy["revision"],
            "revision_frame_hash": head["frame_hash"],
            "revision_payload_hash": head["payload_hash"],
            "schema": REVISION_SCHEMA,
            "materialized_path": legacy["normative_path"],
            "normative_path": legacy["normative_path"],
            "media_type": NORMATIVE_MEDIA_TYPE,
            "normative_sha256": legacy["normative_sha256"],
            "normative_bytes": legacy["normative_bytes"],
            "canonical_repo": legacy["canonical_repo"],
            "commit": legacy["commit"],
        }
        if spec != expected:
            raise ChainError("orient.json normative view metadata does not match the head")
        if allow_unpublished_rev14_draft:
            return orient
        if orient.get("authority") != AUTHORITY_POLICY:
            raise ChainError("orient.json authority/ratification metadata drift")
        if bootstrap_index is None:
            _, bootstrap_index = load_bootstrap()
        expected_bootstrap = {
            "index_path": "anchor/bootstrap/index.json",
            "profile_path": bootstrap_index["profile_path"],
            "profile_sha256": bootstrap_index["profile_sha256"],
            "verifier_path": bootstrap_index["verifier_path"],
            "verifier_sha256": bootstrap_index["verifier_sha256"],
        }
        if orient.get("bootstrap") != expected_bootstrap:
            raise ChainError("orient.json bootstrap pin drift")
        if index_octets is None:
            index_octets = INDEX_PATH.read_bytes()
        expected_index = {
            "path": "anchor/index.json",
            "sha256": sha256(index_octets),
            "bytes": len(index_octets),
        }
        if orient.get("index") != expected_index:
            raise ChainError("orient.json revision index pin drift")
    return orient


def _read_source(path: pathlib.Path, url: Optional[str], offline: bool) -> bytes:
    if url is not None:
        if offline:
            raise ResolutionError("offline mode forbids remote chain or beacon fetches")
        return fetch_https(url)
    return path.read_bytes()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify anchor/chain.jsonl and materialize one RAPP/1 specification revision."
    )
    parser.add_argument("--chain", type=pathlib.Path, default=CHAIN_PATH)
    parser.add_argument("--chain-url")
    parser.add_argument("--orient", type=pathlib.Path, default=ORIENT_PATH)
    parser.add_argument("--orient-url")
    parser.add_argument("--index", type=pathlib.Path, default=INDEX_PATH)
    parser.add_argument("--index-url")
    parser.add_argument("--frames-url")
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--revision")
    selector.add_argument("--seq", type=int)
    selector.add_argument("--frame-hash")
    selector.add_argument("--payload-hash")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=pathlib.Path)
    destination.add_argument("--check", type=pathlib.Path)
    destination.add_argument("--stdout", action="store_true")
    parser.add_argument("--cache", type=pathlib.Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)

    chain_url = args.chain_url
    orient_url = args.orient_url
    index_url = args.index_url
    frames_url = args.frames_url
    if chain_url and args.chain != CHAIN_PATH:
        parser.error("--chain and --chain-url are mutually exclusive")
    if orient_url and args.orient != ORIENT_PATH:
        parser.error("--orient and --orient-url are mutually exclusive")
    if index_url and args.index != INDEX_PATH:
        parser.error("--index and --index-url are mutually exclusive")
    if chain_url and orient_url is None:
        orient_url = ORIENT_URL
    if chain_url and index_url is None:
        index_url = INDEX_URL
    if chain_url and frames_url is None:
        frames_url = REPOSITORY_RAW_URL

    bootstrap_profile, bootstrap_index = load_bootstrap()
    chain_octets = _read_source(args.chain, chain_url, args.offline)
    frames = verify_chain(chain_octets, bootstrap_profile=bootstrap_profile)
    index_octets = _read_source(args.index, index_url, args.offline)
    if frames_url is not None:
        if args.offline:
            raise ResolutionError("offline mode forbids remote frame-object fetches")
        base = frames_url.rstrip("/") + "/"

        def object_loader(path: str) -> bytes:
            return fetch_https(urllib.parse.urljoin(base, path))
    else:
        object_loader = _local_object_loader
    index = verify_revision_index(
        index_octets,
        frames,
        object_loader=object_loader,
        bootstrap_index=bootstrap_index,
        bootstrap_profile=bootstrap_profile,
    )
    orient_octets = _read_source(args.orient, orient_url, args.offline)
    verify_orient(
        orient_octets,
        frames,
        index_octets=index_octets,
        bootstrap_index=bootstrap_index,
    )
    frame = resolve_frame_object(
        frames,
        index,
        revision=args.revision,
        seq=args.seq,
        frame_hash=args.frame_hash,
        payload_hash=args.payload_hash,
        object_loader=object_loader,
        bootstrap_profile=bootstrap_profile,
    )
    octets = resolve_spec_bytes(
        frame,
        cache_dir=args.cache,
        offline=args.offline,
    )
    if args.stdout:
        sys.stdout.buffer.write(octets)
    elif args.check is not None:
        if read_bounded_file(
            args.check,
            maximum_bytes=len(octets),
            expected_size=len(octets),
        ) != octets:
            raise ResolutionError(f"materialized view drift: {args.check}")
    else:
        atomic_write(args.output, octets)
    identity = {
        "revision": frame["payload"]["revision"],
        "seq": frame["seq"],
        "frame_hash": frame["frame_hash"],
        "payload_hash": frame["payload_hash"],
        "normative_sha256": sha256(octets),
        "normative_bytes": len(octets),
    }
    print(json.dumps(identity, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ChainError, ResolutionError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
