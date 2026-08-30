#!/usr/bin/env python3
"""Append the deterministic rev-14 RAPP/1 specification-chain frame."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Dict


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rapp as R
from anchor import bootstrap_verify as B
from anchor import materialize_spec as M


ANCHOR = pathlib.Path(__file__).resolve().parent
CHAIN = ANCHOR / "chain.jsonl"
ORIENT = ANCHOR / "orient.json"
INDEX = ANCHOR / "index.json"
FRAMES = ANCHOR / "frames"
BOOTSTRAP = ANCHOR / "bootstrap"
LOCK = ANCHOR / ".update_anchor.lock"
REVISION = "rev-14"
PREVIOUS_REVISION = "rev-13"
INPUT_PATHS = [
    "SPEC.md",
    "CONSTITUTION.md",
    "FOUNDATION.json",
    "PHILOSOPHY.md",
    "rapp.py",
    "protocols/index.json",
    "protocols/rapp-cicd/1/SPEC.md",
    "protocols/rapp-cicd/1/schema.json",
    "protocols/rapp-deploy/1/SPEC.md",
    "protocols/rapp-deploy/1/schema.json",
    "anchor/materialize_spec.py",
    "anchor/bootstrap_verify.py",
    "anchor/update_anchor.py",
]


def sha256(octets: bytes) -> str:
    return hashlib.sha256(octets).hexdigest()


def fixed_utc(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    utc = parsed.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


@contextlib.contextmanager
def exclusive_lock(path: pathlib.Path):
    path = M._absolute_path(path)
    with M._open_safe_directory(path.parent) as (parent_descriptor, parent):
        descriptor = M._open_leaf(
            parent_descriptor,
            parent,
            path.name,
            os.O_RDWR | os.O_CREAT,
        )
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise M.ResolutionError("anchor update lock is not a regular file")
            if details.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
                M._fsync_directory(parent_descriptor, parent)
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "nt":
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def ensure_committed_inputs() -> None:
    for path in INPUT_PATHS:
        if subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", path],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode != 0:
            raise SystemExit(f"anchor input is not committed: {path}")
    status = subprocess.check_output(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *INPUT_PATHS,
        ],
        cwd=ROOT,
        text=True,
    )
    if status.strip():
        raise SystemExit(
            "commit all anchor inputs before generating; refusing dirty source bytes"
        )


def spec_source() -> tuple[str, str, str]:
    commit = git_output("rev-list", "-1", "HEAD", "--", "SPEC.md")
    if not M.HEX40.fullmatch(commit):
        raise SystemExit("cannot identify the immutable SPEC.md source commit")
    committed = subprocess.check_output(
        ["git", "show", f"{commit}:SPEC.md"],
        cwd=ROOT,
    )
    if committed != (ROOT / "SPEC.md").read_bytes():
        raise SystemExit("SPEC.md does not match its immutable source commit")
    commit_utc = git_output("show", "-s", "--format=%cI", commit)
    return commit, commit_utc, fixed_utc(commit_utc)


def foundation_metadata(verify_remote: bool) -> tuple[dict, dict]:
    foundation = R._strict_json((ROOT / "FOUNDATION.json").read_bytes())
    if set(foundation) != {
        "schema",
        "status",
        "repository",
        "commit",
        "path",
        "sha256",
        "size_bytes",
        "relationship",
    }:
        raise SystemExit("FOUNDATION.json has an unexpected shape")
    if foundation["schema"] != "rapp-foundation-pointer/1":
        raise SystemExit("FOUNDATION.json has the wrong schema")
    if foundation["repository"] != "https://github.com/kody-w/RAPP":
        raise SystemExit("FOUNDATION.json names the wrong product home")
    if not M.HEX40.fullmatch(foundation["commit"]):
        raise SystemExit("FOUNDATION.json commit is not 40 lowercase hex")
    philosophy_octets = (ROOT / "PHILOSOPHY.md").read_bytes()
    philosophy_sha256 = sha256(philosophy_octets)
    if (
        foundation["path"] != "PHILOSOPHY.md"
        or foundation["sha256"] != philosophy_sha256
        or foundation["size_bytes"] != len(philosophy_octets)
    ):
        raise SystemExit("foundation philosophy mirror drift")
    if verify_remote:
        foundation_url = (
            "https://raw.githubusercontent.com/kody-w/RAPP/"
            f"{foundation['commit']}/{foundation['path']}"
        )
        try:
            with urllib.request.urlopen(foundation_url, timeout=30) as response:
                canonical_philosophy = response.read()
        except Exception as error:
            raise SystemExit(f"cannot resolve pinned RAPP foundation: {error}") from error
        if canonical_philosophy == b"404: Not Found":
            raise SystemExit("pinned RAPP foundation path is missing")
        if (
            canonical_philosophy != philosophy_octets
            or sha256(canonical_philosophy) != foundation["sha256"]
            or len(canonical_philosophy) != foundation["size_bytes"]
        ):
            raise SystemExit("pinned RAPP foundation bytes do not match the mirror")
    philosophy = {
        "canonical_repository": foundation["repository"],
        "canonical_commit": foundation["commit"],
        "canonical_path": foundation["path"],
        "canonical_sha256": foundation["sha256"],
        "mirror_path": "PHILOSOPHY.md",
        "mirror_sha256": philosophy_sha256,
    }
    return foundation, philosophy


def operational_profiles() -> Dict[str, dict]:
    profile_index = R._strict_json((ROOT / "protocols" / "index.json").read_bytes())
    if set(profile_index) != {
        "schema",
        "generated_utc",
        "canonical_repository",
        "profiles",
    }:
        raise SystemExit("protocol profile index has an unexpected shape")
    if profile_index["schema"] != "rapp/1-operational-profile-index":
        raise SystemExit("protocol profile index has the wrong schema")
    if profile_index["canonical_repository"] != "https://github.com/kody-w/rapp-1":
        raise SystemExit("protocol profile index names the wrong canonical repository")
    if not isinstance(profile_index["profiles"], list) or not profile_index["profiles"]:
        raise SystemExit("protocol profile index has no profiles")
    result = {}
    for profile in profile_index["profiles"]:
        if set(profile) != {
            "name",
            "human_name",
            "parent",
            "spec_path",
            "spec_sha256",
            "schema_path",
            "schema_sha256",
            "conformance",
        }:
            raise SystemExit("protocol profile entry has an unexpected shape")
        if profile["name"] in result:
            raise SystemExit(f"duplicate protocol profile: {profile['name']}")
        if profile["parent"] != "rapp/1":
            raise SystemExit(f"protocol profile has the wrong parent: {profile['name']}")
        for key in ("spec_path", "schema_path"):
            candidate = pathlib.PurePosixPath(profile[key])
            if (
                candidate.is_absolute()
                or any(part in ("", ".", "..") for part in candidate.parts)
                or not str(candidate).startswith("protocols/")
            ):
                raise SystemExit(f"unsafe protocol profile path: {profile[key]}")
        spec_path = ROOT / profile["spec_path"]
        schema_path = ROOT / profile["schema_path"]
        if sha256(spec_path.read_bytes()) != profile["spec_sha256"]:
            raise SystemExit(f"profile spec hash drift: {profile['name']}")
        if sha256(schema_path.read_bytes()) != profile["schema_sha256"]:
            raise SystemExit(f"profile schema hash drift: {profile['name']}")
        result[profile["name"]] = {
            "status": "live",
            "spec_path": profile["spec_path"],
            "spec_sha256": profile["spec_sha256"],
            "schema_path": profile["schema_path"],
            "schema_sha256": profile["schema_sha256"],
        }
    return result


def json_octets(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=1) + "\n").encode("utf-8")


def bootstrap_bundle() -> tuple[dict, bytes, dict, bytes]:
    verifier_octets = (ANCHOR / "bootstrap_verify.py").read_bytes()
    profile = {
        "schema": B.PROFILE_SCHEMA,
        "version": 1,
        "authority": {
            "canonical_repository": "https://github.com/kody-w/rapp-1",
            "protected_ref": "refs/heads/main",
            "chain_path": "anchor/chain.jsonl",
            "index_path": "anchor/index.json",
            "frame_path_template": "anchor/frames/{frame_hash}.json",
            "stream_id": (
                "rappid:@kody-w/rapp-1-anchor:"
                "a4298c417789ecff68b7be3df4d8b90d397c43f972eaf839977db16dbe02acc6"
            ),
            "genesis_frame_hash": (
                "a5aa6e6ba81d6b97b80ce46bc20905428d5679bb18309d176356bd194cdd005a"
            ),
            "genesis_payload_hash": (
                "7d9c87b7d58ba07b22b68e8b07c0d50714fcc377c627ea9c60bec3bc6518df29"
            ),
        },
        "canonicalization": {
            "standard": "RFC 8785 JCS",
            "encoding": "UTF-8",
            "input": "I-JSON exact-integer subset",
            "integer_min": B.INTEGER_MIN,
            "integer_max": B.INTEGER_MAX,
            "object_key_order": "UTF-16 code units",
            "unicode_normalization": "none",
            "floating_point": "refused",
        },
        "hash_domains": {
            "particle": B.PARTICLE_DOMAIN,
            "wave": B.WAVE_DOMAIN,
        },
        "frame": {
            "spec": B.SPEC,
            "kind": B.KIND,
            "keys": [
                "spec",
                "kind",
                "stream_id",
                "seq",
                "utc",
                "payload",
                "payload_hash",
                "frame_hash",
                "prev",
                "prev_wave",
                "sig",
            ],
            "sig": None,
            "prev_wave": None,
        },
        "chaining": {
            "genesis_seq": 0,
            "genesis_prev": None,
            "successor_seq": "predecessor.seq + 1",
            "successor_prev": "predecessor.payload_hash",
            "utc": "calendar-valid YYYY-MM-DDTHH:MM:SS.mmmZ, nondecreasing",
        },
        "limits": {
            "canonical_frame_bytes": B.MAX_BYTES,
            "json_input_bytes": B.MAX_BYTES,
            "json_nesting_depth": B.MAX_DEPTH,
        },
        "verifier": {
            "path": "anchor/bootstrap_verify.py",
            "sha256": sha256(verifier_octets),
            "bytes": len(verifier_octets),
        },
    }
    profile_octets = json_octets(profile)
    profile_sha256 = sha256(profile_octets)
    index = {
        "schema": B.INDEX_SCHEMA,
        "profile_path": f"anchor/bootstrap/sha256-{profile_sha256}.json",
        "profile_sha256": profile_sha256,
        "profile_bytes": len(profile_octets),
        "verifier_path": "anchor/bootstrap_verify.py",
        "verifier_sha256": sha256(verifier_octets),
        "verifier_bytes": len(verifier_octets),
    }
    index_octets = json_octets(index)
    B.verify_bootstrap_index(index_octets, profile_octets, verifier_octets)
    return profile, profile_octets, index, index_octets


def revision_payload(
    previous_payload: dict,
    spec_octets: bytes,
    commit: str,
    commit_utc: str,
    observed_utc: str,
    *,
    verify_foundation: bool,
) -> dict:
    try:
        spec_text = spec_octets.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("SPEC.md is not valid UTF-8") from error
    if spec_text.encode("utf-8") != spec_octets or spec_octets.startswith(b"\xef\xbb\xbf"):
        raise SystemExit("SPEC.md must be UTF-8 without a byte-order mark")
    payload = json.loads(json.dumps(previous_payload))
    normative_sha256 = sha256(spec_octets)
    payload.update(
        {
            "schema": M.REVISION_SCHEMA,
            "revision": REVISION,
            "previous_revision": previous_payload["revision"],
            "previous_normative_sha256": previous_payload["normative_sha256"],
            "normative_sha256": normative_sha256,
            "normative_bytes": str(len(spec_octets)),
            "commit": commit,
            "commit_utc": commit_utc,
            "observed_utc": observed_utc,
            "normative": {
                "media_type": M.NORMATIVE_MEDIA_TYPE,
                "text": spec_text,
                "sha256": normative_sha256,
                "bytes": len(spec_octets),
            },
            "publication": M.AUTHORITY_POLICY,
        }
    )
    constitution_octets = (ROOT / "CONSTITUTION.md").read_bytes()
    payload["constitution"] = {
        "path": "CONSTITUTION.md",
        "sha256": sha256(constitution_octets),
        "size_bytes": len(constitution_octets),
    }
    foundation, philosophy = foundation_metadata(verify_foundation)
    payload["foundation"] = foundation
    payload["philosophy"] = philosophy
    payload["operational_profiles"] = operational_profiles()
    payload["vocabulary"]["sealed"] = {
        "status": "live",
        "where": "§9.2 sealed egg variant and §9.2.1 profile",
    }
    payload["vocabulary"]["rapp-cicd"] = {
        "status": "live",
        "where": "§11.2 and protocols/rapp-cicd/1/SPEC.md",
    }
    payload["vocabulary"]["rapp-deploy"] = {
        "status": "live",
        "where": "§11.2 and protocols/rapp-deploy/1/SPEC.md",
    }
    payload["vocabulary"]["offspring"] = {
        "status": "live",
        "where": "§9.4 typed lineage and PHILOSOPHY.md",
    }
    payload["vocabulary"]["cross"] = {
        "status": "live",
        "where": "§9.4 typed multi-parent lineage and PHILOSOPHY.md",
    }
    rules = [
        {
            "t": "gotcha",
            "c": (
                "A sealed egg is public ciphertext, not password-protected hosting: "
                "the signed manifest binds AES-256-GCM data and a scoped key service; "
                "no shared DEK belongs in the egg, URL, client, log, or frame."
            ),
        },
        {
            "t": "fact",
            "c": (
                "RAPP CI/CD promotes one immutable release payload hash through an ordered "
                "evidence chain; no ring may rebuild, patch, substitute, or skip the candidate."
            ),
        },
        {
            "t": "gotcha",
            "c": (
                "RAPP Deploy forbids in-place serving mutation: growth happens in an isolated "
                "candidate lineage and reaches users only through bounded, reversible waves."
            ),
        },
        {
            "t": "pattern",
            "c": (
                "A new encounter may produce an offspring or cross with a fresh identity and "
                "typed parent addresses; lineage may continue indefinitely, but every attempt "
                "is bounded and parent authority never transfers implicitly."
            ),
        },
        {
            "t": "fact",
            "c": (
                "kody-w/RAPP remains the public foundation and product home; "
                "kody-w/rapp-1 defines the interoperable protocol only."
            ),
        },
    ]
    for rule in rules:
        if rule not in payload["rules"]:
            payload["rules"].append(rule)
    return payload


def select_chain_base(
    current_chain: bytes,
    canonical_chain: bytes,
    bootstrap_profile: dict,
) -> tuple[bytes, list, object]:
    canonical_frames = M.verify_chain(
        canonical_chain,
        bootstrap_profile=bootstrap_profile,
    )
    if current_chain == canonical_chain:
        return canonical_chain, canonical_frames, None
    current_frames = M.verify_chain(
        current_chain,
        bootstrap_profile=bootstrap_profile,
        allow_unpublished_rev14_draft=True,
    )
    if (
        current_chain.startswith(canonical_chain)
        and len(current_frames) == len(canonical_frames) + 1
        and current_frames[-1]["payload"].get("revision") == REVISION
        and current_frames[-1]["payload"].get("schema") == M.REVISION_SCHEMA
    ):
        return canonical_chain, canonical_frames, current_frames[-1]
    raise SystemExit(
        "stale or competing specification append: rebase onto origin/main and regenerate"
    )


def frame_objects(chain_octets: bytes, frames: list) -> Dict[str, bytes]:
    lines = chain_octets.splitlines()
    if len(lines) != len(frames):
        raise SystemExit("chain line/frame count mismatch")
    objects = {}
    for line, frame in zip(lines, frames):
        path = f"anchor/frames/{frame['frame_hash']}.json"
        try:
            parsed = R._strict_json(line)
        except ValueError as error:
            raise SystemExit(f"cannot publish invalid frame object: {error}") from error
        if parsed != frame:
            raise SystemExit("frame object bytes do not reproduce the chain frame")
        objects[path] = line
    return objects


def revision_index_for(frames: list, bootstrap_index: dict) -> dict:
    head = frames[-1]
    return {
        "schema": "rapp-spec-chain-index/1",
        "generated_utc": head["utc"],
        "canonical_repository": M.AUTHORITY_POLICY["canonical_repository"],
        "canonical_ref": M.AUTHORITY_POLICY["protected_ref"],
        "chain_path": "anchor/chain.jsonl",
        "checkpoint_url_template": (
            "https://raw.githubusercontent.com/kody-w/rapp-1/"
            "{accepted_commit}/anchor/chain.jsonl"
        ),
        "frame_discovery_url_template": (
            "https://raw.githubusercontent.com/kody-w/rapp-1/"
            "{ref}/anchor/frames/{frame_hash}.json"
        ),
        "authority": M.AUTHORITY_POLICY,
        "bootstrap": {
            "index_path": "anchor/bootstrap/index.json",
            "profile_path": bootstrap_index["profile_path"],
            "profile_sha256": bootstrap_index["profile_sha256"],
            "verifier_path": bootstrap_index["verifier_path"],
            "verifier_sha256": bootstrap_index["verifier_sha256"],
        },
        "head": {
            "seq": head["seq"],
            "revision": head["payload"]["revision"],
            "frame_hash": head["frame_hash"],
            "payload_hash": head["payload_hash"],
            "normative_sha256": head["payload"]["normative_sha256"],
            "normative_bytes": int(head["payload"]["normative_bytes"]),
        },
        "entries": [M._frame_entry(frame) for frame in frames],
    }


def orient_for(
    frame: dict,
    bootstrap_index: dict,
    index_octets: bytes,
) -> dict:
    payload = frame["payload"]
    return {
        "schema": "rapp/1-anchor",
        "generated_utc": frame["utc"],
        "stream_id": frame["stream_id"],
        "head": {
            "seq": frame["seq"],
            "frame_hash": frame["frame_hash"],
            "payload_hash": frame["payload_hash"],
        },
        "spec": {
            "revision": REVISION,
            "revision_frame_hash": frame["frame_hash"],
            "revision_payload_hash": frame["payload_hash"],
            "schema": M.REVISION_SCHEMA,
            "materialized_path": payload["normative_path"],
            "normative_path": payload["normative_path"],
            "media_type": M.NORMATIVE_MEDIA_TYPE,
            "normative_sha256": payload["normative"]["sha256"],
            "normative_bytes": payload["normative"]["bytes"],
            "canonical_repo": payload["canonical_repo"],
            "commit": payload["commit"],
        },
        "registered_kinds": payload["registered_kinds"],
        "vocabulary": payload["vocabulary"],
        "operational_profiles": payload["operational_profiles"],
        "philosophy": payload["philosophy"],
        "foundation": payload["foundation"],
        "constitution": payload["constitution"],
        "authority": M.AUTHORITY_POLICY,
        "bootstrap": {
            "index_path": "anchor/bootstrap/index.json",
            "profile_path": bootstrap_index["profile_path"],
            "profile_sha256": bootstrap_index["profile_sha256"],
            "verifier_path": bootstrap_index["verifier_path"],
            "verifier_sha256": bootstrap_index["verifier_sha256"],
        },
        "index": {
            "path": "anchor/index.json",
            "sha256": sha256(index_octets),
            "bytes": len(index_octets),
        },
    }


def publish_chain_and_beacon(
    chain_path: pathlib.Path,
    orient_path: pathlib.Path,
    *,
    expected_chain: bytes,
    candidate_chain: bytes,
    candidate_orient: bytes,
    after_chain=None,
) -> None:
    current = M.read_bounded_file(
        chain_path,
        maximum_bytes=M.MAX_FETCH_BYTES,
    )
    if current != expected_chain:
        raise M.ResolutionError(
            "stale writer: authority chain changed before publication"
        )
    if current != candidate_chain:
        M.atomic_write(chain_path, candidate_chain, expected=current)
    if after_chain is not None:
        after_chain()
    M.atomic_write(orient_path, candidate_orient)


def _main_locked() -> None:
    ensure_committed_inputs()
    bootstrap_profile, profile_octets, bootstrap_index, bootstrap_index_octets = (
        bootstrap_bundle()
    )
    commit, commit_utc, observed_utc = spec_source()
    spec_octets = (ROOT / "SPEC.md").read_bytes()
    current_chain = M.read_bounded_file(
        CHAIN,
        maximum_bytes=M.MAX_FETCH_BYTES,
    )
    canonical_chain = subprocess.check_output(
        ["git", "show", "origin/main:anchor/chain.jsonl"],
        cwd=ROOT,
    )
    base_chain, base_frames, replaced_draft = select_chain_base(
        current_chain,
        canonical_chain,
        bootstrap_profile,
    )
    accepted_frame = None
    head = base_frames[-1]
    if head["payload"]["revision"] == REVISION:
        if len(base_frames) < 2:
            raise SystemExit("rev-14 cannot be the anchor genesis")
        accepted_frame = head
        head = base_frames[-2]
    if head["payload"]["revision"] != PREVIOUS_REVISION:
        raise SystemExit(
            f"expected {PREVIOUS_REVISION} head before {REVISION}, "
            f"found {head['payload']['revision']}"
        )
    if observed_utc < head["utc"]:
        raise SystemExit("source commit time precedes the current anchor head")

    payload = revision_payload(
        head["payload"],
        spec_octets,
        commit,
        commit_utc,
        observed_utc,
        verify_foundation=False,
    )
    frame = R.build_frame(
        "body.pulse",
        head["stream_id"],
        head["seq"] + 1,
        observed_utc,
        payload,
        head["payload_hash"],
    )
    frame_octets = R.canonical(frame).encode("utf-8")
    if len(frame_octets) > R.MAX_CANONICAL_BYTES:
        raise SystemExit("rev-14 frame exceeds the RAPP/1 canonical-byte limit")
    candidate_chain = (
        base_chain + json.dumps(frame, ensure_ascii=False).encode("utf-8") + b"\n"
        if accepted_frame is None
        else canonical_chain
    )
    if accepted_frame is not None and frame != accepted_frame:
        raise SystemExit("accepted rev-14 frame is inconsistent with committed inputs")
    if candidate_chain != current_chain:
        payload = revision_payload(
            head["payload"],
            spec_octets,
            commit,
            commit_utc,
            observed_utc,
            verify_foundation=True,
        )
        frame = R.build_frame(
            "body.pulse",
            head["stream_id"],
            head["seq"] + 1,
            observed_utc,
            payload,
            head["payload_hash"],
        )
        candidate_chain = (
            base_chain
            + json.dumps(frame, ensure_ascii=False).encode("utf-8")
            + b"\n"
        )
    verified = M.verify_chain(
        candidate_chain,
        bootstrap_profile=bootstrap_profile,
    )
    if verified[-1] != frame:
        raise SystemExit("generated frame did not survive full-chain verification")
    objects = frame_objects(candidate_chain, verified)
    candidate_index = revision_index_for(verified, bootstrap_index)
    candidate_index_octets = json_octets(candidate_index)
    M.verify_revision_index(
        candidate_index_octets,
        verified,
        object_loader=lambda path: objects[path],
        bootstrap_index=bootstrap_index,
        bootstrap_profile=bootstrap_profile,
    )
    candidate_orient = orient_for(
        frame,
        bootstrap_index,
        candidate_index_octets,
    )
    candidate_orient_octets = json_octets(candidate_orient)
    M.verify_orient(
        candidate_orient_octets,
        verified,
        index_octets=candidate_index_octets,
        bootstrap_index=bootstrap_index,
    )
    if not candidate_chain.startswith(canonical_chain):
        raise SystemExit("generator would rewrite accepted historical chain bytes")

    with M._open_safe_directory(BOOTSTRAP):
        pass
    profile_path = ROOT / bootstrap_index["profile_path"]
    existing_profiles = set(BOOTSTRAP.glob("sha256-*.json"))
    stale_profiles = existing_profiles - {profile_path}
    if stale_profiles and replaced_draft is None:
        raise SystemExit(
            "rapp-anchor-bootstrap/1 is frozen; publish a new bootstrap version"
        )
    for stale_profile in stale_profiles:
        M.safe_unlink(stale_profile)
    try:
        existing_profile = M.read_bounded_file(
            profile_path,
            maximum_bytes=len(profile_octets),
            expected_size=len(profile_octets),
        )
    except FileNotFoundError:
        existing_profile = None
    if existing_profile is not None and existing_profile != profile_octets:
        raise SystemExit("content-addressed bootstrap profile path has wrong bytes")
    M.atomic_write(profile_path, profile_octets)
    M.atomic_write(BOOTSTRAP / "index.json", bootstrap_index_octets)

    with M._open_safe_directory(FRAMES):
        pass
    expected_object_paths = {ROOT / path for path in objects}
    for path, octets in objects.items():
        target = ROOT / path
        try:
            existing_object = M.read_bounded_file(
                target,
                maximum_bytes=len(octets),
                expected_size=len(octets),
            )
        except FileNotFoundError:
            existing_object = None
        if existing_object is not None and existing_object != octets:
            raise SystemExit(f"content-addressed frame object has wrong bytes: {path}")
        M.atomic_write(target, octets)
    for stale in set(FRAMES.glob("*.json")) - expected_object_paths:
        if (
            replaced_draft is not None
            and stale.name == f"{replaced_draft['frame_hash']}.json"
        ):
            M.safe_unlink(stale)
        else:
            raise SystemExit(f"unexpected frame object is not in the selected chain: {stale}")

    M.atomic_write(INDEX, candidate_index_octets)
    latest_chain = M.read_bounded_file(
        CHAIN,
        maximum_bytes=M.MAX_FETCH_BYTES,
    )
    if latest_chain != current_chain:
        raise M.ResolutionError(
            "stale writer: authority chain changed during generation"
        )
    M.verify_chain(
        latest_chain,
        bootstrap_profile=bootstrap_profile,
        allow_unpublished_rev14_draft=True,
    )
    publish_chain_and_beacon(
        CHAIN,
        ORIENT,
        expected_chain=current_chain,
        candidate_chain=candidate_chain,
        candidate_orient=candidate_orient_octets,
    )
    print(frame["frame_hash"])


def main() -> None:
    with exclusive_lock(LOCK):
        _main_locked()


if __name__ == "__main__":
    main()
