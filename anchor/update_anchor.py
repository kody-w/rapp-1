#!/usr/bin/env python3
"""Append the deterministic rev-14 RAPP/1 specification-chain frame."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Dict


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rapp as R
from anchor import materialize_spec as M


ANCHOR = pathlib.Path(__file__).resolve().parent
CHAIN = ANCHOR / "chain.jsonl"
ORIENT = ANCHOR / "orient.json"
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


def orient_for(frame: dict, previous_orient: dict) -> dict:
    payload = frame["payload"]
    orient = json.loads(json.dumps(previous_orient))
    orient["generated_utc"] = frame["utc"]
    orient["head"] = {
        "seq": frame["seq"],
        "frame_hash": frame["frame_hash"],
        "payload_hash": frame["payload_hash"],
    }
    orient["spec"] = {
        "revision": REVISION,
        "revision_frame_hash": frame["frame_hash"],
        "revision_payload_hash": frame["payload_hash"],
        "schema": M.REVISION_SCHEMA,
        "materialized_path": "SPEC.md",
        "media_type": M.NORMATIVE_MEDIA_TYPE,
        "normative_sha256": payload["normative"]["sha256"],
        "normative_bytes": payload["normative"]["bytes"],
        "canonical_repo": payload["canonical_repo"],
        "commit": payload["commit"],
    }
    for key in (
        "vocabulary",
        "operational_profiles",
        "foundation",
        "philosophy",
        "constitution",
    ):
        orient[key] = payload[key]
    return orient


def main() -> None:
    ensure_committed_inputs()
    commit, commit_utc, observed_utc = spec_source()
    spec_octets = (ROOT / "SPEC.md").read_bytes()
    chain_octets = CHAIN.read_bytes()
    frames = M.verify_chain(chain_octets)
    orient = M.verify_orient(ORIENT.read_bytes(), frames)
    head = frames[-1]

    if head["payload"]["revision"] == REVISION:
        if len(frames) < 2:
            raise SystemExit("rev-14 cannot be the anchor genesis")
        expected_payload = revision_payload(
            frames[-2]["payload"],
            spec_octets,
            commit,
            commit_utc,
            observed_utc,
            verify_foundation=False,
        )
        if head["payload"] != expected_payload:
            raise SystemExit("existing rev-14 frame is inconsistent with committed inputs")
        expected_orient = orient_for(head, orient)
        if orient != expected_orient:
            raise SystemExit("existing rev-14 beacon is inconsistent with the chain")
        print(head["frame_hash"])
        return
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
    frame_octets = R.canonical(frame).encode("utf-8")
    if len(frame_octets) > R.MAX_CANONICAL_BYTES:
        raise SystemExit("rev-14 frame exceeds the RAPP/1 canonical-byte limit")
    candidate_chain = chain_octets + json.dumps(frame, ensure_ascii=False).encode("utf-8") + b"\n"
    verified = M.verify_chain(candidate_chain)
    if verified[-1] != frame:
        raise SystemExit("generated frame did not survive full-chain verification")
    candidate_orient = orient_for(frame, orient)
    M.verify_orient(
        (json.dumps(candidate_orient, ensure_ascii=False, indent=1) + "\n").encode(
            "utf-8"
        ),
        verified,
    )
    if not candidate_chain.startswith(chain_octets):
        raise SystemExit("generator would rewrite historical chain bytes")
    M.atomic_write(CHAIN, candidate_chain)
    M.atomic_write(
        ORIENT,
        (json.dumps(candidate_orient, ensure_ascii=False, indent=1) + "\n").encode(
            "utf-8"
        ),
    )
    print(frame["frame_hash"])


if __name__ == "__main__":
    main()
