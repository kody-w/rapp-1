#!/usr/bin/env python3
"""Append one anchor revision from the committed SPEC.md."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rapp as R


ANCHOR = pathlib.Path(__file__).resolve().parent
CHAIN = ANCHOR / "chain.jsonl"
ORIENT = ANCHOR / "orient.json"
REVISION = "rev-12"


def utc_now() -> str:
    value = datetime.now(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{value.microsecond // 1000:03d}Z"
    )


def main() -> None:
    anchored_paths = [
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
    ]
    for path in anchored_paths:
        if subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", path],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode != 0:
            raise SystemExit(f"anchored path is not committed: {path}")
    status = subprocess.check_output(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "SPEC.md",
            "CONSTITUTION.md",
            "FOUNDATION.json",
            "PHILOSOPHY.md",
            "rapp.py",
            "protocols",
        ],
        cwd=ROOT,
        text=True,
    )
    if status.strip():
        raise SystemExit(
            "commit SPEC.md, CONSTITUTION.md, FOUNDATION.json, PHILOSOPHY.md, rapp.py, and protocols before generating the anchor"
        )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()
    commit_utc = subprocess.check_output(
        ["git", "show", "-s", "--format=%cI", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()
    spec_octets = (ROOT / "SPEC.md").read_bytes()
    constitution_octets = (ROOT / "CONSTITUTION.md").read_bytes()
    observed_utc = utc_now()
    frames = [
        json.loads(line)
        for line in CHAIN.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    head = frames[-1]
    payload = json.loads(json.dumps(head["payload"]))
    payload["revision"] = REVISION
    payload["normative_sha256"] = hashlib.sha256(spec_octets).hexdigest()
    payload["normative_bytes"] = str(len(spec_octets))
    payload["commit"] = commit
    payload["commit_utc"] = commit_utc
    payload["observed_utc"] = observed_utc
    payload["constitution"] = {
        "path": "CONSTITUTION.md",
        "sha256": hashlib.sha256(constitution_octets).hexdigest(),
        "size_bytes": len(constitution_octets),
    }
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
    if (
        not isinstance(foundation["commit"], str)
        or len(foundation["commit"]) != 40
        or any(ch not in "0123456789abcdef" for ch in foundation["commit"])
    ):
        raise SystemExit("FOUNDATION.json commit is not 40 lowercase hex")
    philosophy_octets = (ROOT / "PHILOSOPHY.md").read_bytes()
    philosophy_sha256 = hashlib.sha256(philosophy_octets).hexdigest()
    if (
        foundation["path"] != "PHILOSOPHY.md"
        or foundation["sha256"] != philosophy_sha256
        or foundation["size_bytes"] != len(philosophy_octets)
    ):
        raise SystemExit("foundation philosophy mirror drift")
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
        or hashlib.sha256(canonical_philosophy).hexdigest() != foundation["sha256"]
        or len(canonical_philosophy) != foundation["size_bytes"]
    ):
        raise SystemExit("pinned RAPP foundation bytes do not match the mirror")
    payload["foundation"] = foundation
    payload["philosophy"] = {
        "canonical_repository": foundation["repository"],
        "canonical_commit": foundation["commit"],
        "canonical_path": foundation["path"],
        "canonical_sha256": foundation["sha256"],
        "mirror_path": "PHILOSOPHY.md",
        "mirror_sha256": philosophy_sha256,
    }
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
    operational_profiles = {}
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
        if profile["name"] in operational_profiles:
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
        if hashlib.sha256(spec_path.read_bytes()).hexdigest() != profile["spec_sha256"]:
            raise SystemExit(f"profile spec hash drift: {profile['name']}")
        if hashlib.sha256(schema_path.read_bytes()).hexdigest() != profile["schema_sha256"]:
            raise SystemExit(f"profile schema hash drift: {profile['name']}")
        operational_profiles[profile["name"]] = {
            "status": "live",
            "spec_path": profile["spec_path"],
            "spec_sha256": profile["spec_sha256"],
            "schema_path": profile["schema_path"],
            "schema_sha256": profile["schema_sha256"],
        }
    payload["operational_profiles"] = operational_profiles
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
    frame = R.build_frame(
        "body.pulse",
        head["stream_id"],
        head["seq"] + 1,
        observed_utc,
        payload,
        head["payload_hash"],
    )
    with CHAIN.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(frame, ensure_ascii=False) + "\n")

    orient = json.loads(ORIENT.read_text(encoding="utf-8"))
    orient["generated_utc"] = observed_utc
    orient["head"] = {
        "seq": frame["seq"],
        "frame_hash": frame["frame_hash"],
        "payload_hash": frame["payload_hash"],
    }
    orient["spec"] = {
        "revision": REVISION,
        "normative_path": "SPEC.md",
        "normative_sha256": payload["normative_sha256"],
        "canonical_repo": payload["canonical_repo"],
        "commit": commit,
    }
    orient["vocabulary"] = payload["vocabulary"]
    orient["operational_profiles"] = operational_profiles
    orient["foundation"] = foundation
    orient["philosophy"] = payload["philosophy"]
    orient["constitution"] = payload["constitution"]
    ORIENT.write_text(
        json.dumps(orient, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
    )
    print(frame["frame_hash"])


if __name__ == "__main__":
    main()
