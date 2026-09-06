"""Observe committed reference-estate artifacts; drift and missing evidence fail.

The default scope is five named public repositories, not the whole owner.
Git objects, never dirty working files, supply the measured bytes. Importing
this module never synchronizes or observes repositories.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from datetime import datetime, timezone

import rapp as R


ROOT = Path(__file__).resolve().parent
DEFAULT_REPOS = ("twin", "rapp-body", "rapp-commons", "rapp-map", "RAR")
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class ObservationError(ValueError):
    pass


def git(*args, cwd=None):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
    }
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    command = [
        "git", "-c", "credential.helper=", "-c", "core.hooksPath=" + os.devnull,
        "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always", *args,
    ]
    result = subprocess.run(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=300, check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace")[:4096].strip()
        raise ObservationError("git {} failed: {}".format(args[0], detail))
    return result.stdout


def revision():
    data = R._strict_json((ROOT / "anchor" / "orient.json").read_bytes())
    return {
        "revision": data["spec"]["revision"],
        "frame_hash": data["head"]["frame_hash"],
        "normative_sha256": data["spec"]["normative_sha256"],
    }


def snapshot(path, owner, name, sync):
    """Fetch only the observed HEAD; do not pull, reset, or execute a checkout."""
    if not NAME.fullmatch(owner) or not NAME.fullmatch(name):
        raise ObservationError("unsafe owner or repository name")
    if path.is_symlink():
        raise ObservationError("repository cache must not be a symlink")
    expected_url = "https://github.com/{}/{}.git".format(owner, name)
    if not path.exists():
        if not sync:
            raise ObservationError("repository is absent in offline observation")
        path.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "--bare", "--quiet", expected_url, str(path))
    config = git("config", "--local", "--null", "--list", cwd=path)
    for entry in config.split(b"\0"):
        raw_key = entry.split(b"\n", 1)[0]
        key = raw_key.lower()
        promisor = key.startswith(b"remote.") and key.endswith(b".promisor")
        enabled = promisor and git(
            "config", "--local", "--bool", "--get", raw_key.decode("utf-8"), cwd=path,
        ).strip() == b"true"
        if key == b"extensions.partialclone" or enabled:
            raise ObservationError("partial/promisor clones are unsupported; use a complete local cache")
    top = git("rev-parse", "--absolute-git-dir", cwd=path).decode().strip()
    if not top:
        raise ObservationError("repository has no Git object database")
    bare = git("rev-parse", "--is-bare-repository", cwd=path).strip() == b"true"
    repository_root = Path(top) if bare else Path(
        git("rev-parse", "--show-toplevel", cwd=path).decode().strip()
    )
    if repository_root.resolve() != path.resolve():
        raise ObservationError("cache path is not the root of the selected repository")
    ref = "HEAD"
    if sync:
        origin = git("remote", "get-url", "origin", cwd=path).decode().strip()
        if origin not in (expected_url, expected_url[:-4]):
            raise ObservationError("origin is not the selected public GitHub repository")
        git("fetch", "--no-tags", "--quiet", "origin", "HEAD", cwd=path)
        ref = "FETCH_HEAD"
    commit = git("rev-parse", "--verify", ref + "^{commit}", cwd=path).decode().strip()
    if not OID.fullmatch(commit):
        raise ObservationError("invalid observed commit")
    return commit


def artifact_entries(path, commit):
    raw = git("ls-tree", "-r", "-z", "--full-tree", commit, cwd=path)
    if len(raw) > MAX_TREE_BYTES:
        raise ObservationError("tracked-tree metadata exceeds the observation limit")
    entries = []
    tracked = 0
    for item in raw.split(b"\0"):
        if not item:
            continue
        tracked += 1
        header, raw_name = item.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
        parts = raw_name.split(b"/")
        is_identity = parts[-1] == b"rappid.json"
        is_frame = (
            len(parts) >= 2 and parts[-2] == b"frames"
            and re.fullmatch(rb"[0-9]+\.json", parts[-1]) is not None
        )
        if not (is_identity or is_frame):
            continue
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ObservationError("declared artifact is not a regular Git blob")
        if not OID.fullmatch(oid):
            raise ObservationError("artifact has an invalid Git object identifier")
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ObservationError("artifact path is not representable as UTF-8") from error
        if any(part in (b"", b".", b"..") for part in parts):
            raise ObservationError("unsafe artifact path")
        entries.append((name, oid, "identity" if is_identity else "frame"))
    return tracked, entries


def read_artifact(path, oid):
    size = int(git("cat-file", "-s", oid, cwd=path).strip())
    if size > MAX_ARTIFACT_BYTES:
        raise ObservationError("artifact exceeds the RAPP JSON byte limit")
    raw = git("cat-file", "blob", oid, cwd=path)
    if len(raw) != size:
        raise ObservationError("Git blob size changed during observation")
    actual = hashlib.new("sha1" if len(oid) == 40 else "sha256")
    actual.update(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw)
    if actual.hexdigest() != oid:
        raise ObservationError("Git blob content does not match its object identifier")
    value = R._strict_json(raw)
    if not isinstance(value, dict):
        raise ObservationError("artifact is not a JSON object")
    return value


def finding(report, artifact, category, detail):
    report["drift"].append({
        "artifact": artifact, "category": category, "detail": str(detail),
    })


def check_frames(report, repository, folder, frames):
    head = None
    stream = None
    previous_particle = None
    for expected_seq, (name, value) in enumerate(sorted(
        frames, key=lambda row: (int(PurePosixPath(row[0]).stem), row[0])
    )):
        artifact = repository + "/" + name
        stats = report["frames"]
        stats["total"] += 1
        if value is None:
            continue
        current = value.get("spec") == R.SPEC
        if not current:
            finding(report, artifact, "legacy-envelope",
                    "Preserved legacy data is not a current RAPP/1 frame; no rewrite was attempted.")
            continue
        seq = value.get("seq")
        filename_seq = int(PurePosixPath(name).stem)
        if type(seq) is not int or seq != expected_seq or filename_seq != seq:
            finding(report, artifact, "sequence",
                    "A complete committed chain must start at 0 and match contiguous file sequence numbers.")
        payload = value.get("payload")
        if isinstance(payload, dict):
            try:
                address_ok = R.H("rapp/1:particle", payload) == value.get("payload_hash")
            except (ValueError, TypeError, OverflowError):
                address_ok = False
            if address_ok:
                stats["address_ok"] += 1
            else:
                finding(report, artifact, "particle-address", "Payload address does not reproduce.")
        if type(seq) is int and (
            (seq == 0 and expected_seq == 0 and value.get("prev") is None)
            or (seq == expected_seq and expected_seq > 0
                and value.get("prev") == previous_particle)
        ):
            stats["chain_ok"] += 1
        else:
            finding(report, artifact, "chain-link", "The preceding particle link does not reproduce.")
        if stream is None:
            stream = value.get("stream_id")
        ok, step, why = R.verify_frame(value, head=head, stream_id_of_record=stream)
        if ok:
            stats["conformant"] += 1
            head = value
        else:
            finding(report, artifact, "frame-refusal/step-{}".format(step), why)
        previous_particle = value.get("payload_hash")
    report["chain_scopes"].append({
        "repository": repository, "path": folder,
        "frames": len(frames), "coverage": "complete numbered directory at the observed commit",
    })


def check_identity(report, artifact, value):
    report["identities"]["total"] += 1
    if value is None:
        return
    rid = value.get("rappid", "")
    if not isinstance(rid, str) or not R.rappid_valid(rid):
        finding(report, artifact, "rappid-grammar", "Not the RAPP/1 RAPPID grammar.")
    else:
        match = R._RAPPID.fullmatch(rid)
        owner, slug, tail = match.group(1), match.group(2), match.group(3)
        if tail == hashlib.sha256((owner + "/" + slug).encode()).hexdigest():
            finding(report, artifact, "name-hash-mint", "Identity is the forbidden deterministic name hash.")
        else:
            report["identities"]["grammar_ok"] += 1
    if value.get("schema") != R.SPEC:
        finding(report, artifact, "schema-label", "Identity record does not declare schema rapp/1.")


def observe(estate_root, repos=DEFAULT_REPOS, owner="kody-w", sync=True):
    estate_root = Path(estate_root).resolve()
    if not repos or len(set(repos)) != len(repos):
        raise ObservationError("select at least one repository, without duplicates")
    report = {
        "schema": "rapp-estate-observation/1",
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "protocol": revision(),
        "mode": "synchronized-public-commits" if sync else "local-commits-offline",
        "owner": owner,
        "selected_repositories": list(repos),
        "scope": "Selected repositories only; numbered frames directories and rappid.json Git blobs.",
        "working_tree_files_read": False,
        "repositories": [],
        "chain_scopes": [],
        "frames": {"total": 0, "address_ok": 0, "chain_ok": 0, "conformant": 0},
        "identities": {"total": 0, "grammar_ok": 0},
        "drift": [],
        "observation_errors": [],
        "runtime_started": False,
        "authority_authenticated": False,
    }
    for repo in repos:
        if not isinstance(repo, str) or not NAME.fullmatch(repo):
            raise ObservationError("unsafe repository name")
        path = estate_root / repo
        try:
            commit = snapshot(path, owner, repo, sync)
            tracked, entries = artifact_entries(path, commit)
            report["repositories"].append({
                "name": repo, "commit": commit, "tracked_entries": tracked,
                "artifact_entries": len(entries),
            })
            chains = {}
            for name, oid, kind in entries:
                try:
                    value = read_artifact(path, oid)
                except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
                    report["observation_errors"].append({
                        "repository": repo, "artifact": name, "error": str(error),
                    })
                    value = None
                if kind == "identity":
                    check_identity(report, repo + "/" + name, value)
                else:
                    folder = str(PurePosixPath(name).parent)
                    chains.setdefault(folder, []).append((name, value))
            for folder, frames in sorted(chains.items()):
                check_frames(report, repo, folder, frames)
        except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
            report["observation_errors"].append({"repository": repo, "error": str(error)})
    if report["frames"]["total"] + report["identities"]["total"] == 0:
        report["observation_errors"].append({
            "error": "The selected commits contain no measurable in-scope artifacts.",
        })
    report["status"] = (
        "INCOMPLETE" if report["observation_errors"]
        else "DRIFT" if report["drift"] else "CONFORMANT_IN_SCOPE"
    )
    return report


def render(report):
    stats = report["frames"]
    lines = [
        "RAPP {} - committed reference-estate observation".format(report["protocol"]["revision"]),
        "Scope: " + report["scope"],
        "Mode: " + report["mode"],
    ]
    for repo in report["repositories"]:
        lines.append("  {} @ {}".format(repo["name"], repo["commit"]))
    for row in report["drift"]:
        lines.append("DRIFT {} [{}]: {}".format(row["artifact"], row["category"], row["detail"]))
    for row in report["observation_errors"]:
        lines.append("INCOMPLETE: " + json.dumps(row, sort_keys=True))
    lines.extend([
        "Inspected frames: {}".format(stats["total"]),
        "Stored addresses reproduced: {}/{}".format(stats["address_ok"], stats["total"]),
        "Chain links verified: {}/{}".format(stats["chain_ok"], stats["total"]),
        "Current RAPP envelopes accepted: {}/{}".format(stats["conformant"], stats["total"]),
        "Remaining drift findings: {}".format(len(report["drift"])),
        "Observation errors: {}".format(len(report["observation_errors"])),
        "VERDICT: " + report["status"],
        "This does not certify other repositories, runtime behavior, or owner acceptance.",
    ])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estate-root", type=Path, default=ROOT / "estate")
    parser.add_argument("--owner", default="kody-w")
    parser.add_argument("--repo", action="append", dest="repos")
    parser.add_argument("--no-sync", action="store_true", help="Read local committed HEADs; never use the network.")
    parser.add_argument("--json", action="store_true", help="Print the machine-readable observation.")
    parser.add_argument("--output", type=Path, help="Write JSON to a new report file, refusing replacement.")
    args = parser.parse_args(argv)
    try:
        report = observe(
            args.estate_root, args.repos if args.repos is not None else DEFAULT_REPOS,
            args.owner, not args.no_sync,
        )
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output is not None:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        print(encoded if args.json else render(report), end="" if args.json else "\n")
        return {"CONFORMANT_IN_SCOPE": 0, "DRIFT": 1, "INCOMPLETE": 2}[report["status"]]
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "INCOMPLETE", "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
