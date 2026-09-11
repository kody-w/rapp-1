"""Check local authority-bound views; optionally observe current canonical main.

Offline success is local alignment, not freshness, ratification, or ecosystem
compatibility. The live observation uses the public Atom feed for discovery,
then checks the beacon at the observed immutable commit.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import rapp as R
import realcheck
from anchor import materialize_spec as M


ROOT = Path(__file__).resolve().parent
CANONICAL = "https://github.com/kody-w/rapp-1"
FEED = CANONICAL + "/commits/main.atom"
RAW = "https://raw.githubusercontent.com/kody-w/rapp-1/"
ATOM = "{http://www.w3.org/2005/Atom}"
MAX_BYTES = 16 * 1024 * 1024
MAX_HTTP_BYTES = 2 * 1024 * 1024
FRONT_DOORS = {
    "README.md": r"current (rev-[0-9]+) chain head",
    "index.html": r"RAPP (rev-[0-9]+)",
    "guide/index.html": r"RAPP (rev-[0-9]+)",
}


class AlignmentError(ValueError):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def local_file(root, name, measured=None):
    if (
        not isinstance(name, str) or "\\" in name or "\0" in name
        or any(part in ("", ".", "..") for part in name.split("/"))
        or ":" in name
    ):
        raise AlignmentError("unsafe authority-bound relative path")
    raw = M.read_bounded_file(root.joinpath(*name.split("/")), maximum_bytes=MAX_BYTES)
    if measured is not None:
        measured[name] = {"sha256": digest(raw), "bytes": len(raw)}
    return raw


def verify_anchor(root, measured):
    read = lambda name: local_file(root, name, measured)
    bootstrap_raw = read("anchor/bootstrap/index.json")
    bootstrap_document = R._strict_json(bootstrap_raw)
    profile, bootstrap = M.load_bootstrap(
        index_octets=bootstrap_raw,
        profile_octets=read(bootstrap_document["profile_path"]),
        verifier_octets=read("anchor/bootstrap_verify.py"),
    )
    frames = M.verify_chain(read("anchor/chain.jsonl"), bootstrap_profile=profile)
    index_raw = read("anchor/index.json")
    M.verify_revision_index(
        index_raw, frames, object_loader=read,
        bootstrap_index=bootstrap, bootstrap_profile=profile,
    )
    orient_raw = read("anchor/orient.json")
    orient = M.verify_orient(
        orient_raw, frames, index_octets=index_raw, bootstrap_index=bootstrap,
    )
    normative = M.resolve_spec_bytes(frames[-1], offline=True)
    if read("SPEC.md") != normative:
        raise AlignmentError("SPEC.md differs from the verified chain's normative bytes")
    return orient, orient_raw


def verify_bound_views(root, orient, measured):
    def bound(path, expected, size=None):
        raw = local_file(root, path, measured)
        if not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected):
            raise AlignmentError("invalid declared file digest")
        if digest(raw) != expected:
            raise AlignmentError("authority-bound file differs: " + path)
        if size is not None and (type(size) is not int or size != len(raw)):
            raise AlignmentError("authority-bound file length differs: " + path)

    foundation = R._strict_json(local_file(root, "FOUNDATION.json", measured))
    if foundation != orient["foundation"]:
        raise AlignmentError("FOUNDATION.json differs from the verified chain head")
    philosophy = orient["philosophy"]
    if philosophy["canonical_sha256"] != philosophy["mirror_sha256"]:
        raise AlignmentError("philosophy's asserted byte-identical mirror hashes disagree")
    bound(philosophy["mirror_path"], philosophy["mirror_sha256"])
    constitution = orient["constitution"]
    bound(constitution["path"], constitution["sha256"], constitution["size_bytes"])
    for profile in orient["operational_profiles"].values():
        bound(profile["spec_path"], profile["spec_sha256"])
        bound(profile["schema_path"], profile["schema_sha256"])


def verify_front_doors(root, revision, measured):
    for name, pattern in FRONT_DOORS.items():
        text = local_file(root, name, measured).decode("utf-8")
        labels = set(re.findall(pattern, text))
        if not labels:
            raise AlignmentError("current revision label is absent: " + name)
        if labels != {revision}:
            raise AlignmentError("stale current revision label in {}: {}".format(name, sorted(labels)))


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (
            new.scheme != "https" or new.hostname != old.hostname
            or new.port not in (None, 443) or new.username is not None
            or new.password is not None
        ):
            raise AlignmentError("public authority observation redirected outside its HTTPS origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_public(url):
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https" or parsed.hostname not in ("github.com", "raw.githubusercontent.com")
        or parsed.port not in (None, 443) or parsed.username is not None
        or parsed.password is not None
    ):
        raise AlignmentError("not a public canonical HTTPS URL")
    request = urllib.request.Request(url, headers={
        "User-Agent": "rapp-1-alignment-observer",
        "Accept": "application/atom+xml, application/json, text/plain",
    })
    opener = urllib.request.build_opener(SameOriginRedirect())
    with opener.open(request, timeout=30) as response:
        raw = response.read(MAX_HTTP_BYTES + 1)
    if len(raw) > MAX_HTTP_BYTES:
        raise AlignmentError("public authority response exceeds the observation limit")
    return raw


def feed_head(raw):
    if len(raw) > MAX_HTTP_BYTES or b"<!DOCTYPE" in raw.upper():
        raise AlignmentError("oversized or DTD-bearing authority feed")
    feed = ET.fromstring(raw)
    if feed.tag != ATOM + "feed":
        raise AlignmentError("discovery response is not an Atom feed")
    if feed.findtext(ATOM + "id") != "tag:github.com,2008:/kody-w/rapp-1/commits/main":
        raise AlignmentError("discovery feed is not canonical main")
    entry = feed.find(ATOM + "entry")
    if entry is None:
        raise AlignmentError("canonical-main discovery feed contains no commits")
    value = entry.findtext(ATOM + "id", "")
    match = re.fullmatch(r"tag:github.com,2008:Grit::Commit/([0-9a-f]{40})", value)
    if match is None:
        raise AlignmentError("feed head has no immutable commit identity")
    commit = match.group(1)
    links = [
        link.get("href") for link in entry.findall(ATOM + "link")
        if link.get("rel") == "alternate"
    ]
    if links != [CANONICAL + "/commit/" + commit]:
        raise AlignmentError("feed head link and commit identity disagree")
    return commit


def observe_main(root, orient_raw, fetcher=fetch_public):
    commit = feed_head(fetcher(FEED))
    url = RAW + commit + "/anchor/orient.json"
    remote_raw = fetcher(url)
    if len(remote_raw) > MAX_HTTP_BYTES:
        raise AlignmentError("public beacon exceeds the observation limit")
    remote = R._strict_json(remote_raw)
    if not isinstance(remote, dict) or remote.get("schema") != "rapp/1-anchor":
        raise AlignmentError("the observed commit does not provide a RAPP anchor beacon")
    local_commit = realcheck.git("rev-parse", "--verify", "HEAD^{commit}", cwd=root).decode().strip()
    dirty = bool(realcheck.git("status", "--porcelain", "--untracked-files=normal", cwd=root))
    result = {
        "state": "OBSERVED",
        "discovery": FEED,
        "observed_canonical_main_commit": commit,
        "local_base_commit": local_commit,
        "beacon_url": url,
        "beacon_sha256": digest(remote_raw),
        "local_base_is_current": commit == local_commit,
        "local_beacon_matches": orient_raw == remote_raw,
        "working_tree_has_candidate_changes": dirty,
        "ratification_authenticated_by_this_report": False,
        "network_authentication": "public HTTPS, no GitHub token",
    }
    if not result["local_base_is_current"] or not result["local_beacon_matches"]:
        result["state"] = "STALE_OR_DIVERGENT"
    else:
        result["state"] = "CANDIDATE_ON_CURRENT_MAIN" if dirty else "CURRENT_OBSERVED_CHECKPOINT"
    return result


def observe(root=ROOT, live=False, fetcher=fetch_public):
    root = Path(root).resolve()
    report = {
        "schema": "rapp-alignment-observation/1",
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "Local chain-bound views and named front doors; optional canonical-main freshness.",
        "checks": [], "measured_files": {},
        "freshness": {
            "state": "NOT_OBSERVED",
            "reason": "Offline integrity is not evidence that canonical main is still current.",
        },
        "ratification_authenticated": False,
        "ecosystem_compatibility_measured": False,
    }
    measured = report["measured_files"]
    stage = "bootstrap-chain-index-beacon-and-materialized-spec"
    try:
        orient, orient_raw = verify_anchor(root, measured)
        report["checks"].append({"name": stage, "status": "PASS"})
        report["protocol"] = {
            "revision": orient["spec"]["revision"],
            "normative_source_commit": orient["spec"]["commit"],
            "normative_sha256": orient["spec"]["normative_sha256"],
            "frame_hash": orient["head"]["frame_hash"],
            "particle_hash": orient["head"]["payload_hash"],
        }
        stage = "chain-bound-local-mirrors"
        verify_bound_views(root, orient, measured)
        report["checks"].append({"name": stage, "status": "PASS"})
        stage = "current-front-door-labels-present-and-aligned"
        verify_front_doors(root, orient["spec"]["revision"], measured)
        report["checks"].append({"name": stage, "status": "PASS"})
        if live:
            stage = "live-canonical-main-observation"
            report["freshness"] = observe_main(root, orient_raw, fetcher)
            if report["freshness"]["state"] == "STALE_OR_DIVERGENT":
                raise AlignmentError("the local checkout or beacon differs from observed canonical main")
            report["checks"].append({"name": stage, "status": "PASS"})
        report["status"] = (
            report["freshness"]["state"] if live else "LOCALLY_ALIGNED_NOT_FRESHNESS_CERTIFIED"
        )
        report["exit_code"] = 0
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, subprocess.SubprocessError) as error:
        report["checks"].append({"name": stage, "status": "FAIL", "error": str(error)})
        report["status"] = "REFUSED"
        report["exit_code"] = 1
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--live", action="store_true", help="Observe canonical main; fail on stale base or differing beacon.")
    parser.add_argument("--output", type=Path, help="Write JSON to a new file; never replace earlier evidence.")
    args = parser.parse_args(argv)
    report = observe(args.root, args.live)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        try:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(text)
        except OSError as error:
            print(json.dumps({"status": "REFUSED", "error": str(error)}), file=sys.stderr)
            return 1
    print(text, end="")
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
