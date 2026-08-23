"""rapp_check.py — the RAPP compliance linter.

Point it at any repo checkout and it verdicts every RAPP artifact (rappid.json,
frame chains, egg/schema labels) against the RAPP standard, using the reference
implementation. It classifies a repo as:

  CLEAN     — no RAPP artifacts; nothing to migrate
  COMPLIANT — has artifacts, all pass RAPP
  UNVERIFIED — an external lineage required for verification is unavailable
  DRIFT     — has artifacts that violate RAPP (lists each, by §)

This is the tool that makes the estate-wide migration tractable: run it per repo,
fix on a branch until it reads COMPLIANT, and the owner authorizes the rebirth by merge.

Usage:  python3 rapp_check.py <repo_path> [--json]
Exit:   0 CLEAN/COMPLIANT · 1 UNVERIFIED/DRIFT · 2 error
"""
import glob
import hashlib
import json
import os
import re
import sys

import rapp as R

_32HEX = re.compile(r"^[0-9a-f]{32}$")


def _untagged(payload):
    return hashlib.sha256(R.canonical(payload).encode("utf-8")).hexdigest()


def check_repo(root):
    """Return (verdict, findings[], evidence[]). findings/evidence are dicts."""
    findings, evidence = [], []
    has_artifact = False

    # ---- identity records ----
    for path in sorted(glob.glob(os.path.join(root, "**", "rappid.json"), recursive=True)):
        if ".git/" in path:
            continue
        has_artifact = True
        rel = os.path.relpath(path, root)
        try:
            d = json.load(open(path))
        except Exception as ex:
            findings.append({"artifact": rel, "rule": "unreadable", "detail": str(ex)})
            continue
        rid = d.get("rappid", "")
        schema = d.get("schema", "?")
        # Plant-template exemption: a committed SEED whose identity is minted at
        # plant time carries a `__SENTINEL__` placeholder, not a deployed hash.
        # It is scaffolding, not a deployed identity — §6.1 grammar does not apply
        # (the mint happens at plant). Tight match (double-underscore uppercase
        # sentinel as the whole tail) so no real deployed rappid can slip through.
        _tail = rid.rsplit(":", 1)[-1] if ":" in rid else rid
        _is_template = bool(re.match(r"^__[A-Z0-9_]+__$", _tail))
        if _is_template:
            evidence.append({"artifact": rel,
                             "ok": f"plant-template (identity minted at plant), exempt from §6.1: {rid}"})
        elif R.rappid_valid(rid):
            m = R._RAPPID.match(rid)
            owner, slug, tail = m.group(1), m.group(2), m.group(3)
            if tail == hashlib.sha256(f"{owner}/{slug}".encode()).hexdigest():
                findings.append({"artifact": rel, "rule": "§6.2 name-hash mint",
                                 "detail": f"tail == sha256('{owner}/{slug}')"})
            else:
                evidence.append({"artifact": rel, "ok": f"rappid §6.1 grammar OK: {rid}"})
        else:
            tail = rid.rsplit(":", 1)[-1] if ":" in rid else rid
            if _32HEX.match(tail):
                findings.append({"artifact": rel, "rule": "§6.1 short-tail (C3)",
                                 "detail": f"32-hex tail, not 64-hex: {rid}"})
            else:
                findings.append({"artifact": rel, "rule": "§6.1 grammar (C2)",
                                 "detail": f"not rappid:@owner/slug:64hex — {rid}"})
        if schema not in ("rapp/1",):
            findings.append({"artifact": rel, "rule": "§12 schema label",
                             "detail": f"schema='{schema}', not 'rapp/1'"})
        # §6.3: a parent_rappid must itself be a valid RAPP rappid (not a legacy/provisional id)
        parent = d.get("parent_rappid")
        if parent and not R.rappid_valid(parent):
            findings.append({"artifact": rel, "rule": "§6.3 parent_rappid",
                             "detail": f"parent_rappid not RAPP grammar: {parent}"})

    # ---- frame chains ----
    frame_directories = sorted({
        os.path.dirname(path)
        for path in glob.glob(os.path.join(root, "**", "frames", "*.json"), recursive=True)
        if ".git/" not in path
    })
    chains = []
    chains_by_stream = {}
    for fdir in frame_directories:
        files = sorted((f for f in glob.glob(os.path.join(fdir, "*.json"))
                        if re.match(r"^\d+\.json$", os.path.basename(f))),
                       key=lambda f: int(os.path.basename(f)[:-5]))
        if not files:
            continue
        chain = [json.load(open(path)) for path in files]
        chains.append((fdir, files, chain))
        stream_id = chain[0].get("stream_id")
        if isinstance(stream_id, str):
            chains_by_stream[stream_id] = chain

    fold_cache = {}

    def fold_local(stream_id, particle=None, visiting=()):
        """Fold one locally present lineage, resolving each parent at its claimed particle."""
        key = (stream_id, particle)
        if key in fold_cache:
            return fold_cache[key]
        if stream_id in visiting:
            return False, "§7.7.5", "local parent lineage contains a cycle", None
        chain = chains_by_stream.get(stream_id)
        if chain is None:
            return False, "§7.7.5", (
                f"{R.UNRESOLVED_PARENT} — parent stream {stream_id!r} is not in this checkout"
            ), None
        selected = chain
        if particle is not None:
            matches = [
                index for index, frame in enumerate(chain)
                if frame.get("payload_hash") == particle
            ]
            if not matches:
                return False, "§7.7.5", (
                    f"parent particle {particle} is not present in local stream {stream_id}"
                ), None
            selected = chain[:matches[0] + 1]
        inherited = None
        genesis = selected[0].get("payload", {}) if selected else {}
        parent = genesis.get("parent") if isinstance(genesis, dict) else None
        if parent is not None:
            if not isinstance(parent, dict):
                return False, "§7.7.5", "parent pointer is not an object", None
            inherited_result = fold_local(
                parent.get("rappid"), parent.get("particle"), (*visiting, stream_id)
            )
            if not inherited_result[0]:
                return inherited_result
            inherited = inherited_result[3]
        result = R.fold_body_stream(
            selected, stream_id_of_record=stream_id, inherited=inherited
        )
        fold_cache[key] = result
        return result

    for fdir, files, chain in chains:
        has_artifact = True
        rel = os.path.relpath(fdir, root)
        canon_ok = conformant = 0
        head = None  # thread the head so chain linkage (seq/prev/utc) is actually checked
        for fr in chain:
            p, s = fr.get("payload"), (fr.get("sha256") or fr.get("hash"))
            if p is not None and s is not None and _untagged(p) == s:
                canon_ok += 1
            ok, _, _ = R.verify_frame(fr, head=head, stream_id_of_record=fr.get("stream_id"))
            if ok:
                conformant += 1
                head = fr  # advance only on a valid frame, so seq contiguity is enforced
        if conformant == len(files):
            evidence.append({"artifact": rel, "ok": f"{len(files)} frames conform to §7 envelope"})
        else:
            keys = sorted(json.load(open(files[0])).keys())
            missing = sorted(R.FRAME_KEYS - set(keys))
            findings.append({"artifact": rel, "rule": "§7 frame envelope (C1)",
                             "detail": f"{len(files)-conformant}/{len(files)} non-conformant; "
                                       f"missing {missing}"})
        # §7.7: a body-stream that grows by dimension frames must fold the way any
        # conformant reader rebuilds it — one identity, no stage regression, no fabricated
        # inheritance. A parent stream we do not hold is UNVERIFIED, never clean.
        if any(fr.get("kind") in (R.BODY_DIMENSION, R.BODY_RECONSTRUCTED) for fr in chain):
            ok, step, why, state = fold_local(chain[0].get("stream_id"))
            if ok:
                w = state["weight"]
                evidence.append({"artifact": rel, "ok": (
                    f"§7.7 growth folds: stage {state['stage']['name']} · dimensions "
                    f"{', '.join(sorted(state['dimensions']))} · frame_height "
                    f"{state['frame_height']} · one rappid {state['rappid']}")})
                evidence.append({"artifact": rel, "ok": (
                    f"§7.8 weight: {R.format_weight(w['total_weight_bytes'])} "
                    f"({w['total_weight_bytes']} bytes exactly = {w['frame_weight_bytes']} in frames "
                    f"+ {w['asset_weight_bytes']} in assets)")})
                if not w["complete"]:
                    findings.append({"artifact": rel, "rule": "§7.8 incomplete weight",
                                     "detail": "an asset's size is attested two ways, so it could "
                                               "not be established — weight is never estimated"})
            elif R.UNRESOLVED_PARENT in why:
                findings.append({"artifact": rel, "rule": "§7.7 lineage",
                                 "status": "unverified",
                                 "detail": "parent stream is not in this checkout; "
                                           "resolve it and re-verify (fail closed)"})
            else:
                findings.append({"artifact": rel, "rule": f"§7.7 dimensional growth ({step})",
                                 "detail": why})
        # positive evidence: does RAPP canonicalization already reproduce the real hashes?
        if canon_ok:
            evidence.append({"artifact": rel,
                             "ok": f"§4 canonicalization reproduces {canon_ok}/{len(files)} real payload hashes"})

    # ---- eggs (§9) ----
    for e in sorted(glob.glob(os.path.join(root, "**", "*.egg"), recursive=True)):
        if ".git/" in e:
            continue
        has_artifact = True
        rel = os.path.relpath(e, root)
        try:
            blob = open(e, "rb").read()
            ok, step, why = R.verify_egg(blob)
            if ok:
                evidence.append({"artifact": rel, "ok": "egg conforms to §9 (rapp/1-egg)"})
            else:
                try:
                    m, _ = R.read_egg(blob)
                    sch = m.get("schema", "?")
                except Exception:
                    sch = "?"
                findings.append({"artifact": rel, "rule": "§9 egg",
                                 "detail": f"not a conformant rapp/1-egg (schema={sch}; {step}: {why})"})
        except Exception as ex:
            findings.append({"artifact": rel, "rule": "§9 egg",
                             "detail": f"unreadable egg: {ex}"})

    if not has_artifact:
        return "CLEAN", [], []
    if not findings:
        return "COMPLIANT", findings, evidence
    if all(finding.get("status") == "unverified" for finding in findings):
        return "UNVERIFIED", findings, evidence
    return "DRIFT", findings, evidence


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__.strip().splitlines()[-2]); sys.exit(2)
    root = args[0]
    verdict, findings, evidence = check_repo(root)
    if as_json:
        print(json.dumps({"repo": root, "verdict": verdict,
                          "findings": findings, "evidence": evidence}, indent=2))
    else:
        name = os.path.basename(os.path.abspath(root))
        dot = {"CLEAN": "○", "COMPLIANT": "✅", "UNVERIFIED": "⚠", "DRIFT": "🔧"}[verdict]
        print(f"{dot} {name}: {verdict}")
        for e in evidence:
            print(f"    ✓ {e['artifact']}: {e['ok']}")
        for f in findings:
            print(f"    ✗ {f['artifact']}  [{f['rule']}]  {f['detail']}")
    sys.exit(0 if verdict in ("CLEAN", "COMPLIANT") else 1)


if __name__ == "__main__":
    main()
