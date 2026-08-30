"""realcheck.py — run the RAPP reference implementation against the current,
committed artifacts of the kody-w estate (cloned under ./estate) and report,
byte for byte, what conforms and what remains drift.

This is not a curated vector. It walks every frame chain and every rappid.json
that was actually committed to the public repos. Existing clones are fast-forwarded
before every run so a successful migration cannot leave a stale "live" report.

Run: python3 realcheck.py            (expects ./estate/{twin,rapp-body,...})
"""
import glob
import hashlib
import json
import os
import re

import rapp as R

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "estate")
_32HEX = re.compile(r"^[0-9a-f]{32}$")
_64HEX = re.compile(r"^[0-9a-f]{64}$")

conform = []   # (artifact, note)
drift = []     # (artifact, category, detail)
frame_stats = {"total": 0, "address_ok": 0, "chain_ok": 0, "conformant": 0}


def untagged(payload):
    """The hash reality actually stores: sha256(canonical(payload)), no domain tag."""
    return hashlib.sha256(R.canonical(payload).encode("utf-8")).hexdigest()


def check_frame_chain(name, frame_dir):
    files = sorted(
        (f for f in glob.glob(os.path.join(frame_dir, "*.json"))
         if re.match(r"^\d+\.json$", os.path.basename(f))),
        key=lambda f: int(os.path.basename(f)[:-5]),
    )
    if not files:
        return
    print(f"\n── {name}  ({len(files)} committed frames: {frame_dir.replace(ROOT, 'estate')}) ──")
    prev_address = None
    head = None
    address_ok = 0
    chain_ok = 0
    rapp_conformant = 0
    legacy_envelope = False
    stream_id_of_record = None
    for f in files:
        fr = json.load(open(f))
        seq = fr.get("seq")
        payload = fr.get("payload")
        is_current = set(fr) == R.FRAME_KEYS and fr.get("spec") == R.SPEC
        if is_current:
            stored_address = fr.get("payload_hash")
            computed_address = R.H("rapp/1:particle", payload)
            parent = fr.get("prev")
            stream_id_of_record = stream_id_of_record or fr.get("stream_id")
        else:
            legacy_envelope = True
            stored_address = fr.get("sha256") or fr.get("hash")
            computed_address = untagged(payload) if payload is not None else None
            parent = fr.get("parent_sha") if "parent_sha" in fr else fr.get("prev_hash")

        # (1) does the reference canonicalizer reproduce the stored address?
        if payload is not None and stored_address is not None:
            if computed_address == stored_address:
                address_ok += 1
            else:
                drift.append((f"{name}/{os.path.basename(f)}", "canon-mismatch",
                              f"computed={str(computed_address)[:12]} != stored {str(stored_address)[:12]}"))
        # (2) does the chain link through the previous payload address?
        if seq == 0:
            if parent in (None, "", "null"):
                chain_ok += 1
        elif parent == prev_address:
            chain_ok += 1
        else:
            drift.append((f"{name}/{os.path.basename(f)}", "chain-break",
                          f"parent={str(parent)[:12]} != previous={str(prev_address)[:12]}"))
        # (3) is the committed frame conformant to the RAPP §7 envelope as-is?
        ok, step, why = R.verify_frame(
            fr,
            head=head if is_current else None,
            stream_id_of_record=stream_id_of_record if is_current else None,
        )
        if ok:
            rapp_conformant += 1
            head = fr
        elif is_current:
            drift.append((f"{name}/{os.path.basename(f)}", f"frame-refusal/step-{step}", why))
        prev_address = stored_address
    keys = sorted(json.load(open(files[0])).keys())
    print(f"   canonicalization reproduces stored address  : {address_ok}/{len(files)} frames")
    print(f"   chain links per RAPP §7.4 (prev=parent)     : {chain_ok}/{len(files)} frames")
    print(f"   frames conformant to RAPP §7 envelope as-is : {rapp_conformant}/{len(files)}")
    print(f"   committed envelope keys: {keys}")
    frame_stats["total"] += len(files)
    frame_stats["address_ok"] += address_ok
    frame_stats["chain_ok"] += chain_ok
    frame_stats["conformant"] += rapp_conformant
    if address_ok == len(files) and chain_ok == len(files):
        conform.append((name, f"addresses + chain integrity reproduce all {len(files)} committed frames"))
    if legacy_envelope and rapp_conformant == 0:
        # identify the envelope drift precisely
        fr = json.load(open(files[0]))
        missing = R.FRAME_KEYS - set(fr.keys())
        extra = set(fr.keys()) - R.FRAME_KEYS
        drift.append((f"{name}/frames", "envelope-drift/C1",
                      f"legacy envelope: missing {sorted(missing)}, aliases {sorted(extra)}"))


def check_rappid(path):
    try:
        d = json.load(open(path))
    except Exception as ex:
        drift.append((path.replace(ROOT, "estate"), "unreadable", str(ex)))
        return
    rid = d.get("rappid", "")
    short = path.replace(ROOT, "estate")
    schema = d.get("schema", "?")
    if R.rappid_valid(rid):
        conform.append((short, f"rappid grammar §6.1 OK (64-hex tail): {rid}"))
        # is the tail a name-hash of owner/slug? (the ID-01 forbidden mint)
        m = R._RAPPID.match(rid)
        owner, slug, tail = m.group(1), m.group(2), m.group(3)
        if tail == hashlib.sha256(f"{owner}/{slug}".encode()).hexdigest():
            drift.append((short, "name-hash-mint/C3", f"64-hex tail == sha256('{owner}/{slug}') — forbidden §6.2"))
    else:
        tail = rid.rsplit(":", 1)[-1] if ":" in rid else rid
        if _32HEX.match(tail):
            drift.append((short, "short-tail/C3", f"32-hex (128-bit) tail, not §6.1 64-hex: {rid}"))
        else:
            drift.append((short, "rappid-grammar/C2", f"not §6.1 form: {rid}"))
    if schema != "rapp/1":
        drift.append((short, "schema-label", f"schema='{schema}', not 'rapp/1' (§12 living standard)"))


def sync_estate():
    """Clone or fast-forward public repos so "live" never means a stale cache."""
    import subprocess
    os.makedirs(ROOT, exist_ok=True)
    for repo in ("twin", "rapp-body", "rapp-commons", "rapp-map", "RAR"):
        dst = os.path.join(ROOT, repo)
        print(f"   syncing kody-w/{repo} …")
        if os.path.isdir(os.path.join(dst, ".git")):
            subprocess.run(
                ["git", "-C", dst, "pull", "--ff-only", "-q"],
                check=True,
            )
        else:
            subprocess.run(
                ["git", "clone", "--depth", "1", "-q",
                 f"https://github.com/kody-w/{repo}.git", dst],
                check=True,
            )


print("=" * 74)
print("RAPP rev-7 — REAL-WORLD CHECK against current kody-w estate artifacts")
print("=" * 74)
print("\nsynchronizing public repos (needs git + network):")
sync_estate()

# every frame chain that was actually committed
for name in sorted(os.listdir(ROOT)):
    fd = os.path.join(ROOT, name, "frames")
    if os.path.isdir(fd):
        check_frame_chain(name, fd)

# every rappid.json that was actually committed
print("\n── rappid identity records ──")
for path in sorted(glob.glob(os.path.join(ROOT, "**", "rappid.json"), recursive=True)):
    check_rappid(path)

print("\n" + "=" * 74)
print("VERDICT — where reality meets RAPP")
print("=" * 74)
print(f"\n✅ CONFORMS TO RAPP ({len(conform)}):")
for a, note in conform:
    print(f"   • {a}: {note}")
print(f"\n🔧 IS THE DRIFT RAPP FIXES ({len(drift)}):")
by_cat = {}
for a, cat, detail in drift:
    by_cat.setdefault(cat, []).append((a, detail))
for cat in sorted(by_cat):
    print(f"   [{cat}]")
    for a, detail in by_cat[cat]:
        print(f"      • {a}: {detail}")

print(f"""
── what this proves ──
  Inspected frames: {frame_stats["total"]}
  Stored addresses reproduced: {frame_stats["address_ok"]}/{frame_stats["total"]}
  Chain links verified: {frame_stats["chain_ok"]}/{frame_stats["total"]}
  Current RAPP envelopes accepted: {frame_stats["conformant"]}/{frame_stats["total"]}
  Remaining drift findings: {len(drift)}

  This is a synchronized observation of mutable public repositories, not a
  conformance vector. A clean result means the inspected current estate converged;
  repository history and sealed legacy artifacts preserve the migration evidence.
""".rstrip())
