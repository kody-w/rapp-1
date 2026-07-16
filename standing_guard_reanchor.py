#!/usr/bin/env python3
# standing_guard_reanchor.py — the estate-standard identity re-anchor tool.
# Published to kody-w/rapp-1 as a DURABLE companion to STANDING-GUARD-PLAYBOOK.md so
# any AI can converge a legacy-identity repo with the EXACT verified derivation.
#
# THE DERIVATION (verified against ant-farm's committed _migrated_from trail):
#   a legacy 128-bit tail (32-hex, from a v2 string or a half-migrated canonical form)
#   widens to the 256-bit RAPP/1 §6.1 tail via
#       new64 = Hb("rapp/1:rappid", bytes.fromhex(old32))
#   which is DETERMINISTIC and ORDERING-FREE: a child computes its parent's new id
#   identically without the parent being fixed first, so the whole lineage graph stays
#   coherent. Lineage is preserved in rappid.json _migrated_from / _parent_migrated_from.
#   NB: this is NOT the cardinal sin — the input is the prior IDENTITY hash (entropy),
#   not the name; it widens an existing keyless id, it does not hash owner/slug.
#
# Usage:  python3 standing_guard_reanchor.py <repo_dir>   # then verify with rapp_check.py
# Idempotent: a 64-hex rappid / already-refreshed spec is left unchanged.

#!/usr/bin/env python3
"""Estate-standard identity re-anchor for one repo, verified against ant-farm.

The widening is DETERMINISTIC: a legacy 128-bit tail (32-hex, from a v2 string or a
half-migrated canonical-legacyhash form) becomes the 256-bit §6.1 tail via
    new64 = Hb("rapp/1:rappid", bytes.fromhex(old32))
so parents resolve to the same value everywhere without ordering. Lineage is
preserved in rappid.json _migrated_from / _parent_migrated_from bridges.

Usage: python3 reanchor.py <repo_dir>
Idempotent-ish: only acts on legacy forms; a 64-hex rappid is left alone.
"""
import sys, os, re, json, hashlib

SPECIES = "rappid:@kody-w/rapp:9a8f0a4b5a710e20f4d819a0f37d2a4c9f113b5e78fb3c29e70b54fff48a38f9"
OLD_SPECIES_STRINGS = [
    "rappid:v2:prototype:@rapp/origin:0b635450c04249fbb4b1bdb571044dec@github.com/kody-w/RAPP",
    "rappid:@kody-w/RAPP:0b635450c04249fbb4b1bdb571044dec",
    "rappid:@rapp/origin:0b635450c04249fbb4b1bdb571044dec",
]
NAME = r"[a-z0-9]+(?:-[a-z0-9]+)*"
V2 = re.compile(rf"rappid:v2:(?P<kind>[a-z][a-z0-9-]*):@(?P<owner>{NAME})/(?P<slug>{NAME}):(?P<h>[a-f0-9]{{32}})@github\.com/[^\s\"']+")
CANON32 = re.compile(rf"rappid:@(?P<owner>{NAME})/(?P<slug>{NAME}):(?P<h>[a-f0-9]{{32}})(?![a-f0-9])")

def Hb(space, b): return hashlib.sha256(space.encode() + b"\x0a" + b).hexdigest()
def widen(h32): return Hb("rapp/1:rappid", bytes.fromhex(h32))

def canonize(idstr):
    """Return (new_rappid_64, old_forms[list]) for a v2 or canonical-32 id; or (None,[]) if already 64/none."""
    if not idstr: return None, []
    m = V2.search(idstr)
    if m:
        o,s,h = m.group("owner"), m.group("slug"), m.group("h")
        new = f"rappid:@{o}/{s}:{widen(h)}"
        return new, [f"rappid:@{o}/{s}:{h}", m.group(0)]
    m = CANON32.fullmatch(idstr.strip())
    if m:
        o,s,h = m.group("owner"), m.group("slug"), m.group("h")
        new = f"rappid:@{o}/{s}:{widen(h)}"
        return new, [f"rappid:@{o}/{s}:{h}"]
    return None, []

def main(repo):
    rjp = os.path.join(repo, "rappid.json")
    if not os.path.exists(rjp):
        print("self: (no rappid.json — nothing to re-anchor)"); return
    rj = json.load(open(rjp))
    # own identity
    new_self, old_self = canonize(rj.get("rappid",""))
    # parent
    par = rj.get("parent_rappid")
    if par in OLD_SPECIES_STRINGS or (par and "0b635450" in par):
        new_par, old_par = SPECIES, [par]
    else:
        new_par, old_par = canonize(par or "")
    # apply to rappid.json record
    changed = False
    if new_self:
        rj["rappid"] = new_self
        mf = rj.get("_migrated_from"); mf = mf if isinstance(mf, list) else ([mf] if mf else [])
        for o in old_self:
            if o not in mf: mf.append(o)
        rj["_migrated_from"] = mf; changed = True
    if rj.get("schema") in ("rapp-rappid/2.0","rapp-rappid/1.1"):
        rj["schema"] = "rapp/1"; changed = True
    if new_par:
        if par: rj["_parent_migrated_from"] = par
        rj["parent_rappid"] = new_par; changed = True
    # NOTE: do NOT invent a parent_rappid where one is absent/null — a missing parent
    # is spec-valid (§6.3 only checks it IF present). Only re-anchor an EXISTING legacy parent.
    if changed:
        json.dump(rj, open(rjp,"w"), indent=2); open(rjp,"a").write("\n")

    # coordinated replacement of old identity strings across all text files
    repls = {}
    if new_self:
        for o in old_self: repls[o] = new_self
    if new_par and par: repls[par] = new_par
    # walk & replace (skip rappid.json bridge fields we just wrote, and .git, and frames/eggs)
    for root,_,files in os.walk(repo):
        if "/.git" in root: continue
        for fn in files:
            if not fn.endswith((".json",".md",".html",".svg",".txt",".js",".py",".sh")): continue
            fp = os.path.join(root,fn); rel = os.path.relpath(fp, repo)
            if rel.startswith("frames/") or fn.endswith(".egg"): continue   # immutable
            try: t = open(fp, errors="ignore").read()
            except Exception: continue
            b = t
            if fp == rjp:
                # only replace inside non-bridge context is hard; rappid.json already rewritten via json — skip raw
                continue
            for old,new in repls.items():
                if old in t: t = t.replace(old, new)
            if t != b: open(fp,"w").write(t)

    # refresh frozen spec teaching (mint + v2 grammar + old species root + schema label)
    for rel in ["specs/RAPPID_SPEC.md","specs/SPEC.md","specs/skill.md"]:
        fp = os.path.join(repo, rel)
        if not os.path.exists(fp): continue
        t = open(fp, errors="ignore").read(); b = t
        t = t.replace("Mint via `uuid.uuid4().hex` — collision probability is negligible.",
                      "Mint the 64-hex tail via `Hb(\"rapp/1:rappid\", uuid4_bytes)` (RAPP/1 §6.2, keyless, domain-separated) — NEVER `uuid4().hex` (only 32 hex) and NEVER `sha256(owner/slug)` (the cardinal sin).")
        t = t.replace("canonical rappid contract (`rapp-rappid/2.0`)", "canonical rappid contract (`rapp/1`, §6.1)")
        t = t.replace("Required fields in `../rappid.json` (`rapp-rappid/2.0`)", "Required fields in `../rappid.json` (`rapp/1`)")
        t = re.sub(r"\| `schema`\s*\| yes \| `rapp-rappid/2\.0` \|", "| `schema`       | yes | `rapp/1` |", t)
        for old in OLD_SPECIES_STRINGS:
            t = t.replace(old, SPECIES)
        # In a REFRESHED frozen teaching spec, every remaining schema-name mention
        # becomes rapp/1 (the banner already covers "legacy rapp-rappid/* is read-forever").
        t = t.replace("schema stays `rapp-rappid/2.0`", "schema is `rapp/1` (Art. LIV; formerly rapp-rappid/2.0)")
        t = re.sub(r"`rapp-rappid/(?:2\.0|1\.1)`", "`rapp/1`", t)
        t = t.replace('"schema": "rapp-rappid/2.0"', '"schema": "rapp/1"')
        if t != b and "SUPERSEDED by RAPP/1 §6" not in t:
            t = ("> **Refresh (2026-07-15):** identity/mint sections are SUPERSEDED by RAPP/1 §6 — canonical "
                 "`rappid:@owner/slug:64hex`, keyless mint `Hb(\"rapp/1:rappid\", uuid4)`; the legacy `rappid:v2:...@host` "
                 "form shown below is legacy, read-forever, never emitted. See "
                 "https://raw.githubusercontent.com/kody-w/rapp-1/main/SPEC.md\n\n") + t
        if t != b: open(fp,"w").write(t)

    print(f"self: {rj.get('rappid')}")
    print(f"parent: {rj.get('parent_rappid')}")

if __name__ == "__main__":
    main(sys.argv[1])
