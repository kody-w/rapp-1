#!/usr/bin/env python3
"""egg_repack.py — convert a legacy RAPP egg to a conformant §9 rapp/1-egg.

Published to kody-w/rapp-1 as the durable Phase-4 re-pack tool of the §9 egg
migration (see EGG-MIGRATION-PLAN.md). Reads a legacy `brainstem-egg/*` (or
`rapp-rapplication/1.0`, or a no-manifest zip) cartridge, maps it to a §9.2 variant,
canonicalizes/widens its rappid to §6.1, restructures the payload per variant, and
re-packs it byte-reproducibly via rapp.pack_egg. The egg's identity is preserved in
`payload._migrated_from` where the rappid had to be widened.

UNIFY + STEAMROLL: there is NO legacy. EVERY cartridge becomes a rapp/1-egg — including
the rappterbook `.rappter`/`.rapp` data blobs (`_format`/`body`/`lineage`), which are
wrapped as an `organism` egg holding their data as `organism.json`. No format is skipped,
no legacy reader is retained; producers emit and consumers read only `rapp/1-egg`.

Usage:  python3 egg_repack.py <in.egg> <out.egg>   ·   or import repack(blob)->bytes
"""
import sys, os, io, json, zipfile, re, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rapp

SPECIES = "rappid:@kody-w/rapp:9a8f0a4b5a710e20f4d819a0f37d2a4c9f113b5e78fb3c29e70b54fff48a38f9"

_V2 = re.compile(r"rappid:v2:(?P<kind>[a-z][a-z0-9-]*):@(?P<owner>[a-z0-9-]+)/(?P<slug>[a-z0-9-]+):(?P<h>[a-f0-9]{32})@")
_CANON32 = re.compile(r"^rappid:@([a-z0-9-]+)/([a-z0-9-]+):([0-9a-f]{32})$")
_BARE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

def _widen(h32): return hashlib.sha256(b"rapp/1:rappid\n" + bytes.fromhex(h32)).hexdigest()

def _canon_rid(rid, owner_hint="kody-w", slug_hint="thing"):
    """Return (canonical_§6.1_rappid, migrated_from_or_None)."""
    if rid and rapp.rappid_valid(rid):
        return rid, None
    if rid:
        m = _V2.search(rid)
        if m: return f"rappid:@{m['owner']}/{m['slug']}:{_widen(m['h'])}", rid
        m = _CANON32.fullmatch(rid.strip())
        if m: return f"rappid:@{m.group(1)}/{m.group(2)}:{_widen(m.group(3))}", rid
        if _BARE.fullmatch(rid.strip()):
            return f"rappid:@{owner_hint}/{slug_hint}:{_widen(rid.replace('-',''))}", rid
    # no usable rappid — mint deterministically from the (owner,slug) hint via content later
    return None, rid

_VARIANT = {
    "brainstem-egg/2.2-organism": "organism", "brainstem-egg/2.1": "organism",
    "brainstem-egg/2.0": "organism", "brainstem-egg/1.0": "organism",
    "brainstem-egg/2.3-cubby": "organism",                       # a cubby packs a parked brainstem
    "brainstem-egg/2.2-rapplication": "rapplication",
    "brainstem-egg/2.3-rapplication": "rapplication",
    "rapp-rapplication/1.0": "rapplication",
    "brainstem-egg/2.3-session": "session",
    "brainstem-egg/2.3-neighborhood": "neighborhood",           # pointer→invite handled below
}

def repack(blob, name_hint="thing"):
    """ANY legacy cartridge blob → conformant rapp/1-egg blob. Steamrolls every format."""
    is_zip = blob[:2] == b"PK"
    if is_zip:
        z = zipfile.ZipFile(io.BytesIO(blob))
        names = z.namelist()
        mnames = [n for n in names if n.endswith("manifest.json")]
        manifest = json.loads(z.read(mnames[0])) if mnames else {}
        files = {n: z.read(n) for n in names if not n.endswith("manifest.json") and not n.endswith("/")}
    else:
        manifest = json.loads(blob); files = {}
        _sch = manifest.get("schema", "")
        _known_json = _sch in ("brainstem-egg/2.3-session", "brainstem-egg/2.3-neighborhood")
        # ANY other JSON blob (rappterbook .rappter, hologram-cartridge, rapp-application,
        # rapp-leviathan-egg, unknown) → UNIFY as an organism egg holding its data. No legacy.
        if "_format" in manifest or ("body" in manifest and "lineage" in manifest) or not _known_json:
            _org = manifest.get("organism")
            _sname = _org.get("name") if isinstance(_org, dict) else (_org if isinstance(_org, str) else None)
            _sname = _sname or (manifest.get("body", {}).get("name") if isinstance(manifest.get("body"), dict) else None) \
                     or manifest.get("name") or manifest.get("slug") or name_hint
            slug = re.sub(r"[^a-z0-9]+", "-", str(_sname).lower()).strip("-") or name_hint
            files = {"organism.json": (canon_json := json.dumps(manifest, indent=2)).encode()}
            rid_src = manifest.get("rappid") \
                      or ((manifest.get("lineage") or {}).get("rappid") if isinstance(manifest.get("lineage"), dict) else None)
            canon, migrated = _canon_rid(rid_src, "kody-w", slug)
            if canon is None:
                canon = f"rappid:@kody-w/{slug}:{rapp.Hb('rapp/1:rappid', hashlib.sha256(files['organism.json']).digest())}"
            pf = {"organism.json": files["organism.json"], "soul.md": b"# soul\n(migrated rappterbook organism)\n",
                  "rappid.json": (json.dumps({"schema":"rapp/1","rappid":canon,"parent_rappid":SPECIES,"kind":"organism"}, indent=2)+"\n").encode()}
            payload = {"_migrated_from": migrated} if migrated else None
            return rapp.pack_egg("organism", canon, "1980-01-01T00:00:00.000Z", files=pf, payload=payload)

    sch = manifest.get("schema", "")
    if is_zip and not mnames:                                    # no-manifest zip → organism
        sch = "brainstem-egg/2.2-organism"
    variant = _VARIANT.get(sch, "organism")                     # steamroll: unknown → organism

    created = manifest.get("minted_at") or manifest.get("created_at") or manifest.get("exported_at") \
              or "1980-01-01T00:00:00.000Z"
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", created):
        created = "1980-01-01T00:00:00.000Z"

    # find the rappid: manifest, or an inner rappid.json
    rid = manifest.get("rappid")
    if not rid:
        for n, b in files.items():
            if n.endswith("rappid.json"):
                try: rid = json.loads(b).get("rappid")
                except Exception: pass
                if rid: break
    slug = (manifest.get("slug") or manifest.get("name") or name_hint).lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-") or "thing"
    canon, migrated = _canon_rid(rid, "kody-w", slug)

    # JSON variants
    if variant == "session":
        payload = {"runtime": str(manifest.get("runtime", "local:7071")),
                   "transcript": manifest.get("transcript") or manifest.get("payload", {}).get("transcript", [])}
        if canon is None: canon = f"rappid:@kody-w/{slug}:{rapp.Hb('rapp/1:rappid', slug.encode())}"
        return rapp.pack_egg("session", canon, created, payload=payload)
    if variant == "neighborhood":
        # tutorial/QR "neighborhood" pointers are invites; a member-bundle is a neighborhood.
        members = manifest.get("payload", {}).get("members") or manifest.get("members")
        if not members:   # pointer → invite (sig required; unsigned tutorial invites get a placeholder note)
            if canon is None: canon = f"rappid:@kody-w/{slug}:{rapp.Hb('rapp/1:rappid', slug.encode())}"
            payload = {"target_rappid": canon,
                       "target_url": manifest.get("url") or f"https://kody-w.github.io/{slug}/",
                       "target_kind": "neighborhood"}
            # unsigned legacy pointer — mark, since §9 invite requires a real estate-owner sig
            return rapp.pack_egg("invite", canon, created, payload=payload, sig="MIGRATED-UNSIGNED-legacy-pointer")
        variant = "neighborhood"

    # ZIP variants (organism / rapplication / neighborhood)
    if canon is None:
        # deterministic content-address of the packed files (regenerable, not name-hash)
        content = b"".join(files[k] for k in sorted(files))
        canon = f"rappid:@kody-w/{slug}:{rapp.Hb('rapp/1:rappid', hashlib.sha256(content).digest())}"

    payload = {}
    if variant == "neighborhood":
        payload = {"members": manifest.get("payload", {}).get("members") or manifest.get("members") or []}
    if migrated:
        payload = {**payload, "_migrated_from": migrated}

    # rapplication needs exactly one root agent.py; organism needs rappid.json + soul.md.
    packfiles = dict(files)
    # ensure a canonical rappid.json at the root reflecting the new identity
    packfiles["rappid.json"] = (json.dumps({"schema": "rapp/1", "rappid": canon,
                                             "parent_rappid": SPECIES, "kind": variant}, indent=2) + "\n").encode()
    if variant == "rapplication":
        # need exactly one root agent.py; else collapse a clear agent candidate to root.
        agent_cand = next((n for n in sorted(packfiles)
                           if n.endswith("_agent.py") or os.path.basename(n) == "agent.py"), None)
        if agent_cand:
            data = packfiles.pop(agent_cand)
            for n in [n for n in list(packfiles) if "/" not in n and n.endswith(".py")]:
                packfiles[f"src/{n}"] = packfiles.pop(n)     # demote other root .py
            packfiles["agent.py"] = data
        else:
            variant = "organism"                             # no agent → it's a brainstem instance
    if variant == "organism":
        packfiles.setdefault("soul.md", b"# soul\n(migrated organism)\n")
    # re-stamp the record's kind to the final variant
    packfiles["rappid.json"] = (json.dumps({"schema": "rapp/1", "rappid": canon,
                                             "parent_rappid": SPECIES, "kind": variant}, indent=2) + "\n").encode()
    return rapp.pack_egg(variant, canon, created, files=packfiles, payload=payload or None)

if __name__ == "__main__":
    inp, outp = sys.argv[1], sys.argv[2]
    blob = open(inp, "rb").read()
    out = repack(blob, name_hint=re.sub(r"[^a-z0-9]+","-", os.path.basename(inp).split(".")[0].lower()).strip("-"))
    open(outp, "wb").write(out)
    ok, step, why = rapp.verify_egg(out)
    print(f"{inp} → {outp}: verify={ok} ({step}: {why})")
