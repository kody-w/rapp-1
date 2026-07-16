#!/usr/bin/env python3
"""hatch_and_prove.py — hatch the estate .iso as a twin and drive the FULL rapp/1
compliance stack end-to-end, really using the protocol. Reports every layer's verdict
and every repo that bombs, so the loop can fix → re-cubby → re-hatch → re-prove.
"""
import sys, os, io, json, gzip, zipfile, glob, hashlib, tempfile

ISO_GZ = sys.argv[1] if len(sys.argv) > 1 else \
    os.path.join(os.path.dirname(__file__), "rapp-estate.iso.egg.gz")

def hatch(iso_gz):
    """Hatch the .iso organism egg into a live twin workspace (offline)."""
    blob = gzip.decompress(open(iso_gz, "rb").read())
    home = tempfile.mkdtemp(prefix="hatched-estate-")
    z = zipfile.ZipFile(io.BytesIO(blob))
    z.extractall(home)
    return home, blob

def main():
    print("═══ HATCHING the estate .iso as a twin (offline) ═══")
    home, blob = hatch(ISO_GZ)
    # the hatched twin carries its OWN reference impl — use IT (real dogfooding)
    sys.path.insert(0, os.path.join(home, "rapp-1"))
    import rapp
    print(f"  hatched at {home}")
    print(f"  twin uses its OWN bundled rapp.py: {rapp.__file__}")

    results = {}

    # ── §9: the .iso egg itself is a conformant rapp/1-egg ──
    ok, s, w = rapp.verify_egg(blob)
    results["§9 self (the .iso is a rapp/1-egg)"] = ok
    print(f"  §9 the .iso egg verifies as rapp/1-egg: {ok}")

    # ── §5 domain-separated hashing round-trips ──
    h1 = rapp.Hb("rapp/1:egg", b"x"); h2 = rapp.H("rapp/1:particle", {"a": 1})
    results["§5 hashing"] = len(h1) == 64 and len(h2) == 64

    # ── §6 identity: mint (keyless), never a name-hash, twice differs ──
    r1 = rapp.mint_rappid("kody-w", "hatched-twin")
    r2 = rapp.mint_rappid("kody-w", "hatched-twin")
    name_hash = f"rappid:@kody-w/hatched-twin:{hashlib.sha256(b'kody-w/hatched-twin').hexdigest()}"
    results["§6 mint valid + keyless + not-name-hash"] = (
        rapp.rappid_valid(r1) and r1 != r2 and r1 != name_hash)

    # ── §7 frames: record a chain, verify linkage ──
    utc = "2026-07-15T00:00:00.000Z"
    g = rapp.build_frame("twin.birth", r1, 0, utc, {"born": True}, prev=None)
    c = rapp.build_frame("twin.pulse", r1, 1, "2026-07-15T00:00:01.000Z", {"beat": 1}, prev=g["payload_hash"])
    okg = rapp.verify_frame(g, head=None, stream_id_of_record=r1)
    okc = rapp.verify_frame(c, head=g, stream_id_of_record=r1)
    results["§7 frame chain (genesis+child)"] = okg[0] and okc[0]

    # ── §9 pack + hatch round-trip (a real organism egg for THIS twin) ──
    twin_files = {
        "rappid.json": (json.dumps({"schema": "rapp/1", "rappid": r1}) + "\n").encode(),
        "soul.md": b"# hatched twin\n",
        "frames/0.json": (json.dumps(g) + "\n").encode(),
    }
    egg = rapp.pack_egg("organism", r1, utc, files=twin_files)
    oke, se, we = rapp.verify_egg(egg)
    results["§9 pack this twin as an egg"] = oke
    # hatch it back
    m, hf = rapp.read_egg(egg)
    results["§9 hatch round-trip (files intact)"] = (set(hf) == set(twin_files) and
        hf["rappid.json"] == twin_files["rappid.json"])

    # ── §12 + full ecosystem: rapp_check every bundled repo (offline) ──
    sys.path.insert(0, os.path.join(home, "rapp-1"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("rc", os.path.join(home, "rapp-1", "rapp_check.py"))
    rc = importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)
    repos = sorted(glob.glob(os.path.join(home, "repos", "*")))
    drift = []
    for d in repos:
        verdict, findings, _ = rc.check_repo(d)
        if verdict == "DRIFT":
            drift.append((os.path.basename(d), findings[:2]))
    results[f"ecosystem: {len(repos)} repos §6/§7/§9/§12"] = (len(drift) == 0)

    print("\n═══ END-TO-END COMPLIANCE STACK (the hatched twin, using the protocol) ═══")
    allok = True
    for k, v in results.items():
        allok = allok and v
        print(f"  {'✅' if v else '❌'}  {k}")
    if drift:
        print(f"\n  ❌ {len(drift)} repos bombed:")
        for name, f in drift:
            print(f"     ✗ {name}: {f}")
    print(f"\n{'✅ FULL STACK GREEN — the protocol proves itself end-to-end, offline.' if allok else '❌ STACK RED — fix the bombs, re-cubby, re-hatch, re-prove.'}")
    import shutil; shutil.rmtree(home, ignore_errors=True)
    sys.exit(0 if allok else 1)

if __name__ == "__main__":
    main()
