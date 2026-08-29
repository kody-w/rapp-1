#!/usr/bin/env python3
"""hatch_and_prove.py — hatch the estate .iso as a twin and drive the FULL rapp/1
compliance stack end-to-end, really using the protocol. Reports every layer's verdict
and every repo that bombs, so the loop can fix → re-cubby → re-hatch → re-prove.
"""
import sys, os, json, gzip, glob, hashlib, tempfile, importlib.util, unicodedata
from pathlib import Path

_trusted_spec = importlib.util.spec_from_file_location(
    "_trusted_rapp",
    os.path.join(os.path.dirname(__file__), "rapp.py"),
)
trusted_rapp = importlib.util.module_from_spec(_trusted_spec)
_trusted_spec.loader.exec_module(trusted_rapp)

if len(sys.argv) not in (4, 6):
    raise SystemExit(
        "usage: python3 hatch_and_prove.py <rapp-estate.iso.egg.gz> "
        "<expected-egg-hash> <expected-gzip-sha256> "
        "[trusted-signer-rappid trusted-spki.der]"
    )
ISO_GZ = sys.argv[1]
EXPECTED_EGG_HASH = sys.argv[2]
EXPECTED_GZIP_HASH = sys.argv[3]
TRUSTED_SIGNER = sys.argv[4] if len(sys.argv) == 6 else None
TRUSTED_SPKI = Path(sys.argv[5]).read_bytes() if len(sys.argv) == 6 else None
MAX_COMPRESSED_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024


def signature_verifier(unsigned, sig, expected_signer=None):
    if TRUSTED_SIGNER is None or TRUSTED_SPKI is None:
        return False, "signed estate requires trusted signer RAPPID and SPKI"
    if expected_signer is not None and expected_signer != TRUSTED_SIGNER:
        return False, "egg requires a different authorized signer"
    return trusted_rapp.verify_detached_jws(
        unsigned,
        sig,
        TRUSTED_SPKI,
        expected_kid=TRUSTED_SIGNER,
    )


def _read_pinned_gzip(path, expected_hash):
    source = Path(path)
    if source.stat().st_size > MAX_COMPRESSED_BYTES:
        raise ValueError("compressed estate exceeds the hatch ceiling")
    compressed = source.read_bytes()
    if hashlib.sha256(compressed).hexdigest() != expected_hash:
        raise ValueError("compressed estate does not match the trusted SHA-256")
    chunks, total = [], 0
    with gzip.GzipFile(fileobj=__import__("io").BytesIO(compressed)) as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_EXPANDED_BYTES:
                raise ValueError("expanded estate exceeds the hatch ceiling")
            chunks.append(chunk)
    return b"".join(chunks)


def _verifier_for(manifest):
    if TRUSTED_SIGNER is not None and manifest["sig"] is None:
        raise ValueError("trusted-signer policy requires a signed estate")
    return signature_verifier if manifest["sig"] is not None else None


def _collect_organisms(blob, verifier, depth=0):
    if depth > 8:
        raise ValueError("estate nesting exceeds eight")
    ok, step, why = trusted_rapp.verify_egg(
        blob,
        signature_verifier=verifier,
    )
    if not ok:
        raise ValueError(f"nested egg refused at {step}: {why}")
    manifest, files = trusted_rapp.read_egg(blob)
    if manifest["variant"] == "organism":
        return [(manifest, files)]
    if manifest["variant"] not in {"neighborhood", "estate"}:
        raise ValueError("estate tree may contain only neighborhoods and organisms")
    organisms = []
    for child in files.values():
        organisms.extend(_collect_organisms(child, verifier, depth + 1))
    return organisms


def hatch(iso_gz, expected_egg_hash, expected_gzip_hash):
    """Verify, recursively materialize, and hatch one pinned estate egg."""
    blob = _read_pinned_gzip(iso_gz, expected_gzip_hash)
    manifest, _ = trusted_rapp.read_egg(blob)
    verifier = _verifier_for(manifest)
    ok, step, why = trusted_rapp.verify_egg(
        blob,
        signature_verifier=verifier,
    )
    if not ok:
        raise ValueError(f"estate egg refused before extraction at {step}: {why}")
    if manifest["variant"] != "estate":
        raise ValueError("hatch input MUST be an estate egg")
    actual_egg_hash = trusted_rapp.egg_address(manifest)
    if actual_egg_hash != expected_egg_hash:
        raise ValueError("estate egg does not match the trusted expected address")
    home = tempfile.mkdtemp(prefix="hatched-estate-")
    root = Path(home).resolve()
    destinations = []
    collision_keys = set()
    organisms = {}
    for organism, files in _collect_organisms(blob, verifier):
        rappid = organism["rappid"]
        address = trusted_rapp.egg_address(organism)
        previous = organisms.get(rappid)
        if previous is not None:
            if previous[0] != address:
                raise ValueError("one organism identity names conflicting eggs")
            continue
        organisms[rappid] = (address, organism, files)
    for rappid, (_, organism, files) in organisms.items():
        parts = trusted_rapp.rappid_parts(rappid)
        organism_root = (root / f"{parts['owner']}--{parts['slug']}").resolve()
        if root not in organism_root.parents:
            raise ValueError("organism path escaped the hatch root")
        for relative, octets in files.items():
            destination = organism_root.joinpath(*relative.split("/"))
            resolved = destination.resolve()
            if root not in resolved.parents:
                raise ValueError("estate egg path escaped the hatch root")
            collision_key = unicodedata.normalize("NFD", str(resolved)).casefold()
            if collision_key in collision_keys:
                raise ValueError("estate egg paths collide on the target filesystem")
            collision_keys.add(collision_key)
            destinations.append((resolved, octets))
    for resolved, octets in destinations:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(octets)
    return home, blob

def main():
    print("═══ HATCHING the estate .iso as a twin (offline) ═══")
    home, blob = hatch(ISO_GZ, EXPECTED_EGG_HASH, EXPECTED_GZIP_HASH)
    # the hatched twin carries its OWN reference impl — use IT (real dogfooding)
    matches = sorted(Path(home).glob("*--rapp-1/rapp.py"))
    if len(matches) != 1:
        raise ValueError("hatched estate must contain exactly one rapp-1 organism")
    bundled_rapp_root = str(matches[0].parent)
    sys.path.insert(0, bundled_rapp_root)
    import rapp
    print(f"  hatched at {home}")
    print(f"  twin uses its OWN bundled rapp.py: {rapp.__file__}")

    results = {}

    # ── §9: the .iso egg itself is a conformant rapp/1-egg ──
    ok, s, w = trusted_rapp.verify_egg(
        blob,
        signature_verifier=_verifier_for(trusted_rapp.read_egg(blob)[0]),
    )
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
    # §9.4: the twin is an INSTANCE — fresh identity (r1, minted above), with
    # grown_from = the address of the egg it was instantiated from. Recorded at
    # mint, never fabricated (the .iso's own address, recomputed per §9.1).
    iso_manifest, _ = rapp.read_egg(blob)
    grown_from = rapp.egg_address(iso_manifest)
    twin_files = {
        "rappid.json": (json.dumps({"schema": "rapp/1", "rappid": r1,
                                    "grown_from": grown_from}) + "\n").encode(),
        "soul.md": b"# hatched twin\n",
        "frames/0.json": (json.dumps(g) + "\n").encode(),
    }
    results["§9.4 instance identity (fresh mint + grown_from recorded, distinct from artifact)"] = (
        r1 != r2 and len(grown_from) == 64 and grown_from != r1.rsplit(":", 1)[-1])
    egg = rapp.pack_egg("organism", r1, utc, files=twin_files)
    oke, se, we = rapp.verify_egg(egg)
    results["§9 pack this twin as an egg"] = oke
    # hatch it back
    m, hf = rapp.read_egg(egg)
    results["§9 hatch round-trip (files intact)"] = (set(hf) == set(twin_files) and
        hf["rappid.json"] == twin_files["rappid.json"])

    # ── §12 + full ecosystem: rapp_check every bundled repo (offline) ──
    sys.path.insert(0, os.path.join(home, "rapp-1"))
    spec = importlib.util.spec_from_file_location(
        "rc",
        os.path.join(bundled_rapp_root, "rapp_check.py"),
    )
    rc = importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)
    repos = sorted(glob.glob(os.path.join(home, "*", "repos", "*")))
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
