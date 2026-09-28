"""Rev-17 egg tests: §9.1 container, §9.2 variants, §9.3 producer and consumer (E-13..E-19).

Run: python3 -m unittest test_rev17_eggs (stdlib only)."""
import base64
import json
import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rapp as R  # noqa: E402

UTC = "2026-09-27T12:00:00.000Z"
RID = "rappid:@alice/home:" + "a" * 64
BOB = "rappid:@bob/den:" + "b" * 64
STREET = "rappid:@alice/street:" + "c" * 64
ESTATE = "rappid:@kody/estate:" + "d" * 64
OWNER = "rappid:@kody/estate-owner:" + "9" * 64


def b64url(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def jws(kid, header=None, signature_octets=64):
    """A detached JWS string; §10 form unless header or signature_octets say otherwise."""
    if header is None:
        header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid}
    return b64url(R.canonical(header).encode("utf-8")) + ".." + b64url(bytes(signature_octets))


def vouch(_unsigned, _sig, _expected=None):
    return True, "the caller vouches for every signature"


def identity(rid):
    return ('{"rappid":"' + rid + '"}').encode("utf-8")


def organism(rid=RID, extra=None):
    files = {"rappid.json": identity(rid), "soul.md": b"# soul\n", **(extra or {})}
    return R.pack_egg("organism", rid, UTC, files=files)


def zip_bytes(entries, *, made_by=0x0014, needed=(0x0014, 0x0014), flags=0x0800, method=0,
              date=0x0021, extra=b"", internal=0, external=0, file_comment=b"", disk_start=0,
              prefix=b"", gap=b"", suffix=b"", end_comment=b"", disks=(0, 0), counts=None,
              crc_delta=0):
    """An independent §9.1 ZIP writer with knobs for every field a test mutates."""
    local, central, offset = [], [], len(prefix)
    for index, (name, data) in enumerate(entries):
        encoded = name.encode("utf-8")
        crc = (zlib.crc32(data) + crc_delta) & 0xFFFFFFFF
        common = (flags, method, 0, date, crc, len(data), len(data), len(encoded), len(extra))
        record = struct.pack("<IHHHHHIIIHH", 0x04034B50, needed[0], *common) + encoded + extra + data
        central.append(
            struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, made_by, needed[1], *common,
                        len(file_comment), disk_start, internal, external, offset)
            + encoded + extra + file_comment
        )
        record += gap if index == 0 else b""
        local.append(record)
        offset += len(record)
    directory = b"".join(central)
    on_disk, total = counts or (len(entries), len(entries))
    end = struct.pack("<IHHHHIIH", 0x06054B50, disks[0], disks[1], on_disk, total,
                      len(directory), offset, len(end_comment)) + end_comment
    return prefix + b"".join(local) + directory + end + suffix


def entries_of(blob, mutate=None):
    """(name, octets) entries of a ZIP egg, after mutate(manifest, files), hashes recomputed."""
    manifest, files = R.read_egg(blob)
    manifest, files = json.loads(json.dumps(manifest)), dict(files)
    if mutate:
        mutate(manifest, files)
    manifest["contents"] = R._egg_contents(files)
    return [("manifest.json", R.canonical(manifest).encode("utf-8"))] + [
        (item["path"], files[item["path"]]) for item in manifest["contents"]
    ]


def forge(blob, mutate=None, **knobs):
    """A deliberately refused egg: a valid one, mutated and re-zipped by hand."""
    return zip_bytes(entries_of(blob, mutate), **knobs)


def forge_json(blob, mutate):
    manifest = json.loads(blob)
    mutate(manifest)
    return R.canonical(manifest).encode("utf-8")


def central_offsets(blob):
    count = int.from_bytes(blob[-12:-10], "little")
    at, found = int.from_bytes(blob[-6:-2], "little"), []
    for _ in range(count):
        found.append(at)
        name, extra, comment = struct.unpack_from("<HHH", blob, at + 28)
        at += 46 + name + extra + comment
    return found


def local_offsets(blob):
    return [int.from_bytes(blob[at + 42:at + 46], "little") for at in central_offsets(blob)]


SESSION = {"runtime": "test", "transcript": []}
INVITE = {"target_rappid": STREET, "target_url": "https://example.test/street", "target_kind": "neighborhood"}


class TestProducerRefuses(unittest.TestCase):
    """EG-3 / E-18 (+ E-5, E-6): pack_egg is a §9.3 producer; every refusal is a ValueError."""

    def refuses(self, *args, **kwargs):
        with self.assertRaises(ValueError) as caught:
            R.pack_egg(*args, **kwargs)
        return str(caught.exception)

    def organism_files(self, **extra):
        return {"rappid.json": identity(RID), "soul.md": b"# soul\n", **extra}

    def test_conformant_eggs_are_emitted_and_verify(self):
        invite = R.pack_egg("invite", RID, UTC, payload=INVITE, sig=jws(OWNER))
        self.assertEqual(R.verify_egg_static(invite), (True, None, "ok"))
        self.assertEqual(
            R.verify_egg(invite, signature_verifier=vouch, estate_owner_rappid=OWNER),
            (True, None, "ok"),
        )
        self.assertEqual(R.verify_egg(R.pack_egg("session", RID, UTC, payload=SESSION)), (True, None, "ok"))
        self.assertEqual(R.verify_egg(organism()), (True, None, "ok"))

    def test_unsigned_invite_is_refused(self):
        self.assertIn("REQUIRED", self.refuses("invite", RID, UTC, payload=INVITE))

    def test_bad_path_grammar_is_refused(self):
        for path in ("../x", "CON", "dir/nul", "a//b", "a:b", "x ", "\u212b.txt", "/abs", "a\\b",
                     "C:x", "x.", "a/./b", "", "manifest.json"):
            with self.subTest(path=path):
                self.refuses("organism", RID, UTC, files=self.organism_files(**{path: b"x"}))

    def test_consumer_refuses_the_same_paths_packed_by_hand(self):
        for path in ("../x", "CON", "dir/nul", "a//b", "a:b", "x ", "\u212b.txt"):
            with self.subTest(path=path):
                forged = forge(organism(), lambda _m, files: files.update({path: b"x"}))
                self.assertEqual(R.verify_egg(forged)[:2], (False, "§9.1"))

    def test_provisional_rappids_are_refused(self):
        provisional = "rappid:@kody/twin:9a7d2c1e5b3f4a6d8e0f1a2b3c4d5e6f"
        self.refuses("session", provisional, UTC, payload=SESSION)
        why = self.refuses("invite", RID, UTC, payload={**INVITE, "target_rappid": provisional}, sig=jws(OWNER))
        self.assertIn("§9.2", why)

    def test_manifest_members_are_checked_before_packing(self):
        cases = {
            "created_utc form": dict(variant="session", created_utc="2026-09-27T12:00:00Z", payload=SESSION),
            "payload not an object": dict(variant="session", payload=[]),
            "non-NFC payload name": dict(variant="session", payload={**SESSION, "cafe\u0301": 1}),
            "unassigned code point in a nested name": dict(
                variant="session", payload={"runtime": "t", "transcript": [{"\u0378": 1}]}
            ),
            "sig not text": dict(variant="session", payload=SESSION, sig=42),
            "sig free text": dict(variant="session", payload=SESSION, sig="test-detached-jws"),
            "sig '{}' header": dict(variant="session", payload=SESSION, sig=jws(OWNER, header={})),
            "sig 63 octets": dict(variant="session", payload=SESSION, sig=jws(OWNER, signature_octets=63)),
            "file octets not bytes": dict(
                variant="organism", files={"rappid.json": identity(RID).decode(), "soul.md": b"s"}
            ),
            "JSON variant with files": dict(variant="session", payload=SESSION, files={"a.txt": b"x"}),
            "unknown variant": dict(variant="nest"),
            "session payload shape": dict(variant="session", payload={**SESSION, "extra": 1}),
            "organism without soul.md": dict(variant="organism", files={"rappid.json": identity(RID)}),
            "rapplication without agent.py": dict(variant="rapplication", files={"rappid.json": identity(RID)}),
        }
        for label, case in cases.items():
            with self.subTest(label):
                case = dict(case)
                variant = case.pop("variant")
                created = case.pop("created_utc", UTC)
                self.refuses(variant, RID, created, **case)

    def test_neighborhood_and_estate_sub_egg_mismatches_are_refused(self):
        home, den = organism(RID), organism(BOB)
        street = R.pack_egg("neighborhood", STREET, UTC, files={"alice--home.egg": home, "bob--den.egg": den},
                            payload={"members": [RID, BOB]})
        self.assertEqual(R.verify_egg(street), (True, None, "ok"))
        estate = R.pack_egg("estate", ESTATE, UTC, files={"alice--street.egg": street},
                            payload={"neighborhoods": [STREET]})
        self.assertEqual(R.verify_egg(estate), (True, None, "ok"))
        bad_den = forge(den, lambda _m, files: files.pop("soul.md"))
        self.assertEqual(R.verify_egg(bad_den)[:2], (False, "§9.2"))
        substituted = "rappid:@alice/home:" + "e" * 64
        cases = {
            "member rappid substituted": ("neighborhood", STREET, {"alice--home.egg": home}, {"members": [substituted]}),
            "member renamed in transit": ("neighborhood", STREET, {"alice--house.egg": home}, {"members": [RID]}),
            "one bad member refuses whole": ("neighborhood", STREET, {"alice--home.egg": home, "bob--den.egg": bad_den},
                                             {"members": [RID, BOB]}),
            "estate adopts an organism as a neighborhood": ("estate", ESTATE, {"alice--home.egg": home},
                                                            {"neighborhoods": [RID]}),
            "non-§6.1 member rappid": ("neighborhood", STREET, {}, {"members": ["rappid:@alice/h\u00f3me:" + "a" * 64]}),
            "bad member two levels down": ("estate", ESTATE, {"alice--street.egg": forge(
                street, lambda _m, files: files.update({"bob--den.egg": bad_den}))}, {"neighborhoods": [STREET]}),
        }
        for label, (variant, rid, files, payload) in cases.items():
            with self.subTest(label):
                self.refuses(variant, rid, UTC, files=files, payload=payload)
        forged = forge(street, lambda m, _f: m["payload"].update(members=[substituted, BOB]))
        self.assertEqual(R.verify_egg(forged)[:2], (False, "§9.2"))


class TestZipWriter(unittest.TestCase):
    """EG-1 / E-13 writer: every §9.1 header field as pinned; ZIP64 refused."""

    def test_header_fields_are_pinned(self):
        egg = organism(extra={"notes/a.md": b"a"})
        self.assertEqual(egg[:4], b"PK\x03\x04")
        self.assertEqual(local_offsets(egg)[0], 0)
        for at in local_offsets(egg):
            fields = struct.unpack_from("<HHHHH", egg, at + 4)      # version needed, flags, method, time, date
            self.assertEqual(fields, (20, 0x0800, 0, 0x0000, 0x0021))
            self.assertEqual(struct.unpack_from("<H", egg, at + 28)[0], 0)   # no extra field
        centrals = central_offsets(egg)
        self.assertEqual(len(centrals), 4)
        for at in centrals:
            self.assertEqual(egg[at:at + 4], b"PK\x01\x02")
            made_by, needed = struct.unpack_from("<HH", egg, at + 4)
            self.assertEqual((made_by, needed), (0x0014, 20))
            self.assertEqual(struct.unpack_from("<HHHH", egg, at + 8), (0x0800, 0, 0x0000, 0x0021))
            extra, comment, disk, internal, external = struct.unpack_from("<HHHHI", egg, at + 30)
            self.assertEqual((extra, comment, disk, internal, external), (0, 0, 0, 0, 0))
        self.assertEqual(egg[-22:-18], b"PK\x05\x06")
        disk, directory_disk, on_disk, total, size, offset, comment = struct.unpack("<HHHHIIH", egg[-18:])
        self.assertEqual((disk, directory_disk, on_disk, total, comment), (0, 0, 4, 4, 0))
        self.assertEqual(offset + size, len(egg) - 22)

    def test_two_independent_packers_emit_identical_octets(self):
        extra = {"notes/a.md": b"a", "\u00e9.txt": b"e"}
        egg = organism(extra=extra)
        self.assertEqual(zip_bytes(entries_of(egg)), egg)
        self.assertEqual(organism(extra=extra), egg)

    def test_zip64_is_refused(self):
        self.assertEqual(len(central_offsets(R._zip_pack([("f", b"")] * 65534))), 65534)
        with self.assertRaises(ValueError):
            R._zip_pack([("f", b"")] * 65535)

        class Huge(bytes):
            def __len__(self):
                return 0xFFFFFFFF

        with self.assertRaises(ValueError):
            R._zip_pack([("manifest.json", Huge())])


class TestZipReader(unittest.TestCase):
    """E-13 reader: refuse every other §9.1 container violation; accept any version and attribute values."""

    def setUp(self):
        self.entries = entries_of(organism())

    def assertRefused(self, blob):
        ok, step, why = R.verify_egg(blob)
        self.assertFalse(ok, why)
        self.assertEqual(step, "parse", why)

    def test_free_fields_are_accepted_and_not_interpreted(self):
        for knobs in (dict(made_by=0x0314), dict(made_by=0x003F), dict(needed=(10, 10)),
                      dict(needed=(64, 64)), dict(needed=(0xFFFF, 0xFFFF)), dict(internal=1),
                      dict(external=0o600 << 16),
                      dict(made_by=0x0314, needed=(45, 45), internal=0xFFFF, external=0xFFFFFFFF)):
            with self.subTest(**{key: str(value) for key, value in knobs.items()}):
                self.assertEqual(R.verify_egg(zip_bytes(self.entries, **knobs)), (True, None, "ok"))

    def test_container_violations_are_refused(self):
        cases = {
            "version needed disagrees (local 10, central 20)": dict(needed=(10, 20)),
            "version needed disagrees (local 20, central 10)": dict(needed=(20, 10)),
            "data descriptor flag": dict(flags=0x0808),
            "encryption flag": dict(flags=0x0801),
            "no UTF-8 flag": dict(flags=0),
            "deflate method": dict(method=8),
            "timestamp not 1980-01-01": dict(date=0x0022),
            "extra field": dict(extra=b"\xfe\xca\x00\x00"),
            "file comment": dict(file_comment=b"c"),
            "disk number start": dict(disk_start=1),
            "octets before the first local header": dict(prefix=b"PK\x00\x00"),
            "gap between local records": dict(gap=b"\x00"),
            "octet after the end record": dict(suffix=b"\x00"),
            "archive comment": dict(end_comment=b"c"),
            "disk numbers": dict(disks=(1, 1)),
            "unequal entry counts": dict(counts=(2, 3)),
            "ZIP64 entry count": dict(counts=(0xFFFF, 0xFFFF)),
            "CRC-32 mismatch": dict(crc_delta=1),
        }
        for label, knobs in cases.items():
            with self.subTest(label):
                self.assertRefused(zip_bytes(self.entries, **knobs))

    def test_local_central_disagreement_in_any_shared_field_is_refused(self):
        blob = zip_bytes(self.entries)
        second = local_offsets(blob)[1]
        for label, offset, fmt, value in (
            ("version needed", 4, "<H", 10), ("flags", 6, "<H", 0), ("time", 10, "<H", 1),
            ("date", 12, "<H", 0x0022), ("crc", 14, "<I", 0), ("compressed size", 18, "<I", 0),
            ("size", 22, "<I", 0), ("name length", 26, "<H", 1), ("extra length", 28, "<H", 1),
        ):
            with self.subTest(label):
                forged = bytearray(blob)
                struct.pack_into(fmt, forged, second + offset, value)
                self.assertRefused(bytes(forged))
        forged = bytearray(blob)
        forged[second + 30] ^= 0x20          # local name "Rappid.json", central "rappid.json"
        self.assertRefused(bytes(forged))


class TestPathSet(unittest.TestCase):
    """EG-5 / E-14: path equality is code-point equality; folding and prefixes are the extractor's question."""

    LOOKALIKES = (["README.md", "Readme.md"], ["MANIFEST.JSON"], ["docs", "docs/a.md"])

    def test_path_set_valid_refuses_only_exact_duplicates_and_manifest_json(self):
        for paths in (*self.LOOKALIKES, ["caf\u00e9.txt", "CAF\u00c9.TXT"], ["a/manifest.json"], []):
            with self.subTest(paths=paths):
                self.assertTrue(R._path_set_valid(paths))
        for paths in (["a", "a"], ["manifest.json"], ["x", "manifest.json"]):
            with self.subTest(paths=paths):
                self.assertFalse(R._path_set_valid(paths))

    def test_extractor_helper_keeps_the_filesystem_collision_tests(self):
        for paths in (["README.md", "Readme.md"], ["manifest.json", "MANIFEST.JSON"], ["docs", "docs/a.md"]):
            with self.subTest(paths=paths):
                self.assertFalse(R._path_set_extractable(paths))
        self.assertTrue(R._path_set_extractable(["manifest.json", "rappid.json", "soul.md", "docs/a.md"]))

    def test_lookalike_paths_pack_and_verify(self):
        for paths in self.LOOKALIKES:
            with self.subTest(paths=paths):
                extra = {path: path.encode() for path in paths}
                egg = organism(extra=extra)
                self.assertEqual(R.verify_egg(egg), (True, None, "ok"))
                self.assertEqual(set(R.read_egg(egg)[1]), {"rappid.json", "soul.md", *extra})

    def test_every_path_must_still_be_nfc(self):
        self.assertFalse(R._path_valid("cafe\u0301.txt"))
        forged = forge(organism(), lambda _m, files: files.update({"cafe\u0301.txt": b"x"}))
        self.assertEqual(R.verify_egg(forged)[:2], (False, "§9.1"))

    def test_contents_listing_manifest_json_is_refused(self):
        manifest, files = R.read_egg(organism())
        files = {**files, "manifest.json": b"shadow"}
        manifest = {**manifest, "contents": R._egg_contents(files)}
        blob = zip_bytes([("manifest.json", R.canonical(manifest).encode())]
                         + [(c["path"], files[c["path"]]) for c in manifest["contents"]])
        self.assertFalse(R.verify_egg(blob)[0])


class TestSigForm(unittest.TestCase):
    """verify_egg step (0): a present sig has the §10 detached form whatever the verifier says."""

    def test_placeholder_sigs_are_refused_even_when_the_verifier_vouches(self):
        good = R.pack_egg("invite", RID, UTC, payload=INVITE, sig=jws(OWNER))
        self.assertEqual(R.verify_egg(good, signature_verifier=vouch, estate_owner_rappid=OWNER), (True, None, "ok"))
        unordered = b'{"kid":"' + OWNER.encode() + b'","alg":"EdDSA","b64":false,"crit":["b64"]}'
        extra = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": OWNER, "typ": "JWT"}
        for label, sig in (("'{}' header", jws(OWNER, header={})), ("free text", "test-detached-jws"),
                           ("attached payload", jws(OWNER).replace("..", ".e30.")),
                           ("63-octet signature", jws(OWNER, signature_octets=63)),
                           ("non-canonical header", b64url(unordered) + ".." + b64url(bytes(64))),
                           ("extra header member", jws(OWNER, header=extra)), ("not text", 7)):
            with self.subTest(label):
                forged = forge_json(good, lambda manifest: manifest.update(sig=sig))
                ok, step, why = R.verify_egg(forged, signature_verifier=vouch, estate_owner_rappid=OWNER)
                self.assertEqual((ok, step), (False, "§10"), why)
                self.assertEqual(R.verify_egg_static(forged)[:2], (False, "§10"))
        signed_zip = forge(organism(), lambda manifest, _f: manifest.update(sig=jws(OWNER, header={})))
        self.assertEqual(R.verify_egg(signed_zip, signature_verifier=vouch)[:2], (False, "§10"))


def sealed_payload(**overrides):
    payload = {"schema": "rapp-sealed-artifact/1", "cipher": "A256GCM", "nonce": "MDEyMzQ1Njc4OWFi",
               "plaintext_commitment": "1" * 64, "plaintext_bytes": 4, "media_type": "application/wasm",
               "key_id": "e" * 64, "key_service_rappid": "rappid:@kody/key-service:" + "d" * 64,
               "key_service_url": "https://keys.example.test/chat", "access": "scoped-key-release", **overrides}
    descriptor = {"schema": payload["schema"], "artifact_rappid": SEALED, "created_utc": UTC,
                  **{key: payload[key] for key in ("key_id", "plaintext_commitment", "plaintext_bytes", "media_type")}}
    payload["aad_hash"] = R.H("rapp/1:sealed-aad", descriptor)
    return payload


SEALED = "rappid:@kody/sealed:" + "f" * 64


def sealed(**overrides):
    return R.pack_egg("sealed", SEALED, UTC, files={"ciphertext.bin": bytes(20)},
                      payload=sealed_payload(**overrides), sig=jws(SEALED))


class TestVariants(unittest.TestCase):
    """E-15, E-16 and E-17 (the reference's existing readings, kept) and E-19."""

    def test_rapplication_may_list_is_not_exhaustive(self):
        files = {"rappid.json": identity(RID), "agent.py": b"a", "notes/x.md": b"n", ".hidden": b"h", "README.md": b"r"}
        self.assertEqual(R.verify_egg(R.pack_egg("rapplication", RID, UTC, files=files)), (True, None, "ok"))

    def test_rappid_json_identity_mismatch_is_refused_at_9_2(self):
        wrong = (("other rappid", identity(BOB)), ("not an object", b"[]"), ("not JSON", b"{"),
                 ("schema not rapp/1", ('{"rappid":"' + RID + '","schema":"rapp/2"}').encode()))
        for variant, extra in (("organism", {"soul.md": b"s"}), ("rapplication", {"agent.py": b"a"})):
            good = R.pack_egg(variant, RID, UTC, files={"rappid.json": identity(RID), **extra})
            for label, octets in wrong:
                with self.subTest(variant=variant, label=label):
                    with self.assertRaises(ValueError):
                        R.pack_egg(variant, RID, UTC, files={"rappid.json": octets, **extra})
                    forged = forge(good, lambda _m, files: files.update({"rappid.json": octets}))
                    self.assertEqual(R.verify_egg(forged)[:2], (False, "§9.2"))

    def test_empty_neighborhood_and_estate_are_valid_and_pack_no_files(self):
        for variant, payload in (("neighborhood", {"members": []}), ("estate", {"neighborhoods": []})):
            with self.subTest(variant):
                egg = R.pack_egg(variant, STREET, UTC, payload=payload)
                self.assertEqual(R.verify_egg(egg), (True, None, "ok"))
                manifest, files = R.read_egg(egg)
                self.assertEqual((manifest["contents"], files), ([], {}))
                self.assertEqual(len(central_offsets(egg)), 1)
                with self.assertRaises(ValueError):
                    R.pack_egg(variant, STREET, UTC, files={"stray.txt": b"x"}, payload=payload)

    def test_sealed_schema_cipher_access_are_literals_and_media_type_is_free_text(self):
        self.assertEqual(R.verify_egg(sealed(), signature_verifier=vouch), (True, None, "ok"))
        for media_type in ("text/plain; charset=utf-8", "application/x-anything", "x"):
            with self.subTest(media_type=media_type):
                self.assertEqual(R.verify_egg(sealed(media_type=media_type), signature_verifier=vouch), (True, None, "ok"))
        for label, override in (("schema", {"schema": "rapp-sealed-artifact/2"}), ("cipher", {"cipher": "A128GCM"}),
                                ("access", {"access": "public"}), ("access case", {"access": "Scoped-Key-Release"}),
                                ("empty media_type", {"media_type": ""}), ("padded media_type", {"media_type": " text/x"}),
                                ("media_type over 127", {"media_type": "a" * 128})):
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    sealed(**override)
        forged = forge(sealed(), lambda manifest, _f: manifest["payload"].update(access="public"))
        self.assertEqual(R.verify_egg(forged, signature_verifier=vouch)[:2], (False, "§9.2"))
        with self.assertRaises(ValueError):
            R.pack_egg("sealed", SEALED, UTC, files={"ciphertext.bin": bytes(20)}, payload=sealed_payload())


class TestCallSites(unittest.TestCase):
    """rapp_check egg linting and egg_repack under the §9.3 producer."""

    def check(self, eggs, **kwargs):
        import rapp_check
        with tempfile.TemporaryDirectory() as root:
            for name, blob in eggs.items():
                Path(root, name).write_bytes(blob)
            return rapp_check.check_repo(root, **kwargs)

    def test_rapp_check_eggs(self):
        self.assertEqual(self.check({"home.egg": organism()})[0], "COMPLIANT")
        verdict, findings, evidence = self.check({"invite.egg": R.pack_egg("invite", RID, UTC, payload=INVITE, sig=jws(OWNER))})
        self.assertEqual(verdict, "DRIFT")
        self.assertEqual({item.get("status") for item in findings + evidence}, {"unverified"})
        signed = forge(organism(), lambda manifest, _f: manifest.update(sig=jws(OWNER)))
        self.assertEqual(self.check({"signed.egg": signed}, signature_verifier=vouch), ("COMPLIANT", [], [
            {"artifact": "signed.egg", "ok": "egg conforms to §9 (rapp/1-egg)"}]))
        verdict, findings, _ = self.check({"bad.egg": forge(organism(), lambda _m, files: files.update({"../x": b""}))})
        self.assertEqual((verdict, findings[0]["rule"], findings[0].get("status")), ("DRIFT", "§9 egg", None))

    def test_rapp_check_nested_signed_sub_egg_is_unverified_not_drift(self):
        """A neighborhood packing a signed organism passes steps (0)-(2); without a trusted verifier only §10 is
        unchecked, so rapp_check reports it unverified, as it does the same organism at top level."""
        signed = R.pack_egg("organism", BOB, UTC, files={"rappid.json": identity(BOB), "soul.md": b"# soul\n"},
                            sig=jws(BOB))
        hood = R.pack_egg("neighborhood", STREET, UTC, files={"bob--den.egg": signed}, payload={"members": [BOB]})
        self.assertEqual(R.verify_egg_static(hood), (True, None, "ok"))
        for name, blob in (("den.egg", signed), ("street.egg", hood)):
            with self.subTest(egg=name):
                verdict, findings, evidence = self.check({name: blob})
                self.assertEqual(verdict, "DRIFT")
                self.assertEqual({item.get("status") for item in findings + evidence}, {"unverified"})
        self.assertEqual(self.check({"street.egg": hood}, signature_verifier=vouch)[0], "COMPLIANT")

    def test_egg_repack_migrates_what_it_can_and_refuses_the_rest(self):
        import io
        import zipfile
        import egg_repack
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as legacy:
            legacy.writestr("manifest.json", json.dumps({"schema": "brainstem-egg/2.2-organism", "rappid": RID}))
            legacy.writestr("soul.md", "# legacy soul\n")
        self.assertEqual(R.verify_egg(egg_repack.repack(buffer.getvalue(), name_hint="home")), (True, None, "ok"))
        pointer = json.dumps({"schema": "brainstem-egg/2.3-neighborhood", "rappid": STREET, "url": "https://x.test/"})
        with self.assertRaises(ValueError) as caught:
            egg_repack.repack(pointer.encode(), name_hint="street")
        self.assertIn("unsigned", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
