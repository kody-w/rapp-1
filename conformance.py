"""conformance.py — executable proof that RAPP (rev-13) is implementable and
self-consistent, plus a non-gating observation of one live estate artifact.

Run: python3 conformance.py
Exit 0 = all controlled vectors pass. Mutable remote state never defines
whether the protocol implementation conforms; use realcheck.py for that audit.
"""
import json
import urllib.request
import hashlib
import io
import zipfile
import rapp as R

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  — {detail}" if detail and not ok else ""))

print("=" * 70)
print("RAPP rev-13 — conformance vectors")
print("=" * 70)

# V1 canonicalization determinism (key order independence)
a = R.canonical({"b": 1, "a": [3, 2], "c": {"y": 1, "x": 2}})
b = R.canonical({"c": {"x": 2, "y": 1}, "a": [3, 2], "b": 1})
check("V1 canonicalization is key-order independent", a == b, f"{a} vs {b}")
check("V1b array order IS significant", R.canonical([1, 2]) != R.canonical([2, 1]))

# V2 domain separation (§5): same bytes, different space → different address
val = {"x": 1}
p, w, e = R.H("rapp/1:particle", val), R.H("rapp/1:wave", val), R.H("rapp/1:egg-manifest", val)
check("V2 domain tags separate the address space", len({p, w, e}) == 3, f"{p[:8]} {w[:8]} {e[:8]}")

# V3 identity mint (§6.2): NEVER a name-hash
name_hash = hashlib.sha256(b"kody/twin").hexdigest()
rid = R.mint_rappid("kody", "twin")
tail = rid.rsplit(":", 1)[1]
check("V3 keyless mint is not sha256(owner/slug)", tail != name_hash)
check(
    "V3 rappid matches §6.1 grammar and length bounds",
    (
        R.rappid_valid(rid)
        and not R.rappid_valid("rappid:@" + "a" * 40 + "/x:" + "b" * 64)
        and not R.rappid_valid("rappid:@kody/" + "a" * 101 + ":" + "b" * 64)
    ),
    rid,
)
spki = b"\x30\x2a fake-spki-der-bytes-for-the-vector\x00"
rid_k = R.mint_rappid("kody", "twin", spki_der=spki)
check("V3 keyed tail == Hb('rapp/1:rappid', SPKI)", rid_k.rsplit(":", 1)[1] == R.Hb("rapp/1:rappid", spki))
check("V3 mint-once determinism for keyed identity", R.mint_rappid("kody", "twin", spki) == rid_k)

# V4 frame round-trip: build → verify
sid = "rappid:@kody/twin:" + "a" * 64
g = R.build_frame("body.pulse", sid, 0, "2026-07-15T00:00:00.000Z", {"hello": "world"}, prev=None)
ok, step, why = R.verify_frame(g, head=None, stream_id_of_record=sid)
check("V4 genesis frame builds and verifies", ok, f"step {step}: {why}")
check("V4 genesis has exactly 11 keys", set(g.keys()) == R.FRAME_KEYS)

# V5 tamper detection
t = dict(g); t["payload"] = {"hello": "evil"}
ok, step, _ = R.verify_frame(t, head=None, stream_id_of_record=sid)
check("V5 payload tamper caught at step 2", (not ok) and step == "2")
t2 = dict(g); t2["utc"] = "2099-01-01T00:00:00.000Z"
ok, step, _ = R.verify_frame(t2, head=None, stream_id_of_record=sid)
check("V5 envelope tamper caught at step 3 (wave)", (not ok) and step == "3")

# V6 chain linkage
child = R.build_frame("body.pulse", sid, 1, "2026-07-15T00:00:01.000Z", {"n": 2}, prev=g["payload_hash"])
ok, step, why = R.verify_frame(child, head=g, stream_id_of_record=sid)
check("V6 child frame links to genesis", ok, f"step {step}: {why}")
bad = R.build_frame("body.pulse", sid, 1, "2026-07-15T00:00:01.000Z", {"n": 2}, prev="f" * 64)
ok, step, _ = R.verify_frame(bad, head=g, stream_id_of_record=sid)
check("V6 broken prev caught at step 4", (not ok) and step == "4")

# V7 cross-stream replay (§7.5 step 1a) — genesis of stream A replayed as stream B
ok, step, _ = R.verify_frame(g, head=None, stream_id_of_record="rappid:@kody/other:" + "b" * 64)
check("V7 cross-stream genesis replay refused at 1a", (not ok) and step == "1a")

# V8 absent-vs-null: a frame missing a key is refused (not 11 keys)
short = {k: v for k, v in g.items() if k != "prev_wave"}
ok, step, _ = R.verify_frame(short, head=None, stream_id_of_record=sid)
bad_calendar = dict(g)
bad_calendar["utc"] = "2026-13-45T25:61:61.999Z"
calendar_ok, calendar_step, _ = R.verify_frame(
    bad_calendar,
    head=None,
    stream_id_of_record=sid,
)
check(
    "V8 missing key and impossible calendar time are refused at step 1",
    (not ok) and step == "1" and (not calendar_ok) and calendar_step == "1",
)

# V9 swarm frame must be signed
sw = R.build_frame("swarm.echo", "net:commons", 0, "2026-07-15T00:00:00.000Z", {"x": 1}, prev=None, prev_wave=None)
ok, step, _ = R.verify_frame(sw, head=None, stream_id_of_record="net:commons")
forged = dict(g)
forged["sig"] = "not-a-jws"
forged_ok, forged_step, _ = R.verify_frame(
    forged,
    head=None,
    stream_id_of_record=sid,
)
check(
    "V9 unsigned swarm and unverified frame signatures are refused at step 6",
    (not ok) and step == "6" and (not forged_ok) and forged_step == "6",
)

# V10 sealed artifact: public ciphertext, signed manifest, scoped key release
sealed_rappid = "rappid:@kody/sealed:" + "c" * 64
key_service = "rappid:@kody/key-service:" + "d" * 64
plaintext = b"compiled-private-agent-bytecode"
test_dek = b"\x00" * 32
descriptor = {
    "schema": "rapp-sealed-artifact/1",
    "artifact_rappid": sealed_rappid,
    "created_utc": "2026-08-29T20:00:00.000Z",
    "key_id": "e" * 64,
    "plaintext_commitment": R.sealed_plaintext_commitment(test_dek, plaintext),
    "plaintext_bytes": len(plaintext),
    "media_type": "application/wasm",
}
sealed_payload = {
    "schema": descriptor["schema"],
    "cipher": "A256GCM",
    "nonce": "MDEyMzQ1Njc4OWFi",
    "plaintext_commitment": descriptor["plaintext_commitment"],
    "plaintext_bytes": descriptor["plaintext_bytes"],
    "media_type": descriptor["media_type"],
    "key_id": descriptor["key_id"],
    "key_service_rappid": key_service,
    "key_service_url": "https://keys.example.test/chat",
    "access": "scoped-key-release",
    "aad_hash": R.H("rapp/1:sealed-aad", descriptor),
}
test_signature = "test-detached-jws"
test_nonce = b"0123456789ab"
test_aad = R.canonical(descriptor).encode("utf-8")
known_ciphertext = bytes.fromhex(
    "75e910207b9fceb0b0086f06e9fc6c977f0fbe77d2fe850a695c6cde31843a"
    "111d494c14210202c57751321dab41a1"
)


def test_signature_verifier(unsigned_manifest, sig, expected_signer=None):
    return (
        sig == test_signature
        and unsigned_manifest["variant"] == "sealed"
        and expected_signer == sealed_rappid,
        "test signature mismatch",
    )


def known_answer_decryptor(dek, nonce, aad, ciphertext):
    if (
        dek != test_dek
        or nonce != test_nonce
        or aad != test_aad
        or ciphertext != known_ciphertext
    ):
        raise ValueError("AES-GCM known-answer authentication mismatch")
    return plaintext


sealed = R.pack_egg(
    "sealed",
    sealed_rappid,
    descriptor["created_utc"],
    files={"ciphertext.bin": known_ciphertext},
    payload=sealed_payload,
    sig=test_signature,
)
ok, step, why = R.verify_egg(sealed, signature_verifier=test_signature_verifier)
opened = R.open_sealed_egg(
    sealed,
    test_dek,
    test_signature_verifier,
    known_answer_decryptor,
) if ok else None
check(
    "V10 sealed artifact verifies and opens through crypto adapters",
    ok and opened == plaintext,
    f"step {step}: {why}",
)

tampered_ciphertext = bytearray(known_ciphertext)
tampered_ciphertext[0] ^= 1
tampered_tag = bytearray(known_ciphertext)
tampered_tag[-1] ^= 1
wrong_nonce_payload = dict(sealed_payload)
wrong_nonce_payload["nonce"] = "YWJjZGVmZ2hpamts"
negative_open_blobs = [
    R.pack_egg(
        "sealed",
        sealed_rappid,
        descriptor["created_utc"],
        files={"ciphertext.bin": bytes(tampered_ciphertext)},
        payload=sealed_payload,
        sig=test_signature,
    ),
    R.pack_egg(
        "sealed",
        sealed_rappid,
        descriptor["created_utc"],
        files={"ciphertext.bin": bytes(tampered_tag)},
        payload=sealed_payload,
        sig=test_signature,
    ),
    R.pack_egg(
        "sealed",
        sealed_rappid,
        descriptor["created_utc"],
        files={"ciphertext.bin": known_ciphertext},
        payload=wrong_nonce_payload,
        sig=test_signature,
    ),
]
open_refusals = 0
for blob in negative_open_blobs:
    try:
        R.open_sealed_egg(
            blob,
            test_dek,
            test_signature_verifier,
            known_answer_decryptor,
        )
    except ValueError:
        open_refusals += 1
oversized_payload = dict(sealed_payload)
oversized_payload["plaintext_bytes"] = R.MAX_SEALED_PLAINTEXT_BYTES + 1
oversized = R.pack_egg(
    "sealed",
    sealed_rappid,
    descriptor["created_utc"],
    files={"ciphertext.bin": known_ciphertext},
    payload=oversized_payload,
    sig=test_signature,
)
oversized_ok, oversized_step, _ = R.verify_egg(
    oversized,
    signature_verifier=test_signature_verifier,
)
unsigned_ok, unsigned_step, _ = R.verify_egg(sealed)
wrong_signer_ok, wrong_signer_step, _ = R.verify_egg(
    sealed,
    signature_verifier=lambda _unsigned, _sig, expected: (
        False,
        f"valid signer is not authorized as {expected}",
    ),
)
check(
    "V10b tamper, oversize, missing trust, and wrong signer are refused",
    (
        open_refusals == 3
        and not oversized_ok
        and oversized_step == "§9.2"
        and not unsigned_ok
        and unsigned_step == "§10"
        and not wrong_signer_ok
        and wrong_signer_step == "§10"
    ),
)

trailing_ok, trailing_step, _ = R.verify_egg(
    sealed + b"junk",
    signature_verifier=test_signature_verifier,
)
bad_variant_manifest = {
    "schema": "rapp/1-egg",
    "variant": [],
    "rappid": sealed_rappid,
    "created_utc": descriptor["created_utc"],
    "contents": [],
    "payload": {},
    "sig": None,
}
bad_variant_ok, bad_variant_step, _ = R.verify_egg(
    R.canonical(bad_variant_manifest).encode("utf-8"),
)
nfc_egg = R.pack_egg(
    "organism",
    sealed_rappid,
    descriptor["created_utc"],
    files={
        "rappid.json": b"{}",
        "soul.md": b"# soul\n",
        "cafe\u0301.txt": b"x",
    },
)
nfc_ok, nfc_step, _ = R.verify_egg(nfc_egg)
windows_alias = R.pack_egg(
    "organism",
    sealed_rappid,
    descriptor["created_utc"],
    files={
        "rappid.json": (
            '{"rappid":"' + sealed_rappid + '"}'
        ).encode(),
        "rappid.json.": b"shadow",
        "soul.md": b"# soul\n",
    },
)
alias_ok, alias_step, _ = R.verify_egg(windows_alias)
prefix_conflict = R.pack_egg(
    "organism",
    sealed_rappid,
    descriptor["created_utc"],
    files={
        "rappid.json": (
            '{"rappid":"' + sealed_rappid + '"}'
        ).encode(),
        "soul.md": b"# soul\n",
        "a": b"file",
        "a/b": b"child",
    },
)
prefix_ok, prefix_step, _ = R.verify_egg(prefix_conflict)
manifest_alias = R.pack_egg(
    "organism",
    sealed_rappid,
    descriptor["created_utc"],
    files={
        "rappid.json": (
            '{"rappid":"' + sealed_rappid + '"}'
        ).encode(),
        "soul.md": b"# soul\n",
        "MANIFEST.JSON": b"shadow",
    },
)
manifest_alias_ok, manifest_alias_step, _ = R.verify_egg(manifest_alias)


class Utf8ZipInfo(zipfile.ZipInfo):
    def _encodeFilenameFlags(self):
        return self.filename.encode("utf-8"), self.flag_bits | 0x800


malformed_manifest = dict(R.read_egg(sealed)[0])
malformed_manifest["contents"] = [{"path": "ciphertext.bin"}]
malformed_buffer = io.BytesIO()
with zipfile.ZipFile(malformed_buffer, "w", zipfile.ZIP_STORED) as archive:
    for name, octets in (
        ("manifest.json", R.canonical(malformed_manifest).encode("utf-8")),
        ("ciphertext.bin", known_ciphertext),
    ):
        info = Utf8ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        archive.writestr(info, octets)
malformed_ok, malformed_step, _ = R.verify_egg(malformed_buffer.getvalue())
check(
    "V10c trailing bytes, malformed manifests, and non-NFC paths are refused",
    (
        not trailing_ok
        and trailing_step == "parse"
        and not bad_variant_ok
        and bad_variant_step == "§9.2"
        and not nfc_ok
        and nfc_step == "§9.1"
        and not malformed_ok
        and malformed_step == "parse"
        and not alias_ok
        and alias_step == "§9.1"
        and not prefix_ok
        and prefix_step == "§9.1"
        and not manifest_alias_ok
        and manifest_alias_step == "§9.1"
    ),
)

estate_owner = "rappid:@kody/estate-owner:" + "9" * 64
invite_rappid = "rappid:@kody/invite:" + "8" * 64
invite = R.pack_egg(
    "invite",
    invite_rappid,
    descriptor["created_utc"],
    payload={
        "target_rappid": sealed_rappid,
        "target_url": "https://example.test/estate.egg",
        "target_kind": "estate",
    },
    sig=test_signature,
)
seen_expected = []


def invite_signature_verifier(_unsigned, sig, expected_signer):
    seen_expected.append(expected_signer)
    return sig == test_signature and expected_signer == estate_owner, "wrong owner"


invite_ok, invite_step, invite_why = R.verify_egg(
    invite,
    signature_verifier=invite_signature_verifier,
    estate_owner_rappid=estate_owner,
)
forged_ok, forged_step, _ = R.verify_egg(
    invite,
    signature_verifier=lambda _unsigned, _sig, _expected: (
        False,
        "valid non-owner signer",
    ),
    estate_owner_rappid=estate_owner,
)
check(
    "V10d invite signatures bind to estate-owner authority",
    (
        invite_ok
        and invite_step is None
        and invite_why == "ok"
        and seen_expected == [estate_owner]
        and not forged_ok
        and forged_step == "§10"
    ),
)

wrong_aad = dict(sealed_payload)
wrong_aad["aad_hash"] = "f" * 64
bad_aad = R.pack_egg(
    "sealed",
    sealed_rappid,
    descriptor["created_utc"],
    files={"ciphertext.bin": known_ciphertext},
    payload=wrong_aad,
    sig=test_signature,
)
ok, step, _ = R.verify_egg(
    bad_aad,
    signature_verifier=test_signature_verifier,
)
check("V10e sealed authenticated-data mismatch is refused", (not ok) and step == "§9.2")

extra_plaintext = R.pack_egg(
    "sealed",
    sealed_rappid,
    descriptor["created_utc"],
    files={
        "ciphertext.bin": known_ciphertext,
        "plaintext.wasm": plaintext,
    },
    payload=sealed_payload,
    sig=test_signature,
)
ok, step, _ = R.verify_egg(
    extra_plaintext,
    signature_verifier=test_signature_verifier,
)
identity_mismatch = R.pack_egg(
    "organism",
    sealed_rappid,
    descriptor["created_utc"],
    files={
        "rappid.json": (
            '{"rappid":"rappid:@kody/other:' + "7" * 64 + '"}'
        ).encode(),
        "soul.md": b"# soul\n",
    },
)
identity_ok, identity_step, _ = R.verify_egg(identity_mismatch)
check(
    "V10f sealed plaintext and packaged identity mismatches are refused",
    (
        not ok
        and step == "§9.2"
        and not identity_ok
        and identity_step == "§9.2"
    ),
)

print()
vector_count = len(results)
vector_ok = sum(results)
print("-" * 70)
print(f"CONTROLLED VECTORS: {vector_count} checks | {vector_ok} PASS | {vector_count - vector_ok} FAIL")

print()
print("=" * 70)
print("LIVE OBSERVATION — kody-w/twin/frames/0.json (non-gating)")
print("=" * 70)
try:
    raw = urllib.request.urlopen(
        "https://raw.githubusercontent.com/kody-w/twin/main/frames/0.json", timeout=20).read()
    real = json.loads(raw)
    payload = real["payload"]
    if set(real) == R.FRAME_KEYS and real.get("spec") == R.SPEC:
        tagged = R.H("rapp/1:particle", payload)
        hash_ok = tagged == real["payload_hash"]
        ok, step, why = R.verify_frame(
            real, head=None, stream_id_of_record=real["stream_id"])
        print(f"  [{'CURRENT' if hash_ok and ok else 'DRIFT'}] frame uses the rapp/1 envelope")
        print(f"       particle reproduces stored payload_hash: {hash_ok}")
        print(f"       frame verifies as its stream genesis: {ok}"
              + ("" if ok else f" (step {step}: {why})"))
    else:
        stored = real.get("sha256") or real.get("hash")
        untagged = hashlib.sha256(R.canonical(payload).encode()).hexdigest()
        ok, step, why = R.verify_frame(real)
        print("  [HISTORICAL] frame uses a pre-RAPP envelope")
        print(f"       canonical bytes reproduce legacy stored hash: {untagged == stored}")
        print(f"       current verifier refusal: {not ok}"
              + (f" (step {step}: {why})" if not ok else ""))
        print(f"       envelope keys: {sorted(real.keys())}")
except Exception as ex:
    print(f"  [UNAVAILABLE] live observation not fetched: {ex}")

print()
print("-" * 70)
print(f"{vector_count} controlled checks | {vector_ok} PASS | {vector_count - vector_ok} FAIL")
import sys
sys.exit(0 if vector_ok == vector_count else 1)
