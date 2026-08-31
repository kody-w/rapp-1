"""conformance.py — executable proof that RAPP (rev-15) is implementable and
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
import copy
import threading
import rapp as R

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  — {detail}" if detail and not ok else ""))

print("=" * 70)
print("RAPP rev-15 — conformance vectors")
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

# V11 generic signed lens cracking and tile lineage
lineage_lens_stream = "rappid:@kody/lens:" + "1" * 64
lineage_output_stream = "rappid:@kody/tiles:" + "2" * 64
second_output_stream = "rappid:@kody/tiles-two:" + "3" * 64
seeded_lens_stream = "rappid:@kody/seeded-lens:" + "4" * 64
seeded_output_stream = "rappid:@kody/seeded-tiles:" + "5" * 64


def lineage_signature_verifier(unsigned, sig, expected_signer=None):
    signer = unsigned["stream_id"]
    return (
        sig == "sig:" + signer
        and (expected_signer is None or expected_signer == signer),
        "signature is not bound to the frame stream",
    )


def lineage_runner(lens_payload, parent_frames, replay):
    result = {
        "operation": lens_payload["mutation"]["operation"],
        "label": replay["inputs"]["label"],
        "parents": [frame["payload"] for frame in parent_frames],
    }
    if replay["mode"] == "seeded":
        result["stochastic_inputs"] = replay["stochastic_inputs"]
    return [result]


lineage_lens = R.build_lens_frame(
    lineage_lens_stream,
    0,
    "2026-08-31T10:00:00.000Z",
    runner="example.wrap",
    mutation={"operation": "wrap", "parent_order": "declared"},
    inputs=["label"],
    stochastic_inputs=[],
    facets=["result"],
    prev=None,
    sig="sig:" + lineage_lens_stream,
)
clean_one = R.build_frame(
    "body.pulse",
    lineage_output_stream,
    0,
    "2026-08-31T10:00:00.000Z",
    {"source": "one"},
    prev=None,
)
clean_two = R.build_frame(
    "body.pulse",
    second_output_stream,
    0,
    "2026-08-31T10:00:00.000Z",
    {"source": "two"},
    prev=None,
)
lineage_store = {}
accepted_geneses = set()
registered_kind_families = {
    "body.lens": "body",
    "body.pulse": "body",
    "body.re-genesis": "body",
    "body.tile": "body",
    "memory.save": "memory",
    "memory.tile": "memory",
    "swarm.tile": "swarm",
}


def remember(frame, era, frames, *, persisted=True, invocation_id=None):
    lineage_store[(frame["frame_hash"], era)] = {
        "frames": list(frames),
        "persisted": persisted,
        "invocation_id": invocation_id,
    }
    accepted_geneses.add((frames[0]["stream_id"], era))


remember(lineage_lens, lineage_lens["frame_hash"], [lineage_lens])
remember(clean_one, clean_one["frame_hash"], [clean_one])
remember(clean_two, clean_two["frame_hash"], [clean_two])


def lineage_resolver(frame_hash, era):
    return lineage_store[(frame_hash, era)]


def registered_genesis_verifier(stream_id, era):
    return (stream_id, era) in accepted_geneses


def registered_kind_family_resolver(kind):
    return registered_kind_families.get(kind)


def equip_semantic_resolver(resolver):
    resolver.genesis_verifier = registered_genesis_verifier
    resolver.kind_family_resolver = registered_kind_family_resolver
    return resolver


equip_semantic_resolver(lineage_resolver)


lens_ref = R.make_lineage_ref(lineage_lens, lineage_lens["frame_hash"])
clean_one_ref = R.make_lineage_ref(clean_one, clean_one["frame_hash"])
clean_two_ref = R.make_lineage_ref(clean_two, clean_two["frame_hash"])
replay_one = {"mode": "deterministic", "inputs": {"label": "g1"}}
tile_one = R.build_tile_frame(
    "body.tile",
    lineage_output_stream,
    1,
    "2026-08-31T10:00:01.000Z",
    lens=lens_ref,
    parents=[clean_one_ref],
    replay=replay_one,
    resolver=lineage_resolver,
    runner=lineage_runner,
    prev=clean_one["payload_hash"],
    head=clean_one,
    signature_verifier=lineage_signature_verifier,
)
tile_one_ref = R.make_lineage_ref(tile_one, clean_one["frame_hash"])
remember(tile_one, clean_one["frame_hash"], [clean_one, tile_one])
tile_one_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)

wrong_lens_stream = lineage_lens_stream + ":instance"
wrong_family_lens = R.build_frame(
    R.LENS_KIND,
    wrong_lens_stream,
    0,
    "2026-08-31T10:00:00.000Z",
    copy.deepcopy(lineage_lens["payload"]),
    prev=None,
    sig="sig:" + wrong_lens_stream,
)
wrong_family_ok = R.verify_lens_frame(
    wrong_family_lens,
    stream_id_of_record=wrong_lens_stream,
    signature_verifier=lineage_signature_verifier,
    kind_family_resolver=registered_kind_family_resolver,
)
wrong_signer_ok = R.verify_lens_frame(
    lineage_lens,
    stream_id_of_record=lineage_lens_stream,
    signature_verifier=lambda _unsigned, _sig, _expected: (
        False,
        "wrong stream signer",
    ),
    kind_family_resolver=registered_kind_family_resolver,
)
check(
    "V11 signed body.lens is exact-kind, body-stream, and signer bound",
    (
        R.verify_lens_frame(
            lineage_lens,
            stream_id_of_record=lineage_lens_stream,
            signature_verifier=lineage_signature_verifier,
            kind_family_resolver=registered_kind_family_resolver,
        )[0]
        and not wrong_family_ok[0]
        and not wrong_signer_ok[0]
    ),
)
check(
    "V11a one lens crack produces a generation-1 tile",
    (
        tile_one_ok[0]
        and tile_one["payload"]["generation"] == 1
        and tile_one["payload"]["root_sources"] == [clean_one_ref]
    ),
)

replay_two = {"mode": "deterministic", "inputs": {"label": "g2"}}
tile_two = R.build_tile_frame(
    "body.tile",
    lineage_output_stream,
    2,
    "2026-08-31T10:00:02.000Z",
    lens=lens_ref,
    parents=[tile_one_ref],
    replay=replay_two,
    resolver=lineage_resolver,
    runner=lineage_runner,
    prev=tile_one["payload_hash"],
    head=tile_one,
    signature_verifier=lineage_signature_verifier,
    kind_family_resolver=registered_kind_family_resolver,
)
tile_two_ref = R.make_lineage_ref(tile_two, clean_one["frame_hash"])
remember(
    tile_two,
    clean_one["frame_hash"],
    [clean_one, tile_one, tile_two],
)
tile_two_ok = R.verify_tile_frame(
    tile_two,
    head=tile_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    kind_family_resolver=registered_kind_family_resolver,
)
prev_as_parent_payload = copy.deepcopy(tile_two["payload"])
prev_as_parent_payload["parents"] = [
    {"frame_hash": tile_one["payload_hash"], "era": clean_one["frame_hash"]}
]
prev_as_parent = R.build_frame(
    "body.tile",
    lineage_output_stream,
    2,
    tile_two["utc"],
    prev_as_parent_payload,
    prev=tile_one["payload_hash"],
)
prev_as_parent_ok = R.verify_tile_frame(
    prev_as_parent,
    head=tile_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    kind_family_resolver=registered_kind_family_resolver,
)
check(
    "V11b repeated cracking reaches generation 2 and prev is not an input pointer",
    (
        tile_two_ok[0]
        and tile_two["payload"]["generation"] == 2
        and tile_two["prev"] == tile_one["payload_hash"]
        and tile_two["payload"]["parents"][0]["frame_hash"]
        == tile_one["frame_hash"]
        and not prev_as_parent_ok[0]
    ),
)

tile_three = R.build_tile_frame(
    "body.tile",
    second_output_stream,
    1,
    "2026-08-31T10:00:03.000Z",
    lens=lens_ref,
    parents=[clean_two_ref, tile_two_ref],
    replay={"mode": "deterministic", "inputs": {"label": "merge"}},
    resolver=lineage_resolver,
    runner=lineage_runner,
    prev=clean_two["payload_hash"],
    head=clean_two,
    signature_verifier=lineage_signature_verifier,
)
remember(
    tile_three,
    clean_two["frame_hash"],
    [clean_two, tile_three],
)
check(
    "V11c multi-parent generation uses max depth and exact first-seen root order",
    (
        tile_three["payload"]["generation"] == 3
        and tile_three["payload"]["root_sources"]
        == [clean_two_ref, clean_one_ref]
        and R.verify_tile_frame(
            tile_three,
            head=clean_two,
            stream_id_of_record=second_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
    ),
)

substitute_lens = R.build_lens_frame(
    "rappid:@kody/other-lens:" + "6" * 64,
    0,
    "2026-08-31T10:00:00.000Z",
    runner="example.wrap",
    mutation={"operation": "substitute", "parent_order": "declared"},
    inputs=["label"],
    stochastic_inputs=[],
    facets=["result"],
    prev=None,
    sig="sig:" + "rappid:@kody/other-lens:" + "6" * 64,
)


def lens_substitution_resolver(frame_hash, era):
    if (frame_hash, era) == (
        lineage_lens["frame_hash"],
        lineage_lens["frame_hash"],
    ):
        return {
            "frames": [substitute_lens],
            "persisted": True,
            "invocation_id": None,
        }
    return lineage_resolver(frame_hash, era)


equip_semantic_resolver(lens_substitution_resolver)


substitution_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lens_substitution_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
clean_as_lens_payload = copy.deepcopy(tile_one["payload"])
clean_as_lens_payload["lens"] = clean_one_ref
clean_as_lens = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    clean_as_lens_payload,
    prev=clean_one["payload_hash"],
)
clean_as_lens_ok = R.verify_tile_frame(
    clean_as_lens,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11d lens substitution and a non-lens lens reference are refused",
    not substitution_ok[0] and not clean_as_lens_ok[0],
)


def missing_parent_resolver(frame_hash, era):
    if frame_hash == clean_one["frame_hash"]:
        raise KeyError("missing parent")
    return lineage_resolver(frame_hash, era)


equip_semantic_resolver(missing_parent_resolver)


missing_parent_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=missing_parent_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
wrong_era_payload = copy.deepcopy(tile_one["payload"])
wrong_era_payload["parents"][0]["era"] = clean_two["frame_hash"]
wrong_era = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    wrong_era_payload,
    prev=clean_one["payload_hash"],
)


def wrong_era_resolver(frame_hash, era):
    if frame_hash == clean_one["frame_hash"]:
        return {
            "frames": [clean_one],
            "persisted": True,
            "invocation_id": None,
        }
    return lineage_resolver(frame_hash, era)


equip_semantic_resolver(wrong_era_resolver)


wrong_era_ok = R.verify_tile_frame(
    wrong_era,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=wrong_era_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11e missing parents and wrong parent eras are controlled refusals",
    not missing_parent_ok[0] and not wrong_era_ok[0],
)

duplicate_payload = copy.deepcopy(tile_three["payload"])
duplicate_payload["parents"] = [clean_two_ref, clean_two_ref]
duplicate_tile = R.build_frame(
    "body.tile",
    second_output_stream,
    1,
    tile_three["utc"],
    duplicate_payload,
    prev=clean_two["payload_hash"],
)
duplicate_ok = R.verify_tile_frame(
    duplicate_tile,
    head=clean_two,
    stream_id_of_record=second_output_stream,
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
cycle_ok = R.verify_lineage_dag(
    {
        clean_one["frame_hash"]: [tile_one["frame_hash"]],
        tile_one["frame_hash"]: [clean_one["frame_hash"]],
    }
)
check(
    "V11f cycles and duplicate direct parents are refused",
    not cycle_ok[0] and not duplicate_ok[0],
)

bad_generation_payload = copy.deepcopy(tile_two["payload"])
bad_generation_payload["generation"] = 1
bad_generation = R.build_frame(
    "body.tile",
    lineage_output_stream,
    2,
    tile_two["utc"],
    bad_generation_payload,
    prev=tile_one["payload_hash"],
)
bad_roots_payload = copy.deepcopy(tile_three["payload"])
bad_roots_payload["root_sources"] = list(
    reversed(bad_roots_payload["root_sources"])
)
bad_roots = R.build_frame(
    "body.tile",
    second_output_stream,
    1,
    tile_three["utc"],
    bad_roots_payload,
    prev=clean_two["payload_hash"],
)
check(
    "V11g generation and root-source laundering are refused",
    (
        not R.verify_tile_frame(
            bad_generation,
            head=tile_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            bad_roots,
            head=clean_two,
            stream_id_of_record=second_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
    ),
)

seeded_lens = R.build_lens_frame(
    seeded_lens_stream,
    0,
    "2026-08-31T10:00:00.000Z",
    runner="example.seeded-wrap",
    mutation={"operation": "seeded-wrap", "parent_order": "declared"},
    inputs=["label"],
    stochastic_inputs=["nonce", "seed"],
    facets=["result"],
    prev=None,
    sig="sig:" + seeded_lens_stream,
)
seeded_clean = R.build_frame(
    "body.pulse",
    seeded_output_stream,
    0,
    "2026-08-31T10:00:00.000Z",
    {"source": "seeded"},
    prev=None,
)
remember(seeded_lens, seeded_lens["frame_hash"], [seeded_lens])
remember(seeded_clean, seeded_clean["frame_hash"], [seeded_clean])
seeded_lens_ref = R.make_lineage_ref(seeded_lens, seeded_lens["frame_hash"])
seeded_clean_ref = R.make_lineage_ref(seeded_clean, seeded_clean["frame_hash"])
seeded_replay = {
    "mode": "seeded",
    "inputs": {"label": "seeded"},
    "stochastic_inputs": {"nonce": "n-001", "seed": 7},
}
seeded_tile = R.build_tile_frame(
    "body.tile",
    seeded_output_stream,
    1,
    "2026-08-31T10:00:01.000Z",
    lens=seeded_lens_ref,
    parents=[seeded_clean_ref],
    replay=seeded_replay,
    resolver=lineage_resolver,
    runner=lineage_runner,
    prev=seeded_clean["payload_hash"],
    head=seeded_clean,
    signature_verifier=lineage_signature_verifier,
)
missing_seed_payload = copy.deepcopy(seeded_tile["payload"])
del missing_seed_payload["replay"]["stochastic_inputs"]["nonce"]
missing_seed = R.build_frame(
    "body.tile",
    seeded_output_stream,
    1,
    seeded_tile["utc"],
    missing_seed_payload,
    prev=seeded_clean["payload_hash"],
)
replay_mismatch_payload = copy.deepcopy(tile_one["payload"])
replay_mismatch_payload["output"]["label"] = "substituted"
replay_mismatch = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    replay_mismatch_payload,
    prev=clean_one["payload_hash"],
)
check(
    "V11h deterministic and seeded replay are exact and complete",
    (
        tile_one_ok[0]
        and not R.verify_tile_frame(
            tile_one,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
        )[0]
        and R.verify_tile_frame(
            seeded_tile,
            head=seeded_clean,
            stream_id_of_record=seeded_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            missing_seed,
            head=seeded_clean,
            stream_id_of_record=seeded_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            replay_mismatch,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
    ),
)

immutable_lens = copy.deepcopy(lineage_lens)
immutable_clean = copy.deepcopy(clean_two)
immutable_tile_parent = copy.deepcopy(tile_one)
immutable_replay = {"mode": "deterministic", "inputs": {"label": "immutable"}}
immutable_replay_before = copy.deepcopy(immutable_replay)


def mutating_runner(lens_payload, parent_frames, replay):
    result = lineage_runner(
        copy.deepcopy(lens_payload),
        copy.deepcopy(parent_frames),
        copy.deepcopy(replay),
    )
    if replay["inputs"]["label"] == "immutable":
        result[0]["immutable"] = True
    lens_payload["mutation"]["operation"] = "mutated"
    for parent_frame in parent_frames:
        parent_frame["payload"]["mutation_attempt"] = "mutated"
    replay["inputs"]["label"] = "mutated"
    return result


immutable_tile = R.build_tile_frame(
    "body.tile",
    second_output_stream,
    1,
    "2026-08-31T10:00:04.000Z",
    lens=lens_ref,
    parents=[clean_two_ref, tile_one_ref],
    replay=immutable_replay,
    resolver=lineage_resolver,
    runner=mutating_runner,
    prev=clean_two["payload_hash"],
    head=clean_two,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11i cracking cannot mutate lens, fresh frame, worn frame, or replay",
    (
        lineage_lens == immutable_lens
        and clean_two == immutable_clean
        and tile_one == immutable_tile_parent
        and immutable_replay == immutable_replay_before
        and immutable_tile["payload"]["output"]["immutable"] is True
    ),
)

transient_store = dict(lineage_store)
transient_store[(tile_one["frame_hash"], clean_one["frame_hash"])] = {
    "frames": [clean_one, tile_one],
    "persisted": False,
    "invocation_id": "invocation-1",
}


def transient_resolver(frame_hash, era):
    return transient_store[(frame_hash, era)]


equip_semantic_resolver(transient_resolver)


def idempotent_facet_claim(_crack_id, _tile_index, frame_hash):
    return frame_hash


durable_from_transient = R.accept_tile_frame(
    tile_two,
    head=tile_one,
    stream_id_of_record=lineage_output_stream,
    resolver=transient_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    facet_claim=idempotent_facet_claim,
)
same_invocation = R.verify_tile_frame(
    tile_two,
    head=tile_one,
    stream_id_of_record=lineage_output_stream,
    resolver=transient_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    invocation_id="invocation-1",
)
wrong_invocation = R.verify_tile_frame(
    tile_two,
    head=tile_one,
    stream_id_of_record=lineage_output_stream,
    resolver=transient_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    invocation_id="invocation-2",
)
actionable_transient = R.accept_tile_frame(
    tile_two,
    head=tile_one,
    stream_id_of_record=lineage_output_stream,
    resolver=transient_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    facet_claim=idempotent_facet_claim,
)
non_replayable_payload = copy.deepcopy(tile_two["payload"])
non_replayable_payload["replay"] = {"mode": "non-replayable"}
non_replayable = R.build_frame(
    "body.tile",
    lineage_output_stream,
    2,
    tile_two["utc"],
    non_replayable_payload,
    prev=tile_one["payload_hash"],
)
check(
    "V11j transient ancestry is same-invocation read-only, never durable/actionable",
    (
        not durable_from_transient[0]
        and same_invocation[0]
        and not wrong_invocation[0]
        and not actionable_transient[0]
        and not R.verify_tile_frame(
            non_replayable,
            head=tile_one,
            stream_id_of_record=lineage_output_stream,
            resolver=transient_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
            invocation_id="invocation-1",
        )[0]
    ),
)

unsigned_swarm_tile = R.build_frame(
    "swarm.tile",
    "net:tiles",
    0,
    "2026-08-31T10:00:01.000Z",
    copy.deepcopy(tile_one["payload"]),
    prev=None,
    prev_wave=None,
)
unsigned_swarm_ok = R.verify_tile_frame(
    unsigned_swarm_tile,
    stream_id_of_record="net:tiles",
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
memory_tile_stream = lineage_output_stream + ":memory"
memory_clean = R.build_frame(
    "memory.save",
    memory_tile_stream,
    0,
    "2026-08-31T10:00:00.000Z",
    {"source": "memory"},
    prev=None,
)
remember(memory_clean, memory_clean["frame_hash"], [memory_clean])
memory_clean_ref = R.make_lineage_ref(
    memory_clean,
    memory_clean["frame_hash"],
)
memory_tile = R.build_tile_frame(
    "memory.tile",
    memory_tile_stream,
    1,
    "2026-08-31T10:00:01.000Z",
    lens=lens_ref,
    parents=[memory_clean_ref],
    replay={"mode": "deterministic", "inputs": {"label": "memory"}},
    resolver=lineage_resolver,
    runner=lineage_runner,
    prev=memory_clean["payload_hash"],
    head=memory_clean,
    signature_verifier=lineage_signature_verifier,
)
signed_swarm_tile = R.build_tile_frame(
    "swarm.tile",
    "net:tiles",
    0,
    "2026-08-31T10:00:01.000Z",
    lens=lens_ref,
    parents=[clean_one_ref],
    replay={"mode": "deterministic", "inputs": {"label": "swarm"}},
    resolver=lineage_resolver,
    runner=lineage_runner,
    prev=None,
    sig="sig:net:tiles",
    signature_verifier=lineage_signature_verifier,
)
wrong_tile_family = R.build_frame(
    "memory.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    copy.deepcopy(tile_one["payload"]),
    prev=clean_one["payload_hash"],
)
wrong_tile_family_ok = R.verify_tile_frame(
    wrong_tile_family,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11k tile family binding and normal swarm signatures are mandatory",
    (
        R.verify_tile_frame(
            memory_tile,
            head=memory_clean,
            stream_id_of_record=memory_tile_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and R.verify_tile_frame(
            signed_swarm_tile,
            stream_id_of_record="net:tiles",
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not unsigned_swarm_ok[0]
        and unsigned_swarm_ok[1] == "6"
        and not wrong_tile_family_ok[0]
    ),
)

extra_lens_payload = copy.deepcopy(lineage_lens["payload"])
extra_lens_payload["extra"] = None
extra_lens = R.build_frame(
    R.LENS_KIND,
    lineage_lens_stream,
    0,
    lineage_lens["utc"],
    extra_lens_payload,
    prev=None,
    sig="sig:" + lineage_lens_stream,
)
missing_parent_order_payload = copy.deepcopy(lineage_lens["payload"])
del missing_parent_order_payload["mutation"]["parent_order"]
missing_parent_order_lens = R.build_frame(
    R.LENS_KIND,
    lineage_lens_stream,
    0,
    lineage_lens["utc"],
    missing_parent_order_payload,
    prev=None,
    sig="sig:" + lineage_lens_stream,
)
duplicate_facets_payload = copy.deepcopy(lineage_lens["payload"])
duplicate_facets_payload["facets"] = ["result", "result"]
duplicate_facets_lens = R.build_frame(
    R.LENS_KIND,
    lineage_lens_stream,
    0,
    lineage_lens["utc"],
    duplicate_facets_payload,
    prev=None,
    sig="sig:" + lineage_lens_stream,
)
missing_tile_payload = copy.deepcopy(tile_one["payload"])
del missing_tile_payload["root_sources"]
missing_tile = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    missing_tile_payload,
    prev=clean_one["payload_hash"],
)
provenance_class_payload = copy.deepcopy(tile_one["payload"])
provenance_class_payload["provenance_class"] = "invalid"
provenance_class_tile = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    provenance_class_payload,
    prev=clean_one["payload_hash"],
)
check(
    "V11l extra/missing members, duplicate facets, and provenance_class are refused",
    (
        not R.verify_lens_frame(
            extra_lens,
            stream_id_of_record=lineage_lens_stream,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_lens_frame(
            missing_parent_order_lens,
            stream_id_of_record=lineage_lens_stream,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_lens_frame(
            duplicate_facets_lens,
            stream_id_of_record=lineage_lens_stream,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            missing_tile,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            provenance_class_tile,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
    ),
)

regenesis = R.build_frame(
    "body.re-genesis",
    "rappid:@kody/reborn:" + "7" * 64,
    0,
    "2026-08-31T10:00:00.000Z",
    {"migrated_from": {"stream_id": lineage_output_stream}},
    prev=None,
    sig="sig:" + "rappid:@kody/reborn:" + "7" * 64,
)
relabeled_tile_payload = R.build_frame(
    "body.pulse",
    "rappid:@kody/relabeled-tile:" + "8" * 64,
    0,
    "2026-08-31T10:00:00.000Z",
    copy.deepcopy(tile_one["payload"]),
    prev=None,
)
check(
    "V11m relabeled rapp-tile/1 payload cannot launder generation to 0",
    (
        R.verify_clean_frame(
            clean_one,
            stream_id_of_record=lineage_output_stream,
            kind_family_resolver=registered_kind_family_resolver,
        )[0]
        and not R.verify_clean_frame(
            tile_one,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            kind_family_resolver=registered_kind_family_resolver,
        )[0]
        and not R.verify_clean_frame(
            regenesis,
            stream_id_of_record=regenesis["stream_id"],
            signature_verifier=lineage_signature_verifier,
            kind_family_resolver=registered_kind_family_resolver,
        )[0]
        and not R.verify_clean_frame(
            relabeled_tile_payload,
            stream_id_of_record=relabeled_tile_payload["stream_id"],
            kind_family_resolver=registered_kind_family_resolver,
        )[0]
        and R.TILE_KINDS
        == {
            "body.tile": "body",
            "memory.tile": "memory",
            "swarm.tile": "swarm",
        }
    ),
)

fan_source_stream = "rappid:@kody/fan-source:" + "a" * 64
fan_memory_stream = fan_source_stream + ":audience"
fan_lens_stream = "rappid:@kody/fan-lens:" + "b" * 64
catch_lens_stream = "rappid:@kody/catch-lens:" + "c" * 64
fan_source = R.build_frame(
    "body.pulse",
    fan_source_stream,
    0,
    "2026-08-31T11:00:00.000Z",
    {"source": "fan-out"},
    prev=None,
)
fan_lens = R.build_lens_frame(
    fan_lens_stream,
    0,
    "2026-08-31T11:00:00.000Z",
    runner="example.fan-out",
    mutation={"operation": "fan-out", "parent_order": "declared"},
    inputs=["context"],
    stochastic_inputs=[],
    facets=["glass-half-full", "glass-half-empty"],
    prev=None,
    sig="sig:" + fan_lens_stream,
)
catch_lens = R.build_lens_frame(
    catch_lens_stream,
    0,
    "2026-08-31T11:00:00.000Z",
    runner="example.dream-catch",
    mutation={"operation": "dream-catch", "parent_order": "dream-catcher"},
    inputs=["context"],
    stochastic_inputs=[],
    facets=["dream-caught"],
    prev=None,
    sig="sig:" + catch_lens_stream,
)
remember(fan_source, fan_source["frame_hash"], [fan_source])
remember(fan_lens, fan_lens["frame_hash"], [fan_lens])
remember(catch_lens, catch_lens["frame_hash"], [catch_lens])
fan_source_ref = R.make_lineage_ref(fan_source, fan_source["frame_hash"])
fan_lens_ref = R.make_lineage_ref(fan_lens, fan_lens["frame_hash"])
catch_lens_ref = R.make_lineage_ref(catch_lens, catch_lens["frame_hash"])


def fan_runner(lens_payload, parent_frames, replay):
    operation = lens_payload["mutation"]["operation"]
    if operation == "fan-out":
        return [
            {
                "audience": "operators",
                "context": replay["inputs"]["context"],
                "source": parent_frames[0]["frame_hash"],
                "status": "review",
            },
            {
                "audience": "public",
                "context": replay["inputs"]["context"],
                "source": parent_frames[0]["frame_hash"],
                "status": "publish",
            },
        ]
    if operation == "dream-catch":
        return [
            {
                "context": replay["inputs"]["context"],
                "parents": [frame["frame_hash"] for frame in parent_frames],
                "outputs": [
                    frame["payload"]["output"] for frame in parent_frames
                ],
            }
        ]
    return lineage_runner(lens_payload, parent_frames, replay)


fan_replay = {"mode": "deterministic", "inputs": {"context": "launch"}}
fan_tile_a = R.build_tile_frame(
    "body.tile",
    fan_source_stream,
    1,
    "2026-08-31T11:00:01.000Z",
    lens=fan_lens_ref,
    parents=[fan_source_ref],
    replay=fan_replay,
    resolver=lineage_resolver,
    runner=fan_runner,
    prev=fan_source["payload_hash"],
    head=fan_source,
    signature_verifier=lineage_signature_verifier,
    tile_index=0,
)
fan_tile_b = R.build_tile_frame(
    "memory.tile",
    fan_memory_stream,
    0,
    "2026-08-31T11:00:01.000Z",
    lens=fan_lens_ref,
    parents=[fan_source_ref],
    replay=fan_replay,
    resolver=lineage_resolver,
    runner=fan_runner,
    prev=None,
    signature_verifier=lineage_signature_verifier,
    tile_index=1,
)
fan_tile_a_ref = R.make_lineage_ref(
    fan_tile_a,
    fan_source["frame_hash"],
)
fan_tile_b_ref = R.make_lineage_ref(
    fan_tile_b,
    fan_tile_b["frame_hash"],
)
remember(
    fan_tile_a,
    fan_source["frame_hash"],
    [fan_source, fan_tile_a],
)
remember(
    fan_tile_b,
    fan_tile_b["frame_hash"],
    [fan_tile_b],
)
check(
    "V11n one fresh marble fans out to ordered sibling facet tiles",
    (
        fan_tile_a["payload"]["crack"]["crack_id"]
        == fan_tile_b["payload"]["crack"]["crack_id"]
        == R.crack_id(fan_lens_ref, [fan_source_ref], fan_replay)
        and fan_tile_a["payload"]["crack"]["facet"] == "glass-half-full"
        and fan_tile_b["payload"]["crack"]["facet"] == "glass-half-empty"
        and fan_tile_a["payload"]["crack"]["tile_index"] == 0
        and fan_tile_b["payload"]["crack"]["tile_index"] == 1
        and fan_tile_a["payload"]["crack"]["tile_count"] == 2
        and fan_tile_b["payload"]["crack"]["tile_count"] == 2
        and fan_tile_a["payload"]["parents"] == [fan_source_ref]
        and fan_tile_b["payload"]["parents"] == [fan_source_ref]
        and fan_tile_a["payload"]["generation"] == 1
        and fan_tile_b["payload"]["generation"] == 1
        and fan_tile_a["prev"] == fan_source["payload_hash"]
        and fan_tile_b["prev"] is None
        and fan_tile_a["frame_hash"] != fan_tile_b["frame_hash"]
    ),
)

alias_stream = "rappid:@kody/fan-alias:" + "d" * 64
duplicate_output_slot = R.build_frame(
    "body.tile",
    alias_stream,
    0,
    "2026-08-31T11:00:01.000Z",
    copy.deepcopy(fan_tile_a["payload"]),
    prev=None,
)


def fan_facet_claim(crack_identifier, tile_index, _frame_hash):
    if (
        crack_identifier == fan_tile_a["payload"]["crack"]["crack_id"]
        and tile_index == 0
    ):
        return fan_tile_a["frame_hash"]
    return None


duplicate_output_ok = R.accept_tile_frame(
    duplicate_output_slot,
    stream_id_of_record=alias_stream,
    resolver=lineage_resolver,
    runner=fan_runner,
    signature_verifier=lineage_signature_verifier,
    facet_claim=fan_facet_claim,
)
wrong_output_slot_payload = copy.deepcopy(fan_tile_a["payload"])
wrong_output_slot_payload["crack"]["tile_index"] = 1
wrong_output_slot_payload["crack"]["facet"] = "glass-half-empty"
wrong_output_slot = R.build_frame(
    "body.tile",
    fan_source_stream,
    1,
    fan_tile_a["utc"],
    wrong_output_slot_payload,
    prev=fan_source["payload_hash"],
)
wrong_output_slot_ok = R.verify_tile_frame(
    wrong_output_slot,
    head=fan_source,
    stream_id_of_record=fan_source_stream,
    resolver=lineage_resolver,
    runner=fan_runner,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11o crack/facet IDs prevent duplicate or substituted sibling slots",
    not duplicate_output_ok[0] and not wrong_output_slot_ok[0],
)

fan_siblings = [
    (fan_tile_a, fan_tile_a_ref),
    (fan_tile_b, fan_tile_b_ref),
]
fan_siblings.sort(key=lambda item: (item[0]["utc"], item[0]["frame_hash"]))
dream_parent_refs = [item[1] for item in fan_siblings]
dream_tile = R.build_tile_frame(
    "body.tile",
    fan_source_stream,
    2,
    "2026-08-31T11:00:02.000Z",
    lens=catch_lens_ref,
    parents=dream_parent_refs,
    replay={"mode": "deterministic", "inputs": {"context": "reconcile"}},
    resolver=lineage_resolver,
    runner=fan_runner,
    prev=fan_tile_a["payload_hash"],
    head=fan_tile_a,
    signature_verifier=lineage_signature_verifier,
)
reversed_dream_payload = copy.deepcopy(dream_tile["payload"])
reversed_dream_payload["parents"] = list(
    reversed(reversed_dream_payload["parents"])
)
reversed_dream_payload["crack"]["crack_id"] = R.crack_id(
    reversed_dream_payload["lens"],
    reversed_dream_payload["parents"],
    reversed_dream_payload["replay"],
)
reversed_dream = R.build_frame(
    "body.tile",
    fan_source_stream,
    2,
    dream_tile["utc"],
    reversed_dream_payload,
    prev=fan_tile_a["payload_hash"],
)
reversed_dream_ok = R.verify_tile_frame(
    reversed_dream,
    head=fan_tile_a,
    stream_id_of_record=fan_source_stream,
    resolver=lineage_resolver,
    runner=fan_runner,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11p Dream-Catcher deterministically fans siblings back into one tile",
    (
        R.verify_tile_frame(
            dream_tile,
            head=fan_tile_a,
            stream_id_of_record=fan_source_stream,
            resolver=lineage_resolver,
            runner=fan_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and dream_tile["payload"]["parents"] == dream_parent_refs
        and set(
            ref["frame_hash"] for ref in dream_tile["payload"]["parents"]
        )
        == {fan_tile_a["frame_hash"], fan_tile_b["frame_hash"]}
        and dream_tile["payload"]["root_sources"] == [fan_source_ref]
        and dream_tile["payload"]["generation"] == 2
        and not reversed_dream_ok[0]
    ),
)

marble_lens_stream = "rappid:@kody/marble-lens:" + "e" * 64
full_environment_stream = "rappid:@kody/full-environment:" + "f" * 64
empty_environment_stream = "rappid:@kody/empty-environment:" + "0" * 64
full_output_stream = "rappid:@kody/full-perspective:" + "1" * 64
empty_output_stream = "rappid:@kody/empty-perspective:" + "2" * 64
marble_lens = R.build_lens_frame(
    marble_lens_stream,
    0,
    "2026-08-31T11:10:00.000Z",
    runner="example.marble-perspective",
    mutation={"operation": "marble-perspective", "parent_order": "declared"},
    inputs=[],
    stochastic_inputs=[],
    facets=["perspective"],
    prev=None,
    sig="sig:" + marble_lens_stream,
)
full_environment = R.build_frame(
    "body.pulse",
    full_environment_stream,
    0,
    "2026-08-31T11:10:00.000Z",
    {"status": "glass-half-full"},
    prev=None,
)
empty_environment = R.build_frame(
    "body.pulse",
    empty_environment_stream,
    0,
    "2026-08-31T11:10:00.000Z",
    {"status": "glass-half-empty"},
    prev=None,
)
marble_source_before = copy.deepcopy(fan_source)
full_environment_before = copy.deepcopy(full_environment)
empty_environment_before = copy.deepcopy(empty_environment)
remember(marble_lens, marble_lens["frame_hash"], [marble_lens])
remember(
    full_environment,
    full_environment["frame_hash"],
    [full_environment],
)
remember(
    empty_environment,
    empty_environment["frame_hash"],
    [empty_environment],
)
marble_lens_ref = R.make_lineage_ref(
    marble_lens,
    marble_lens["frame_hash"],
)
full_environment_ref = R.make_lineage_ref(
    full_environment,
    full_environment["frame_hash"],
)
empty_environment_ref = R.make_lineage_ref(
    empty_environment,
    empty_environment["frame_hash"],
)


def marble_runner(lens_payload, parent_frames, replay):
    if lens_payload["mutation"]["operation"] == "marble-perspective":
        return [
            {
                "marble": parent_frames[0]["frame_hash"],
                "perspective": parent_frames[1]["payload"]["status"],
                "replay": replay["inputs"],
            }
        ]
    return fan_runner(lens_payload, parent_frames, replay)


marble_replay = {"mode": "deterministic", "inputs": {}}
full_perspective_tile = R.build_tile_frame(
    "body.tile",
    full_output_stream,
    0,
    "2026-08-31T11:10:01.000Z",
    lens=marble_lens_ref,
    parents=[fan_source_ref, full_environment_ref],
    replay=marble_replay,
    resolver=lineage_resolver,
    runner=marble_runner,
    prev=None,
    signature_verifier=lineage_signature_verifier,
)
empty_perspective_tile = R.build_tile_frame(
    "body.tile",
    empty_output_stream,
    0,
    "2026-08-31T11:10:01.000Z",
    lens=marble_lens_ref,
    parents=[fan_source_ref, empty_environment_ref],
    replay=marble_replay,
    resolver=lineage_resolver,
    runner=marble_runner,
    prev=None,
    signature_verifier=lineage_signature_verifier,
)
implicit_environment_payload = copy.deepcopy(full_perspective_tile["payload"])
implicit_environment_payload["parents"] = [fan_source_ref]
implicit_environment_payload["root_sources"] = [fan_source_ref]
implicit_environment_payload["crack"]["crack_id"] = R.crack_id(
    implicit_environment_payload["lens"],
    implicit_environment_payload["parents"],
    implicit_environment_payload["replay"],
)
implicit_environment = R.build_frame(
    "body.tile",
    full_output_stream,
    0,
    full_perspective_tile["utc"],
    implicit_environment_payload,
    prev=None,
)
implicit_environment_ok = R.verify_tile_frame(
    implicit_environment,
    stream_id_of_record=full_output_stream,
    resolver=lineage_resolver,
    runner=marble_runner,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11q exact lens plus verified environment determines marble facets",
    (
        full_perspective_tile["payload"]["crack"]["crack_id"]
        != empty_perspective_tile["payload"]["crack"]["crack_id"]
        and full_perspective_tile["payload"]["output"]["perspective"]
        == "glass-half-full"
        and empty_perspective_tile["payload"]["output"]["perspective"]
        == "glass-half-empty"
        and full_perspective_tile["payload"]["generation"] == 1
        and empty_perspective_tile["payload"]["generation"] == 1
        and fan_source == marble_source_before
        and full_environment == full_environment_before
        and empty_environment == empty_environment_before
        and not implicit_environment_ok[0]
    ),
)


def untrusted_lineage_resolver(frame_hash, era):
    return lineage_store[(frame_hash, era)]


def genesis_only_resolver(frame_hash, era):
    return lineage_store[(frame_hash, era)]


genesis_only_resolver.genesis_verifier = registered_genesis_verifier
missing_genesis_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=untrusted_lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    kind_family_resolver=registered_kind_family_resolver,
)
false_genesis_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
    genesis_verifier=lambda _stream_id, _era: False,
    kind_family_resolver=registered_kind_family_resolver,
)
missing_kind_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=genesis_only_resolver,
    runner=lineage_runner,
    signature_verifier=lineage_signature_verifier,
)
wrong_kind_ok = R.verify_clean_frame(
    clean_one,
    stream_id_of_record=lineage_output_stream,
    kind_family_resolver=lambda _kind: "memory",
)
check(
    "V11r semantic acceptance requires exact kind and registered genesis authority",
    (
        not missing_genesis_ok[0]
        and not false_genesis_ok[0]
        and not missing_kind_ok[0]
        and not wrong_kind_ok[0]
        and tile_one_ok[0]
    ),
)

omitted_claim_ok = R.accept_tile_frame(
    fan_tile_a,
    head=fan_source,
    stream_id_of_record=fan_source_stream,
    resolver=lineage_resolver,
    runner=fan_runner,
    signature_verifier=lineage_signature_verifier,
)
idempotent_claim_store = {}
idempotent_claim_lock = threading.Lock()


def atomic_idempotent_claim(crack_identifier, tile_index, frame_hash):
    key = (crack_identifier, tile_index)
    with idempotent_claim_lock:
        idempotent_claim_store.setdefault(key, frame_hash)
        return idempotent_claim_store[key]


idempotent_first = R.accept_tile_frame(
    fan_tile_a,
    head=fan_source,
    stream_id_of_record=fan_source_stream,
    resolver=lineage_resolver,
    runner=fan_runner,
    signature_verifier=lineage_signature_verifier,
    facet_claim=atomic_idempotent_claim,
)
idempotent_second = R.accept_tile_frame(
    fan_tile_a,
    head=fan_source,
    stream_id_of_record=fan_source_stream,
    resolver=lineage_resolver,
    runner=fan_runner,
    signature_verifier=lineage_signature_verifier,
    facet_claim=atomic_idempotent_claim,
)
race_store = {}
race_lock = threading.Lock()
race_barrier = threading.Barrier(2)
race_results = []
race_errors = []


def racing_claim(crack_identifier, tile_index, frame_hash):
    race_barrier.wait(timeout=10)
    key = (crack_identifier, tile_index)
    with race_lock:
        race_store.setdefault(key, frame_hash)
        return race_store[key]


def run_racing_accept(frame, head, stream_id):
    try:
        result = R.accept_tile_frame(
            frame,
            head=head,
            stream_id_of_record=stream_id,
            resolver=lineage_resolver,
            runner=fan_runner,
            signature_verifier=lineage_signature_verifier,
            facet_claim=racing_claim,
        )
        race_results.append(result[0])
    except Exception as exc:
        race_errors.append(str(exc))


race_threads = [
    threading.Thread(
        target=run_racing_accept,
        args=(fan_tile_a, fan_source, fan_source_stream),
    ),
    threading.Thread(
        target=run_racing_accept,
        args=(duplicate_output_slot, None, alias_stream),
    ),
]
for race_thread in race_threads:
    race_thread.start()
for race_thread in race_threads:
    race_thread.join(timeout=15)
check(
    "V11s persisted acceptance requires one atomic idempotent facet claim",
    (
        not omitted_claim_ok[0]
        and idempotent_first[0]
        and idempotent_second[0]
        and sorted(race_results) == [False, True]
        and not race_errors
        and all(not thread.is_alive() for thread in race_threads)
    ),
)

reversed_dream_input = list(reversed(dream_parent_refs))
reversed_dream_input_before = copy.deepcopy(reversed_dream_input)
dream_built_from_reversed = R.build_tile_frame(
    "body.tile",
    fan_source_stream,
    2,
    "2026-08-31T11:00:02.000Z",
    lens=catch_lens_ref,
    parents=reversed_dream_input,
    replay={"mode": "deterministic", "inputs": {"context": "reconcile"}},
    resolver=lineage_resolver,
    runner=fan_runner,
    prev=fan_tile_a["payload_hash"],
    head=fan_tile_a,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11t Dream-Catcher producer normalizes reversed inputs without mutation",
    (
        dream_built_from_reversed == dream_tile
        and reversed_dream_input == reversed_dream_input_before
        and dream_built_from_reversed["payload"]["parents"]
        == dream_parent_refs
    ),
)


def nested_object(depth):
    value = {"leaf": True}
    for _ in range(depth):
        value = {"next": value}
    return value


def nested_container(depth):
    value = {}
    for _ in range(depth - 1):
        value = {"next": value}
    return value


depth64_output = nested_container(62)
depth64_payload = copy.deepcopy(tile_one["payload"])
depth64_payload["output"] = depth64_output
depth64_tile = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    depth64_payload,
    prev=clean_one["payload_hash"],
)
depth65_output = nested_container(63)
depth65_payload = copy.deepcopy(tile_one["payload"])
depth65_payload["output"] = depth65_output
depth65_tile = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    depth65_payload,
    prev=clean_one["payload_hash"],
)
oversized_output = {"blob": "x" * R.MAX_CANONICAL_BYTES}
oversized_tile_payload = copy.deepcopy(tile_one["payload"])
oversized_tile_payload["output"] = oversized_output
oversized_tile = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    oversized_tile_payload,
    prev=clean_one["payload_hash"],
)
deep_output = nested_object(70)
deep_tile_payload = copy.deepcopy(tile_one["payload"])
deep_tile_payload["output"] = deep_output
deep_tile = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    deep_tile_payload,
    prev=clean_one["payload_hash"],
)
deep_replay_payload = copy.deepcopy(tile_one["payload"])
deep_replay_payload["replay"]["inputs"]["label"] = nested_object(70)
deep_replay_tile = R.build_frame(
    "body.tile",
    lineage_output_stream,
    1,
    tile_one["utc"],
    deep_replay_payload,
    prev=clean_one["payload_hash"],
)
deep_lens_payload = copy.deepcopy(lineage_lens["payload"])
deep_lens_payload["mutation"]["environment"] = nested_object(70)
deep_lens = R.build_frame(
    "body.lens",
    lineage_lens_stream,
    0,
    lineage_lens["utc"],
    deep_lens_payload,
    prev=None,
    sig="sig:" + lineage_lens_stream,
)
oversized_build_refused = False
try:
    R.build_tile_frame(
        "body.tile",
        lineage_output_stream,
        1,
        tile_one["utc"],
        lens=lens_ref,
        parents=[clean_one_ref],
        replay=replay_one,
        resolver=lineage_resolver,
        runner=lambda _lens, _parents, _replay: [oversized_output],
        prev=clean_one["payload_hash"],
        head=clean_one,
        signature_verifier=lineage_signature_verifier,
    )
except ValueError:
    oversized_build_refused = True
oversized_lens_build_refused = False
try:
    R.build_lens_frame(
        lineage_lens_stream,
        0,
        lineage_lens["utc"],
        runner="example.oversized",
        mutation={
            "parent_order": "declared",
            "blob": "x" * R.MAX_CANONICAL_BYTES,
        },
        inputs=[],
        stochastic_inputs=[],
        facets=["result"],
        prev=None,
        sig="sig:" + lineage_lens_stream,
    )
except ValueError:
    oversized_lens_build_refused = True
check(
    "V11u depth 64 passes; 65 and oversized lens/tile values refuse",
    (
        R._json_depth(depth64_tile) == 64
        and R.verify_tile_frame(
            depth64_tile,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lambda _lens, _parents, _replay: [depth64_output],
            signature_verifier=lineage_signature_verifier,
        )[0]
        and R._json_depth(depth65_tile) == 65
        and not R.verify_tile_frame(
            depth65_tile,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lambda _lens, _parents, _replay: [depth65_output],
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            oversized_tile,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lambda _lens, _parents, _replay: [oversized_output],
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            deep_tile,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lambda _lens, _parents, _replay: [deep_output],
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            deep_replay_tile,
            head=clean_one,
            stream_id_of_record=lineage_output_stream,
            resolver=lineage_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_lens_frame(
            deep_lens,
            stream_id_of_record=lineage_lens_stream,
            signature_verifier=lineage_signature_verifier,
            kind_family_resolver=registered_kind_family_resolver,
        )[0]
        and oversized_build_refused
        and oversized_lens_build_refused
    ),
)

stress_lens_stream = "rappid:@kody/stress-lens:" + "3" * 64
stress_source_stream = "rappid:@kody/stress-source:" + "4" * 64
stress_lens = R.build_lens_frame(
    stress_lens_stream,
    0,
    "2026-08-31T11:20:00.000Z",
    runner="example.depth",
    mutation={"operation": "depth", "parent_order": "declared"},
    inputs=[],
    stochastic_inputs=[],
    facets=["result"],
    prev=None,
    sig="sig:" + stress_lens_stream,
)
stress_source = R.build_frame(
    "body.pulse",
    stress_source_stream,
    0,
    "2026-08-31T11:20:00.000Z",
    {"source": "stress"},
    prev=None,
)
remember(stress_lens, stress_lens["frame_hash"], [stress_lens])
remember(stress_source, stress_source["frame_hash"], [stress_source])
stress_lens_ref = R.make_lineage_ref(
    stress_lens,
    stress_lens["frame_hash"],
)
stress_root_ref = R.make_lineage_ref(
    stress_source,
    stress_source["frame_hash"],
)
stress_replay = {"mode": "deterministic", "inputs": {}}


def stress_runner(_lens_payload, parent_frames, _replay):
    return [{"parent": parent_frames[0]["frame_hash"]}]


stress_parent_ref = stress_root_ref
stress_target = None
stress_depth = 1200
for stress_generation in range(1, stress_depth + 1):
    stress_stream = (
        f"rappid:@kody/depth-{stress_generation}:"
        f"{stress_generation:064x}"
    )
    stress_payload = {
        "schema": R.TILE_SCHEMA,
        "crack": {
            "crack_id": R.crack_id(
                stress_lens_ref,
                [stress_parent_ref],
                stress_replay,
            ),
            "facet": "result",
            "tile_index": 0,
            "tile_count": 1,
        },
        "lens": copy.deepcopy(stress_lens_ref),
        "parents": [copy.deepcopy(stress_parent_ref)],
        "root_sources": [copy.deepcopy(stress_root_ref)],
        "generation": stress_generation,
        "replay": copy.deepcopy(stress_replay),
        "output": {"parent": stress_parent_ref["frame_hash"]},
    }
    stress_target = R.build_frame(
        "body.tile",
        stress_stream,
        0,
        "2026-08-31T11:20:01.000Z",
        stress_payload,
        prev=None,
    )
    remember(
        stress_target,
        stress_target["frame_hash"],
        [stress_target],
    )
    stress_parent_ref = R.make_lineage_ref(
        stress_target,
        stress_target["frame_hash"],
    )
stress_ok = R.verify_tile_frame(
    stress_target,
    stream_id_of_record=stress_target["stream_id"],
    resolver=lineage_resolver,
    runner=stress_runner,
    signature_verifier=lineage_signature_verifier,
)
check(
    "V11v iterative DFS verifies 1200 worn generations without recursion",
    stress_ok[0] and stress_target["payload"]["generation"] == stress_depth,
)

signature_lens_before = copy.deepcopy(lineage_lens)


def mutating_signature_verifier(unsigned, sig, expected_signer):
    unsigned["payload"]["mutation"]["operation"] = "callback-mutation"
    unsigned["payload"]["inputs"].append("injected")
    return lineage_signature_verifier(unsigned, sig, expected_signer)


signature_mutation_ok = R.verify_lens_frame(
    lineage_lens,
    stream_id_of_record=lineage_lens_stream,
    signature_verifier=mutating_signature_verifier,
    kind_family_resolver=registered_kind_family_resolver,
)
signature_preimage = {
    key: lineage_lens[key]
    for key in lineage_lens
    if key not in ("frame_hash", "sig")
}
check(
    "V11w signature callbacks cannot mutate verified lens/frame bytes",
    (
        signature_mutation_ok[0]
        and lineage_lens == signature_lens_before
        and lineage_lens["payload_hash"]
        == R.H("rapp/1:particle", lineage_lens["payload"])
        and lineage_lens["frame_hash"]
        == R.H("rapp/1:wave", signature_preimage)
    ),
)


def lineage_with_intermediate(intermediate_kind, suffix):
    stream = (
        f"rappid:@kody/{suffix}:"
        + hashlib.sha256(suffix.encode()).hexdigest()
    )
    genesis = R.build_frame(
        "body.pulse",
        stream,
        0,
        "2026-08-31T11:30:00.000Z",
        {"stage": "genesis"},
        prev=None,
    )
    intermediate = R.build_frame(
        intermediate_kind,
        stream,
        1,
        "2026-08-31T11:30:01.000Z",
        {"stage": "intermediate"},
        prev=genesis["payload_hash"],
    )
    target = R.build_frame(
        "body.pulse",
        stream,
        2,
        "2026-08-31T11:30:02.000Z",
        {"stage": "target"},
        prev=intermediate["payload_hash"],
    )
    accepted_geneses.add((stream, genesis["frame_hash"]))
    return genesis, intermediate, target


unregistered_chain = lineage_with_intermediate(
    "body.unknown",
    "unregistered-chain",
)
wrong_family_chain = lineage_with_intermediate(
    "memory.save",
    "wrong-family-chain",
)
bad_chain_records = {}
for chain_frames in (unregistered_chain, wrong_family_chain):
    target = chain_frames[-1]
    era = chain_frames[0]["frame_hash"]
    bad_chain_records[(target["frame_hash"], era)] = {
        "frames": list(chain_frames),
        "persisted": True,
        "invocation_id": None,
    }


def bad_chain_resolver(frame_hash, era):
    if (frame_hash, era) in bad_chain_records:
        return bad_chain_records[(frame_hash, era)]
    return lineage_resolver(frame_hash, era)


equip_semantic_resolver(bad_chain_resolver)


def tile_for_bad_chain(chain_frames, suffix):
    target = chain_frames[-1]
    parent_ref = R.make_lineage_ref(
        target,
        chain_frames[0]["frame_hash"],
    )
    payload = {
        "schema": R.TILE_SCHEMA,
        "crack": {
            "crack_id": R.crack_id(lens_ref, [parent_ref], replay_one),
            "facet": "result",
            "tile_index": 0,
            "tile_count": 1,
        },
        "lens": copy.deepcopy(lens_ref),
        "parents": [copy.deepcopy(parent_ref)],
        "root_sources": [copy.deepcopy(parent_ref)],
        "generation": 1,
        "replay": copy.deepcopy(replay_one),
        "output": lineage_runner(
            lineage_lens["payload"],
            [target],
            replay_one,
        )[0],
    }
    return R.build_frame(
        "body.tile",
        (
            f"rappid:@kody/{suffix}:"
            + hashlib.sha256(suffix.encode()).hexdigest()
        ),
        0,
        "2026-08-31T11:30:03.000Z",
        payload,
        prev=None,
    )


unregistered_chain_tile = tile_for_bad_chain(
    unregistered_chain,
    "unregistered-output",
)
wrong_family_chain_tile = tile_for_bad_chain(
    wrong_family_chain,
    "wrong-family-output",
)
check(
    "V11x every resolved era-chain frame requires registered kind/family",
    (
        not R.verify_tile_frame(
            unregistered_chain_tile,
            stream_id_of_record=unregistered_chain_tile["stream_id"],
            resolver=bad_chain_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
        and not R.verify_tile_frame(
            wrong_family_chain_tile,
            stream_id_of_record=wrong_family_chain_tile["stream_id"],
            resolver=bad_chain_resolver,
            runner=lineage_runner,
            signature_verifier=lineage_signature_verifier,
        )[0]
    ),
)

non_string_key_refused = False
try:
    R.canonical({1: "x"})
except ValueError:
    non_string_key_refused = True
malformed_runner_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lambda _lens, _parents, _replay: [{1: "x"}],
    signature_verifier=lineage_signature_verifier,
)
malformed_runner_build_refused = False
try:
    R.build_tile_frame(
        "body.tile",
        lineage_output_stream,
        1,
        tile_one["utc"],
        lens=lens_ref,
        parents=[clean_one_ref],
        replay=replay_one,
        resolver=lineage_resolver,
        runner=lambda _lens, _parents, _replay: [{1: "x"}],
        prev=clean_one["payload_hash"],
        head=clean_one,
        signature_verifier=lineage_signature_verifier,
    )
except ValueError:
    malformed_runner_build_refused = True
check(
    "V11y non-string JSON keys are controlled runner/build refusals",
    (
        non_string_key_refused
        and not malformed_runner_ok[0]
        and malformed_runner_build_refused
    ),
)

cyclic_dict = {}
cyclic_dict["self"] = cyclic_dict
cyclic_list = []
cyclic_list.append(cyclic_list)
cyclic_dict_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lambda _lens, _parents, _replay: [cyclic_dict],
    signature_verifier=lineage_signature_verifier,
)
cyclic_list_ok = R.verify_tile_frame(
    tile_one,
    head=clean_one,
    stream_id_of_record=lineage_output_stream,
    resolver=lineage_resolver,
    runner=lambda _lens, _parents, _replay: [{"cycle": cyclic_list}],
    signature_verifier=lineage_signature_verifier,
)
cyclic_build_refused = False
try:
    R.build_tile_frame(
        "body.tile",
        lineage_output_stream,
        1,
        tile_one["utc"],
        lens=lens_ref,
        parents=[clean_one_ref],
        replay=replay_one,
        resolver=lineage_resolver,
        runner=lambda _lens, _parents, _replay: [cyclic_dict],
        prev=clean_one["payload_hash"],
        head=clean_one,
        signature_verifier=lineage_signature_verifier,
    )
except ValueError:
    cyclic_build_refused = True
check(
    "V11z cyclic dict/list runner outputs terminate with controlled refusal",
    not cyclic_dict_ok[0] and not cyclic_list_ok[0] and cyclic_build_refused,
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
