"""05 — Verify a physical RAPPID Calling Card without a private envelope.

The physical payload is a non-secret URI. Its `.rappid-card.json` resource is an
ordinary eleven-key frame. The manifest particle, Ed25519 JWS, signed runtime policy,
signed issuer authorization, signed revocation view, approved endpoint origin, observed
fetch trace, and durable SQLite nonce state all verify before hydration can reach awake.

Run: python3 examples/05_rappid_card.py
"""
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import rapp as R


VECTOR_DIR = os.path.join(ROOT, "vectors", "rappid-card")
with open(os.path.join(VECTOR_DIR, "deck.json"), encoding="utf-8") as handle:
    deck = json.load(handle)
with open(os.path.join(VECTOR_DIR, "physical.rappid-card.json"), "rb") as handle:
    frame = R.read_card_resource(handle.read())
with open(os.path.join(VECTOR_DIR, "physical-payload.txt"), encoding="utf-8") as handle:
    physical_payload = handle.read().strip()

fixture = next(vector for vector in deck["vectors"] if vector["physical"])
assert frame == fixture["frame"]
assert physical_payload == fixture["link"]

link = R.parse_card_link(physical_payload)
assert physical_payload == R.build_card_link(
    frame, link["endpoint"], link["nonce"])
assert link["manifest_hash"] == frame["payload_hash"]
assert frame["payload_hash"] == R.H("rapp/1:particle", frame["payload"])
assert set(frame) == R.FRAME_KEYS

parts = {
    name: base64.b64decode(octets)
    for name, octets in deck["parts_b64"].items()
}
keys = {
    entry["kid"]: base64.b64decode(entry["spki_der_b64"])
    for entry in deck["trust"]
}
trust = R.CardTrustStore(keys, fixture["runtime_policy_authority"])
state_path = os.path.join(ROOT, "examples", ".rappid-card-example.sqlite")


def remove_state():
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(state_path + suffix)
        except FileNotFoundError:
            pass


remove_state()
try:
    state = R.SQLiteCardState(state_path)
    ok, step, reason, result = R.verify_card_link(
        physical_payload,
        frame,
        trust,
        fixture["now_utc"],
        fixture["runtime_policy"],
        fixture["authority_view"],
        fixture["revocation_view"],
        state,
        fixture["connection_id"],
        fixture["fetch_trace"],
        parts,
        fixture["continuity"],
    )
    assert ok, f"physical card refused at {step}: {reason}"
    assert state.nonce_state(link["nonce"])["state"] == "awake"

    print("physical payload reproduced:", physical_payload)
    print("resource is one frame       :", len(frame), "keys ·", frame["kind"])
    print("manifest particle matches   :", link["manifest_hash"])
    print("endpoint origin authorized  :", frame["payload"]["endpoint_origin"])
    authorization = next(
        entry for entry in fixture["authority_view"]["authorizations"]
        if entry["issuer_key_id"] == frame["payload"]["key_id"])
    print("issuer authorization        :", authorization["role"],
          authorization["not_before_utc"], "→", authorization["not_after_utc"])
    print("signed registry sequences   :", result["authority_seq"],
          result["revocation_seq"])
    print("hydration inventory         :", ", ".join(
        entry["part"] for entry in frame["payload"]["inventory"]))
    print("verification result         :", result["status"], result["rappid"])

    replay = R.verify_card_link(
        physical_payload,
        frame,
        trust,
        fixture["now_utc"],
        fixture["runtime_policy"],
        fixture["authority_view"],
        fixture["revocation_view"],
        R.SQLiteCardState(state_path),
        fixture["connection_id"],
        fixture["fetch_trace"],
        parts,
        fixture["continuity"],
    )
    assert not replay[0] and replay[1] == "replay-nonce"
    print("same nonce after restart    :", f"refused at {replay[1]} ({replay[2]})")

    production_refusal = next(
        vector for vector in deck["vectors"]
        if vector["name"] == "test-profile-production")
    production_trust = R.CardTrustStore(
        keys, production_refusal["runtime_policy_authority"])
    production_path = state_path + ".production"
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(production_path + suffix)
        except FileNotFoundError:
            pass
    refused = R.verify_card_link(
        production_refusal["link"],
        production_refusal["frame"],
        production_trust,
        production_refusal["now_utc"],
        production_refusal["runtime_policy"],
        production_refusal["authority_view"],
        production_refusal["revocation_view"],
        R.SQLiteCardState(production_path),
        production_refusal["connection_id"],
        production_refusal["fetch_trace"],
        parts,
        production_refusal["continuity"],
    )
    assert not refused[0] and refused[1] == "signature"
    print("debug card under prod policy:", f"refused at {refused[1]} ({refused[2]})")
finally:
    remove_state()
    for suffix in (".production", ".production-wal", ".production-shm"):
        try:
            os.remove(state_path + suffix)
        except FileNotFoundError:
            pass
