"""05 — Verify a physical RAPPID Calling Card payload without a private envelope.

The physical payload is only a compact, non-secret URI. Its `m` parameter addresses a
signed manifest served through the virtual `.rappid-card.json` extension. That resource
is an ordinary eleven-key `rapp/1` frame: the manifest is `payload`, its address is
`payload_hash`, and the existing `sig` member is a detached Ed25519 JWS.

This example reproduces the committed physical fixture, hydrates only its signed
inventory, answers the one-time continuity challenge, and reaches `awake`. It then
shows that the same nonce cannot be replayed and that the visibly synthetic debug
profile is refused in production mode.

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
trust = {
    entry["kid"]: {
        "spki_der": base64.b64decode(entry["spki_der_b64"]),
        "synthetic": entry["synthetic"],
    }
    for entry in deck["trust"]
}
revocations = {frame["payload"]["revocation_url"]: fixture["revoked"]}
replay = R.CardReplayCache()

ok, step, reason, result = R.verify_card_link(
    physical_payload,
    frame,
    trust,
    fixture["now_utc"],
    revocations,
    fixture["environment"],
    replay,
    fixture["connection_id"],
    parts,
    fixture["continuity"],
    mode="test",
)
assert ok, f"physical card refused at {step}: {reason}"

print("physical payload reproduced:", physical_payload)
print("resource is one frame       :", len(frame), "keys ·", frame["kind"])
print("manifest particle matches   :", link["manifest_hash"])
print("signed hydration inventory  :", ", ".join(
    entry["part"] for entry in frame["payload"]["inventory"]))
print("verification result         :", result["status"], result["rappid"])

ok, step, reason, _ = R.verify_card_link(
    physical_payload,
    frame,
    trust,
    fixture["now_utc"],
    revocations,
    fixture["environment"],
    replay,
    fixture["connection_id"],
    parts,
    fixture["continuity"],
    mode="test",
)
assert not ok and step == "replay-nonce"
print("same nonce presented twice  :", f"refused at {step} ({reason})")

ok, step, reason, _ = R.verify_card_link(
    physical_payload,
    frame,
    trust,
    fixture["now_utc"],
    revocations,
    fixture["environment"],
    R.CardReplayCache(),
    "production-connection",
    parts,
    fixture["continuity"],
    mode="production",
)
assert not ok and step == "schema"
print("debug card in production    :", f"refused at {step} ({reason})")
