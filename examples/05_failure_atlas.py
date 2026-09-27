"""05 — Failure atlas. Make each frame verification layer reject once.

Each case starts from a fresh frame so one mutation cannot hide another. The
expected step is asserted, turning the book's failure table into executable
documentation. Run: python3 examples/05_failure_atlas.py
"""
import base64
from copy import deepcopy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rapp as R


SID = "rappid:@reader/failure-atlas:" + "a" * 64
UTC = "2026-08-20T12:00:00.000Z"


def refusal(name, frame, expected_step, *, head=None, stream_id=SID):
    ok, step, why = R.verify_frame(
        frame, head=head, stream_id_of_record=stream_id)
    assert not ok and step == expected_step, (name, ok, step, why)
    print(f"{name:18} -> step {step}: {why}")


base = R.build_frame("note.write", SID, 0, UTC, {"text": "hello"}, prev=None)
ok, step, why = R.verify_frame(base, head=None, stream_id_of_record=SID)
assert ok, (step, why)

missing = deepcopy(base)
del missing["prev_wave"]
refusal("missing key", missing, "1")

refusal(
    "cross-stream replay",
    deepcopy(base),
    "1a",
    stream_id="rappid:@reader/other:" + "b" * 64,
)

payload_edit = deepcopy(base)
payload_edit["payload"]["text"] = "changed"
refusal("payload edit", payload_edit, "2")

envelope_edit = deepcopy(base)
envelope_edit["utc"] = "2026-08-20T12:00:01.000Z"
refusal("envelope edit", envelope_edit, "3")

not_genesis = R.build_frame(
    "note.write", SID, 1, UTC, {"text": "seq one"}, prev=base["payload_hash"])
refusal("bad genesis", not_genesis, "4")

# A producer refuses to emit the next two frames, so each starts valid and is then forged.
wrong_wire = R.build_frame(
    "note.write", SID, 0, UTC, {"text": "wave where null"}, prev=None)
wrong_wire["prev_wave"] = "f" * 64
wrong_wire["frame_hash"] = R.H(          # re-hash, so the wire (not the wave) is what fails
    "rapp/1:wave",
    {k: v for k, v in wrong_wire.items() if k not in ("frame_hash", "sig")},
)
refusal("wrong wire link", wrong_wire, "5")

# A well-formed §10 detached JWS; frame_hash excludes sig, so removing it breaks no hash.
SWARM_SIG = (
    base64.urlsafe_b64encode(
        R.canonical({"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": "rappid:@reader/swarm-signer:" + "c" * 64}).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    + ".."
    + base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
)
unsigned_swarm = R.build_frame(
    "swarm.echo", "net:commons", 0, UTC, {"text": "unsigned"}, prev=None,
    sig=SWARM_SIG)
unsigned_swarm["sig"] = None
refusal(
    "unsigned swarm",
    unsigned_swarm,
    "6",
    stream_id="net:commons",
)

print("all seven refusal locations observed")
