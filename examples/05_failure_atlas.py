"""05 — Failure atlas. Make each frame verification layer reject once.

Each case starts from a fresh frame so one mutation cannot hide another. The
expected step is asserted, turning the book's failure table into executable
documentation. Run: python3 examples/05_failure_atlas.py
"""
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

wrong_wire = R.build_frame(
    "note.write", SID, 0, UTC, {"text": "wave where null"}, prev=None,
    prev_wave="f" * 64,
)
refusal("wrong wire link", wrong_wire, "5")

unsigned_swarm = R.build_frame(
    "swarm.echo", "net:commons", 0, UTC, {"text": "unsigned"}, prev=None)
refusal(
    "unsigned swarm",
    unsigned_swarm,
    "6",
    stream_id="net:commons",
)

print("all seven refusal locations observed")
