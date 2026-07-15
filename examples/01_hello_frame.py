"""01 — Hello, frame. The smallest complete RAPP program.

Mint one genesis frame, then verify it. If verify returns ok, you have produced
a byte-for-byte content-addressed record that any other RAPP implementation on
earth will accept. Run: python3 examples/01_hello_frame.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R

# A stream is identified by a rappid. Mint one (keyless: a UUID-anchored join key).
stream = R.mint_rappid("kody", "hello")
print("stream id:", stream)

# Build the genesis frame (seq 0, no parent). The payload is any I-JSON object.
frame = R.build_frame(
    kind="note.write",
    stream_id=stream,
    seq=0,
    utc="2026-07-15T12:00:00.000Z",
    payload={"text": "hello, frame"},
    prev=None,
)
print(json.dumps(frame, indent=2))

ok, step, why = R.verify_frame(frame, head=None, stream_id_of_record=stream)
print("\nverify:", "OK" if ok else f"FAILED at {step}: {why}")
print("particle (payload address):", frame["payload_hash"][:16], "…")
print("wave (whole-frame address):", frame["frame_hash"][:16], "…")
