"""02 — A worldline. Chain frames into an append-only biography and verify it end to end.

Each frame's `prev` is the previous frame's PARTICLE (payload_hash). That single
link makes the chain tamper-evident: change any past payload and every later `prev`
stops matching. Run: python3 examples/02_build_a_chain.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rapp as R

stream = R.mint_rappid("kody", "diary")
events = [
    ("2026-07-15T09:00:00.000Z", {"woke": True}),
    ("2026-07-15T09:30:00.000Z", {"coffee": 1}),
    ("2026-07-15T18:00:00.000Z", {"shipped": "rapp/1"}),
]

chain, head = [], None
for seq, (utc, payload) in enumerate(events):
    prev = head["payload_hash"] if head else None
    fr = R.build_frame("diary.entry", stream, seq, utc, payload, prev=prev)
    ok, step, why = R.verify_frame(fr, head=head, stream_id_of_record=stream)
    assert ok, f"frame {seq} failed at {step}: {why}"
    chain.append(fr); head = fr
    print(f"seq {seq}: {payload}  →  particle {fr['payload_hash'][:12]}…  ✓")

print(f"\nverified a {len(chain)}-frame worldline for {stream}")

# Now tamper with the past. A naive edit is caught immediately at the frame itself:
chain[0]["payload"]["woke"] = False
ok, step, why = R.verify_frame(chain[0], head=None, stream_id_of_record=stream)
print("\nnaive edit of frame 0's payload → frame 0 verify:",
      "OK (bad!)" if ok else f"REJECTED at step {step} — {why}  ✓")

# A *smart* attacker recomputes frame 0's payload_hash to make frame 0 self-verify —
# but that new particle no longer matches frame 1's `prev`, so the CHAIN rejects it.
chain[0]["payload_hash"] = R.H("rapp/1:particle", chain[0]["payload"])
ok, step, why = R.verify_frame(chain[0], head=None, stream_id_of_record=stream)
print("attacker fixes frame 0's hash   → frame 0 verify:", "OK" if ok else why)
ok, step, why = R.verify_frame(chain[1], head=chain[0], stream_id_of_record=stream)
print("…but the chain link at frame 1  → verify:",
      "OK (bad!)" if ok else f"REJECTED at step {step} — {why}  ✓")
