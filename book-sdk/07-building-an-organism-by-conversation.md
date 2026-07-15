# Chapter 7 — Building an Organism by Conversation

This is the payoff. Everything so far was a capability; here we chain them into the real thing —
minting, planting, and *growing* a RAPP organism, mostly by talking to the brainstem. By the end
you have a living door with a verifiable worldline that anyone can check.

## 7.1 Birth

Ask the brainstem to scaffold the organism:

> **You:** Use RappSdkBuilder to scaffold a new RAPP organism `@me/scratch`, then give me the rappid and confirm the genesis verified.

> **Brainstem:** Done. Minted rappid `rappid:@me/scratch:b07586ea…`. Genesis frame verified: yes.

(That is the real exchange from chapter 3.) You now hold two files — `rappid.json` and
`frames/0.json` — a born organism, its genesis already passing §7.5.

## 7.2 Planting

Commit the seed to a repo so the organism is addressable on the public web:

```
mkdir scratch && cd scratch && git init && mkdir frames
#   write rappid.json (root) and frames/0.json from the scaffold output
git add . && git commit -m "plant @me/scratch — RAPP genesis" && git push
```

Your organism is live. `raw.githubusercontent.com/you/scratch/main/rappid.json` and `frames/0.json`
resolve, and anyone can verify the genesis.

## 7.3 Growth — appending a verifiable worldline

A life is a chain of frames, each linking to the previous one's particle. Here is the growth loop
using the SDK directly (the brainstem drives the same calls when you ask it to "record an entry"):

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A, json

sdk = A.RappSdkBuilderAgent()
rid = "rappid:@me/scratch:b07586ea…"          # your organism's rappid

# rebuild head = genesis (in practice you load frames/<n>.json)
head = json.loads(sdk.perform(action="scaffold", id="@me/scratch"))["files"]["frames/0.json"]

events = [
    ("2026-07-15T09:30:00.000Z", {"coffee": 1}),
    ("2026-07-15T18:00:00.000Z", {"shipped": "my first organism"}),
]
chain = [head]
for i, (utc, payload) in enumerate(events, start=1):
    # build the next frame linking to head's particle
    import rapp_sdk_builder_agent as M
    fr = M.build_frame("scratch.entry", head["stream_id"], i, utc, payload, prev=head["payload_hash"])
    ok, step, why = M.verify_frame(fr, head=head, stream_id_of_record=head["stream_id"])
    assert ok, f"frame {i} failed at {step}: {why}"
    chain.append(fr); head = fr
    print(f"seq {i}: {payload}  →  particle {fr['payload_hash'][:12]}…  ✓ (verified against head)")

print(f"grew a {len(chain)}-frame worldline")
PY
```

```
seq 1: {'coffee': 1}       →  particle 8c69295600b9…  ✓ (verified against head)
seq 2: {'shipped': 'my first organism'}  →  particle 946e70fff991…  ✓ (verified against head)
grew a 3-frame worldline
```

Each new frame is verified **against the head** before it is kept — seq contiguous, `prev` equal to
the head's particle, time not running backward. Commit each `frames/<n>.json`, and your organism's
biography grows, tamper-evident, one verifiable moment at a time.

## 7.4 Doing it by conversation

You do not have to write that loop. Because the SDK is a brainstem agent, you can teach *growth* as
a conversation. A brainstem with the SDK Builder plus a small "append an entry to my organism"
habit lets you say:

> **You:** Record in my scratch organism that I shipped my first organism today.

and the brainstem loads the head, calls the SDK to build and verify the next frame, and commits it.
The protocol recedes; what remains is you telling your engine what happened, and your engine keeping
an honest, verifiable memory of it. That is the entire point of RAPP: a medium where an agent's life
is written down in a form anyone can trust — reached, now, by talking.

## 7.5 What you built

Step back and count what a single dropped-in file gave you:

- a **compliant identity**, minted the one lawful way,
- a **planted organism** anyone can fetch and verify,
- a **growing worldline** where every frame is checked against the last,
- and a **conversational interface** to all of it, because the SDK rode the brainstem's one door.

You did not implement RAPP. You *used* it — correctly, by construction, and out loud.
