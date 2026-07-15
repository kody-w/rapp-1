# Chapter 4 — Frames: Build and Verify

A genesis is the first moment of a life; a **frame** is every moment after. This chapter uses the
SDK's `frame` and `verify` actions to build records and check them, and shows the particle/wave
duality the SDK computes for you on every frame.

## 4.1 Building a frame

The `frame` action builds an eleven-field frame for a stream. Give it the stream's full rappid, a
`kind` (`noun.verb`), a `payload`, and a timestamp:

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A, json
rid = json.loads(A.RappSdkBuilderAgent().perform(action="mint", id="@me/diary"))["rappid"]
out = A.RappSdkBuilderAgent().perform(
    action="frame", id=rid, kind="diary.entry",
    utc="2026-07-15T09:00:00.000Z", payload={"woke": True})
print(out)
PY
```

```json
{
  "status": "ok", "action": "frame",
  "frame": { "spec": "rapp/1", "kind": "diary.entry", "stream_id": "rappid:@me/diary:…",
             "seq": 0, "utc": "2026-07-15T09:00:00.000Z", "payload": {"woke": true},
             "payload_hash": "…", "frame_hash": "…", "prev": null, "prev_wave": null, "sig": null },
  "verified_as_genesis": true,
  "particle": "…",   "wave": "…"
}
```

The response hands back two addresses, and names them: the **particle** (`payload_hash`, the
address of *what happened*) and the **wave** (`frame_hash`, the address of *this exact record*). The
SDK computes both on every frame — you never choose between them, you receive both. When you later
chain frames, each one's `prev` will point to the previous frame's **particle**; that is the
worldline.

## 4.2 Verifying a frame

Never trust a frame's own hash fields — recompute them. The `verify` action runs the full §7.5
checklist and tells you the exact step if anything is wrong:

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A, json
frame = json.loads(A.RappSdkBuilderAgent().perform(action="scaffold", id="@me/x"))["files"]["frames/0.json"]
print(A.RappSdkBuilderAgent().perform(action="verify", frame=frame))
PY
```

```json
{"status": "ok", "action": "verify", "valid": true, "failing_step": null, "reason": "ok"}
```

Now watch it catch a forgery. Tamper with the payload and the particle no longer matches:

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A, json
frame = json.loads(A.RappSdkBuilderAgent().perform(action="scaffold", id="@me/x"))["files"]["frames/0.json"]
frame["payload"] = {"born": "tampered"}       # rewrite history, leave the hash stale
print(A.RappSdkBuilderAgent().perform(action="verify", frame=frame))
PY
```

```json
{"status": "ok", "action": "verify", "valid": false, "failing_step": "2", "reason": "payload_hash mismatch"}
```

`failing_step: "2"` — the particle check. Every rejection the SDK gives you is *explainable*: not
"invalid," but "step 2: payload_hash mismatch." That is what makes the protocol debuggable. (Recall
from the reference book that a smart attacker who recomputes the particle then trips step 3, the
wave; and one who recomputes both trips step 4, the chain link — you have to beat all three, and
then every later frame too.)

## 4.3 Say it to the brainstem

```
curl -s -X POST http://localhost:7071/chat -H 'Content-Type: application/json' \
 -d '{"user_input": "Use RappSdkBuilder to verify this frame and tell me if it is valid and which step fails if not: {\"spec\":\"rapp/1\", ... }"}'
```

The brainstem routes it to `perform(action="verify", frame={…})` and reports back the boolean and
the failing step. In practice you rarely paste a raw frame — you let the agent both build and verify
in one flow, which is exactly what `scaffold` and the growth loop in chapter 7 do.

## 4.4 What the SDK will not let you do

The SDK builds frames through `build_frame`, which always emits exactly the eleven keys and always
computes the particle before the wave. There is no code path that produces a ten-field frame, an
extra ad-hoc key, or a stale hash. As with identity, the invalid shape is unreachable — the SDK's
job is to make "correct RAPP" the only thing you *can* build.
