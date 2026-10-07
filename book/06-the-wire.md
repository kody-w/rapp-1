---
layout: book
title: The Wire
book_label: Chapter 6
book_progress: 52
book_order: 60
description: Carry RAPP through one synchronous endpoint and append-only frames
---

[← Chapter 5: The Frame](05-the-frame.md) · [Book contents](README.md) ·
[Chapter 7: The Egg →](07-the-egg.md)

# Chapter 6 — The Wire: `POST /chat`

> **In this chapter:** use the one synchronous endpoint, understand the asynchronous frame form,
> test it against the pinned Grail, and keep local, cloud, and managed tiers on one contract.

Frames are the record; the wire is how they move and how agents actually talk. RAPP keeps the
wire deliberately small: one synchronous endpoint and one asynchronous artifact form. “Engine,
not experience” means capabilities grow behind the door or as registered frame kinds, never by
inventing another envelope.

## 6.1 One Endpoint

```
POST /chat
Content-Type: application/json

{ "user_input": "<plain-language request>",
  "session_id": "<optional>",
  "conversation_history": [ {"role": "...", "content": "..."} ] }
```

The response:

```
200 OK
{ "response": "<assistant text>", "agent_logs": "<what fired>", "session_id": "<id>" }
```

That is the whole contract for talking to a RAPP brainstem. There is exactly one required input
key — `user_input`; an empty or whitespace-only value counts as missing. History entries have a
`role` of `user`, `assistant`, or `tool` and string `content`. Unknown request members are ignored
for forward compatibility. A successful response has at least the three shown members.
`agent_logs` is one newline-separated string, empty when no agent ran. The Grail also returns
`model`, `requested_model`, and `voice_mode`; consumers ignore members they do not recognize.

The brainstem loads its `soul.md` as the system prompt, discovers its agents, and decides via
tool-calling which of them run. New capability is a new agent file dropped into `agents/`, not a
new route: the synchronous wire does not grow.

## 6.2 Malformed Requests Use One Refusal Shape

A malformed request is HTTP 400 with exactly one `error` string:

```json
{
  "error": "<human-readable message>"
}
```

The status and member set are fixed. The text is useful to a human, but it is not frozen: a Grail
bug-fix release may reword it. A cross-version probe therefore compares the status and member set;
`--same-version` also compares the exact text.

Frame verification refusals remain the §7.5 checklist's concern. They are not tunneled through a
special `/chat` error envelope.

## 6.3 The Grail Is the Executable Reference

The pinned Grail is the reference for the synchronous wire. The shared suite in
`conformance/grail/` defines 25 scenarios once: successful model turns, tool calls, validation
order, health, version, and not-found behavior. A port must match the oracle's status, members, and
contract values.

Fourteen scenarios never reach the model. They form the live hub-join probe. The full suite also
compares a proposed Grail release or an in-process implementation against the same fake model.

## 6.4 The Asynchronous Form

The second wire form is an append-only §7 frame published to a stream: a repository path, an event
log, or another transport that preserves the exact frame value. The transport is not allowed to
reparent, rename, or “upgrade” the frame in flight. Consumers verify it against the stream of
record and current trusted head.

Within that form there are two stream disciplines.

## 6.5 Two Kinds of Stream

The `stream_id` of chapter 5 tells you which wire discipline applies:

- **Biography streams** are addressed by a **rappid** (`rappid:@owner/slug:64hex`). They are one
  agent's worldline. `prev_wave` is null; integrity is the particle chain; a signature is
  optional for a keyless organism.
- **Swarm streams** are addressed by a **`net:` id** (e.g. `net:commons`) — a shared space many
  actors append to, like the Commons where brainstems introduce themselves. Here `prev_wave`
  chains the *waves* (whole frames), and every frame **MUST** be signed (chapter 5, step 6),
  because in a shared stream you cannot trust the envelope of a frame you did not write. The
  reference `verify_frame` enforces exactly this split: it demands `prev_wave` on `net:` streams
  past genesis and refuses an unsigned swarm frame (vector V9).

The same frame object serves both; only the discipline around it differs, and the `stream_id`
prefix declares which discipline is in force.

## 6.6 Tiers Are the Same Shape

The brainstem runs locally (a Flask server on `localhost:7071`), on a cloud endpoint, or behind a
managed studio — and all three speak the same `POST /chat` contract with the same `user_input`
shape and required response members. Moving from your laptop to the cloud is a change of
`RAPP_BRAINSTEM_URL`, not a change of protocol. This is the deepest reason the wire is kept to one
endpoint: the moment there are two doors, the tiers drift apart. One door, every tier, is what lets
the same client drive all of them.

## 6.7 Checkpoint: One Request, One Shape

Against a running brainstem:

```bash
curl -sS http://localhost:7071/chat \
  -H 'content-type: application/json' \
  -d '{
    "user_input": "Describe your loaded capabilities in one sentence."
  }'
```

Require the three core response members and ignore any others. Then send `{ "messages": [] }`: the
server should return HTTP 400 with exactly one `error` string, not guess that `messages` meant
`user_input`.

## 6.8 Exercises

**Exercise 6-1.** Send missing, empty, and wrong-typed `user_input` values to a test server. Record
the HTTP status and member set. Repeat against another Grail bug-fix version and note whether only
the human-readable text changed.

**Exercise 6-2.** Run the 14-scenario HTTP hub-join probe against a live test node. Read
`conformance/grail/report.json` and prove no model scenario ran. *A selected solution appears in
Appendix C.*

**Exercise 6-3.** Write a client that requires `response`, `agent_logs`, and `session_id`, checks
their types, and ignores additional response members.

**Exercise 6-4.** Build an asynchronous reader that receives a frame and a path-of-record stream
identifier separately. Prove a valid genesis replayed under another path fails at 1a.

## 6.9 Chapter Summary

- RAPP has one synchronous endpoint, `POST /chat`, and one asynchronous form, the §7 frame.
- Only `user_input` is required; successful responses have three required members and may add more.
- Malformed requests use HTTP 400 with exactly one human-readable `error` string.
- The 25-scenario Grail suite is the executable wire reference; 14 scenarios need no model.
- Biography and swarm streams use the same frame with different wave/signature rules.
- Deployment tiers change the URL, not the protocol shape.

The wire carries frames between living agents. To hand over a whole organism — identity, soul,
code, and state — we need a larger content-addressed unit.

---

[← Chapter 5: The Frame](05-the-frame.md) · [Book contents](README.md) ·
[Chapter 7: The Egg →](07-the-egg.md)
