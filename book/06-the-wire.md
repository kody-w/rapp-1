---
layout: book
title: The Wire
book_label: Chapter 6
book_progress: 52
description: Carry RAPP through one synchronous endpoint and append-only frames
---

[← Chapter 5: The Frame](05-the-frame.md) · [Book contents](README.md) ·
[Chapter 7: The Egg →](07-the-egg.md)

# Chapter 6 — The Wire: `POST /chat`

> **In this chapter:** use the one synchronous endpoint, understand the asynchronous frame form,
> make retries idempotent, and keep local, cloud, and managed tiers on the same request shape.

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
  "idempotency_key": "<optional>",
  "conversation_history": [ {"role": "...", "content": "..."} ] }
```

The response:

```
200 OK
{ "response": "<assistant text>", "agent_logs": ["<what fired>"], "session_id": "<id>" }
```

That is the whole contract for talking to a RAPP brainstem. There is exactly one required input
key — `user_input`. Unknown request members are ignored for forward compatibility. A successful
response has exactly the three shown members; producers do not grow private success envelopes.

The brainstem loads its `soul.md` as the system prompt, discovers its agents, and decides via
tool-calling which of them run. New capability is a new agent file dropped into `agents/`, not a
new route: the synchronous wire does not grow.

## 6.2 Errors Are Typed, Not Prose

A protocol you can rely on fails in named ways. RAPP §8 specifies HTTP 422 with one exact shape
for malformed input, an unknown session, or a protocol refusal:

```json
{
  "error": {
    "code": "unknown-session",
    "step": null
  }
}
```

`code` is registered in the estate registry. `step` is null or one of the frame verification
steps `"1"`, `"1a"`, `"2"`, `"3"`, `"4"`, `"5"`, `"6"`. Authentication challenges exposed by
a particular host are deployment behavior; they must not create a second successful chat shape.

An error that is only a human sentence is a dead end for the program on the other side; a typed
error is a branch it can take.

## 6.3 Idempotency

Agents retry. Networks drop responses after the work was done. A request may carry an
`idempotency_key`, and replaying the same key returns the original response rather than appending a
second turn. With a `session_id`, the key is scoped to that session; without one, the key also
deduplicates session creation.

Content addressing makes duplicate work visible, but the idempotency key preserves the full
request result — including the session identifier and response — when a caller cannot know whether
the first response was lost before or after execution.

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
managed studio — and all three speak the identical `POST /chat` with the identical `user_input`
shape. Moving from your laptop to the cloud is a change of `RAPP_BRAINSTEM_URL`, not a change of
protocol. This is the deepest reason the wire is kept to one endpoint: the moment there are two
doors, the tiers drift apart. One door, every tier, is what lets the same client drive all of
them.

## 6.7 Checkpoint: One Request, One Shape

Against a running brainstem:

```bash
curl -sS http://localhost:7071/chat \
  -H 'content-type: application/json' \
  -d '{
    "user_input": "Describe your loaded capabilities in one sentence.",
    "idempotency_key": "book-ch6-001"
  }'
```

Repeat the exact request. A conformant implementation returns the original result instead of
creating a duplicate turn. Then send `{ "messages": [] }`: the server should return a typed 422,
not guess that `messages` meant `user_input`.

## 6.8 Chapter Summary

- RAPP has one synchronous endpoint, `POST /chat`, and one asynchronous form, the §7 frame.
- Only `user_input` is required; successful responses have exactly three members.
- Protocol failures use registered error codes and optional verification-step identifiers.
- Idempotency covers both ordinary turns and session creation.
- Biography and swarm streams use the same frame with different wave/signature rules.
- Deployment tiers change the URL, not the protocol shape.

The wire carries frames between living agents. To hand over a whole organism — identity, soul,
code, and state — we need a larger content-addressed unit.

---

[← Chapter 5: The Frame](05-the-frame.md) · [Book contents](README.md) ·
[Chapter 7: The Egg →](07-the-egg.md)
