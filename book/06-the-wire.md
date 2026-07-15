# Chapter 6 — The Wire: `POST /chat`

Frames are the record; the wire is how they move and how agents actually talk. RAPP keeps the
wire deliberately small — one endpoint. "Engine, not experience" means there is one door, and
everything an agent can do enters through it.

## 6.1 One Endpoint

```
POST /chat
Content-Type: application/json

{ "user_input": "<plain-language request>", "session_id": "<optional>",
  "conversation_history": [ {"role": "...", "content": "..."} ] }
```

The response:

```
200 OK
{ "response": "<assistant text>", "agent_logs": "<what fired>", "session_id": "<id>" }
```

That is the whole contract for talking to a RAPP brainstem. There is exactly one required input
key — `user_input` — and sending the wrong key (`messages` instead of `user_input`) is the single
most common integration mistake; the server answers it with a clear `422`, not a guess. The
brainstem loads its `soul.md` as the system prompt, discovers its agents, and decides via
tool-calling which of them run. New capability is a new agent file dropped into `agents/`, not a
new route: the wire does not grow.

## 6.2 Errors Are Typed, Not Prose

A protocol you can rely on fails in named ways. RAPP §8 specifies structured errors — HTTP
status plus a machine-readable reason — so that a caller can branch on the failure:

- `422 Unprocessable` — the request shape was wrong (missing `user_input`, malformed history).
- `401 Unauthorized` — the brainstem needs a token (the Copilot device-code flow on first use).
- Frame-bearing endpoints reject a non-conforming frame with the failing **verify step** from
  chapter 5, so "why did you reject my frame?" always has the answer "step *N*: *reason*."

An error that is only a human sentence is a dead end for the program on the other side; a typed
error is a branch it can take.

## 6.3 Idempotency

Agents retry. Networks drop responses after the work was done. So any frame-appending operation
carries an idempotency key, and replaying the same key returns the same result rather than
appending twice. Because a frame is content-addressed, this is natural: the same intended frame
has the same particle, and the server can recognize "I have already appended this" by address.
Idempotency is not an add-on here; it falls out of content addressing.

## 6.4 Two Kinds of Stream

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

## 6.5 Tiers Are the Same Shape

The brainstem runs locally (a Flask server on `localhost:7071`), on a cloud endpoint, or behind a
managed studio — and all three speak the identical `POST /chat` with the identical `user_input`
shape. Moving from your laptop to the cloud is a change of `RAPP_BRAINSTEM_URL`, not a change of
protocol. This is the deepest reason the wire is kept to one endpoint: the moment there are two
doors, the tiers drift apart. One door, every tier, is what lets the same client drive all of
them.

The wire carries frames between living agents. But an agent also has to be *born*, and *moved* as
a whole — its soul, its agents, its memory, its identity, packed into one thing you can hand to
someone. That thing is the egg.
