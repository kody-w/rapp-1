# Chapter 1 — The Grail Brainstem

A **brainstem** is the RAPP engine: a Flask server that loads `soul.md` as its system prompt,
auto-discovers Python agents from `agents/*_agent.py`, and calls the model with tool-calling so
your plain-English request reaches the right agent. A **grail brainstem** is the canonical
installation of that engine — the reference build the installer produces, the one every other
tier mirrors. This chapter stands one up and confirms it is healthy, because everything else in
the book runs against it.

## 1.1 Installing

One command clones the canonical installer into `~/.brainstem`, builds a Python 3.11 virtualenv,
installs requirements, and starts the engine on port 7071:

```
curl -sSfL https://raw.githubusercontent.com/kody-w/rapp-installer/main/install.sh | bash
```

On first use the brainstem triggers the GitHub Copilot device-code login — that is how it reaches
the model. Follow the prompt once and it remembers.

## 1.2 The health check

The brainstem answers a single, honest health endpoint. Get in the habit of calling it before you
do anything else:

```
curl -s http://localhost:7071/health
```

```json
{
  "status": "ok",
  "version": "0.6.16",
  "agents": ["ContextMemory", "HackerNews", "ManageMemory", "RappAgent", "Twin", "Recall"],
  "brainstem_dir": "/Users/you/.brainstem/src/rapp_brainstem",
  "quarantined": [],
  "soul": ".../soul.md",
  "model": "gpt-5.4"
}
```

Read this output like an instrument panel:

- **`status: ok`** — the engine is up.
- **`agents`** — the agents it discovered this boot. Right now it is the built-ins; by the end of
  chapter 2 you will see `RappSdkBuilder` join this list.
- **`quarantined`** — agents it found but *refused to load* (an import error, a bad manifest). An
  empty list is what you want. If your agent ever fails to appear in `agents`, look here first.
- **`brainstem_dir`** — where the engine lives. Its `agents/` subdirectory is where you drop new
  skills. Note this path; you will use it in chapter 2.

## 1.3 The one door

Everything you ask the brainstem goes through one endpoint — `POST /chat`:

```
curl -s -X POST http://localhost:7071/chat \
  -H 'Content-Type: application/json' \
  -d '{"user_input": "who are you?"}'
```

```json
{ "response": "…", "agent_logs": "…", "session_id": "…" }
```

Three things come back. **`response`** is the assistant's text — what you show a human.
**`agent_logs`** records which agents fired and what they returned — this is your window into the
machinery, and we will read it constantly to *prove* the SDK agent actually ran rather than the
model merely describing what it would do. **`session_id`** threads a multi-turn conversation; pass
it back (with `conversation_history`) to keep memory coherent.

One required key: `user_input`. The single most common integration mistake is sending `messages`
instead — the brainstem answers that with a clear error rather than a guess.

## 1.4 Why one door matters for building

You never add a REST route to teach the brainstem something new. You add an **agent**. The wire
stays exactly one endpoint; capability grows behind it. That is precisely why the SDK Builder can
be a single dropped-in file and still become fully drivable by conversation: it plugs into the
tool-calling behind the one door, and the door does not change. Local, cloud, or studio — same
door, same `user_input` shape — so what you learn here against `localhost:7071` is identical to
driving a brainstem in the cloud; only the URL differs.

With a healthy grail brainstem in front of you and its `agents/` directory located, you are ready
to give it a new skill. That is one `cp` away.
