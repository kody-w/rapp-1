# Chapter 2 — Dropping In the SDK Builder

Here is the moment that makes the brainstem feel alive: you copy one file into a directory, and a
running server gains a new skill with no restart. This chapter does exactly that and proves the
brainstem picked it up.

## 2.1 Install the file

Fetch the agent straight from the public standard repo into your brainstem's `agents/` directory
(the path you noted from `/health` in chapter 1):

```
curl -sSL https://raw.githubusercontent.com/kody-w/rapp-1/main/agents/rapp_sdk_builder_agent.py \
  -o ~/.brainstem/src/rapp_brainstem/agents/rapp_sdk_builder_agent.py
```

That is the whole install. No `pip install`, no config, no restart. The agent has zero third-party
dependencies — it embeds the RAPP primitives — so there is nothing else to resolve.

## 2.2 Watch the brainstem discover it

Call `/health` again:

```
curl -s http://localhost:7071/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['agents']); print('quarantined:', d['quarantined'])"
```

```
['ContextMemory', 'HackerNews', 'ManageMemory', 'RappAgent', 'RappSdkBuilder', 'Twin', 'Recall']
quarantined: []
```

`RappSdkBuilder` has joined the roster, and `quarantined` is empty — the brainstem loaded it
cleanly. This is real output from a real running brainstem; the agent was discovered the instant
the file landed.

## 2.3 What the brainstem saw

The brainstem's auto-discovery looks for a class extending `BasicAgent` in any `agents/*_agent.py`
file. Our agent gives it three things:

```python
__manifest__ = {                       # 1. the registry card — schema, name, tags, example call
    "schema": "rapp-agent/1.0",
    "name": "@rapp/sdk_builder",
    "display_name": "RAPP SDK Builder",
    ...
}

class RappSdkBuilderAgent(BasicAgent):  # 2. the class the brainstem instantiates
    def __init__(self):
        self.name = "RappSdkBuilder"
        self.metadata = { "name": self.name, "description": "...", "parameters": { ... } }
        super().__init__(name=self.name, metadata=self.metadata)

    def perform(self, **kwargs):        # 3. what runs when the model calls the tool
        ...
```

- **`__manifest__`** is the agent's public card — how a registry lists it. It does not affect
  loading, but it is how the agent describes itself to the ecosystem.
- **`metadata.parameters`** is a JSON Schema. The brainstem turns it into the tool definition the
  model sees, so the model knows the agent takes an `action` (one of `mint`, `scaffold`, `frame`,
  `verify`, `canonicalize`, `check`, `sync`) plus fields like `id`, `payload`, `repo`. Good
  parameter descriptions here are what let plain English route correctly.
- **`perform(**kwargs)`** is the body. It returns a **string** (we return JSON strings), which the
  brainstem feeds back to the model to compose your answer.

## 2.4 The safety net that makes it droppable anywhere

Notice the top of the file:

```python
try:
    from agents.basic_agent import BasicAgent      # inside a brainstem
except Exception:
    class BasicAgent:                              # standalone fallback shim
        ...
```

Inside a brainstem, the agent inherits the real `BasicAgent`. Dropped somewhere with no brainstem
— a script, a notebook, a CI job — it falls back to a tiny built-in shim so it *still runs*. That
is why the same file is both "a brainstem agent" and "an importable SDK." You will use both faces
in this book.

## 2.5 A first, honest proof

Before we drive it through the model, prove the code itself works by running the file directly —
this uses the standalone shim, no brainstem involved:

```
python3 ~/.brainstem/src/rapp_brainstem/agents/rapp_sdk_builder_agent.py
```

```
mint     : {"status": "ok", "action": "mint", "rappid": "rappid:@me/notes:d768dfcb…", "valid": true, …}
scaffold : { "status": "ok", "action": "scaffold", "verified": true, … } …
canon    : {"status": "ok", "action": "canonicalize", "canonical": "{\"a\":[3,2],\"b\":1}", "particle": "d1edcfc5…", …}
verify   : {"status": "ok", "action": "verify", "valid": true, "failing_step": null, "reason": "ok"}
```

Four operations, all green: it minted a valid rappid, scaffolded a verified organism seed,
canonicalized a value into its content address, and verified a frame. The engine works. Now let's
learn each capability — and then hand the wheel to the brainstem.
