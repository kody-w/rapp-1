# Chapter 8 — Extending the Agent, and Reference

You have used every action the SDK Builder ships with. This last chapter shows how to add your own,
and collects the action reference you will keep open while building.

## 8.1 Adding an action

The agent dispatches on an `action` string in `perform`. Adding a capability is three small edits,
all in the one file:

1. **Add the action to the enum** in `metadata.parameters` so the model knows it exists:

   ```python
   "action": { "type": "string",
     "enum": ["mint", "scaffold", "frame", "verify", "canonicalize", "check", "sync", "egg"], … }
   ```

2. **Route it** in `perform`:

   ```python
   if action == "egg":
       return self._egg(kwargs)
   ```

3. **Implement it**, returning a JSON string. For example, an `egg` action that content-addresses
   an organism seed's manifest:

   ```python
   def _egg(self, kw):
       manifest = kw.get("payload") or {}
       return json.dumps({"status": "ok", "action": "egg",
                          "egg_manifest": H("rapp/1:egg-manifest", manifest)})
   ```

Drop the edited file back into `agents/`, call `/health`, and the brainstem rediscovers it — the new
verb is instantly drivable by conversation. That is the whole extension model: the SDK grows the
same way the brainstem does, by editing one file.

## 8.2 Keep it honest

Two disciplines carried from how this SDK itself was built:

- **Verify your verifier.** When you add a `check`-style judgment, run it against *real* artifacts
  and have someone (or something) adversarial try to make it green when it should be red. This SDK's
  compliance check shipped with a blind spot that only a hostile pass against live repos exposed.
- **Prove provenance.** If you embed protocol logic, add (or keep) a `sync`-style action that binds
  your copy to the public standard and can prove parity. A component that cannot demonstrate it
  speaks the real protocol is exactly the drift RAPP exists to end.

## 8.3 Action reference

Every action takes an `action` string plus the fields below. All return a JSON string.

| action | fields | does |
|--------|--------|------|
| `mint` | `id` (`@owner/slug`) | mint a keyless compliant rappid (§6.2) |
| `scaffold` | `id`, `utc?` | mint identity **and** build+verify a genesis frame → a ready-to-plant seed (`rappid.json` + `frames/0.json`) |
| `frame` | `id` (full rappid), `kind`, `payload`, `utc?`, `seq?`, `prev?` | build an eleven-field frame; returns it with its particle + wave |
| `verify` | `frame` (object) | run the §7.5 checklist; returns `valid` + `failing_step` + `reason` |
| `canonicalize` | `value` (any I-JSON) | canonical bytes + addresses in the `particle`/`wave`/`egg-manifest` spaces |
| `check` | `repo` (`owner/name` or URL) | fetch the repo's `rappid.json` and verdict `CLEAN`/`COMPLIANT`/`DRIFT` with §-cited findings |
| `sync` | — | fetch the public reference impl and prove the embedded SDK computes identical addresses |

### Install

```
curl -sSL https://raw.githubusercontent.com/kody-w/rapp-1/main/agents/rapp_sdk_builder_agent.py \
  -o ~/.brainstem/src/rapp_brainstem/agents/rapp_sdk_builder_agent.py
```

### Drive (any action, by conversation)

```
curl -s -X POST http://localhost:7071/chat -H 'Content-Type: application/json' \
  -d '{"user_input": "Use RappSdkBuilder to <what you want>"}'
```

### Run standalone (no brainstem)

```
python3 rapp_sdk_builder_agent.py            # self-test: mint · scaffold · canonicalize · verify
python3 -c "import rapp_sdk_builder_agent as A; print(A.RappSdkBuilderAgent().perform(action='sync'))"
```

## 8.4 Where to go next

- The **reference book** (`book/`) — the RAPP protocol in prose, front to back.
- The **visual guide** (`guide/`) — the same protocol in pictures.
- `SPEC.md` — the normative standard, when you need the exact letter.
- `rapp.py` — the reference implementation the SDK embeds; read it, it is ~140 lines.

You now hold the whole loop: a grail brainstem, an SDK that makes correct RAPP the only thing you
can build, and the ability to drive it all by talking. Go plant something.
