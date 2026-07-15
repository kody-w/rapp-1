# Chapter 3 — Identity: Mint and Scaffold

Everything an organism does hangs off one thing that must be right: its identity. This chapter uses
the SDK to mint a compliant `rappid` and to **scaffold** a whole ready-to-plant organism seed — and
it shows you why the SDK will never hand you a broken identity.

## 3.1 Minting a rappid

The `mint` action mints a keyless rappid — the everyday case for an organism that holds no keypair:

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A
print(A.RappSdkBuilderAgent().perform(action="mint", id="@me/notes"))
PY
```

```json
{"status": "ok", "action": "mint",
 "rappid": "rappid:@me/notes:d768dfcb8cb2b5e8df746e2917b1c2c3640f94e1805c70c000c87380603b1bd2",
 "valid": true,
 "note": "keyless mint (§6.2): tail = Hb('rapp/1:rappid', uuid4)"}
```

Look at what you got: `rappid:@me/notes:` followed by a **64-hex** tail minted from fresh entropy
through the domain-tagged construction `Hb("rapp/1:rappid", uuid4)`. The SDK cannot produce a
name-hash — the forbidden `sha256("me/notes")` that collides for everyone who ever names something
`me/notes`. It mints from randomness, tags the hash space, and validates the grammar before
returning (`valid: true`). Identity done right is not something you remember to do; the SDK makes
the wrong thing unreachable.

## 3.2 Scaffolding a whole organism

Minting an id is step one. The `scaffold` action does the rest — it hands you a complete,
verifiable organism seed:

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A, json
print(A.RappSdkBuilderAgent().perform(action="scaffold", id="@me/scratch"))
PY
```

```json
{
  "status": "ok", "action": "scaffold", "verified": true, "verify_step": null,
  "files": {
    "rappid.json": {
      "schema": "rapp/1",
      "rappid": "rappid:@me/scratch:b07586ea…",
      "kind": "organism", "name": "scratch", "parent_rappid": null,
      "frames": "frames/index.json"
    },
    "frames/0.json": {
      "spec": "rapp/1", "kind": "organism.genesis",
      "stream_id": "rappid:@me/scratch:b07586ea…", "seq": 0,
      "utc": "2026-07-15T00:00:00.000Z",
      "payload": { "born": { "owner": "me", "slug": "scratch" } },
      "payload_hash": "…", "frame_hash": "…", "prev": null, "prev_wave": null, "sig": null
    }
  },
  "note": "A ready-to-plant RAPP organism seed. Commit rappid.json + frames/0.json; the genesis passes §7.5 verify."
}
```

Two files, and they are everything a RAPP organism needs to exist:

- **`rappid.json`** — the identity record, already `schema: "rapp/1"`, with a compliant rappid and
  a null `parent_rappid` (this organism has no parent; a child would carry its parent's rappid
  here).
- **`frames/0.json`** — the **genesis frame** of its worldline, in the full eleven-field form,
  seq 0, `prev: null`, with its particle and wave already computed.

And crucially: `"verified": true`. The SDK did not just build the genesis — it ran the §7.5 verify
checklist against it before handing it to you. You are not trusting the scaffold; you are receiving
a frame that already passed the same check any stranger will run.

## 3.3 Planting it

To turn the seed into a live organism, commit the two files to a GitHub repo:

```
mkdir scratch && cd scratch && git init
#   write rappid.json  and  frames/0.json  from the scaffold output
mkdir frames   #   put frames/0.json here
git add . && git commit -m "plant @me/scratch — RAPP organism genesis"
git push
```

That is a planted organism. Anyone can now fetch your `rappid.json` and `frames/0.json` from
`raw.githubusercontent.com`, verify the genesis themselves, and address you by your rappid. In
chapter 7 we will grow this worldline; for now you have a born, verifiable organism.

## 3.4 Now say it to the brainstem

Everything above was a direct call. The same capability is one sentence to your brainstem:

```
curl -s -X POST http://localhost:7071/chat -H 'Content-Type: application/json' \
 -d '{"user_input": "Use the RappSdkBuilder agent to scaffold a new RAPP organism with id @me/scratch, then tell me the minted rappid and whether its genesis frame verified."}'
```

Real response from the running brainstem:

```
RESPONSE:
Done.
- Minted rappid: rappid:@me/scratch:b07586ea16db76bada0989adb765f0cce28e92089d7af019e5aef5abd87f4689
- Genesis frame verified: yes
I used the RappSdkBuilder scaffold action, and it returned a valid organism seed with verified: true.

AGENT_LOGS: [RappSdkBuilder] { "status": "ok", "action": "scaffold", "verified": true, … }
```

Read the `agent_logs` line: `[RappSdkBuilder]` with the real scaffold JSON. That is proof the model
did not *describe* minting an identity — it *called the agent*, which minted and verified for real.
The plain English "scaffold a new RAPP organism" routed, through the tool schema, to
`perform(action="scaffold", id="@me/scratch")`. This is the whole promise of the SDK-as-agent: the
protocol becomes something you *talk* your brainstem into doing, correctly, every time.
