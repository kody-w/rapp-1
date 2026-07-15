# Chapter 5 — Content Addressing, and Proving Provenance

Under identity and frames sits the machinery that makes them trustworthy: canonicalization and
domain-separated hashing. This chapter uses the SDK's `canonicalize` action to see that machinery
directly, and the `sync` action to prove — not assume — that this agent computes the *real* RAPP
addresses.

## 5.1 Canonicalize and address a value

The `canonicalize` action turns any I-JSON value into its one canonical byte string and its
addresses in the RAPP hash spaces:

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A
print(A.RappSdkBuilderAgent().perform(action="canonicalize", value={"b": 1, "a": [3, 2]}))
PY
```

```json
{"status": "ok", "action": "canonicalize",
 "canonical": "{\"a\":[3,2],\"b\":1}",
 "particle":     "d1edcfc5b6d3d3b7556d286476d0ea41c2433e28acc553726b89012c3d4bdada",
 "wave_of_value":"8299b84bce7843bfcb517ec3ee3a5e42e086c7449201bc948dbe59c68351e45f",
 "egg_manifest": "5d494828b8760c6c27e02d297ecbbdc93074b6974be8063ce6dc15376031995f"}
```

Two lessons in one output:

- **Canonicalization erased key order.** You passed `{"b":1,"a":[3,2]}`; the canonical form is
  `{"a":[3,2],"b":1}` — keys sorted, no whitespace. Anyone, in any language, canonicalizes this
  value to those exact bytes. That is why the hash is portable.
- **The same value has three different addresses.** `particle`, `wave_of_value`, and `egg_manifest`
  are all SHA-256 of the *same* canonical bytes — but each in a different **domain space**
  (`rapp/1:particle`, `rapp/1:wave`, `rapp/1:egg-manifest`). Domain separation makes a payload
  address, a frame address, and an egg address structurally incapable of colliding, even on
  identical bytes.

## 5.2 The `sync` action: provenance you can check

The SDK embeds the RAPP primitives so it runs offline. Fair question: is the embedded copy the
*real* thing, or a drifted fork? Do not trust — verify. The `sync` action fetches the canonical
reference implementation from the public standard repo and hashes a known vector through *both*:

```
python3 - <<'PY'
import rapp_sdk_builder_agent as A
print(A.RappSdkBuilderAgent().perform(action="sync"))
PY
```

```json
{"status": "ok", "action": "sync",
 "embedded_matches_public_reference": true,
 "source": "https://raw.githubusercontent.com/kody-w/rapp-1/main/rapp.py",
 "vector_particle": "d1edcfc5b6d3d3b7556d286476d0ea41c2433e28acc553726b89012c3d4bdada",
 "note": "Same vector hashed through the embedded and the freshly-fetched reference implementation; equal ⇒ this agent computes canonical RAPP addresses."}
```

`embedded_matches_public_reference: true`. The agent just downloaded the live `rapp.py`, executed
it, and confirmed its own embedded `H("rapp/1:particle", …)` produces the *identical* address. This
is the SDK-builder's answer to the whole disease this ecosystem fought: a component that does not
merely *claim* to speak RAPP but *demonstrates*, against the public source of truth, that it
computes the same bytes. If a future edit ever drifted the embedded copy, `sync` would go `false`
and you would know.

## 5.3 This is the builder "building from the public repos"

Notice what `sync` really is: the agent reaching across the network to the **publicly deployed**
standard and binding itself to it. The same move powers `check` (next chapter), which fetches a
repo's real `rappid.json` from `raw.githubusercontent.com` and lints it. The SDK Builder is not a
static copy of a spec frozen at authoring time — it is a client of the live, public RAPP, able to
prove its own fidelity and to measure the stack against the standard as the standard actually
exists today.

## 5.4 Say it to the brainstem

```
curl -s -X POST http://localhost:7071/chat -H 'Content-Type: application/json' \
 -d '{"user_input": "Ask RappSdkBuilder to sync and confirm its embedded RAPP implementation matches the public reference."}'
```

The brainstem calls `perform(action="sync")` and reports the match. It is a satisfying thing to be
able to *ask* your engine, in English, "are you still speaking the real protocol?" — and get a
computed, honest yes.
