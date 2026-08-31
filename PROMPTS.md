# The RAPP Prompt Book — you never type code

RAPP is driven by conversation. Every task in this repository is a prompt you copy and
paste; the machine types, you watch. There are two machines you can hand a prompt to:

- **Your brainsurgeon** — an agentic coding CLI (Claude Code, GitHub Copilot CLI, or any
  AI that can run commands). It clones, runs, and narrates while you watch.
- **Your brainstem** — your local RAPP engine (`POST /chat`, plain English). Once the SDK
  Builder agent is installed (one prompt below), the brainstem speaks RAPP natively.

Each prompt states what you should expect to see, so you always know whether it worked.
A red result is a finding, not something to patch around.

---

## 1 · Prove the spec to me (start here)

Paste into your brainsurgeon:

```text
You are my hands — I watch, you type. Clone https://github.com/kody-w/rapp-1 and prove
RAPP to me end to end: (1) run python3 conformance.py — I expect 49/49 PASS; (2) run
python3 anchor/materialize_spec.py --check SPEC.md and show that the checked-in view
matches the verified specification-chain head; (3) run python3 realcheck.py — the spec
against the live public estate — and explain the verdict in plain English; (4) run
python3 examples/01_hello_frame.py and walk me through the frame it built, one line per
key. Narrate as you go, show real output, and stop on any red result — a red check is a
finding, not something to patch around.
```

**Expect:** `49 controlled checks | 49 PASS | 0 FAIL`, a JSON revision identity
for the byte-exact materialized chain head, an estate verdict with zero drift
findings, and an 11-key frame explained.

## 2 · Build me a verifiable chain

```text
In my clone of https://github.com/kody-w/rapp-1 (clone it if I don't have one), run
python3 examples/02_build_a_chain.py, then explain how each frame's prev links to the
head's payload_hash and why tampering with any payload breaks every later link. Then
prove it: tamper with one payload in memory, re-verify, and show me exactly which
verification step (§7.5) refuses and why.
```

**Expect:** a green chain, then a deliberate refusal at step 2 or 4 with the reason.

## 2.1 · Resolve a protocol revision by its durable identity

```text
In my clone of https://github.com/kody-w/rapp-1, read anchor/README.md and use
anchor/materialize_spec.py to verify the full DOGG specification chain. Show me
the head frame hash and payload hash, resolve that same revision by head, rev
label, seq, frame hash, and payload hash, and prove every lookup materializes
byte-identical SPEC.md. Explain why the frame hash is the durable revision
identity, orient.json is only a beacon, and the Atom feed and mutable main URLs
are discovery only. Separate hash-proven integrity from authority: until an
authenticated checkpoint exists, owner-ratified acceptance onto protected
canonical main selects the chain. Do not claim the unsigned chain is
authenticated.
```

**Expect:** five lookups resolving one verified frame and one byte-identical
normative Markdown file.

## 2.2 · Crack a fresh frame through two lens generations

```text
In my clone of https://github.com/kody-w/rapp-1, read SPEC.md §7.7 and use only
the stdlib helpers in rapp.py. Build one verified fresh body.pulse at generation
0 and one signed body.lens. Run crack(frame, lens) without changing the fresh
frame's bytes; append its output as tile/worn body.tile frame T1 at generation
1. Crack T1 through the lens and append next-generation tile/worn frame T2 at
generation 2. Show the ordered input-frame parents and generation-0
root_sources, prove frame.prev still names the actual stream predecessor
payload_hash rather than a crack input, and replay both persisted tile payloads
byte-identically with an injected runner/resolver. Then attempt to omit T1,
lower generation, substitute the lens, add provenance_class, and use a
transient candidate for an actionable result; show each controlled §7.7
refusal.
```

**Expect:** fresh frame (0) → crack → append tile/worn T1 (1) → crack T1 →
append next tile/worn T2 (2), with all earlier frame bytes unchanged, roots preserved,
deterministic replay green, and every laundering or transient-side-effect
attempt refused.

## 2.3 · Fan one fresh frame out and Dream-Catch it back in

```text
Using SPEC.md §7.7.4 and rapp.py, crack one fresh generation-0 frame into two
generation-1 sibling facet tiles as ordered outputs of one exact lens
invocation. Show their shared crack.crack_id, signed facet names, distinct
tile_index values, common tile_count, exact
common parent, and independent frame.prev stream links. Prove this is lineage
fan-out, not a RAPP stream fork. Persist both siblings, then use a signed
Dream-Catcher lens to consume them as an unordered cross-stream input vector
sorted by (utc, frame_hash). Emit one generation-2 tile that retains both exact
parent references and the cumulative root-source union. Reverse the inputs and
reuse an occupied output slot to show deterministic-order and duplicate-slot
refusals.
```

**Expect:** one fresh frame → two distinct sibling worn frames → one
Dream-Caught next-generation tile, with no parent identity or history lost.

## 2.4 · Prove the marble environment is explicit

```text
Treat one fresh frame as marble. Crack it through the same signed lens twice:
once with a verified glass-half-full environment frame and once with a
verified glass-half-empty environment frame. Show that exact parent references
produce different crack.crack_id values and different facet tiles while the
marble and environment frame bytes remain unchanged. Repeat using an explicit
declared replay status parameter. Then omit the environment/status entirely
and show §7.7 refusing the persisted tile rather than consulting ambient
process state, globals, environment variables, files, clocks, or network data.
```

**Expect:** exact lens + exact recorded environment determines the facet;
ambient environment never does.

## 2.5 · Prove hardened tile acceptance

```text
Run the rev-15 V11 hardening vectors. Show that a rapp-tile/1 payload relabeled
under a non-tile kind cannot contribute generation 0; lineage resolution fails
without the exact registered (stream_id, era) genesis and kind-family binding;
stateless verification cannot stand in for persisted acceptance; and persisted
acceptance requires one atomic idempotent (crack_id, tile_index) claim. Race two
different frames for one facet slot and show exactly one winner. Build the same
Dream-Catcher tile from forward and reversed caller inputs and prove identical
normalized bytes without caller mutation. Finally refuse >1 MiB/depth-64 lens,
replay, frame, and runner outputs, then verify a 1200-generation lineage without
using recursive traversal. Also prove a malicious signature callback cannot
mutate nested frame payloads, every intermediate era-chain kind/family is
checked, depth 64 passes while 65 fails, and runner output with a non-string
object key is a controlled refusal. Return a self-referential dict and list
from the runner and prove both terminate promptly with controlled non-I-JSON
refusals rather than hanging traversal.
```

**Expect:** laundering, false genesis authority, omitted/racing claims,
noncanonical stored order, oversize, and excessive nesting are refused; deep
valid lineage remains green.

## 3 · Mint my identity the lawful way

```text
Using the reference implementation in my clone of https://github.com/kody-w/rapp-1,
mint a keyless rappid for @me/notes with rapp.py's mint_rappid, show me the result, and
explain why RAPP forbids hashing a NAME into an identity (the cardinal sin) — then
demonstrate the sin: compute what a name-hash identity would look like, and show me why
two people choosing the same name would collide.
```

**Expect:** a `rappid:@me/notes:<64 hex>` that is different every mint, and a collision
demonstration.

## 4 · Pack and verify an egg

```text
In my clone of https://github.com/kody-w/rapp-1, run python3 examples/06_pack_an_egg.py,
then show me: the egg's manifest, its one content address, and proof that packing the
same files twice gives byte-identical eggs. Then corrupt one packed file in memory and
show me verify_egg refusing with the exact failing step.
```

**Expect:** byte-identical eggs across two packs, then a §5 content-hash refusal.

## 4.1 · Seal restricted bytecode for a public mirror

```text
Read RAPP/1 SPEC.md §9.2.1 and package my compiled artifact as a `sealed`
rapp/1-egg. Use a fresh random 256-bit DEK and 12-byte AES-GCM nonce, bind the
canonical sealed descriptor as AAD, require a signed manifest, and publish only
ciphertext plus the manifest. Pin any GitHub Raw URL to a commit SHA. Do not put
the DEK, password, master key, plaintext, or raw entitlement token in the egg,
URL, logs, or source. Use the existing POST /chat wire for a scoped key-service
organism to return only a recipient-wrapped DEK. Prove the egg passes
verify_egg, then mutate ciphertext length, AAD hash, and add a plaintext file
and show each is refused.
```

**Expect:** a signed `variant:"sealed"` egg whose public bytes contain only
`ciphertext.bin`, followed by three deliberate §9.2 refusals.

## 5 · Install the RAPP toolkit into my brainstem

```text
Install the RAPP SDK Builder agent into my local brainstem: download
https://raw.githubusercontent.com/kody-w/rapp-1/main/agents/rapp_sdk_builder_agent.py
into my brainstem's agents/ directory (~/.brainstem/src/rapp_brainstem/agents/ on a
standard install — find the right one), no restart needed. Then verify the install two
ways: (1) run the agent's sync action and show me it proves the embedded primitives
match the public rapp.py byte-for-byte; (2) ask my brainstem on http://localhost:7071
to "mint a keyless rappid for @me/hello" and show me the response field of the reply.
```

**Expect:** `embedded_matches_public_reference: true`, then a fresh rappid from your own
brainstem.

## 6 · Now just talk to your brainstem

With the toolkit installed, these go straight into brainstem chat — no brainsurgeon
needed:

```text
mint a keyless rappid for @me/notes
```

```text
scaffold a new RAPP organism called @me/scratch
```

```text
verify this frame: { …paste any frame JSON… }
```

```text
check https://github.com/kody-w/twin for RAPP compliance
```

## 7 · Audit anything I've built for drift

```text
Using the conformance tools in https://github.com/kody-w/rapp-1 (clone it), audit
<PATH-OR-REPO-URL> for RAPP compliance: every frames/*.json must reproduce its stored
addresses under the one canonicalizer, chain links must verify, and any rappid.json must
satisfy the §6.1 grammar. Report drift the way realcheck.py does — what conforms, what
drifts, and for each drift the exact spec section it violates. Do not fix anything yet;
findings first.
```

**Expect:** a conforms/drift report with spec citations, and no unrequested changes.

## 8 · Implement RAPP in my language

```text
Read SPEC.md and chapter 11 of the book in https://github.com/kody-w/rapp-1 (clone it),
then implement a conforming RAPP core in <LANGUAGE> in dependency order: canonical, then
H/Hb, then rappid grammar, then build_frame/verify_frame. After each primitive, prove
parity by running the same vectors through the reference rapp.py and my new code and
comparing bytes — the way the repo's own parity_check.py does. Stop and show me the
first divergence if any vector ever differs; identical bytes are the whole point.
```

**Expect:** a growing implementation where every step ends in a byte-parity proof.

## 9 · Something's red and I want to understand it

```text
In my clone of https://github.com/kody-w/rapp-1, run python3 examples/05_failure_atlas.py
and teach me the refusal steps: for each failure it demonstrates, tell me the spec
section, what a lazy implementation would have wrongly accepted, and what real-world bug
that refusal prevents. RAPP treats a red check as the system working — show me why.
```

**Expect:** a guided tour of every refusal in the failure atlas.

## 10 · Qualify and deploy an AI without changing it under users

```text
In my clone of https://github.com/kody-w/rapp-1, read protocols/README.md,
protocols/rapp-cicd/1/SPEC.md, and protocols/rapp-deploy/1/SPEC.md. Run
python3 operations_conformance.py and stop if any vector is red. Then copy the
three files under protocols/examples/ for my release, replacing fixture values
with measured source, artifact, Grail, topology, state, data-policy, and health
values. Validate each file with rapp_cicd.py or rapp_deploy.py. Do not allow
in-place serving mutation, skipped stages, stale evidence, silent degradation,
or a mutable rollback target.
```

**Expect:** a content-addressed release, an ordered qualification policy, and a
cellular deployment plan that can prove pause, quarantine, restore, and exact
rollback before it receives broad user traffic.

---

*The interactive book edition gives every code example its own **Copy prompt** control —
[read it there](https://kody-w.github.io/rapp-1/book/) and the whole book works this way.*
