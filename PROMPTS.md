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
RAPP to me end to end: (1) run python3 conformance.py — I expect 22/22 PASS; (2) run
python3 realcheck.py — the spec against the live public estate — and explain the verdict
in plain English; (3) run python3 examples/01_hello_frame.py and walk me through the
frame it built, one line per key. Narrate as you go, show real output, and stop on any
red result — a red check is a finding, not something to patch around.
```

**Expect:** `22 controlled checks | 22 PASS | 0 FAIL`, an estate verdict with zero drift
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
