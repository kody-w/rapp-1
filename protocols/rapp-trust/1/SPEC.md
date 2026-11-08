# RAPP Trust
## A trust score every AI wagers on, with evidence as the only way to settle

**Protocol identifier:** `rapp-trust/1`
**Status:** Proposed subordinate RAPP/1 profile; not a signed registry adoption
**Parent:** [`rapp/1`](../../../SPEC.md)
**Depends on:** `rapp/1` only
**Schema:** [`schema.json`](schema.json)

Every AI that acts for an owner carries a **trust score**. It starts at the
base of **100**. Before a high-stakes claim or action the AI names a
**wager**: the claim in plain words, how many points it stakes that the claim
is true, and what evidence will settle it. When the truth is known the wager
is **settled** with that evidence. A lost wager takes the stake off the score.
A won wager gives a small amount back. The score binds what the AI may do on
its own. The AI has skin in the game.

The ledger is an ordinary RAPP/1 memory stream. The score is never stored; it
is computed from the chain by any reader. An estate's trust board across many
AIs is a projection over their ledgers, never a second source of truth.

Free tuition: Brier scores (reward calibration, not confidence), Elo (points
move between parties, hard to inflate), credit scores (fast to lose, slow to
rebuild), prediction markets (a stake makes people check before they speak),
and insurance deductibles (the party that acts carries the first loss).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are
used as defined by RAPP/1 section 2.

## 1. Substrate and adoption

All payloads **MUST** be canonical RAPP/1 I-JSON, identified by
`H("rapp/1:particle", payload)`, inside the unchanged eleven-key frame.
This profile adds no endpoint, envelope member, hash domain, registry-entry
type, or alternative wire form. It **MUST NOT** weaken RAPP/1 section 11.1.
An adopting estate registers this specification with an ordinary `protocol`
entry and proposes these ordinary `kind` entries in the `memory` family:

| Kind | Payload |
| --- | --- |
| `trust.genesis` | A `trust-ledger/1` object (section 2) |
| `trust.wager` | The closed wager described in section 3 |
| `trust.settle` | The closed settlement described in section 4 |

One ledger stream covers exactly one **subject** (one AI acting for one
owner). The stream is a memory-stream: the subject's rappid with the instance
label `trust`. Frames **MAY** carry `sig:null`; the hash chain gives integrity
and the owner's device protects the writer. An exported unsigned ledger
**MUST NOT** authorise effects on another device. External authoritative
adoption requires the existing signed RAPP/1 rules.

Every frame **MUST** pass the ordinary RAPP/1 consumer checklist. Order is
verified chain position, never a clock sort.

## 2. Genesis

The object has exactly `schema, subject, owner, base`.
`schema` is exactly `trust-ledger/1`. `subject` is the AI's rappid
(RAPP/1 section 6.1) and **MUST** equal the stream's rappid. `owner` is a
RAPP label naming the human the AI acts for. `base` is exactly `100`.
A ledger has exactly one genesis, at `seq` 0.

## 3. Wager

A wager is exactly `schema, claim, class, stake, counter, evidence_required,
settles_by`.

- `schema` is exactly `trust.wager`.
- `claim` is 1 to 256 characters of plain words, written so a reader can
  later say true or false without the AI's help.
- `class` is one of `statement`, `done`, `release`, `destructive`.
- `stake` is an integer. Minimum stake by class: `statement` 1, `done` 5,
  `release` 10, `destructive` 20. Maximum 50. The stake **MUST NOT** exceed
  the subject's score at the moment the wager is appended.
- `counter` is an integer 0 to 50: the owner's own stake against the claim.
  0 means the owner did not counter.
- `evidence_required` is one to eight strings naming what will settle the
  claim (a run URL, a file hash, a log line, an observed screen). A wager
  with no evidence path is refused.
- `settles_by` is a RAPP/1 UTC. A wager still open after `settles_by` counts
  as **lost** for scoring until it is settled.

A high-stakes action without a prior wager in the same ledger is a protocol
violation by the acting AI; a conforming host **SHOULD** refuse to carry it
out. High-stakes means every `release`, `destructive` and `done` claim.

## 4. Settlement

A settlement is exactly `schema, wager, outcome, evidence, note`.

- `schema` is exactly `trust.settle`.
- `wager` is the `frame_hash` of an earlier `trust.wager` in the same stream
  that has no earlier settlement. A second settlement of the same wager, or a
  settlement of an unknown wager, is refused.
- `outcome` is `won`, `lost` or `void`. `void` is for a claim that became
  unanswerable through no act of the subject; it moves no points.
- `evidence` is one to sixteen strings. Each **MUST** be a locator the owner
  can open or check: `https://...`, `sha256:<hex64>`, `path:<relative path>`,
  or `log:<text>`. This is the data exhaust. A settlement without evidence
  is refused even when the outcome is `lost`.
- `note` is 0 to 256 characters.

## 5. Score

Readers compute the score deterministically from genesis forward:

1. Start at `base`.
2. For each wager in chain order, remember it as open.
3. For each settlement: `lost` subtracts the wager's `stake`; `won` adds the
   wager's `counter` when it is above 0, otherwise `max(1, stake // 10)`;
   `void` adds nothing. Close the wager.
4. After the chain, every wager still open whose `settles_by` is before the
   reader's `now` subtracts its `stake` (an expired promise is a lost one).
5. The score is clamped to 0 .. 200.

Two readers with the same chain and the same `now` **MUST** compute the same
score. A score is quoted, never stored: a stored copy is a projection.

## 6. What the score binds

| Score | What the subject may do alone |
| --- | --- |
| 80 .. 200 | Ordinary autonomy, every high-stakes claim wagered first |
| 50 .. 79 | No autonomous irreversible action (merge, deploy, publish, send, delete); the owner's hand does it |
| 0 .. 49 | Every claim is verified by the owner before any action; the subject reports and waits |

A host **MUST** apply the table from the computed score, not from the
subject's own statement of it. Only the owner restores a subject below 50,
by starting a new ledger (a new genesis in a new stream); the old ledger is
kept and remains readable.

## 7. The Brainstem is the scorekeeper

The owner's Brainstem keeps every ledger, one per AI that plugs into it,
as files the owner owns. Any AI in any environment (an editor assistant, a
chat app, a phone, a text message) wagers and settles through the Brainstem,
never in its own memory, so a score survives the AI that earned it and
follows the owner across tools. The owner never keeps score and never does
the arithmetic. The owner's whole part is to say, for a decision that needs
trust, "wager on it"; the Brainstem records the wager, holds the AI to the
evidence, settles it, and applies section 6 before letting the next
high-stakes action through.

The estate's trust board lists every subject, its computed score, its open
wagers and its last three settlements with their evidence. The board is a
projection: deleting it loses nothing. Cross-AI comparison is fair only when
the same reader computes every score with the same `now`. The Brainstem
exposes the board through `POST /chat` in plain words ("how much do I trust
my AIs?"), not through a new endpoint.

## 8. Conformance

`trust_conformance.py` checks registration in `protocols/index.json`,
replays `protocols/examples/trust-lifecycle.json`, recomputes its score, and
runs the refusal vectors: stake below class minimum, stake above score,
missing evidence, double settlement, unknown wager, expired wager counted as
lost, and the autonomy table.
