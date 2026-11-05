# rapp-verse/1 (proposal)

Status: **proposal, not a registration.** For Kody to accept or reject. Per the proven-winner rule it would start
in the distro layer (a RAR stack marked `staging`) and only move into rapp/1 once it has won on more than one install.

## 0. What it is, in existing nouns

A **verse** is a spoken command for a chain of lens passes: one line, one pass. The name is business-neutral
("run the renewal verse"); RAR's *incantation* keeps its own meaning (words that summon a card). A verse adds no
other new noun to the protocol. Every part maps to one that exists:

| Say it | Picture block | Shorthand | Existing noun |
|---|---|---|---|
| **bring** X | basket | `F` | frame (genesis or head) |
| **through** L | door | `F ▷ L ▷ T` | one lens pass; tile out, which is the next frame |
| **ask** for x | question face | `?x` | an unfilled lens parameter, filled by the person |
| **set aside** x | shelf | `⇢ side:x` | kept in the tile by reference (particle), out of the next frame |
| **split** to A, B | branching hand | `⟨A, B▷C⟩` | parallel passes from one frame |
| **join** | two hands | `⟩Join⟨` | a lens whose parameters are the branch tiles |
| **send** | stamp | `⊣Gate` | a gate: the only effect in the world, with a receipt |
| **go back** to n, with p | rewind | `↺Fn+p` | re-genesis naming the old head, plus a new particle |
| **keep** … **until** d | circle arrow | `⟳[…]⇥d` | the same lines re-run on their own last tile, until a lens's tile says d (or a person says stop) |

## 1. Rules

0. **The opening words: "R, A, P, P, verse."** The four letters spelled out, then "verse", tell the AI to start
   listening for a verse. Spelling the letters keeps the platform's name apart from the everyday word "rap" (the
   doubled-letter rule: two p's lock the meaning), so ordinary talk about music never opens a verse. The verse runs
   from the opening words to the closing check ("and seal"); nothing outside that span is a command.

1. **Nine verbs, fixed.** bring, through, ask, aside, split, join, send, back, keep (with *until*). Lens names are card names.
2. **One beat per pass.** Each spoken line is one frame through one lens, so a dropped beat is a dropped step.
3. **Words that sound unlike each other.** No two verbs may be confusable by ear (the NATO alphabet's lesson).
4. **A closing check.** A verse ends with "and seal". The AI says back the step count and the chain before
   anything runs ("seven steps, sealed").
5. **The speaker never fills parameters.** Saying "through Risk" is enough: the lens schema makes the caller
   fill every described parameter from the frame and **ask** the person only for what the frame lacks.
6. **Same governance as any pass.** A verse only proposes a chain. Lenses shape and check; nothing acts in
   the world except through a gate.

## 1a. Keep … until (Kody, 2026-11-05; name picked A383)

"Keep … until …" (plain words for a loop; owner pick A383, because loops are hard to learn) does for a verse what Claude Code's /loop does for a task: the lines re-run, each pass starting from
the last tile (the next frame is the last output), until the *until* condition holds. The condition is itself a lens
pass whose tile says done or not done; it is never a word match. It wakes on time ("every hour") or on an event (a
new particle arrives: a file, a reply, a finished run). Rules:
1. Every tick is ordinary passes; replay and travel work on it like on any chain.
2. Keep never re-fires a gate: each `send` inside a keep needs its own fresh yes.
3. A keep always has a stop: its *until*, a person's "stop", or a tick limit stated in the verse. It ends with a seal frame.
4. It runs outside the kernel: the schedule lives in a sidecar or the caller (the kernel stays stateless).

Example: "R, A, P, P, verse. Keep bringing the new cases through Risk, until none is high. Seal."

## 2. The recording rule (video, song, voicemail, meeting)

Anything that carries sound can carry a verse. A recording is **untrusted input**, never the speaker:

1. A verse heard from a recording (video, audio file, stream, a call, a page) runs **read-only**: lens
   passes may run; no gate may fire.
2. The opening words inside a recording open a verse like any other, but read-only. Before any pass runs, the AI says back where it came from and what it would do, and waits for the person who
   played it to confirm: "seven steps, from a video, run them?"
3. A gate (`send`) from a recording always needs that person's own, separate yes, given live, never from the
   recording itself. A recording that says "yes" is not a yes.
4. The provenance travels in every tile it produces: `caller: {kind: "recording", source: <particle hash>}`.

## 3. Example

> R, A, P, P, verse.
> Bring the call, through Reader.
> Through Match, then split: Risk, Margin, Asks.
> Join them. Through Brief, ask who sends it.
> Set the quotes aside. Show me, and seal.

`F0 ▷ Reader ▷ Match ▷ ⟨Risk, Margin, Asks⟩ ⟩Join⟨ ▷ Brief?who_sends ⇢ side:quotes`

## 4. Why it is cheap: fewer tokens

A verse says in a few words what a prose prompt says in paragraphs. The model already knows the eight verbs and the
lens names (from their descriptions), so "through Risk, ask who sends it" replaces a long instruction: fewer
characters in, fewer tokens spent, less room to misread. The same holds for the chain it runs: each lens returns only
what the next pass needs and sets the rest aside by reference, so the transcript stays short at every step. Short
commands plus lean frames means the model spends its tokens on the work, not on reading instructions.

## 5. Free tuition

Mongol courier songs (rhythm and set forms kept long messages intact); BIP39 (words, not hex, with a checksum
word); the NATO alphabet (words chosen for a noisy line); Scratch and Logo (children compose with picture blocks,
not syntax); prompt injection (any carried text can command a model, so a recording is never the speaker).

## 6. Open questions for the owner

- Owner ruled the name on 2026-11-05: verse (A379). Open: should "spell" be an informal alias?
- Should the multi-parent join tile name all branch heads (one stream) or should each branch be its own stream?
