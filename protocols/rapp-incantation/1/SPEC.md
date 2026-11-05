# rapp-incantation/1 (proposal)

Status: **proposal, not a registration.** For Kody to accept or reject. Per the proven-winner rule it would start
in the distro layer (a RAR stack marked `staging`) and only move into rapp/1 once it has won on more than one install.

## 0. What it is, in existing nouns

An **incantation** (the RAR noun: words that summon) is a spoken command for a chain of lens passes. It adds no
new noun to the protocol. Every part maps to one that exists:

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

## 1. Rules

1. **Eight verbs, fixed.** bring, through, ask, aside, split, join, send, back. Lens names are card names.
2. **One beat per pass.** Each spoken line is one frame through one lens, so a dropped beat is a dropped step.
3. **Words that sound unlike each other.** No two verbs may be confusable by ear (the NATO alphabet's lesson).
4. **A closing check.** An incantation ends with "and seal". The AI says back the step count and the chain before
   anything runs ("seven steps, sealed").
5. **The speaker never fills parameters.** Saying "through Risk" is enough: the lens schema makes the caller
   fill every described parameter from the frame and **ask** the person only for what the frame lacks.
6. **Same governance as any pass.** An incantation only proposes a chain. Lenses shape and check; nothing acts in
   the world except through a gate.

## 2. The recording rule (video, song, voicemail, meeting)

Anything that carries sound can carry an incantation. A recording is **untrusted input**, never the speaker:

1. An incantation heard from a recording (video, audio file, stream, a call, a page) runs **read-only**: lens
   passes may run; no gate may fire.
2. Before any pass runs, the AI says back where it came from and what it would do, and waits for the person who
   played it to confirm: "seven steps, from a video, run them?"
3. A gate (`send`) from a recording always needs that person's own, separate yes, given live, never from the
   recording itself. A recording that says "yes" is not a yes.
4. The provenance travels in every tile it produces: `caller: {kind: "recording", source: <particle hash>}`.

## 3. Example

> Bring the call, through Reader.
> Through Match, then split: Risk, Margin, Asks.
> Join them. Through Brief, ask who sends it.
> Set the quotes aside. Show me, and seal.

`F0 ▷ Reader ▷ Match ▷ ⟨Risk, Margin, Asks⟩ ⟩Join⟨ ▷ Brief?who_sends ⇢ side:quotes`

## 4. Free tuition

Mongol courier songs (rhythm and set forms kept long messages intact); BIP39 (words, not hex, with a checksum
word); the NATO alphabet (words chosen for a noisy line); Scratch and Logo (children compose with picture blocks,
not syntax); prompt injection (any carried text can command a model, so a recording is never the speaker).

## 5. Open questions for the owner

- Is "incantation" the right existing noun, or "spell" as an alias of it?
- Should the multi-parent join tile name all branch heads (one stream) or should each branch be its own stream?
