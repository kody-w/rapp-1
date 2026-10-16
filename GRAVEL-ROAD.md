# The Gravel Road: a constitution

RAPP is an open gravel road that nobody owns. The grail is its bedrock and never changes. Everything else is built
around it, and the vehicles that drive on it are what people pay for, never the road itself.

This constitution governs every repo that carries it. Where it and a repo's own rules disagree, this one wins,
except the grail's own constitution, which governs the grail.

## Article I. The layers
Five layers, each built only on the one below it. A need in a higher layer never changes a lower one.

| Layer | What it is | Rule |
|---|---|---|
| 1. The grail | The Brainstem kernel (`kody-w/rapp-installer`) | It is never changed for one use case. It changes only when every user needs it and it can't be done from outside, and only its owner opens that window. |
| 2. RAPP/1 | The protocol (`kody-w/rapp-1`): identity, frames, wire, egg, registry | One envelope. New needs become new registered kinds, never new formats. |
| 3. The gravel road | Public repos: patterns, reference agents, tools | Each is useful by itself and never needs a paid product to work. |
| 4. Userland | An agent file in `agents/`, a sidecar that talks only through `/chat` and `/health`, or a distro that pins the kernel by hash | Wrap the grail. Never edit it. Say which route you are taking before building. |
| 5. Vehicles | Products and services built in userland and sold | Kept private until their owner says yes. Never moved down into layers 1 to 3. |

## Article II. Organisms
Every account, org and repo is an organism, or can wake into one, and so is any folder with a soul and skills.
An organism is plain files: `soul.md` (who it is), `agents/` (what it can do), memory (what it learned), and
`/chat` (how it speaks). Pointing the unchanged kernel at the folder wakes it up.

## Article III. Wrapping
Larger organisms wrap smaller ones (a repo into an org, an org into an estate) by asking them at their own
`/chat` door, never by importing their code. Each part stays itself, and every exchange stays readable. Each
level answers for what it wraps in one plain sentence.

## Article IV. The folder is the AI
A skill is a file. A file dropped into `agents/` is usable on the next message, and a file moved out is gone.
Skills are granted, lent and taken back with ordinary file moves. Workflows are folders, and a job's place in the
tree is its stage. Build at the folder level, which outlasts every model update.

## Article V. Code is the truth
The code and its tests say what an organism does. Don't keep documents that restate the code. Write down only
what the code can't say:
- `decisions/`: why, and what was rejected;
- `GLOSSARY.md`: what the words mean here;
- a thin README map.

## Article VI. Teach once, keep forever
1. A conversation that worked becomes one `agent.py`.
2. It must pass with the chat history dropped.
3. If it fails, regenerate it from the same transcript plus the failure, with attempts running in parallel; the
   first one that passes is kept.

Build in the cloud on sample data; run locally on real data.

## Article VII. Nothing is thrown away
Data exhaust is as valuable as oil, and a failed project documents a use case worth building.
- Nothing is deleted until it is on a private repo and a backup, and the copy has been restored as a test.
- Unpushed work on a public repo goes to a private twin, never to the public repo.
- Every saved project gets a catalog card, so it can be found again.

## Article VIII. Every change has a name
- Work done by an AI is authored by that machine's own account and committed by its human owner. It is never
  re-signed as a person's.
- Every action goes in a ledger and can be undone.

## Article IX. Owners never see the machinery
The owner talks to the device, the repo or the org itself, and it answers as itself, in plain words. Three
surfaces only:
- chat;
- one page;
- one text, sent only when truly needed.

The owner never gets a command to type. Routine care is the device's job. Uncertain calls go to the owner's
decision twin first.

## Article X. Lines that never bend
1. **Two worlds.** Work and customer content never enters a personal or company repo.
2. **No secrets in any repo.** Record where a secret lives, never its value.
3. **Public changes go out only as a pull request, with the owner's yes.**
4. **Done means live and verified, with the denominator stated.** Anything not exercised is called unverified.
5. **No money, accounts or launches without the owner's yes at that moment.**

## Article XI. The tests every idea must pass
- **Only we can:** name another AI that can do this today. If one can, drop the idea.
- **Someone needs it:** who has this problem today, what do they do instead, and why would they switch?
- **All along:** would a person say "my AI should have been able to do this all along"?
- **Frees the owner:** does it remove something the owner has to know or manage?
- **Grows the road:** does it make the open road better for everyone, or ride on it without taking from it?

## Article XII. Changing this constitution
Only the owner amends it, by a dated entry below. Every repo that carries it links to the canonical copy rather
than editing its own.

### Amendments
- 2026-10-16: adopted.
