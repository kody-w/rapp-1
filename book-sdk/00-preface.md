# Building with RAPP

### The SDK Builder Agent in a Grail Brainstem

*A hands-on textbook. Every command here was run against a real, running brainstem
(`v0.6.16`) with `rapp_sdk_builder_agent.py` hotloaded into it; every output shown is real.*

---

## Preface

The other two books in this repository teach the RAPP **protocol** — the reference book in
prose, the visual guide in pictures. This book is different. It teaches you to **build with
RAPP using your own hands and your own brainstem**, through one file you drop in:
`rapp_sdk_builder_agent.py`.

By the end you will have:

- a **grail brainstem** running locally — the canonical RAPP engine,
- the **SDK Builder agent** hotloaded into it, discovered with no restart,
- a real **RAPP organism** you minted, scaffolded, and grew a verifiable worldline for,
- and the ability to **lint any repo in the stack** for RAPP compliance — all by talking to
  your brainstem in plain English.

### What you need

- Python 3.11 and a GitHub account (the brainstem authenticates to the GitHub Copilot API).
- Nothing else. The SDK agent is a single self-contained file with no third-party dependencies —
  it embeds the RAPP reference primitives and can prove, on demand, that its embedded copy
  computes byte-identical addresses to the public standard.

### The shape of the thing

RAPP is "engine, not experience." The **brainstem** is the engine: a small server that loads a
`soul.md` as its system prompt, auto-discovers agents from `agents/*_agent.py`, and routes your
plain-English requests to them through the model's tool-calling. You extend it by **dropping a
file in** — no rebuild, no restart. That is the whole extension model, and the SDK Builder agent
is built to ride it.

```
   you ──"scaffold @me/scratch"──▶  brainstem  ──tool-call──▶  RappSdkBuilder.perform(action="scaffold")
                                        │                              │
                                    soul.md                     mints rappid, builds
                                  (system prompt)               + verifies genesis frame
                                        │                              │
   you ◀──"minted rappid: …, genesis verified: yes"──────────────────┘
```

### How to read it

Chapter 1 stands up the grail brainstem and confirms it is healthy. Chapter 2 drops the SDK
Builder in and watches the brainstem discover it. Chapters 3–6 take the SDK one capability at a
time — identity, frames, content addressing, compliance — each shown twice: first as a direct
call you can run yourself, then as a sentence you say to the brainstem. Chapter 7 is the payoff:
building and growing a real organism entirely by conversation. Chapter 8 shows you how to extend
the agent, and the appendix is the action reference.

Run everything. A brainstem you have only read about is a demo. A brainstem you have taught a new
skill by dropping a file in, and then driven by talking to it, is yours.

Let's stand one up.
