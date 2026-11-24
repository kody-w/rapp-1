# Kernel climb — how every fork of the Brainstem kernel improves without breaking it

Status: **current** (proposed and accepted by the owner 2026-11-24).
Applies to: the Grail (`kody-w/rapp-installer`), its release train (canary, nightly,
alpha, beta), and **any fork or distro of the kernel**, public or private.

Article 15 says the Grail's bytes never change. This page is the practice around that
rule: where improvements go, how they climb, how a release is decided, and how forks
learn from each other. It adds no wire surface and no new noun.

## Why (what one night of climbing showed)

Measured on 2026-11-23/24 across the Grail and four rings:

- The kernel barely needed to change. The agent base class was byte-identical between
  the Grail and a public MIT distro (1 of 1). That distro's 8 of 8 field lessons were in
  installers, not the kernel.
- Breakage came from the edges: 2 of 2 failures were test setup and a CI publish step.
- Retries did not fix anything: 4 of 4 retries failed; one real change then fixed 4 of 4
  rings.

## The rules

1. **The kernel is frozen by hash.** `rapp_brainstem/brainstem.py` changes only in a
   release window the owner opens, with a written reason that every user needs it and it
   cannot be done from outside. Every ring fails closed on different kernel bytes.
2. **Improvements live at the edges.** Installers, tests, CI, packaging and agents
   (`agents/*_agent.py`). A use case is never a kernel change.
3. **Everything enters at canary and climbs one ring at a time.** At each ring the
   change passes that ring's CI and a hands-on check (unit tests, installer checks, fresh
   and upgrade installs in a sandbox) before it moves on. Ring-owned files
   (`.ring/`, `.github/workflows/`) are applied per ring, the same way, one at a time.
4. **Every climb compares every Brainstem on the same checks.** Run one identical check
   list on the Grail and each ring and record one line per Brainstem. The goal is that a
   difference shows, not only a failure.
5. **A red stops the climb.** Find the cause and fix it where it lives. Never retry past
   it and never bypass a gate. A known upstream bug gets a link and a workaround in our
   own files.
6. **Every step records its go or no-go and why.** One line per step: what changed, the
   scores before and after, the undo, the run links, the decision and its reason. This
   record is what an owner's twin learns from, so it must hold the no-gos too.
7. **Grail entry needs a reason a user would feel.** A change that only helps people
   running the checks waits and rides with the next real release. The owner makes the
   final call in the release window; a twin may recommend, never decide.
8. **Forks learn from each other, never copy across the line.** Read other public
   distros on a schedule, anonymously. Write their lessons fresh in your own words, pass
   them through your boundary check, and climb them like any other change. Content from
   a private or work fork never flows into a personal one.

## Any other fork of the kernel

A fork follows the same eight rules against its own pinned kernel. It names every
difference from upstream, re-runs the comparison against upstream on a schedule, and
sends fixes that every user needs upstream as a proposal rather than carrying them
forever (Debian's patch series; Chromium forks).

## Who did this before

Linux (a small kernel and a release train with one maintainer pulling), Chrome (canary
to stable), Rust (testing compiler changes against its whole package ecosystem before
release) and Debian (a named patch series per distro). The hard lesson they share: the
kernel stays stable because the work happens around it, on a schedule, with evidence.
