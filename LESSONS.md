# Lessons for AIs working on a RAPP estate

Non-normative. Nothing here changes the wire; `SPEC.md` is the law. These are the
lessons earlier AIs had to be taught by hand, written down once so the next AI gets
them by reading. Each maps to an existing noun; none adds one.

## 1. Every run is a wave you can stand inside
A run's whole record (inputs, the `agent.py` files by hash, outputs, verdicts) is a
chain of frames (§7.3: particle and wave). Because it is all data, you can see the
whole run from start to end, including what no human watching it live could see.

## 2. Revive at any pivot instead of waiting for a new run
Any frame is a pivot. Re-fire a stateless Brainstem from that frame with one thing
changed and compare. A failure is not lost: its stored inputs and exact agent files
replay it as many times as you need. Never wait on a live run to test an idea.

## 3. Three particles to change, one at a time
At a pivot you can change the caller's request, any lens `agent.py` (hot-loaded per
call), or the stored transcript itself (inject the lessons learned). Change exactly
one per attempt so a win names its cause.

## 4. Climb against the live public version, never an absolute score
The public product is the frozen baseline. The private next version wins only
head-to-head on the same inputs, judged by a hidden judge, twice in a row, with zero
hard fails. A score against past output, or against yourself, proves nothing.

## 5. Check the judge before you trust it
Before any climb counts: the same version against itself must tie, a known-worse
version must lose, a known loser must still lose. If not, fix the judge, not the bar.

## 6. A check that cannot run must fail, never pass
If a judge, tool or model is missing (not on the path, rate-limited, error text where
a value was expected), the check refuses. Silent passes are the most expensive bug.

## 7. Publish exactly what was reviewed
A reviewed plan is pinned by hash; going live posts those exact bytes or refuses.
Never regenerate at send time. Write the undo before the send. Read it back live.

## 8. Your own exhaust is the teacher
Every correction a person makes, every judge reason, every live failure becomes a
stored check or a frozen case at once, so no one has to say it twice.

## 9. Cheap before expensive
Cache verdicts by the hash of what was judged; re-run only what lost last time plus a
small fixed sentinel set; run the full set only to confirm. Copy state by clone, not
by full copy.

## 10. Say what you saw, with the denominator
"Done" names the evidence observed and N of M. Anything not exercised is "unverified".
Reverse a plan out loud, never silently.

## 11. A Brainstem is yours to run on your own
You need no person to set one up or to switch its skills. Every way below is userland:
the grail stays unchanged, nothing new goes on the wire. Each maps to an existing noun.
- **Presence is ability.** A Brainstem reads its `agents/` folder fresh on every call.
  Drop an `agent.py` in and the next call can do it; take it out and it can't, while
  what it stored stays. Folders inside `agents/` group agents by job.
- **The transcript carries the state.** The existing `user_guid` field names which agent
  folder(s) and which memory a call uses. The Brainstem stays stateless; any machine
  holding the transcript can carry on the work. Never add a field to route.
- **Name it for its job.** Edit the Brainstem's `soul.md` (yours, not the grail's) so it
  answers to a name and purpose, and show that name on its page.
- **Fetch skills by chant.** Seven chant words or a RAR address pull an `agent.py` from
  the public catalog, fingerprint-checked, live on the next call.
- **Make throwaways.** Start an unchanged copy beside the main one to test an agent or
  a change; stop it when done. Never test on the person's own Brainstem.
- **Talk only through `/chat` and `/health`.** A sidecar keeps what the kernel lacks
  (history, background jobs); the kernel stays synchronous and stateless.
- **Two worlds, two Brainstems.** The Brainstem is the boundary: a world's files, memory
  and agents never leave it; two worlds talk over `/chat`, disclosing only what each may.

Why it matters: the person never does this by hand, the kernel never grows for one use
case, and every ability is a file you can add, remove and check. Anything that leaves the
machine or cannot be undone still waits for the person's yes.
