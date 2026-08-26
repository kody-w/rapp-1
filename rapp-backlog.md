# rapp-backlog — rapp/1

Open work on the spec and its anchor. Public repo: keep this free of estate
internals, customer content and anything a reader here has no business seeing.

## Open

- [ ] **The anchor is unsigned, and says so.** There is no authenticated §13 registry and
      no established owner-signing authority, so a signature would be fabrication — the
      exact ground `rapp-frame-net` was retired on. Unsigned is lawful for a body-stream
      (§7.5 step 6 binds swarm-streams only) and the beacon states it. When the trust
      ceremony happens, **the anchor should be the first thing signed**: a signed anchor is
      what turns "canon we publish" into "canon you can prove".

- [ ] **Downstream pins should resolve through the anchor rather than hardcode a hash.**
      A pin that was correct the day it was written goes stale silently; that is what
      happened to `6d06daba…` across five files while live SPEC.md moved to `cea7847f…`.

- [ ] **Vocabulary coverage is partial.** Live terms are read out of the normative text;
      retired ones are curated by hand. A term that is retired without being recorded here
      keeps circulating — which is how `metropolis` survived in its author's memory while
      being absent from every live source.

- [ ] **`deck-theme.json` documents the private-theme path but nothing exercises it.**
      The refusal behaviour (never silently fall back from a private theme to this default)
      is implemented and tested locally, not against a real private repo.

## Known limit

`raw.githubusercontent.com/.../main/...` is CDN-cached for several minutes and ignores
cache-busting query strings. To verify a publish immediately, fetch the **commit-pinned**
URL — which is also the right form for anything that must not shift underneath a consumer.
