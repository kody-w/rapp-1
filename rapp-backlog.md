# rapp-backlog — rapp/1

Open work on the spec and its anchor. Public repo: keep this free of estate
internals, customer content and anything a reader here has no business seeing.

## Open

- [x] **The anchor is now bound to a signed registry (2026-09-01).** The owner minted the
      estate-owner key and published `kody-w/rapp-map/ecosystem-spec.json` (registry_seq 1,
      detached JWS EdDSA): it pins the current normative hash through a `protocol` entry and
      registers the anchor stream's genesis. The chain frames themselves remain unsigned; a
      follow-up may carry `sig` on frames (frame_hash does not cover `sig`, so existing waves
      are unchanged) once the generator learns the ceremony. `orient.json`'s
      `authenticated_registry_checkpoint` is still null until the generator is taught to point
      at the registry — that is the next generator change.

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

- [ ] **§13 registry document: name the container (rev-N+1 candidate, blocks every extender).**
      §13.1 names `schema`, `registry_seq`, `sig`; §13.3 names every entry's exact members;
      nothing names the member that holds the entries, nor how `canonical_source` travels in
      the document. No estate — this one included — has ever published a `rapp/1-registry`,
      and a stranger who tries (PR #15 did) has to invent the shape. Until closed,
      `rapp_registry.load_document` requires the caller to name the entries member.

- [ ] **Kind ownership across estates (rev-N+1 candidate).** Each estate binds kinds in its own
      registry, so on a `net:` swarm stream two estates can bind the same kind string to
      different families. Candidate rule: the first label of a kind is a namespace owned by one
      estate; the convention exists (`acme.*`, `ms-rapp.*`), the rule does not.

- [ ] **Egg variants — closed at the protocol or estate-registered?** §9.2 calls the seven
      variants "the ratified set" and `rapp.py` hard-codes `EGG_VARIANTS`; §13.3 defines an
      `egg-variant` registry entry. Both cannot be the rule. A vendor variant is registrable but
      not packable by the reference until one is chosen.

## Known limit

`raw.githubusercontent.com/.../main/...` is CDN-cached for several minutes and ignores
cache-busting query strings. To verify a publish immediately, fetch the **commit-pinned**
URL — which is also the right form for anything that must not shift underneath a consumer.
