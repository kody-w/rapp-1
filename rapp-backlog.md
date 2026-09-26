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

- [x] **§13 registry document: name the container — drafted as rev-17, normative on owner
      acceptance.** §13.1 now names `schema`, `registry_seq`, `canonical_source`, `entries`, and
      `sig`, exactly the shape of the one published signed registry; any other top-level member
      carries no meaning. `rapp_registry.load_document` defaults the entries member to `entries` and
      refuses any other name. (Was: nothing named the member holding the entries or how
      `canonical_source` travels, so a stranger — PR #15 — had to invent the shape.)

- [ ] **Kind ownership across estates (rev-N+1 candidate).** Each estate binds kinds in its own
      registry, so on a `net:` swarm stream two estates can bind the same kind string to
      different families. Candidate rule: the first label of a kind is a namespace owned by one
      estate; the convention exists (`acme.*`, `ms-rapp.*`), the rule does not.

- [ ] **Egg variants — closed at the protocol or estate-registered?** §9.2 calls the seven
      variants "the ratified set" and `rapp.py` hard-codes `EGG_VARIANTS`; §13.3 defines an
      `egg-variant` registry entry. Both cannot be the rule. A vendor variant is registrable but
      not packable by the reference until one is chosen.

- [ ] **Registry capacity (rev-N+1 candidate; not blocking the rev-17 LTS lock).** §4 caps a
      registry at 1 MiB canonical and §13.3 makes every entry append-only, so an estate's registry
      has a lifetime budget. With realistic URIs and an EdDSA signature a rev-17 declared entry is
      about 0.65–0.95 KB, so a registry holds roughly 1,100–1,500 declared entries beside its other
      entries. At one entry per release, notices only for changes, and newest pinned at milestones
      that lasts years; a continuation — a successor document that carries retained entries forward
      by hash — needs its own design before an estate approaches the cap.

- [ ] **`rapp.utc_valid` accepts non-ASCII digits in the year.** Python's `\d` matches other
      scripts' digits, so `٢٠٢٦-08-01T00:00:00.000Z` passes it, though §7.4's form is 24 ASCII
      octets and bytewise order equals time order only for those. `rapp_registry` refuses such values
      in every registry time member, first-seen and issuance time, owner-tenure and key-acceptability
      check, and authority query; `rapp.verify_frame` itself is parity-pinned, so its fix and a
      conformance vector belong to a reviewed reference change.

## Known limit

`raw.githubusercontent.com/.../main/...` is CDN-cached for several minutes and ignores
cache-busting query strings. To verify a publish immediately, fetch the **commit-pinned**
URL — which is also the right form for anything that must not shift underneath a consumer.
