# The anchor

This directory is RAPP's public, pullable anchor: an append-only chain of frames
(`chain.jsonl`, one frame per spec revision) and a small beacon (`orient.json`) carrying the
current spec revision and normative sha256, the ratified public Constitution
hash, the pinned public RAPP foundation, the philosophy mirror hash, the
registered kinds, operational profile pins, and the vocabulary with each
term's status. Resolve spec and profile questions through it instead of
hardcoding a moving branch or re-deriving rules in code.

These files are generator-owned and never hand-edited. The anchor is unsigned on purpose —
no authenticated registry exists yet, and signing without one would be fabrication — and the
beacon says so itself.

- Beacon: `https://raw.githubusercontent.com/kody-w/rapp-1/main/anchor/orient.json`
- Chain: `https://raw.githubusercontent.com/kody-w/rapp-1/main/anchor/chain.jsonl`

## The feed: subscribe to the DOGG

The anchor's official feed surface is the Atom feed GitHub already publishes for this
directory's commits — no server, no key, no extra artifact that could drift:

```
https://github.com/kody-w/rapp-1/commits/main/anchor.atom
```

Every entry in that feed is one tick of the anchor: a commit that moved the chain or the
beacon. Any feed reader, automation, or foreign agent can subscribe to it today; polling it
is how a stranger's agent learns the anchor moved without knowing anything else about this
estate. (The repo-wide feed at `commits/main.atom` also exists but carries every commit, not
just ticks.)

**Reach:** GitHub serves `.atom` without CORS headers, so browser pages cannot fetch a feed
cross-origin — feeds are for agents, readers, and CI, not for page JavaScript. A page that needs
the anchor reads `orient.json` from raw directly.

**Discipline:** the feed is discovery, not verification. Its entry IDs are commit SHAs, not
frame hashes. On a tick, pull `orient.json` and `chain.jsonl` and verify the chain's own
hashes — trust the chain, never the feed. A feed is just XML someone served you.

**Doctrine — feeds over the API:** estate tools pull Atom feeds instead of the GitHub REST
API whenever a feed carries the answer (change detection, ticks, release pulses). Feeds are
plain cacheable web requests with no token and no rate ceiling; the API is reserved for what
feeds cannot carry. High-traffic consumers (RAR clients included) especially.
