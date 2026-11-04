# rapp-alm/1 — how installable things live for years (PROPOSAL)

**Status: proposal.** Nothing here is registered (§13 has no authenticated registry yet). It records what the
grail-layers pack installer and RAR proved on 2026-11-04, so the rule set is fixed at the start instead of
discovered later. Kody accepts or rejects it by merging this pull request.

## 1. Scope
Everything a person adds to a Brainstem from a catalog: layers, agents, senses, pages, and the bundles that carry
them (packs, starters, distros). It does not change the wire (§8), the frame (§7) or the egg container (§9.1).

## 2. One noun for bundles, four part kinds
- A **pack** is a list of parts, each pinned by sha256, plus optional `includes` (other packs). A starter and a
  distro are packs (a distro also pins the kernel sha). These are labels, not formats.
- Part kinds: `layer` (applied in memory over the unchanged kernel), `agent` (`*_agent.py`; factories are
  `*_factory_agent.py`), `sense` (`*_sense.py`: one extra reply field), `page` (`*_page.py`: routes at
  `/api/<name>/`; a local convenience that carries no RAPP semantics, like `GET /health`: §8 still holds, so any
  capability a page offers MUST also be reachable as an agent behind `/chat`). **`organ` is an alias of `page`**; the §9.2 organism row's `organs/*` reads as pages.
- **A pack is an egg without your data; an egg is a pack plus your data.** Proposed: a `pack` variant in §9.2
  (ZIP; payload `{includes:[<name>], parts:[{id, kind, point, file}], kernel:<64hex|null>}`; contents = the
  part files). Until ratified, packs stay `rapp-rar-stack/1.2` JSON in RAR.

## 3. Lifecycle (each state is a status on the name, never a deletion)
`published` → `current` → `alias of X` → `retiring on <date>` → `tombstone`.
- Published bytes MUST NOT change. A fix is a new version with new shas.
- A retired name MUST keep serving every URL it ever served, and SHOULD say "this is now X".
- A tombstone MAY be written only after a measured check shows zero use.

## 4. Installing a cart (MUST)
1. **Order-free.** The installer MUST resolve the cart as a sorted set (includes first) and MUST produce the
   same plan for any order or repetition of the same names. Conformance: every subset of a pool, in at least
   identity, reversed and shuffled-with-duplicate orders, yields one plan (reference test:
   `grail-layers/tests/permute_packs.py`; 0 of 31 subsets differed on 2026-11-04).
2. **Content-addressed.** The same sha installs once, whichever packs carry it.
3. **Declared conflicts.** Two exclusive parts on one point refuse the whole cart with a plain reason;
   composable parts (`WRAPS`) chain. Never silent last-wins.
4. **Plan, then gate, then change.** Every file is fetched and sha-checked before anything changes; layers boot
   in a lab and answer a real `/chat` before live changes; agents, senses and pages are written only after.
5. **Never overwrite.** Same tool name = upgrade in place with a kept copy. Different bytes under a taken name
   install under a scoped name (`<publisher_or_pack>__<file>`).
6. **Partial carts.** A dropped part that another selected pack relies on is a warning shown before install.
7. **One cart, one catalog.** Pack names and catalog agents (`@publisher/name_agent`) share one cart and one
   installer.

## 5. Publishers at scale
Ids are publisher-scoped (`@publisher/part`) from the first publish. A pack can only add; it never edits the
kernel or another publisher's part. Critical parts name two owners.

## 6. Known drift this proposal closes later (not in this PR)
- Moving Day's move file is a brainfreeze snapshot (tar.gz), not a §9 `organism` egg. It should become one.
- rappter-distro's own senses/organs loader is now an alias of the grail-layers `senses_and_pages` layer.
- The RAPP Store's 23 rapplications are §9 `rapplication` eggs that RAR does not yet list as packs.

## 7. Free tuition (who paid for each rule)
Debian (declared conflicts, tasks), npm left-pad (published bytes never vanish), Nix and Silverblue (plan, gate,
one-step undo), Dynamics 365 solution layers (no silent last-wins), xz 2024 (two owners, pinned bytes), Ansible
and Windows install order (order-free plans), app stores and Steam Workshop (one store, paid creators bring review
load). Full table: https://kody-w.github.io/grail-layers/ALM.md
