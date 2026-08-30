# The rapp/1 Protocol Constitution

**Status: DRAFT — pending full ratification by the estate owner.** Article
15's permanent byte-immutability rule was explicitly owner-authorized on
2026-08-29 and becomes binding when the pull request carrying these exact bytes
is merged under Article 14.

`SPEC.md` is the law of **bytes** — what a conformant implementation must emit and
refuse. This Constitution is the law of **change** — how the standard, this repository,
and every claim they make may lawfully evolve. When the two disagree about bytes, the
SPEC wins; when they disagree about process, this Constitution wins.

**Relation to the Federal Constitution.** The estate's Federal Constitution (pinned at
`rapp-god/authority/records/federal-governance.json`, content withheld behind the
private boundary) governs estate-level ratification and owner decisions. `SPEC.md`
cites several of its articles; because readers of a public standard must be able to
resolve every citation, Articles 2–7 below restate, in public, the principles the SPEC
relies on — with a concordance at the end. If the Federal Constitution is later
published and conflicts, it prevails and this document is amended, visibly.

---

## Article 1 — One Spec of Record

There is exactly one normative source for rapp/1: **`SPEC.md` in this repository.**
Mirrors (rapp-god's authority tree, rendered books, the reference manual) carry
provenance stamps and reproduce it; they never fork it. A mirror that drifts from the
authority file is a drift finding, not a second opinion. The books are *teaching*
surfaces: where a book and the SPEC disagree, the SPEC is right and the book has a bug.

## Article 2 — One Label, One Shape

A versioned token — `rapp/1`, `rapp/1-egg`, any `name/X.Y` — **must never denote two
shapes.** Any revision that changes a key set, a field grammar, or a hash rule moves
the token. This is the article that makes the wire trustworthy: the label on the bytes
is a complete statement of how to verify them. *(Cited by SPEC §7.1, §12 as Fed. Const.
Art. II.)*

## Article 3 — No Legacy

rapp/1 is a **living standard**: revised in place, never forked into parallel versions,
with **no perpetual backward compatibility.** A change to a canonical form is a total
migration of every instance plus deletion of the old form. The single exception is
sealed re-genesis history (SPEC §12.1) — retained bit-exact under `legacy/`, never
served as current. Published content-addressed artifacts are immutable; the way out is
always forward. *(Cited by SPEC §6.3, §12 as Fed. Const. Art. III.)*

## Article 4 — Growth by Registration, Never by Fork

New capability enters as a **new registered `kind`, egg variant, or registry entry on
the same envelope** — never as a new envelope, a second frame shape, or a second door
beside `POST /chat`. If a proposal cannot be expressed as a registration, it is a
rev-N+1 conversation, not a patch. *(Cited by SPEC §7.2 as Fed. Const. Art. IV.)*

## Article 5 — The Registry Is the Root of Trust, and Appends Are the Law

The registry (SPEC §13) is signed, append-only, and `registry_seq`-monotonic. Entries
are never removed or renamed; retirement is a `deprecated` flag. **The append is the
linearization point**: a concurrent competing write fails closed. Nothing in the estate
may resolve trust — genesis, keys, tombstones, ownership — around the registry.
*(Concurrency clause cited by SPEC §12.1 as Fed. Const. Art. IX; mirror provenance by
SPEC §11, §13.1 as Art. VIII.)*

## Article 6 — Authority Is the Owner's, Scoped in Time

Fork resolution, stream bricking, re-genesis, and the retirement of a spec are
**owner-authorized operations** — one authorized convergence, never an implementer's
improvisation. "Owner-signed" is evaluated against the owner **in effect at the
artifact's time** (SPEC §13.2), so succession never rewrites history. Estate-level
scope — what belongs in this repo versus elsewhere — follows the master plan the
registry points to. *(Cited by SPEC §7.6, §12.1 as Fed. Const. Art. X; scope by SPEC
§11 as Art. VII.)*

## Article 7 — Identity Is Minted, Never Derived

The rappid tail is minted once — from entropy or from a public key — and is **never
the hash of a name.** This repository exists in part because that sin shipped to
production three ways; §6.2 outlaws it and no future revision may relax it. Names are
chosen; identities are minted; they must never be the same operation.

## Article 8 — Red Oracles Are the System Working

A failing conformance vector, a parity break, a refused frame, a drifted estate watch,
a red CI gate — these are **findings, never obstacles.** The lawful responses are: fix
the artifact upstream, or prove the oracle wrong and fix the oracle. Bypassing,
skipping, or muting an oracle to ship is a constitutional violation, whoever does it —
human or agent.

## Article 9 — Claims Are Computed and Dated

Every real-world claim on every surface — README, landing page, guide, books — is a
**dated capture generated by running code**, never an undated "currently." The estate
is live and observations decay; the scheduled estate watch re-observes and files drift
as issues. Captured historical reports (the before/after case study) are immutable
evidence and are labeled as captures, not as the present.

## Article 10 — One Canonicalizer, Proven, Everywhere

Any copy of the reference primitives — embedded in an agent, ported to another
language, quoted in a book — must **prove byte parity** with `rapp.py` against shared
vectors (`parity_check.py`, CI-enforced; the SDK agent's `sync` action for the fetch
path). A divergent copy is not a variant; it is the drift this protocol was written to
end, found at home.

## Article 11 — Prompts Are the Human Interface

A person using RAPP **never needs to type code.** Every surface leads with copy-paste
prompts (`PROMPTS.md`, the book's Copy-prompt controls) addressed to the user's
brainstem (plain-English `/chat`) or brainsurgeon (an agentic CLI). Code and commands
remain on every page — as the machine layer the prompts drive, and as the provenance a
reader can always inspect. Teaching the protocol and hiding the protocol are different
things; RAPP does the first.

## Article 12 — Print Is a Contract

Published books bake URLs, names, and numbers into paper. Therefore: **this repository
is never renamed**, its Pages paths never move, and a shipped edition's captured
numbers are never retroactively edited — corrections ship as new printings, and the
committed PDF may never lag its book source (CI-enforced). What the reader holds must
stay resolvable for as long as the estate stands.

## Article 13 — The Protocol Is Meant to Be Implemented

The standard exists to be implemented by strangers. The licensing that makes that
legally true (spec and code granted; the books remaining authored works) is enacted by
the owner-ratified `LICENSE` at the repository root; until ratification, this article
records the intent the README has always stated. Marks follow the estate's one-line
fine-print convention — never per-mention.

## Article 14 — Amendment

This Constitution changes by pull request ratified by the estate owner. Article
numbers are **append-only**: an article is amended in place or deprecated by a visible
flag, never renumbered and never silently deleted — so every citation ever made
remains resolvable. The amendment history is the git history; there is no other record.

## Article 15 — The Grail Never Changes

Once an estate owner authenticates a Grail kernel pin through the RAPP/1
registry, the exact bytes identified by its domain-separated `grail_id` are
permanent. Repository, ref, commit, path, raw SHA-256, and product name are
provenance locators; none can redefine that identity.

1. The Grail's bytes never change under that identity.
2. Every ring and every release/deployment stage, including future or renamed
   stages, must fail closed when the candidate bytes or resolved runtime entry
   point differ from the pin.
3. A pipeline may not test different bytes and substitute the Grail afterward;
   the exact release-shaped artifact that executes the pin must earn release.
4. Different bytes are a different Grail. They may receive a new identity and
   explicit lineage, but never overwrite, retag, alias, or silently replace the
   old Grail.

Existing growth-by-registration and no-legacy rules determine where new
behavior belongs. This article does not authorize unregistered protocol
surfaces. It is entrenched: future amendments may strengthen verification but
may not authorize mutation of an already-declared Grail under the same
identity.

---

## Concordance — resolving SPEC.md's Federal Constitution citations

| SPEC citation | Where it binds in SPEC | Restated publicly as |
|---|---|---|
| Fed. Const. Art. II | §7.1, §12 — one label, one shape | Article 2 |
| Fed. Const. Art. III | §6.3, §7.1, §9.4, §12 — no legacy, total migration | Article 3 |
| Fed. Const. Art. IV | §7.2 — new kinds, same envelope | Article 4 |
| Fed. Const. Art. VII | §11, §13.3 — master plan, scope | Article 6 |
| Fed. Const. Art. VIII | §11, §13.1 — provenance-stamped mirrors | Articles 1, 5 |
| Fed. Const. Art. IX | §12.1 — the append is the linearization point | Article 5 |
| Fed. Const. Art. X | §1, §7.6, §12.1 — owner fork resolution, retired specs | Article 6 |

*Drafted 2026-08-26 in public session. Article 15 owner-authorized 2026-08-29
and recorded as ratified by the merge that introduces its exact bytes;
full-document ratification remains the estate owner's word. One spec, one
canonicalizer, one mint, one frame, one immutable Grail.*
