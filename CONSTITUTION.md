# The rapp/1 Protocol Constitution

**Status: RATIFIED BY THE ESTATE OWNER.** Articles 15 and 16 were explicitly
owner-authorized on 2026-08-29 and 2026-08-30. Article 17 and full-document
public ratification were owner-authorized on 2026-08-30 and become effective
when the pull request carrying these exact bytes is merged under Article 14.

The normative revision text carried by the selected, verified head of
`anchor/chain.jsonl` is the law of **bytes** — what a conformant implementation
must emit and refuse. `SPEC.md` is the byte-exact materialized view of that
head. The unsigned chain proves integrity and lineage; until an authenticated
RAPP registry/checkpoint exists, owner-ratified acceptance onto this canonical
owner-controlled protected repository selects which verified chain is
authoritative. This Constitution is the law of **change** — how the standard,
this repository, and every claim they make may lawfully evolve.

**Relation to private estate governance.** Private constitutions may govern
estate-level product, company, or owner decisions, but they do not govern public
RAPP/1 bytes or protocol amendment. The owner-selected verified specification
chain and this public Protocol Constitution are final for protocol conformance and
governance. Historical Federal-Constitution citations in the materialized
`SPEC.md` resolve to the public restatements in Articles 2–7 and the
concordance below. A conflicting private rule must be changed or treated as
nonconformant; it cannot silently override this public standard.

---

## Article 1 — One Specification Chain of Record

There is exactly one normative history for rapp/1:
**`anchor/chain.jsonl`, the append-only DOGG specification chain.** Every
protocol adjustment appends one valid `rapp/1` frame extending the prior head.
The frame hash is the durable protocol-revision identity; `rev-N` names are
lookup labels. Historical frames remain immutable and globally resolvable.

The chain is unsigned and does not authenticate its own head. It proves that
selected bytes form one intact history. Until an authenticated RAPP registry or
checkpoint is ratified, the authoritative selection is the chain snapshot
accepted by the owner onto protected `refs/heads/main` in
`https://github.com/kody-w/rapp-1`; an out-of-band pinned immutable commit and
head frame hash are equivalent selection evidence. A fork can be internally
valid without being authoritative.

For inline specification revisions, the frame payload carries the exact
normative UTF-8 text and its raw SHA-256 and byte length. `SPEC.md` is generated
from that text as the current human view; it is not independent authority.
`orient.json` is only a beacon to the head, and git is transport and provenance.
Mirrors, rendered books, and reference manuals carry provenance and never fork
the chain. Drift from a verified revision is a finding, not a second opinion.

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

Immutable governance history is a separate narrow exception. The rev-5 through
rev-13 anchor frames remain interpretable through their immutable pointer
payloads because erasing them would destroy the amendment record. Those payload
profiles are historical authority records, not permission to accept or emit a
retired live protocol form. No new specification revision after rev-13 may use
the legacy pointer-only profile.

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
product organization follows the master plan the registry points to. A master
plan cannot redefine this repository's protocol scope, authority, canonical
bytes, or amendment process. *(Cited by SPEC §7.6, §12.1 as Fed. Const. Art. X;
estate-product scope by SPEC §11 as Art. VII.)*

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

This Constitution and the protocol change by an owner-ratified pull request
that appends the corresponding valid specification revision frame to
`anchor/chain.jsonl`. The linearization point is owner-ratified acceptance of
the commit containing that frame onto protected canonical `refs/heads/main`.
Competing work based on an older head **must** rebase onto the accepted head and
regenerate; force-push, history replacement, or publication of a competing
successor as authoritative is prohibited.

Article numbers are **append-only**: an article is amended in place or
deprecated by a visible flag, never renumbered and never silently deleted — so
every citation ever made remains resolvable. The selected specification chain
is the amendment record. Git commits transport those bytes and preserve review,
provenance, protection, and ratification; git history is not a second normative
content source and never substitutes for the required chain append.

**Rev-14 transition.** Rev-14 is ratified under rev-13 Article 14, whose
then-effective text made the owner-ratified pull request and git history the
amendment mechanism. Owner acceptance of the prepared rev-14 chain snapshot onto
canonical protected main makes its final frame effective. The chain-append
process in this amended Article governs rev-15 and later.

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

## Article 16 — Growth Must Not Mutate the Serving AI

A production AI is a versioned serving lineage, not a writable checkout.
Capability growth occurs in an isolated candidate lineage and reaches users
only after the exact candidate earns promotion through machine-verifiable
evidence.

1. A candidate becomes immutable when qualification begins. Every stage
   evaluates and promotes the same content-addressed release; rebuilding,
   patching, substituting, or restoring different bytes between gates is
   forbidden.
2. Preprod is a production-shaped gate, not another mutable development ring.
   It must exercise the exact candidate, authenticated dependencies, state
   compatibility, rollback, and restore before production approval.
3. A serving AI must not rewrite its code, agents, prompts, models, tools,
   policies, or state schema in place. Learning and self-improvement produce a
   new candidate identity while acknowledged user state remains protected.
4. User exposure is progressive, bounded, observable, and reversible.
   Unhealthy or stale evidence freezes advancement; cell isolation,
   quarantine, explicit degradation, or exact rollback contains failure
   without presenting failure as success.
5. Production health is continuously renewed. Model, tool, dependency,
   behavior, state, security, privacy, capacity, cost, and regional health are
   evidence-bearing release properties, not assumptions made once at deploy.
6. **RAPP CI/CD** (`rapp-cicd/1`) and **RAPP Deploy** (`rapp-deploy/1`) are the
   normative operational profiles for an estate claiming RAPP production
   conformance.
7. A portable, self-documented organism may continue growing after graduation
   by producing a newly identified offspring. A cross of two or more organisms
   creates another new identity with explicit typed parent addresses; it never
   merges parent identities, authority, ownership, or history. Each concrete
   attempt remains bounded even though the lineage may continue indefinitely.

These profiles wrap RAPP/1; they do not enlarge its wire or mutate its
primitives. Their invariant core stays deliberately small. New checks,
component kinds, health objectives, and resilience controls are policy-defined
extension points so the platform can innovate without weakening safety or
forking the protocol.

This article is entrenched. Future amendments may strengthen its evidence and
recovery requirements, but may not authorize unqualified user traffic,
in-place serving mutation, silent degradation, or bypass of a red gate.

## Article 17 — RAPP Is the Foundation; This Repository Is the Protocol

The canonical public RAPP foundation, product home, reference implementation,
organism model, and philosophy remain in `kody-w/RAPP`.

This repository, `kody-w/rapp-1`, is the protocol authority: canonicalization,
content addressing, identity, frames, wire, eggs, trust, registries, and
protocol-level profiles.

1. Protocol authority does not transfer product authority.
2. A downstream Rappter or RapterBox LLC product may implement RAPP/1 without
   becoming part of the foundation or this protocol repository.
3. Private company doctrine, ownership administration, customer data, and
   proprietary product code do not belong here.
4. `FOUNDATION.json` pins the canonical product-home relationship.
5. `PHILOSOPHY.md` in this repository is a byte-identical public mirror for
   protocol readers; on drift, the pinned `kody-w/RAPP` source wins.

This article changes repository scope, not RAPP/1 bytes or wire semantics.

## Article 18 — The Wire Is Frozen

The forms a `rapp/1` artifact is verified by — canonicalization, the hash and its
tags, the rappid grammar and mint, the eleven-key envelope and its addresses, the
consumer checklist, the two wire forms, and the egg container and address (SPEC
§4, §5, §6.1–6.2, §7.1, §7.3, §7.5, §8, §9.1) — **never change under the `rapp/1`
token.** A change to any of them is a new token, `rapp/2`, specified beside this
one; `rapp/1` artifacts verify forever, and no consumer may refuse one because a
later token exists.

Article 3 governs an estate's own artifacts and retired legacy encodings. It does
not reach the frozen wire. Article 4 is how `rapp/1` keeps growing: registration,
vocabulary, profiles, and the registry.

*Why:* an independent implementation must be finishable. Linux never broke
userspace and outlived every competitor that did. A protocol that can revise the
bytes a stranger already wrote code for is a protocol that stranger cannot bet
on. Freezing the wire is the estate giving up the right to be wrong in one place
so that everyone else can rely on it in every other.

This article changes no `rapp/1` bytes; it binds every future revision.

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

*Drafted 2026-08-26 in public session. Article 15 owner-authorized 2026-08-29;
Articles 16–17 and the complete public Protocol Constitution owner-ratified
2026-08-30. Article 18 drafted 2026-09-01; ratified by the merge carrying rev-15. The merge introducing these exact bytes is the public ratification
record. One spec, one canonicalizer, one mint, one frame, one immutable Grail,
one qualified path to users.*
