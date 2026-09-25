# Extending RAPP without touching rapp-1

RAPP grows by registration, never by fork (Constitution Art. 4). The unit of extension
is not a pull request to this repository — it is an **estate**: a party that publishes
its own signed §13 registry. A vendor's factory, a company, a team, one laptop: each is
an estate the moment it has an `estate_owner` rappid and a registry document that owner
signs. This page is the lane. Nothing on it needs a change to `rapp/1`.

## What an estate owns

| You want | Where it lives | Spec |
|---|---|---|
| your own event vocabulary (`acme.widget-made`) | a `kind` entry in **your** registry, bound to `memory`, `swarm`, or `body` | §6.1.1, §7.2, §13.3 |
| your own egg variant or error code | `egg-variant` / `error-code` entries in your registry | §13.3 (see the open question below) |
| your signers and their keys | `spki` entries; rotation by `re-anchor`; compromise by `tombstone` | §10, §13.2 |
| your production runtime pinned | a `grail-kernel` entry | §11.1 |
| a subordinate profile (`acme-factory/1`) with its own normative text | **your** repository; adopted by a `protocol` entry pinning repo, path, and SHA-256 | §11.2, `protocols/README.md` |
| tooling that needs a library (Ed25519 signing, HSMs, a database) | **your** repository; it imports `rapp.py`'s canonicalizer, never re-types it | Art. 10 |
| to say which RAPP/1 you implement | a `protocol` entry `name:"rapp/1"` whose `spec_hash` comes from **this** repository's anchor | §13.3 |
| to say an organism is deprecated, superseded, or archived | `lifecycle` entries (one signed chain per rappid) | §13.5 |
| the registry document itself | exactly `schema`, `registry_seq`, `canonical_source`, `entries`, `sig`; other members carry no meaning | §13.1 |

Every estate pins RAPP/1 the same way, so two estates interoperate on bytes while
disagreeing on everything else. That is the point.

## The rules that keep the wire shared

1. **The first label of a kind is yours; the family is a binding.** `acme.widget-made` is
   grammatical (§6.1.1) and means nothing until your registry binds it to a family.
   Nothing infers family from the prefix — ever (§6.1.1: "never prefix inference").
2. **Never claim the `rapp/1` name or namespace** for another protocol (§13.3). Your
   profile is `acme-factory/1`, subordinate to `rapp/1`, and refuses in favour of
   `SPEC.md` on conflict (`protocols/README.md`).
3. **No new endpoint, no new envelope.** Eleven keys, `POST /chat`, or an append-only
   frame. New capability is a new agent behind `/chat` or a new registered kind (§8, Art. 4).
4. **Unsigned is a draft.** A registry without the owner's §10 signature can be
   published, reviewed, and rehearsed, and it authorizes nothing (§13.1). The reference
   (`rapp_registry.load_document`) reports it as `draft`, never `verified`. The loader also
   requires the caller's out-of-band trust anchor (the estate-owner rappid) and refuses a
   registry that names any other owner before it looks at the signature.
5. **Pin through the anchor, not by hand.** Read `spec.normative_sha256` from
   `anchor/orient.json` (or a commit-pinned copy of it) when you write your `protocol`
   entry. A hand-typed hash rots silently; `examples/07_your_own_estate.py` shows the
   resolving form.

## The reference will check your estate

```bash
python3 examples/07_your_own_estate.py      # a complete fictional estate, checked end to end
```

`rapp_registry.py` (stdlib only) validates every §13.3 entry type to its exact member
set, binds kinds to families and families to stream forms, walks owner succession, and
applies superseded-key and tombstone refusal at a time. Feed `Registry.signature_verifier()`
to `rapp.verify_frame(signature_verifier=…)` and signed frames resolve their keys from
your registry. Signature verification itself uses the optional `cryptography` import
inside `rapp.verify_detached_jws`; without it, signed artifacts are refused, never
assumed.

`Registry.lifecycle_state_at(rappid, utc)` answers from an organism's signed
`lifecycle` chain (§13.5) whether it was active, deprecated, superseded, or archived
at that time, and returns `None` — never a guessed deprecation — when none of the
estate's notices is in effect then. `Registry.successor_at(rappid, utc)` returns the
successor that the notice in effect then names, or `None` (a scheduled notice names
none before its `since_utc`); naming grants nothing, and because only current notices
are acyclic, a walk along successors at one time stops where it has already been.
Notices are persisted like every declared entry: pass the ones you accepted back as
`persisted_entries=`, and a later registry that drops or rewrites one is refused, so a
state changes only by a new notice on the record.

`load_document` also verifies key-lifecycle entries: a valid enclosing registry
signature is not a substitute for a tombstone or re-anchor's own signature. The
same holds for every declared entry (§13.4, today `grail-kernel` and `lifecycle`): its own owner
signature is checked at its `activated_utc`, `first_seen=` (or `verification_utc=`
for a first sighting) applies the per-entry 300-second first-seen bound, and
`persisted_entries=` refuses a later registry that dropped or changed a
declaration. A copy of a declared entry found outside the registry counts only
when it is byte-identical to one the registry carries.
The issuer must be the owner in tenure at the authenticated issuance/action
time; an owner's own succession record is signed by the outgoing owner at that
boundary, after checking that its tenure is nonempty and chronologically
possible. A required rotation proof must come from a key that was not already
retired, excluding only the supersession introduced by that record.
For that required proof, retirement is matched by the validated key tail, so
renaming the source RAPPID cannot revive the same retired SPKI. Optional
old-key signatures on compromise records are checked cryptographically without
pretending the compromised key still has authority. Compromise requires a
registered tombstone. Ambiguous predecessors and reused ancestral key tails
(including renamed aliases) are refused rather than silently choosing one.

Tombstones require explicit caller configuration:
`load_document(..., tombstone_issued_at=resolver)`. The resolver receives
`H("rapp/1:particle", entry)` for the exact signed entry and must return an
authenticated issuance UTC from accepted history or an explicitly trusted
estate profile. It is not a document field or an unverified caller-supplied
timestamp. Without this evidence the loader refuses to guess. In particular,
`revoked_utc` is an effective revocation cutoff, not proof of when the tombstone
was issued.

This is still not a complete distributed consumer. The caller retains trusted
heads and registry high-water marks, enforces freshness, and verifies the history
needed to establish a compromise tombstone's **same-append** provenance. A
standalone snapshot cannot prove when each entry was appended. Historical
upgrade/tag-migration evidence and owner-authorized re-genesis remain separate
checks. The reference canonicalizer implements the documented exact-integer
profile; it is not an implementation of every binary64 input allowed by JCS.

## What is not yet closed (do not improvise it — it is a rev-N+1 conversation)

These are recorded in `rapp-backlog.md` for the owner's ratification. Until then they
are interoperable only by out-of-band agreement, and a candidate registry should say so.

- **The registry document's container** — closed by rev-17 (§13.1): the entries are the
  `entries` member and the document carries its own `canonical_source`. It becomes
  normative when the owner accepts the rev-17 chain snapshot; until then the loader already
  refuses any other entries-member name.
- **Tombstone issuance time.** §13.2 scopes an issuer's authority to the
  artifact's time, but the exact tombstone entry carries only `revoked_utc`,
  not a separate issuance time. A current owner can discover an earlier
  compromise cutoff. Equating those two times would invent an interoperability
  rule. Until a ratified profile closes this gap, the loader requires the
  explicit trusted issuance resolver described above.
- **Kind ownership across estates.** On a `net:` swarm stream, two estates could bind the
  same kind string to different families. A namespace rule (the first label belongs to one
  estate) would close it; today it is a convention.
- **Egg variants: closed at the protocol, or estate-registered?** §9.2 calls its seven
  variants "the ratified set" and `rapp.py` hard-codes them, while §13.3 defines an
  `egg-variant` registry entry. A vendor variant is registrable but not packable by the
  reference until this is resolved.

## How to propose a change to `rapp/1` itself

First distinguish an extension from a change to a frozen form. Registered kinds,
registry entries, vocabulary and subordinate profiles can grow under `rapp/1`.
A twelfth frame key, a changed canonical form/hash tag, or a changed wire form
cannot be introduced by a later `rapp/1` revision: §12 and Constitution Article 18
require a new `rapp/2` token while existing `rapp/1` artifacts keep verifying.

Open an issue in the shape the existing ones use (a PII-free use case, the
ambiguous clause, the questions, and the fail-closed behaviour you adopt
meanwhile), then read `CONTRIBUTING.md`. A permitted normative amendment is
carried by an owner-ratified successor in the specification chain; `SPEC.md` is
its generated view, never an independently edited authority.
