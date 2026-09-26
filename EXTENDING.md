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
| every component of one release of a family pinned together (an LTS line and its corrections, a newest channel) | one `release-pin` entry per pinned release + its `rapp/1-release-manifest` (`schema`, `release_scope`, `release`, `components`); the `release_scope` names the release family, and `release` names the release for people; paths are ASCII; a newest family graduates to LTS by being pinned in the LTS channel | §13.5 |
| to say an organism — or a repository that never minted a rappid — is deprecated, superseded, or archived, and since when | `lifecycle` notices (one signed chain per subject: a rappid, or a repository's HTTPS URI) | §13.6 |
| to let a key speak for you on one stream (a pulse, a notice feed) | `stream-signer` grants — keyless organisms stay keyless | §13.7 |
| your own signature on each of those four (a kernel, a release, a notice, a grant) | a declared entry: signed by the owner in effect at its `activated_utc`, retained unchanged once accepted; a copy elsewhere counts only when its canonical form equals a carried entry's | §13.4 |
| a subordinate profile (`acme-factory/1`) with its own normative text | **your** repository; adopted by a `protocol` entry pinning repo, path, and SHA-256 | §11.2, `protocols/README.md` |
| tooling that needs a library (Ed25519 signing, HSMs, a database) | **your** repository; it imports `rapp.py`'s canonicalizer, never re-types it | Art. 10 |
| to say which RAPP/1 you implement | a `protocol` entry `name:"rapp/1"` whose `spec_hash` comes from **this** repository's anchor | §13.3 |
| the registry document itself | exactly `schema`, `registry_seq`, `canonical_source` (an absolute HTTPS URI, or a URN for a private store), `entries`, `sig`; other members carry no meaning; an entry type a consumer does not implement is ignored unless marked `critical`; every number written as an integer (no fraction or exponent); at most 1 MiB canonical, so spend entries on releases and changes | §13.1, §13.3, §4 |

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
python3 examples/09_distributed_hive_lts.py # pinned releases, lifecycle notices, a pulse signer
```

`rapp_registry.py` (stdlib only) validates every §13.3 entry type to its exact member
set, binds kinds to families and families to stream forms, walks owner succession, and
applies superseded-key and tombstone refusal at a time. Feed `Registry.signature_verifier()`
to `rapp.verify_frame(signature_verifier=…)` and signed frames resolve their keys from
your registry. Signature verification itself uses the optional `cryptography` import
inside `rapp.verify_detached_jws`; without it, signed artifacts are refused, never
assumed.

`load_document` also verifies key-lifecycle entries: a valid enclosing registry
signature is not a substitute for a tombstone or re-anchor's own signature. The
same holds for every declared entry (§13.4: `grail-kernel`, `release-pin`,
`lifecycle`, and `stream-signer`): its own owner signature is checked at its
`activated_utc`, `first_seen=` (or `verification_utc=` for a first sighting) applies
the per-entry 300-second first-seen bound — a signed registry carrying a declared
entry is refused without one — and `persisted_entries=` (every declared entry you accepted, in the order
your accepted registry held them) refuses a later registry that dropped, changed, or reordered a
declaration. A copy of a declared entry found outside the registry
counts only when its canonical form equals one the registry carries — the same JSON value, however
it is formatted — and `Registry.declared_entry_ok(copy)` answers that only for a verified registry.
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

`verify_snapshot(registry, fetch, release_scope=…)` — or `channel=…`, or
`manifest_hash=…`, exactly one, never the manifest's `release` name — turns one
pinned release of a verified registry into a verified snapshot (§13.5): a family's
current release, a channel's head, or one exact pinned release, which a successor
supersedes without retiring. It fetches the pinned manifest and every pinned file
through your `fetch`, and returns the files only when the manifest's canonical bytes,
hash, and kernel coherence, every file's length and SHA-256, and every
door-of-record binding verify (`examples/09_distributed_hive_lts.py`). Pass every
declared entry you accepted as `persisted_entries=`: `load_document` then also refuses a
later registry that adds a `grail-kernel` to a family one of whose releases you
accepted. `rapp_check.py` lints a committed release manifest's structure and canonical
bytes and reports it as unverified evidence: it has authority only through a verified
`release-pin`.

`Registry.lifecycle_state_at(subject, utc)` answers from a subject's signed
`lifecycle` chain (§13.6) whether it was active, deprecated, superseded, or archived
at that time, and returns `None` — never a guessed deprecation — when none of the
estate's notices is in effect then. It answers only for a registry `load_document`
returned as "verified" (a draft only with `allow_draft=True`); a `Registry` you built
directly raises instead, so a `None` always means "no notice", never "not checked". A subject is an organism's rappid or, for a
repository that never minted one, its HTTPS URI spelled exactly as your release
manifests spell it; `lifecycle_subject(component)` picks the right one for a release
component, so a station keeps a signed lifecycle without an identity of its own, and
moving it is a `superseded` notice naming its new repository.
`Registry.successor_at(subject, utc)` returns the successor — a rappid or a repository
URI — that the notice in effect then names, or `None` (a scheduled notice names
none before its `since_utc`); naming grants nothing, and because a registry whose
successors in effect at any one time form a cycle is refused whole, a walk along the
successors in effect at one time always ends.
Notices are persisted like every declared entry: pass the ones you accepted back as
`persisted_entries=`, and a later registry that drops or rewrites one is refused, so a
state changes only by a new notice on the record.

Stream signers decide who speaks for you on a stream (§13.7).
`Registry.verify_authorized_frame(frame, head=…, stream_id_of_record=…)` runs §7.5 with
your registry's `signature_verifier()`, kind binding included, and then the authority
rule: a valid frame whose signer is neither your owner in effect nor granted its stream,
kind, and time fails at step `"authority"`, never at a §7.5 step, and
`Registry.authorization_verifier()` hands the same rule to a profile's
`authorization_verifier`. Like `verify_snapshot`, these answer only for a registry
`load_document` returned as "verified" (a draft only with `allow_draft=True`, as a
rehearsal; a `Registry` you built directly never); `authority_decision` is the bare
rule over the entries. §13.7 binds a consumer that follows no profile-defined signer
rule; a profile with its own (`rapp-work/1` §1, a `rapp-cicd/1` stage approver) keeps it
and may meet it this way. A grant may start before its `activated_utc` and so adopt
frames already published in its window. Authority is decided against the verified
registry in hand: a newer registry can add a grant that adopts earlier frames but never
withdraw one, so re-evaluate a cached refusal against a newer registry.

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
