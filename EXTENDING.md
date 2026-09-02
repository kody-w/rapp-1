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

## What is not yet closed (do not improvise it — it is a rev-N+1 conversation)

These are recorded in `rapp-backlog.md` for the owner's ratification. Until then they
are interoperable only by out-of-band agreement, and a candidate registry should say so.

- **The registry document's container.** §13.1 names `schema`, `registry_seq`, and `sig`;
  §13.3 names every entry; nothing names the member that holds the entries or how
  `canonical_source` is carried. `rapp_registry.load_document` therefore requires the
  caller to name the entries member — it will not guess.
- **Kind ownership across estates.** On a `net:` swarm stream, two estates could bind the
  same kind string to different families. A namespace rule (the first label belongs to one
  estate) would close it; today it is a convention.
- **Egg variants: closed at the protocol, or estate-registered?** §9.2 calls its seven
  variants "the ratified set" and `rapp.py` hard-codes them, while §13.3 defines an
  `egg-variant` registry entry. A vendor variant is registrable but not packable by the
  reference until this is resolved.

## How to propose a change to `rapp/1` itself

If your need cannot be expressed as a registration — a twelfth key, a new hash space, a
sibling endpoint — it is a revision. Open an issue in the shape the existing ones use
(a PII-free use case, the ambiguous clause, the questions, and the fail-closed behaviour
you adopt meanwhile), then read `CONTRIBUTING.md`: `SPEC.md` is generated from the chain
and a revision is appended with `anchor/update_anchor.py`, ratified by the owner.
