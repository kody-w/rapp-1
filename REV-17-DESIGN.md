# RAPP/1 rev-17: design of record

**Status:** proposed. This document explains the rev-17 draft; it is not normative. The normative text is
[`SPEC.md`](SPEC.md) as materialized from the rev-17 draft frame, and the executable checks are
[`rapp_registry.py`](rapp_registry.py). Rev-17 becomes in force only when the owner accepts its chain
snapshot onto protected `main` (§12.2). Until then every rule below is a draft, and no estate registry uses
the new entry types.

## 1. Why a revision, and what it may not touch

RAPP/1 is the long-term-support release of the whole ecosystem: one estate-signed release pins every
component, and a successor release family uses a new release scope. The distributed Hive is the goal: the
network is one Hive of plain folders and files, found by raw URL, and "instant full RAPP/1" is one command
that resolves the graph at pinned commits into a verified local snapshot. Rev-17 adds what that needs, and
only by growth (Constitution Art. 4, §12): registry entry types and the registry container.

Nothing frozen moves. §12 "freezes every form a `rapp/1` artifact is verified by (§4, §5, §6.1–6.2, §7.1,
§7.3, §7.5, §8, §9.1)". Rev-17 adds no hash tag, no §7.5 step, no re-anchor case, no frame key, and no
change to `rapp.py`. The proof runs on every branch: `rapp.py`, `conformance/vectors.json`, and
`anchor/bootstrap*` are byte-identical to rev-16 `main`; rev-16's chain is a byte prefix of the rev-17
chain; the rev-17 head frame has the eleven keys and token `rapp/1` and verifies as rev-16's successor;
and every rev-16 conformance vector (canonical forms, frame and tamper cases, egg address) reproduces.

## 2. Decisions

Evidence is quoted from `main` at `591e014` (rev-16).

| # | Hypothesis | Needed? | Evidence (§ and quote) | Change |
|---|---|---|---|---|
| 1 | Component pins per release scope, so the LTS scope pins every component | **Yes** | §11.1: "at most one `grail-kernel` entry for any release scope" and "an existing scope is never rebound"; §13.3 `grail-kernel`: `path` at `commit` "**MUST** resolve through the repository tree to exactly one regular blob"; §13.3 `protocol` is "an estate adoption pin" with no scope and no commit. One kernel file per scope cannot pin a release of many repositories, and §4 caps a registry at 1 MiB. | `release-pin` declared entry naming a `rapp/1-release-manifest` by particle hash; release families, channels, kernel coherence and order, and all-or-nothing verified snapshots (§13.5) |
| 2 | Estate-signed lifecycle (deprecated, superseded, archived; `superseded_by`, since) | **Yes** | §13.3: "retirement is a `deprecated:true` flag" on registry entries only; §10: "Compromise is declared by an owner-signed **tombstone**" (keys, not organisms); §6.2: "Re-anchor is lawful in exactly three cases" (identity, not succession). Nothing carries a successor or a start time. | `lifecycle` declared entry: one signed chain per **subject**, a rappid or the HTTPS URI of a repository that has no rappid (§13.6) |
| 3 | Stream signer authorization for the network's `body.pulse` stream | **Yes** | §7.5 step 6: "if `sig`≠null, verify per §10"; §10 resolves the signer's key "from the §13 registry" — any registered key, on any stream. Role binding exists only where a rule names it: invites "**MUST** verify with `kid` in the §13.2 estate-owner succession", sealed eggs need `kid` "exactly equal to `manifest.rappid`", and owner-signed registry records. | `stream-signer` declared grant; an authority check above §7.5 that adds no §7.5 step (§13.7) |
| 4 | Estate-signed member inventory binding: rappid, then repo, then raw base, then LTS ref | **Yes, inside 1** | §6.1: `owner = lclabel ; the lowercase GitHub login` and `slug = lclabel` — a rappid names no repository (repository names such as `RAPP` or `RAPP_Store` are not lclabels); §10 names "the door-of-record `rappid.json`", but nothing binds one. | Each manifest component binds `rappid` (optional) → `repository` → `commit` (the LTS ref) → `files` (bytes), with `identity_path` proving the door of record (§13.5). The raw base is not signed: for GitHub it is derived (`https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>`), and any other transport (a LAN host, `file://`) is fine because every byte is checked against the pinned digest. Signing it would add no security and would tie releases to one substrate. |
| 5 | Keyless identities for about 300 station repos; can estate-bound keys be added without a re-anchor (§§6.2, 6.3)? | **No new mechanism** | §6.2: keyless "`tail = Hb("rapp/1:rappid", uuid4_octets)`"; "Re-anchor is lawful in exactly three cases"; §10: keyless rappids "assert location, not authorship"; §12 freezes §6.1–6.2. | A keyless identity can never gain its own key: there is no lawful fourth re-anchor case, and adding one would change a frozen form (`rapp/2`). Estate-bound keys are added without any re-anchor as `stream-signer` grants — authority, not identity. Releases (component `rappid: null`) and lifecycle notices (repository subjects) need no rappid, so the lock needs no station minting. |
| 6 | Should the discovery chain (seed, beacon, sniff schemas) become a RAPP/1 subordinate protocol? | **No** | Constitution Art. 17: this repository is "canonicalization, content addressing, identity, frames, wire, eggs, trust, registries, and protocol-level profiles", while RAPP keeps the "foundation, product home, reference implementation, organism model, and philosophy". The seed is an observation-only document, and the live beacon and `estate.json` paths serve placeholder status documents. | None here. §13.5 makes every discovery document a locator, so trust never depends on it; the LTS manifest pins the discovery convention and its resolver by digest as RAPP files. Revisit only if a second independent resolver needs a wire contract. |
| 7 | `body.pulse` binding, payload, and stream id | **No core change** | §7.2 defines the `body` family; the published estate registry (`registry_seq` 2) binds `body.pulse` to it; §6.1.1: a body stream id is a rappid; §8: "memory/body-stream frames **MAY** be unsigned"; §13.3: "every stream registers its creation genesis". The network's live stream `rappid:@kody-w/rapp1-network:71216534…` is keyless; its first pulse is a valid `rapp/1` frame that binds to `body.pulse` (checked with this reference), and its genesis is not yet registered. | None. The stream id is the network organism's rappid; the payload belongs to the network convention (RAPP), and an estate may adopt a written payload contract with an ordinary `protocol` entry. The estate registers the stream's `genesis`, then grants a keyed pulse signer (§13.7). Until then pulses are integrity-only. |
| 8a | Registry container | **Yes** | `EXTENDING.md`: "nothing names the member that holds the entries or how `canonical_source` is carried". | §13.1 names exactly `schema`, `registry_seq`, `canonical_source`, `entries`, `sig`; any other member carries no meaning. The published registry already has this shape and still verifies. |
| 8b | Entry-level signatures | **Yes** | §13.3 `grail-kernel`: "A consumer verifies the entry signer as the estate owner in effect at `activated_utc`"; §11.1: `activated_utc` "**MUST NOT** be more than 300 seconds after the verifier's first-seen time". The reference checked only tombstone and re-anchor signatures. | §13.4 declared entries: owner-in-effect signature at `activated_utc`, a per-entry first-seen bound, byte-identical copies only, and retention of every accepted declaration. |
| 8c | LTS corrections | **Yes, inside 1** | §11.1: "at most one `grail-kernel` entry for each `grail_id`" and "an existing scope is never rebound": a correction that keeps kernel v0.6.9 cannot declare it again under a new scope. | A release scope names a release **family** with at most one kernel; its releases are successive `release-pin` entries in one channel. A new kernel is a new family (a new scope). |
| 8d | Reference answers from unverified registries | tooling | `Registry.protocols` returned the first pin per name — for the published registry, a deprecated one; authority answers ignored whether the registry had been verified. | `current_protocol` returns the sole non-deprecated pin. Every answer — `verify_snapshot`, `frame_authorized`, `verify_authorized_frame`, the lifecycle in effect (`lifecycle_at`, `lifecycle_state_at`, `successor_at`), and `declared_entry_ok` for a copy — comes only from a registry `load_document` returned as verified (a draft only with `allow_draft=True`); structural accessors stay readable. Registry time values must be ASCII, because the frozen `rapp.utc_valid` also accepts other scripts' digits. |

Not blocking the lock, and left open in `rapp-backlog.md`: tombstone issuance time, kind ownership across
estates, egg-variant closure, the registry's lifetime capacity (§6), and a `rapp.utc_valid` fix for
non-ASCII digits in frames (the registry already refuses them; `rapp.py` changes only through its parity
process). One limit is recorded for estates rather than changed here: profile adoption
pins are estate-wide, and `rapp-work/1` requires exactly one active pin per profile name whose hash is the
implementation's own, so the LTS line and the newest channel share each profile text. A changed profile
text is therefore a new profile name (for example `rapp-work/2`) adopted beside the old one, never a moved
pin; a release manifest also pins the texts each release was built against.

## 3. Reuse before adding

The nine existing §13.3 entry types were each considered first.

- **`grail-kernel`** pins one blob per scope, and one entry per `grail_id`: it cannot pin a release of many
  repositories, nor the kernel's companion files, and a correction cannot repeat it. Rev-17 keeps it as the
  family's kernel binding and requires every release manifest of the family to agree with it.
- **`protocol`** is an estate-wide adoption pin (`spec_repo`, `spec_path`, `spec_hash`) with no commit and
  no scope; profiles require one active pin per name. It stays the adoption record.
- **`genesis`, `kind`, `spki`** register streams, kinds, and keys. The pulse stream needs them unchanged.
- **`tombstone`, `re-anchor`** revoke keys and move identities in three lawful cases. Neither retires an
  organism, names a successor, or binds a key to a stream.
- **`egg-variant`, `error-code`** are unrelated.
- The `deprecated` flag retires a registry entry, not an organism or a repository.
- Outside §13.3, the `rapp-cicd/1` release capsule pins one product's single source commit and artifact,
  with components identified only by digest: it has no per-component repository, commit, or path, so it
  cannot fetch or verify many repositories, and it travels in a signed frame that itself needs signer
  authority.

So rev-17 adds three declared entry types, and one document outside the registry (the release manifest),
so that a release of about 300 repositories costs one registry entry.

## 4. The entries

Every declared entry carries `activated_utc`, `declared_by`, and `sig`. `sig` is a detached §10 JWS by the
estate owner in effect at `activated_utc` (`kid` = `declared_by`) over `canonical(entry \ {sig})`, and the
whole registry is refused if one entry fails (§13.4). An entry's bytes are its canonical form (§4): every
accepted declaration is retained unchanged by every later registry, and a copy elsewhere counts only when
its canonical form equals that of an entry of an accepted registry, however it is formatted.
`H("rapp/1:particle", entry)` over the complete signed entry names it.

```text
release-pin   {type:"release-pin", release_scope, channel, predecessor, manifest_hash,
               repository, object_format, commit, path, activated_utc, declared_by, sig}
lifecycle     {type:"lifecycle", subject, state, superseded_by, since_utc, previous,
               activated_utc, declared_by, sig}
stream-signer {type:"stream-signer", stream_id, signer, kinds, since_utc, until_utc,
               activated_utc, declared_by, sig}
manifest      {schema:"rapp/1-release-manifest", release_scope, release, components:[component]}
component     {id, kind, rappid, identity_path, repository, object_format, commit, immutable_ref,
               files:[{path, sha256, size_bytes}]}
registry      {schema:"rapp/1-registry", registry_seq, canonical_source, entries, sig}
```

- **Release pins (§13.5).** `release_scope` names a release family; a family's `grail-kernel`, if any,
  appears before its first `release-pin`, and none joins a family after one of its releases was accepted.
  `channel` is an lclabel; each channel is one linear chain through `predecessor` (the `manifest_hash` of
  the pin it follows), and its head is the channel's current release. `manifest_hash` is unique. The
  manifest is stored as exactly `canonical(manifest)` at an immutable commit. Components are sorted by
  `id`; files by the UTF-8 bytes of `path`, under the §9.1 path grammar; `sha256` is over raw bytes. A
  component with `rappid` names its door of record through `identity_path`. When the family has a kernel,
  exactly one `kind:"kernel"` component matches the `grail-kernel` entry. A verified snapshot is every
  pinned file, checked by length and SHA-256, or nothing.
- **Lifecycle notices (§13.6).** `state` is `active`, `deprecated`, `superseded`, or `archived`; `active`
  names no successor and `superseded` must name one. `subject` and `superseded_by` are rappids or HTTPS
  repository URIs, compared byte-for-byte. One chain per subject through `previous` =
  `H("rapp/1:particle", earlier entry)`; `since_utc` and `activated_utc` never decrease; the notice in
  effect at `t` is the last whose `since_utc` ≤ `t`. The successors in effect at any one time never form a
  cycle. A component's lifecycle is read from its `rappid` when it binds one, otherwise from its
  `repository`. A re-anchor moves no chain: the new rappid has notices only if the estate declares them.
  A notice grants and revokes nothing.
- **Stream signers (§13.7).** `signer` is a keyed rappid with an `spki` entry in the same registry; `kinds`
  are registered kinds (deprecated or not) whose family fits `stream_id`'s form, strictly ascending, and
  never a re-genesis kind; the window is `since_utc` ≤ `utc` < `until_utc` (or open). A consumer that
  follows no profile-defined signer rule treats a verified frame as the estate's statement only when its
  `kid` is the owner in effect or a covering grant's signer. Unsigned frames never speak for the estate.
  Grants are never inherited across a rotation. A registry whose grants break these rules is refused
  whole.

The exact JSON Schemas are in the appendix.

## 5. The distributed Hive against these entries

The distributed Hive's own documents set the requirements: RAPP proposal 0020 on
`experimental/proposal-0020-distributed-hive` and HIVE-MD's "Remote member spaces" on `kody-w/rapp-model-hive`
`experimental/hive-md-distributed`. Proposal 0020 says hashes prove integrity only and that "How that
signature covers the `hives[]` pin is RAPP/1's to define (§10, §13)". HIVE-MD says authenticity "stays
unverified until the estate that pins this root is anchored". Rev-17 answers both.

- **The Hive root and every station, authenticated.** The LTS release manifest pins the Hive root's public
  copy as a component (for example `kind:"hive"`) at its commit, with `PUBLISHED.md` and the member
  pointers as files, and pins each station as a component at its LTS commit with the files the network
  reads (its member card and shared files). `estate.json`'s `hives[]` entry, the beacon, the seed, and the
  pointers stay locators: they must agree with the manifest, and a disagreement is a drift finding. A
  resolver produces the verified snapshot with `verify_snapshot(registry, fetch, channel=…)` and matches
  pointers to components by `repository`.
- **Hashes.** The manifest pins raw bytes. HIVE-MD lists the SHA-256 of text normalized to LF and NFC.
  For every file the Hive accepts (it refuses carriage returns) that is already NFC, the two are equal, so
  a resolver checks both; the raw digest is the one with authority.
- **LTS pins.** The release manifest is the signed LTS pin set. A separate `lts-pins.json` should be
  generated from it, never maintained beside it.
- **Lifecycle.** Pointers, cards, and portfolio entries carry lifecycle as copies. They should use exactly
  the four §13.6 states so a copy can be checked against the signed notice; the current Hive draft's
  `frozen` and `retired` have no §13.6 meaning (`archived` is the state for a repository kept readable
  with no further releases).
- **Stations without rappids.** A station is pinned with `rappid: null` and has lifecycle notices under its
  repository URI. A move is a `superseded` notice naming the new repository.
- **Doors of record.** A door-of-record binding needs a strict JSON identity file at the pinned commit. The
  Hive's public copy publishes JSON as markdown-wrapped pages (for example `portfolio/rappid.json.md`),
  which do not parse as JSON; until a plain `rappid.json` is published at a pinnable public path, the
  network organism's component carries `rappid: null`.
- **Pulses.** Walk and crawl pulses are `body.pulse` frames on the network organism's existing keyless
  stream. They verify as frames today; they speak for the estate once the estate grants a keyed pulse
  signer and the frames are signed.

## 6. For the estate that signs

- **Entry order.** `estate_owner` and `spki`; `kind`; the pulse stream's `genesis`; each family's
  `grail-kernel` before that family's first `release-pin`; the `release-pin` entries; `lifecycle` notices;
  `stream-signer` grants after their signer's `spki` and their kinds.
- **Families, channels, scopes.** One release scope per kernel family, for example an LTS family bound to
  kernel `brainstem-v0.6.9` and a newest family per newest kernel. Corrections of the LTS release are new
  `release-pin` entries of the same scope in the LTS channel; the newest channel moves to each new family.
  Channel names are lclabels; the portfolio's words `rapp1-lts` and `newest` fit.
- **Manifests.** Publish each manifest as exactly its canonical bytes in a **public** repository at an
  immutable commit (the release pin's locator), for example under `releases/<manifest_hash>.json`. The
  kernel component carries the `grail-kernel` entry's repository, object format, commit, and tag, pins the
  kernel file with the entry's digest and size, and pins the kernel's other frozen files beside it.
- **Components.** One per repository at its LTS commit. `id` is an lclabel (lowercase ASCII and hyphens),
  so map repository names to ids once and keep them; `repository` is `https://github.com/<owner>/<repo>`
  spelled as the estate always spells it. Suggested kinds: `kernel` (reserved), `protocol`, `organism`,
  `hive`, `station`, `document`. Pin normative bytes and member cards; a front door such as a README may
  be pinned too, since a release freezes only its own snapshot and the repository's head stays editable.
- **Lifecycle.** Declare notices for changes: deprecations, supersessions, moves, archiving. No notice
  means no declared lifecycle, never deprecation, so an active repository needs none. The subject is the
  component's rappid when it has one, otherwise its repository URI.
- **Pulse signer.** Register the existing stream's `genesis` (its first frame's `frame_hash`), then one
  grant `{stream_id: <network rappid>, signer: <pulse key rappid>, kinds: ["body.pulse"], since_utc,
  until_utc: null}` for a dedicated keyed pulse key whose private half never enters a repository. This
  keeps the stream and its history; a new keyed stream would start another.
- **Loading and persistence.** Load a signed registry that carries declared entries with
  `verification_utc=` (first sighting) or `first_seen=` (from persisted first-seen times), persist every
  accepted declared entry, and pass them back as `persisted_entries=` next time.
- **Size.** The registry is capped at 1 MiB canonical (§4) and every entry is append-only, so it has a
  lifetime budget. With realistic URIs and an EdDSA signature a declared entry is 0.65–0.95 KB (a
  `release-pin` about 0.95 KB, a notice 0.65–0.75 KB, a grant about 0.75 KB); the published registry's
  other entries take about 4 KB. That leaves room for roughly 1,100–1,500 declared entries, ever. A
  release costs one entry however many components it pins, so spend them on releases and changes: pin
  every LTS correction, pin the newest channel at milestones rather than every build, and declare
  notices only for changes. At that cadence the budget lasts years; a continuation mechanism is recorded
  in `rapp-backlog.md` for design before an estate approaches the cap.

## 7. Owner-only choices

1. **Accept rev-17.** Recommendation: accept the integrated draft (`experimental/rapp1-core-rev17`) as one
   revision. The slices `experimental/rapp1-core-registry-container`, `-release-pin`, `-lifecycle`, and
   `-stream-signer` carry the same rules one piece at a time (each numbered §13.5), for a partial choice.
2. **Station identities.** Recommendation: mint none for the lock. When a station needs a stable identity,
   mint it keyless if its streams can be signed by a granted key, and keyed only if it must seal eggs or
   sign as itself. Minting is permanent (§6.2).
3. **The pulse signer.** Recommendation: a dedicated keyed pulse key granted on the existing stream, rather
   than the estate-owner key or a new stream.
4. **Scope URIs and channel names.** Recommendation: one scope per kernel family; channels `rapp1-lts` and
   `newest`.
5. **"A successor release uses a new scope."** Recommendation: read it as a successor release family — a new
   kernel — using a new scope, while corrections that keep the LTS kernel stay in the LTS scope. §11.1's
   one `grail-kernel` per `grail_id` requires this.

## 8. Verification

Every branch runs the full CI-equivalent gate: `conformance.py` (22), `operations_conformance.py` (54),
`work_conformance.py` (17), `registry_conformance.py` (every registry test module plus the language-neutral
`conformance/registry-vectors.json`), `anchor.test_spec_chain`, materialization, anchor idempotence, the
front doors, the Internet-Draft, `conformance/make_vectors.py --check`, parity, `rapp_check.py .`, every
example, `test_rapp_work`, and the token and envelope proof in §1, on Python 3.9 and 3.14, plus a
`signatures` CI job that runs the registry suite with real Ed25519 keys and refuses skips. Against real
data: the published estate registry (`registry_seq` 2) still verifies; `rapp_check.py` gives byte-identical
output with and without rev-17 on the RAPP, model Hive, public Hive copy, and estate repositories; and the
network's first pulse verifies as a frame and correctly does not yet speak for the estate. The schemas
below agree with `rapp_registry.py` on every value in the registry vectors, except values refused only by
rules a schema cannot state (listed with each schema).

## Appendix: JSON Schemas (informative)

`rapp_registry.validate_entry`, `validate_release_manifest`, and `validate_document` are the checks; these
schemas express the same single-object rules for tools that want a schema, and each `description` lists
the rules only the reference can check. `test_registry_container.py` keeps their member lists equal to the
reference's.

<!-- schemas:begin -->
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:rapp:1:rev-17:registry-additions",
  "title": "RAPP/1 rev-17 registry additions (informative; rapp_registry.py is the executable check)",
  "$defs": {
    "rappid": {
      "description": "§6.1 rappid: rappid:@<owner 1-39>/<slug 1-100>:<64 lowercase hex>, owner and slug lclabels",
      "type": "string",
      "pattern": "^rappid:@(?=[a-z0-9-]{1,39}/)[a-z0-9]+(?:-[a-z0-9]+)*/(?=[a-z0-9-]{1,100}:)[a-z0-9]+(?:-[a-z0-9]+)*:[0-9a-f]{64}$"
    },
    "utc": {
      "description": "§7.4 fixed UTC form; must also be a real calendar time (rapp.utc_valid)",
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
    },
    "https": {
      "description": "absolute HTTPS URI, no whitespace",
      "type": "string",
      "pattern": "^https://[^\\s]+$"
    },
    "hex64": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
    },
    "lclabel64": {
      "type": "string",
      "pattern": "^(?=.{1,64}$)[a-z0-9]+(?:-[a-z0-9]+)*$"
    },
    "lclabel100": {
      "type": "string",
      "pattern": "^(?=.{1,100}$)[a-z0-9]+(?:-[a-z0-9]+)*$"
    },
    "kind": {
      "description": "§6.1.1 kind: lclabel '.' lclabel, each 1-64",
      "type": "string",
      "pattern": "^(?=[a-z0-9-]{1,64}\\.)[a-z0-9]+(?:-[a-z0-9]+)*\\.(?=[a-z0-9-]{1,64}$)[a-z0-9]+(?:-[a-z0-9]+)*$"
    },
    "stream_id": {
      "description": "§6.1.1 stream forms: body-stream (a rappid), memory-stream (rappid ':' lclabel 1-64), swarm-stream ('net:' lclabel)",
      "anyOf": [
        {
          "$ref": "#/$defs/rappid"
        },
        {
          "type": "string",
          "pattern": "^rappid:@(?=[a-z0-9-]{1,39}/)[a-z0-9]+(?:-[a-z0-9]+)*/(?=[a-z0-9-]{1,100}:)[a-z0-9]+(?:-[a-z0-9]+)*:[0-9a-f]{64}:(?=[a-z0-9-]{1,64}$)[a-z0-9]+(?:-[a-z0-9]+)*$"
        },
        {
          "type": "string",
          "pattern": "^net:[a-z0-9]+(?:-[a-z0-9]+)*$"
        }
      ]
    },
    "subject": {
      "description": "§13.6 lifecycle subject: an organism's rappid, or the absolute HTTPS URI of a repository that has no rappid (spelled exactly as the estate's release manifests spell it)",
      "anyOf": [
        {
          "$ref": "#/$defs/rappid"
        },
        {
          "$ref": "#/$defs/https"
        }
      ]
    },
    "path": {
      "description": "§9.1 path grammar (rapp._path_valid): relative POSIX path, no empty/'.'/'..' segment, no '\\\\' or ':' or control character, no segment ending in space or dot, no Windows reserved name, no drive prefix; ALSO Unicode NFC, which a pattern cannot express",
      "type": "string",
      "pattern": "^(?![A-Za-z]:)(?!\\.\\.?(?:/|$))(?!(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])(?:\\.|/|$))[^/\\\\:\\x00-\\x1f]*[^/\\\\:\\x00-\\x1f .](?:/(?!\\.\\.?(?:/|$))(?!(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])(?:\\.|/|$))[^/\\\\:\\x00-\\x1f]*[^/\\\\:\\x00-\\x1f .])*$"
    },
    "uint53": {
      "type": "integer",
      "minimum": 0,
      "maximum": 9007199254740991
    },
    "sig": {
      "description": "detached §10 JWS (kid = declared_by) over canonical(entry \\ {sig})",
      "type": "string",
      "minLength": 1
    },
    "object_id_by_format": {
      "if": {
        "properties": {
          "object_format": {
            "const": "sha1"
          }
        }
      },
      "then": {
        "properties": {
          "commit": {
            "pattern": "^[0-9a-f]{40}$"
          }
        }
      },
      "else": {
        "properties": {
          "commit": {
            "pattern": "^[0-9a-f]{64}$"
          }
        }
      }
    },
    "release-pin": {
      "description": "§13.3/§13.5 release-pin (declared, persisted). Cross-entry rules not expressible here: manifest_hash unique; one channel per release_scope; predecessor names an EARLIER release-pin of the same channel; one root and no fork per channel; activated_utc never decreases along a channel; a scope's grail-kernel (if any) precedes its first release-pin.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "type",
        "release_scope",
        "channel",
        "predecessor",
        "manifest_hash",
        "repository",
        "object_format",
        "commit",
        "path",
        "activated_utc",
        "declared_by",
        "sig"
      ],
      "properties": {
        "type": {
          "const": "release-pin"
        },
        "release_scope": {
          "$ref": "#/$defs/https"
        },
        "channel": {
          "$ref": "#/$defs/lclabel64"
        },
        "predecessor": {
          "anyOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/hex64"
            }
          ]
        },
        "manifest_hash": {
          "$ref": "#/$defs/hex64"
        },
        "repository": {
          "$ref": "#/$defs/https"
        },
        "object_format": {
          "enum": [
            "sha1",
            "sha256"
          ]
        },
        "commit": {
          "type": "string"
        },
        "path": {
          "$ref": "#/$defs/path"
        },
        "activated_utc": {
          "$ref": "#/$defs/utc"
        },
        "declared_by": {
          "$ref": "#/$defs/rappid"
        },
        "sig": {
          "$ref": "#/$defs/sig"
        }
      },
      "allOf": [
        {
          "$ref": "#/$defs/object_id_by_format"
        }
      ]
    },
    "lifecycle": {
      "description": "§13.3/§13.6 lifecycle notice (declared, persisted). Not expressible here: superseded_by != subject; one chain per subject through previous = H('rapp/1:particle', earlier entry) naming an EARLIER entry of the same subject, one root, no fork; since_utc and activated_utc never decrease along the chain; no cycle among the successors in effect at any one time.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "type",
        "subject",
        "state",
        "superseded_by",
        "since_utc",
        "previous",
        "activated_utc",
        "declared_by",
        "sig"
      ],
      "properties": {
        "type": {
          "const": "lifecycle"
        },
        "subject": {
          "$ref": "#/$defs/subject"
        },
        "state": {
          "enum": [
            "active",
            "deprecated",
            "superseded",
            "archived"
          ]
        },
        "superseded_by": {
          "anyOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/subject"
            }
          ]
        },
        "since_utc": {
          "$ref": "#/$defs/utc"
        },
        "previous": {
          "anyOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/hex64"
            }
          ]
        },
        "activated_utc": {
          "$ref": "#/$defs/utc"
        },
        "declared_by": {
          "$ref": "#/$defs/rappid"
        },
        "sig": {
          "$ref": "#/$defs/sig"
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "state": {
                "const": "active"
              }
            }
          },
          "then": {
            "properties": {
              "superseded_by": {
                "type": "null"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "state": {
                "const": "superseded"
              }
            }
          },
          "then": {
            "properties": {
              "superseded_by": {
                "not": {
                  "type": "null"
                }
              }
            }
          }
        }
      ]
    },
    "stream-signer": {
      "description": "§13.3/§13.7 stream-signer grant (declared, persisted). Not expressible here: kinds strictly ascending bytewise; until_utc (when not null) after since_utc; signer has an spki entry in the same registry; every kind is registered in the same registry (deprecated or not) with a family whose stream form is stream_id's.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "type",
        "stream_id",
        "signer",
        "kinds",
        "since_utc",
        "until_utc",
        "activated_utc",
        "declared_by",
        "sig"
      ],
      "properties": {
        "type": {
          "const": "stream-signer"
        },
        "stream_id": {
          "$ref": "#/$defs/stream_id"
        },
        "signer": {
          "$ref": "#/$defs/rappid"
        },
        "kinds": {
          "type": "array",
          "minItems": 1,
          "uniqueItems": true,
          "items": {
            "allOf": [
              {
                "$ref": "#/$defs/kind"
              },
              {
                "not": {
                  "enum": [
                    "memory.re-genesis",
                    "swarm.re-genesis",
                    "body.re-genesis"
                  ]
                }
              }
            ]
          }
        },
        "since_utc": {
          "$ref": "#/$defs/utc"
        },
        "until_utc": {
          "anyOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/utc"
            }
          ]
        },
        "activated_utc": {
          "$ref": "#/$defs/utc"
        },
        "declared_by": {
          "$ref": "#/$defs/rappid"
        },
        "sig": {
          "$ref": "#/$defs/sig"
        }
      }
    },
    "release-manifest": {
      "description": "§13.5 rapp/1-release-manifest, stored as exactly canonical(manifest) (UTF-8, no BOM, no trailing newline) and pinned by manifest_hash = H('rapp/1:particle', manifest). Not expressible here: components sorted ascending by id with no duplicate; files sorted by UTF-8 path bytes with no duplicate and no case-insensitive (NFD, casefold) collision or file/directory clash; identity_path is one of the component's files; one rappid bound at most once per manifest; at most 1 MiB canonical; kernel coherence with the scope's grail-kernel ('kernel' kind is reserved).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "schema",
        "release_scope",
        "release",
        "components"
      ],
      "properties": {
        "schema": {
          "const": "rapp/1-release-manifest"
        },
        "release_scope": {
          "$ref": "#/$defs/https"
        },
        "release": {
          "type": "string",
          "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
        },
        "components": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "id",
              "kind",
              "rappid",
              "identity_path",
              "repository",
              "object_format",
              "commit",
              "immutable_ref",
              "files"
            ],
            "properties": {
              "id": {
                "$ref": "#/$defs/lclabel100"
              },
              "kind": {
                "$ref": "#/$defs/lclabel64"
              },
              "rappid": {
                "anyOf": [
                  {
                    "type": "null"
                  },
                  {
                    "$ref": "#/$defs/rappid"
                  }
                ]
              },
              "identity_path": {
                "anyOf": [
                  {
                    "type": "null"
                  },
                  {
                    "$ref": "#/$defs/path"
                  }
                ]
              },
              "repository": {
                "$ref": "#/$defs/https"
              },
              "object_format": {
                "enum": [
                  "sha1",
                  "sha256"
                ]
              },
              "commit": {
                "type": "string"
              },
              "immutable_ref": {
                "anyOf": [
                  {
                    "type": "null"
                  },
                  {
                    "type": "string",
                    "pattern": "^refs/tags/[\\s\\S]+$"
                  }
                ]
              },
              "files": {
                "type": "array",
                "items": {
                  "type": "object",
                  "additionalProperties": false,
                  "required": [
                    "path",
                    "sha256",
                    "size_bytes"
                  ],
                  "properties": {
                    "path": {
                      "$ref": "#/$defs/path"
                    },
                    "sha256": {
                      "$ref": "#/$defs/hex64"
                    },
                    "size_bytes": {
                      "$ref": "#/$defs/uint53"
                    }
                  }
                }
              }
            },
            "allOf": [
              {
                "$ref": "#/$defs/object_id_by_format"
              },
              {
                "if": {
                  "properties": {
                    "rappid": {
                      "type": "null"
                    }
                  }
                },
                "then": {
                  "properties": {
                    "identity_path": {
                      "type": "null"
                    }
                  }
                },
                "else": {
                  "properties": {
                    "identity_path": {
                      "type": "string"
                    }
                  }
                }
              }
            ]
          }
        }
      }
    },
    "registry-document": {
      "description": "§13.1 registry document: exactly these five members carry meaning; any other top-level member is covered by sig and carries none. sig null = unsigned draft, never authority.",
      "type": "object",
      "required": [
        "schema",
        "registry_seq",
        "canonical_source",
        "entries",
        "sig"
      ],
      "properties": {
        "schema": {
          "const": "rapp/1-registry"
        },
        "registry_seq": {
          "$ref": "#/$defs/uint53"
        },
        "canonical_source": {
          "$ref": "#/$defs/https"
        },
        "entries": {
          "type": "array"
        },
        "sig": {
          "anyOf": [
            {
              "type": "null"
            },
            {
              "$ref": "#/$defs/sig"
            }
          ]
        }
      }
    }
  }
}
```
<!-- schemas:end -->
