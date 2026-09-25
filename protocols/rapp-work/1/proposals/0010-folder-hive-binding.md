# Proposal 0010: bind a folder Hive to a work organization

| | |
|---|---|
| **Status** | Draft, not accepted. Nothing here is in force. The owner decides. |
| **Gap** | G10: an organization cannot bind a folder Hive. |
| **Home spec** | Canonical `rapp-work/1` §§1, 2 and 4 ([`../SPEC.md`](../SPEC.md)) |
| **Proposed vehicle** | A new, additive sibling profile, `rapp-work-folder-hive/1` (working name). `rapp-work/1` is not changed. |
| **Companion** | G5, the owner as the Hive's notary: branch `experimental/gap-g5-owner-notary`, file `protocols/rapp-work/1/proposals/0005-owner-as-hive-notary.md`. That proposal builds on this one. This one stands alone. |
| **Branch** | `experimental/gap-g10-folder-hive-binding` |

## Summary

A folder Hive is a git repository of markdown files with no owner inside. It has
no RAPPID, no Mother stream and no registry, so canonical `rapp-work/1` cannot bind
it. `work.organization` names one `rapp-hive/1` Hive by `hive_rappid`, and
`work.vector` records only an authenticated `rapp-hive/1` checkpoint. Both payloads
are closed, and the seven `work.*` kinds are closed.

This proposal leaves `rapp-work/1` exactly as it is. It adds one small sibling
profile with two kinds of its own on a body stream of its own:

1. **`folder-hive.organization`**: an organization declaration with the same
   accountable-body fields as `rapp-work/1` §2, whose one Hive is a folder Hive
   named by a **binding triple**: the Hive id, the first (root) commit, and the
   founder key fingerprint. The binding also pins the exact convention bytes that
   define "accepted".
2. **`folder-hive.vector`**: the organization's signed record of an **accepted
   head**. It is a commit that the Hive's own rules accept from the pinned root. Each
   vector must name a head that comes strictly after the previous one, both by git
   ancestry and by the Hive's own acceptance of every commit in between.

The folder Hive stays experimental. The profile belongs in the newest release
scope, beside the folder profile of the RAPP Work Constitution Part V.1, until a
real team has used it for a real week. RAPP/1 LTS and canonical `rapp-work/1` pull
nothing experimental.

## Context: what is true today

All references are to `kody-w/rapp-1` at `591e014` unless stated otherwise.

### Canonical `rapp-work/1` (`protocols/rapp-work/1/SPEC.md`)

SHA-256 `283359355c3fe2858e28744368255683af3ed28a68e290e56c231e7d4b13c08e`.

- **§1** requires every authoritative payload to travel in a signed, frozen
  eleven-key frame, on the organization's body stream. It lists exactly seven kinds
  and says: "The set is closed for `rapp-work/1`. No eighth `work.*` kind, new
  registry entry type, alternate envelope, or endpoint is implied." Adoption is one
  `protocol` entry and seven `kind` entries, plus pins of `rapp-hive/1`,
  `rapp-cicd/1` and `rapp-deploy/1`.
- **§2** binds "the accountable `owner_rappid`", "one hard `world_id`" and "one
  sovereign `hive_rappid`", and says: "The organization and Hive identities are
  distinct. A name, repository, checkout, URL, plugin directory, or local path cannot
  derive or replace either RAPPID. Owner authority is evaluated through the adopting
  estate's signed registry and time-scoped signer rules, never from an organization
  claim alone."
- **§4**: "`rapp-work/1-vector` captures the authenticated `rapp-hive/1` checkpoint"
  (`registry_seq`, `registry_hash`, `hive_rappid`, `mother_head_frame_hash`,
  `catalog_hash`, plus the signed Mother head). The consumer "MUST verify the
  registry, Mother history, catalog, and signed checkpoint under `rapp-hive/1`". It
  also says: "Git ancestry, fetch success, a newer file timestamp, or a moving branch
  cannot substitute for this check."
- **§9**: "JSON Schema, a payload particle, Git commit, raw URL, static file, catalog
  item, unsigned receipt, or local success result is not authority."

### The closed schema and the reference

- `protocols/rapp-work/1/schema.json` (SHA-256
  `ff30f9878f12fa4ad7d93c4c205eb1cb580137a7dee87aa9d23c88a93466d19e`) closes both
  payloads with `additionalProperties: false`. `hive_rappid`
  must match the RAPPID grammar. `hive_checkpoint` has exactly five members, and
  `mother_head.frame_hash` is 64 lowercase hex.
- `rapp_work.py`: `validate_organization` requires the eight exact keys and a RAPPID
  `hive_rappid` distinct from the organization. `validate_vector` requires the
  checkpoint's `hive_rappid` to equal the organization's and the Mother stream to be
  that RAPPID. `authorize_frame` refuses any kind outside the closed seven ("rapp-work
  frame: kind is not one of the closed work kinds"). `validate_registry_adoption`
  refuses any other live `work.*` kind ("rapp-work registry: unrecognized live work
  kinds").
- The pins: `protocols/index.json` records the SPEC and schema hashes. Both files are
  in `anchor/update_anchor.py` `INPUT_PATHS`. The rev-16 head frame records them under
  `operational_profiles["rapp-work/1"]`. `work_conformance.py` fails on any drift, and
  `kody-w/rapp-work` `RAPP_WORK_PIN.json` pins the same two hashes at `591e014`.

### RAPP/1 and its Constitution

- **Art. 2**: a revision that changes a key set, a field grammar or a hash rule moves
  the token. So a folder Hive cannot be squeezed into `rapp-work/1-organization` or
  `rapp-work/1-vector` in place.
- **Art. 4**: new capability enters by registration on the same envelope. If it
  cannot, "it is a rev-N+1 conversation, not a patch".
- **Art. 7** and SPEC §6.2: identities are minted once, from entropy or a public key,
  never derived from a name. SPEC §6.3: a tail that is not 64 lowercase hex (for
  example a 32-hex one) is provisional and "MUST NOT appear in any emitted frame,
  `stream_id`, egg, or registry entry".
- **Art. 18**: canonicalization, hashes, the RAPPID grammar and mint, the eleven-key
  envelope, the consumer checklist and the wire never change under `rapp/1`.
- SPEC §6.1.1 and §7.2: a kind is `lclabel "." lclabel`, and the registry binds it to
  exactly one family. §13.3: every stream registers its creation `genesis`. A
  `protocol` entry is "an estate adoption pin, never a power to redefine a
  protocol". §11.2 item 4: a profile is activated by a `protocol` entry pinning its
  exact repository, path and SHA-256.
- `rapp-hive/1` §9.1 (in `kody-w/rapp-work` at `29ead23`) is the precedent for a
  separate stream: its receipts are "owner-signed on a separately registered body
  stream, not appended to the Mother as an alternative convergence".

### The folder Hive

The convention is `HIVE-MD.md` in `kody-w/rapp-model-hive`, branch
`experimental/hive-md`, commit `2bd7c95` (SHA-256 `f3186e0d…fd96`). Its checker and
Brainstem agent is one file, `agents/hive_agent.py` (SHA-256 `e9a2d724…e8dd`).

- `HIVE.md` holds `hive` ("a random id fixed by the first commit"), `version`,
  `approvals` (new Hives start at 2), and optional `fields` and `previous`.
- "Every commit after the pinned first commit has one parent and an SSH signature
  (namespace `git`) by a key that the tree at its parent lists under
  `members/<name>/keys/`, in that name." Each commit is judged by the rules as they
  stood at its parent. "History is one line". "`hive` and `.gitattributes` never
  change". "The first refused commit stops verification."
- The checker mints the id as the first 32 hex digits of SHA-256 over the founder
  key, a time, the title and 16 random bytes. It creates repositories with
  `--object-format=sha1`. `check_root` accepts a root only if it has no parent, holds
  only `HIVE.md`, `.gitattributes` and the founder's one key file (plus `MEMBER.md`),
  has `version: 1`, and is signed by that key in the founder's name. Joining needs
  the root commit id from the invitation, and the agent then shows the founder
  fingerprint to "compare it with the invitation".
- Hive Hub cards (`kody-w/hive-hub`, branch `experimental/organism-fit`) already
  carry this triple as `hive`, `root` and `founder`.
- The RAPP Work Constitution (`kody-w/rapp-work`, branch
  `experimental/rapp-work-constitution`, commit `9e945f8`) says in Part II that the
  convention "is outside `rapp-work/1` and claims no `rapp-work/1` or RAPP/1
  conformance", and that "binding such a Hive to a work organization would also need
  upstream changes to canonical `rapp-work/1` §§1, 2 and 4". Part V.2 (proposed, G9)
  says a signed commit by an admitted key authorizes effects inside that Hive only,
  and "an effect that crosses a world boundary still needs one under `rapp-work/1`".
  Part V.4 (proposed, G8) says members are names bound to keys by the Hive's signed
  history. Article 16: nothing leaves the canary ring until a real team has used it
  for a real week.

### Recorded evidence (reproducible, synthetic)

Run against the rapp-1 reference at `591e014` on Python 3.9.6 and 3.13, with
identical results:

- An adopting registry holding the seven `work.*` kinds plus `folder-hive.organization`
  and `folder-hive.vector` (and, for the companion G5 proposal, `notary.notarization`),
  all family `body`, passes `rapp_work.validate_registry_adoption`. Adding
  `work.folder-vector` is refused:
  `rapp-work registry: unrecognized live work kinds ['work.folder-vector']`. So a
  sibling profile must not use the `work` label.
- `rapp_work.validate_organization` refuses a `hive` object in place of
  `hive_rappid` ("expected keys …"), refuses an extra `hive` member, and refuses a
  32-hex Hive id used as a RAPPID tail (`hive_rappid: expected RAPP/1 rappid`).
  `rapp.rappid_valid` is false for it.
- `rapp_work.validate_vector` refuses a git-commit checkpoint ("expected keys …") and
  a 40-hex commit id as `mother_head.frame_hash` ("expected 64 lowercase hex").
- Frames of kinds `folder-hive.organization` and `folder-hive.vector` built with
  `rapp.build_frame` pass `rapp.verify_frame` steps 1 to 6 with a fixture signature
  verifier. They have exactly the eleven keys. The envelope does not change.
- Replaying the public synthetic model Hive (`tools/build_example.py`'s story, run in
  a scratch folder) gives root `f934db89e0c73d71843d634b8ddbd53154732735`, Hive id
  `185d0eb5d4b1247b260042d0d840d5c3` and founder
  `SHA256:q18VTrWDieC+Sc25wpbcIHm4/gUotkmUJpyFgDeOdyY`. These match its Hive Hub
  card. It has 41 accepted commits, and its forged push (`96c271b4bf`, journey J9) is
  refused. Its keys are public test keys, so they prove nothing.

## The problem, precisely

1. **Identity.** `hive_rappid` must be a RAPPID. A folder Hive has none. Its `hive:`
   id is 32 hex digits, so as a RAPPID tail it would be provisional (SPEC §6.3) and
   must never be emitted. Minting a RAPPID "for" the folder Hive and writing it into
   `hive_rappid` would give that field a second meaning. A `rapp-work/1` verifier
   would look for a `rapp-hive/1` Mother stream and fail. That breaks Art. 2's rule
   that the label on the bytes says how to verify them.
2. **State.** A folder Hive's state is a git commit that its own rules accept. It
   has no registry sequence, Mother frame or catalog. `rapp-work/1-vector` cannot
   carry a commit, and §4 and §9 correctly refuse git as authority.
3. **Kinds and streams.** No eighth `work.*` kind is allowed, and the reference
   refuses one. A foreign kind cannot be appended to a `rapp-work/1` organization's
   body stream either. `authorize_frame` refuses it, and every later `work.*` frame
   chains through it, so `rapp-work/1` consumers could no longer verify that stream.

So G10 cannot be closed inside `rapp-work/1`. It needs a new token.

## Vehicles considered

| Vehicle | What it is | For | Against |
|---|---|---|---|
| **(a) `rapp-work/2`** | A successor token: the organization's Hive becomes a tagged union (`rapp-hive/1` or folder), and the vector's checkpoint becomes a union too. All seven schemas are re-issued as `rapp-work/2-*`. | One organization model. Folder-Hive organizations get catalogs, migrations, receipts, observations and rollbacks. | Moves the whole profile token. It needs an anchor revision, a new `protocols/index.json` entry, a new SDK pin (`RAPP_WORK_PIN.json`), and new reference and conformance code. The `work.*` kinds are bound to `rapp-work/1` schemas, so an estate could not adopt both without a total migration or new kind names. It also puts an experimental convention into the organization profile before that convention graduates. RAPP/1 LTS keeps `rapp-work/1` anyway, so two organization shapes exist either way. |
| **(b) Sibling profile** (recommended) | `rapp-work-folder-hive/1`: its own two kinds (`folder-hive.*`, never `work.*`), its own closed payloads, on its own body stream. It is subordinate to `rapp-work/1`: it reuses that profile's rules by reference, yields to it on any conflict, and is adopted by an estate's `protocol` entry. | Additive. Zero bytes change in `rapp-work/1`, its schema, its reference or the anchor, and it needs no SDK re-pin. It is growth by registration (Art. 4). The experiment stays in the newest scope and can be tried by one estate with one team. If real use says so, it can later be folded into (a). | A second organization-shaped declaration: the §2 fields with the Hive member replaced. A folder-Hive organization gets only a binding and vectors in `/1`, with no catalogs, migrations, receipts, observations or rollbacks. Those stay with `rapp-work/1` organizations. |
| **(c1) Overload `hive_rappid`** | Mint a RAPPID for the folder Hive and use it in an unchanged `rapp-work/1-organization`. | No new records. | Refused. The field would mean two things (Art. 2). `work.vector`, `work.migration` and `work.observation` become impossible, and every `rapp-work/1` verifier would fail on a missing Mother stream. |
| **(c2) Squeeze into `work.receipt` or evidence** | Record accepted heads as a `catalog-verified` receipt whose evidence is a particle of `{root, head}`. | No new kinds. | Refused. Receipt types and subjects are closed, and a receipt saying "catalog verified" that means "Hive head accepted" is the drift Art. 2 forbids. |
| **(c3) Make the folder Hive a `rapp-hive/1` Hive** | Give it an owner, a Mother stream and a registry. | Uses the profile in force. | Refused. It contradicts the convention (no owner inside) and G5's premise, and `rapp-hive/2` is frozen (Work Constitution Art. 16). |

**Recommendation: (b), now, as an experiment in the newest release scope, with (a)
kept as the graduation option.** The owner decides at graduation, with real-use
evidence, whether the sibling becomes a ratified subordinate profile or is folded
into `rapp-work/2`.

**Where the profile's normative text should live** (owner decision):
- **Recommended while experimental:** the frontier track beside the folder profile
  that Work Constitution Part V.1 plans for `kody-w/rapp-workspace`. It is adopted
  by an estate's `protocol` entry (the `EXTENDING.md` lane).
- **At graduation:** either `protocols/rapp-work-folder-hive/1/` in this repository,
  which adds anchor inputs and needs an owner-ratified chain revision, or `rapp-work/2`.

Putting it into `kody-w/rapp-1` now would put an experiment into the index of the
LTS protocol authority.

## Proposed change

### Changes to canonical `rapp-work/1`

None. `protocols/rapp-work/1/SPEC.md`, `schema.json`, `rapp_work.py`,
`work_conformance.py`, `protocols/index.json`, `anchor/**` and the conformance
vectors stay byte for byte as they are.

### Proposed normative text: a new profile document (insertion)

The quoted text below is the exact proposed text of a new document,
`protocols/rapp-work-folder-hive/1/SPEC.md`, at the location the owner chooses.
Here "this profile" means `rapp-work-folder-hive/1`.

> # RAPP Work folder-Hive binding
>
> **Protocol identifier:** `rapp-work-folder-hive/1`
> **Status:** Experimental additive profile (newest release scope only)
> **Parent:** `rapp-work/1` (canonical, `kody-w/rapp-1`), under `rapp/1`
> **Depends on:** a folder Hive convention pinned by exact bytes
>
> The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD** and **MAY** are used
> as defined by RAPP/1 section 2.
>
> ## 1. Foundation and registration
>
> This profile binds one work organization to one folder Hive and records which
> states of that Hive the organization accepted. It changes no RAPP/1 byte and no
> `rapp-work/1` byte, kind, schema or rule. Every authoritative payload:
>
> 1. is canonical RAPP/1 I-JSON identified by `H("rapp/1:particle", payload)`;
> 2. travels in the frozen eleven-key RAPP/1 frame and is signed (`sig` is never
>    `null`);
> 3. is appended to the folder-Hive organization's own body stream, whose `stream_id`
>    is its `organization_rappid`; and
> 4. is accepted only after registry, signature, signer, stream and payload
>    authorization, as in `rapp-work/1` §1.
>
> An adopting estate **MUST**:
>
> 1. hold an active canonical `rapp-work/1` adoption (`rapp-work/1` §1);
> 2. append one `protocol` entry pinning this exact specification;
> 3. append exactly these two `kind` entries, both bound to the `body` family:
>
>    | Kind | Only permitted payload schema |
>    | --- | --- |
>    | `folder-hive.organization` | `rapp-work-folder-hive/1-organization` |
>    | `folder-hive.vector` | `rapp-work-folder-hive/1-vector` |
>
> 4. append one `protocol` entry pinning the exact bytes of each folder Hive
>    convention version that its organizations bind (section 3); and
> 5. register every folder-Hive organization stream's creation `genesis` (RAPP/1
>    §13.3).
>
> The kind set is closed for this profile. Its kinds never use the `work` label, so
> the closed `work.*` set of `rapp-work/1` is untouched. A folder-Hive organization
> body stream carries only these two kinds. No new registry entry type, envelope,
> endpoint or `work.*` kind is implied. On any conflict, RAPP/1 wins, then
> `rapp-work/1`, then this profile.
>
> ## 2. Folder-Hive organization
>
> The `rapp-work-folder-hive/1-organization` payload is the genesis declaration of
> one folder-Hive organization body stream (`seq` 0). It has exactly these members:
>
> | Member | Grammar and meaning |
> | --- | --- |
> | `schema` | `"rapp-work-folder-hive/1-organization"` |
> | `organization_rappid` | RAPPID; also the frame `stream_id` |
> | `owner_rappid` | RAPPID; the accountable owner, exactly as in `rapp-work/1` §2 |
> | `world_id` | label; the one hard world, exactly as in `rapp-work/1` §2 |
> | `release_scope` | absolute HTTPS URI, exactly as in `rapp-work/1` §2 |
> | `policy_sha256` | 64 lowercase hex, exactly as in `rapp-work/1` §2 |
> | `hive` | the binding (section 3) |
> | `created_utc` | RAPP/1 §7.4 form; equals the genesis frame's `utc` |
>
> Every grammar is the one `rapp-work/1/schema.json` uses for the same member. The
> organization identity is minted (RAPP/1 §6.2) and is never derived from the Hive,
> its id, its root, its founder, a repository, a URL or a path. Owner authority is
> evaluated through the adopting estate's signed registry and time-scoped signer
> rules, never from the declaration alone. The frame is signed by the owner in effect
> at its `utc`. A folder-Hive organization is not a `rapp-work/1` organization: it
> carries no `work.*` payload, and no `work.*` payload may name it.
>
> ## 3. The binding: one folder Hive, named by three values and a convention
>
> `hive` has exactly these members:
>
> | Member | Grammar | Role |
> | --- | --- | --- |
> | `convention` | object: exactly `name` (text, 1 to 64 characters), `spec_sha256` (64 lowercase hex) and `checker_sha256` (64 lowercase hex) | The exact rules that define "accepted" |
> | `hive_id` | exactly 32 lowercase hex digits | The Hive's own name under its convention: `HIVE.md` `hive:` |
> | `object_format` | `"sha1"` or `"sha256"` | The Hive repository's git object format |
> | `root` | 40 lowercase hex for `sha1`, 64 for `sha256` | The Hive's first commit: evidence and locator |
> | `root_sha256` | 64 lowercase hex | SHA-256 twin of the root commit object |
> | `founder` | `"SHA256:"` followed by exactly 43 characters of unpadded standard base64 | The founder key fingerprint: evidence |
>
> **Definitions.**
>
> - *Commit octets*: the octets git hashes to name a commit object, that is
>   `"commit " || decimal byte length of the content || 0x00 || content`, where
>   *content* is exactly what `git cat-file commit <id>` prints.
> - *SHA-256 twin*: `lowercase_hex(SHA-256(commit octets))`. For `object_format`
>   `"sha256"`, the twin **MUST** equal the object id itself.
> - *Founder fingerprint*: OpenSSH's SHA-256 fingerprint of the founder's Ed25519
>   public key, that is `"SHA256:" || base64(SHA-256(key blob))` without `=` padding,
>   where the key blob is the SSH wire encoding `string("ssh-ed25519") ||
>   string(32-octet public key)` (RFC 4253 §6.6, RFC 8709).
>
> **What is identity and what is evidence.** The folder Hive has no RAPP/1 identity,
> and this profile does not mint one for it.
>
> - `hive_id` is the convention's own name for the Hive: 128 bits, minted from fresh
>   randomness when the Hive is created, fixed by the root, and never changed. It is
>   carried only as this plain value. It is never a RAPPID, a RAPPID tail, a
>   `stream_id` or a `kid`, and it is never "upgraded" to one. On its own it is not
>   unique, since anyone can write any 32 hex digits into a new root.
> - `root` and `root_sha256` are content addresses, derived from bytes. They are the
>   evidence of exactly which genesis the organization bound, and a locator for it.
>   They are not an identity (RAPP/1 Art. 7).
> - `founder` is derived from a public key. It is evidence that the root was signed by
>   the key the organization expected, and it is the value people compare by voice or
>   on a Hive card. It gives the founder no authority after the root.
> - `convention` pins the rules. The only authority in the binding is the signed
>   genesis frame: the organization's accountable claim that this is its Hive.
>
> **Verification against the Hive's own bytes.** Before accepting a genesis, a
> consumer **MUST**, in order, and **MUST** refuse (never repair) on any failure:
>
> 1. Find exactly one active `protocol` entry in the authenticated adopting registry
>    whose `name` equals `convention.name` and whose `spec_hash` equals
>    `convention.spec_sha256`. Obtain checker bytes whose SHA-256 equals
>    `convention.checker_sha256`, or a port proven to give the same verdicts on
>    shared vectors (as Constitution Art. 10 requires for copies of `rapp.py`). The
>    checker is read and run as code of the consumer's own choosing; nothing from the
>    Hive is executed.
> 2. Obtain the Hive's objects by any transport into a repository the consumer
>    controls, with the convention's git hygiene: hooks, submodules, alternates,
>    remote helpers and filesystem monitors are off. Transport carries bytes. It
>    proves nothing.
> 3. Read the object `root`. Recompute its object id in `object_format` and its
>    SHA-256 twin from its commit octets; both must match (`root`, `root_sha256`). A
>    SHA-1 implementation that detects collision attacks (git's default) is
>    **REQUIRED**, and an object it flags is refused.
> 4. Run the convention's root check on `root`: no parent; a tree with exactly
>    `HIVE.md`, `.gitattributes` and the founder's one key file (plus the convention's
>    optional `MEMBER.md`); `HIVE.md` `version: 1`; signed in the `git` namespace by
>    the key in that key file, in the founder's name; the key file a valid request of
>    that key for this Hive.
> 5. Require `HIVE.md` in the root tree to name `hive: <hive_id>`.
> 6. Compute the founder fingerprint of the key in the root's key file, which is
>    also the root's signing key. It must equal `founder`.
>
> A different root with the same `hive_id` is a different Hive and is refused. A
> consumer resolves the adopting estate's live `folder-hive.organization` geneses
> through its registry. If two live folder-Hive organizations in one estate bind the
> same `root`, the consumer **MUST** refuse both until the estate owner deprecates
> one (RAPP/1 §13.3), as for a fork (RAPP/1 §7.6). Across estates, bindings are
> independent.
>
> ## 4. Accepted-head vector
>
> **Accepted head.** A commit `H` is an *accepted head* of the bound Hive when the
> pinned convention, run from `root`, judges every commit on the one line from `root`
> to `H` and refuses none. Each commit has exactly one parent, the commit that passed
> just before it, and is judged by the rules and membership in the tree at that
> parent. `HIVE.md` at `H` must still name `hive_id`. Git ancestry alone is not
> acceptance: a descendant that contains one refused commit is not accepted. The
> proof is the consumer's own replay of the Hive's bytes. No payload, signature
> count, hosting badge or fetch result substitutes for it.
>
> `rapp-work-folder-hive/1-vector` has exactly these members:
>
> | Member | Grammar and meaning |
> | --- | --- |
> | `schema` | `"rapp-work-folder-hive/1-vector"` |
> | `organization_payload_hash` | particle hash of the organization genesis payload |
> | `observed_utc` | RAPP/1 §7.4 form; equals the frame's `utc` |
> | `head` | object with exactly `commit`, `commit_sha256`, `height`, `rules_version` and `rules_sha256` |
> | `previous_vector_payload_hash` | `null` for the first vector; otherwise the particle hash of the retained vector |
>
> Within `head`:
>
> - `commit` is the accepted head's object id, in the binding's `object_format`.
> - `commit_sha256` is its SHA-256 twin.
> - `height` (`uint53`) is the number of commits after `root` on the line (the root
>   is 0).
> - `rules_version` (a whole number from 1 to 999999999) is `HIVE.md` `version:` at
>   `commit`.
> - `rules_sha256` is the convention's subject hash of `HIVE.md` at `commit`: the
>   SHA-256 of its UTF-8 text after LF and NFC normalization, the same hash the
>   convention's rules approvals name.
>
> The first vector may name any accepted head, including the root at height 0.
>
> **Acceptance.** A consumer **MUST**, before accepting a vector:
>
> 1. verify the frame (RAPP/1 §7.5, signature required) on the organization's
>    stream, with the signer the owner in effect at its `utc`;
> 2. verify the closed payload and its binding to the retained genesis;
> 3. check `commit` against its octets (`commit_sha256`) as in section 3, step 3;
> 4. establish that `commit` is an accepted head at exactly `height`, and that
>    `rules_version` and `rules_sha256` match `HIVE.md` at `commit`; and
> 5. for every vector after the first, all of the following against the retained
>    vector *R*:
>    - `previous_vector_payload_hash` equals *R*'s particle hash;
>    - `height` is greater than *R*'s `height`;
>    - *R*'s `commit` is the ancestor of `commit` exactly `height − R.height`
>      first-parent steps back;
>    - every commit after *R*'s `commit` up to `commit` is accepted (a consumer may
>      judge from *R* only because *R* was itself established from `root`);
>    - `rules_version` is at least *R*'s; and
>    - `observed_utc` is at least *R*'s.
>
> The consumer persists the accepted vector as high-water, as `rapp-work/1` §4
> requires for `rapp-hive/1` vectors:
>
> - the same head again is not a successor and is refused, although an exact replay
>   of the retained frame changes nothing;
> - a lower `height` is rollback;
> - the same `height` with a different `commit` is a fork;
> - a higher `height` that does not descend from the retained head is a fork of
>   rewritten history;
> - a descending line that contains a refused commit is refused; and
> - resetting or deleting retained vector state is not recovery.
>
> A fork is surfaced as a drift finding and refused past the fork point. Only the
> Hive's members can repair their Hive, by resetting the shared copy to the last
> commit that verified. A stuck Hive's remedy is a new Hive, bound by a new
> organization genesis.
>
> ## 5. What a git commit does and does not authorize
>
> Inside the Hive, the convention decides. A signed commit by an admitted key
> authorizes effects inside that Hive only. For this profile, a commit, its signature,
> its ancestry, a fetch, a branch or tag, a hosting provider's mark, a commit time
> and an author name are evidence at most, never authority (`rapp-work/1` §9). Only a
> signed `folder-hive.vector` frame by the owner in effect records that the
> organization accepted a head, and only after the consumer has replayed it.
>
> A vector authorizes nothing inside the Hive. It does not grant membership in the
> organization, key release, publication, or any effect in another world. It records
> which state the organization accepted, and nothing more.
>
> ## 6. World boundary and data classes
>
> The organization's `world_id` is its one hard world. Binding moves no Hive content
> into that world. A vector carries only identifiers, content addresses, counts and
> versions. Hive content enters the organization's world only through a separate,
> deliberate act under another profile. Because an estate binds a root at most once
> (section 3), one estate never binds one Hive into two worlds.
>
> Genesis and vector payloads are neutral metadata. They **MUST NOT** carry Hive file
> content, member names or keys (other than `founder`), request notes, titles or
> paths. Their cadence and heights still reveal activity, and `founder` can link the
> Hive to other uses of the founder's key. So they are GODD by default (`rapp-hive/1`
> §2). Publishing them as DOGG is a separate decision that needs proven
> global-publication rights. A binding or vector never classifies Hive content and
> never authorizes a DOGG publication.
>
> ## 7. Conformance
>
> An implementation claiming this profile verifies both closed payloads and their
> kind bindings, the adoption prerequisites, the binding triple against the Hive's
> bytes, accepted heads by replay under the pinned convention, and vector high-water
> with rollback and fork refusal. It passes the profile's positive and refusal
> vectors. It claims nothing about `rapp-work/1` conformance.

## Example payloads (non-normative)

These use synthetic values only. The RAPPIDs are placeholders, like
`protocols/examples/work-lifecycle.json` (a real organization mints its tails).
`hive-md` is only an example registry name. The Hive values come from the public
synthetic model Hive in `kody-w/rapp-model-hive` at `2bd7c95`, rebuilt with its own
`tools/build_example.py` story. Its keys are public test keys that prove nothing.
Particle hashes were computed with `rapp_profile.particle_hash` at `591e014`.

Genesis, `folder-hive.organization`, particle
`b359b54abb163cc9e5e38d8eef573223eb393726f0946ade0728dfee9c509738`:

```json
{
  "schema": "rapp-work-folder-hive/1-organization",
  "organization_rappid": "rappid:@example/folder-hive-organization:4444444444444444444444444444444444444444444444444444444444444444",
  "owner_rappid": "rappid:@example/work-owner:5555555555555555555555555555555555555555555555555555555555555555",
  "world_id": "example-world",
  "release_scope": "https://example.com/release-scopes/newest",
  "policy_sha256": "dc5d79f04fda9b13fe51e87e9525881f2cf4189a3393e978a17e919b51fffe07",
  "hive": {
    "convention": {
      "name": "hive-md",
      "spec_sha256": "f3186e0d88cc36e18582171fff4ed9a68feddc4ae316f66fb8acc2982892fd96",
      "checker_sha256": "e9a2d7243da31fd2388f140bb8138c3d8d2db428ad09075530eb049a0355e8dd"
    },
    "hive_id": "185d0eb5d4b1247b260042d0d840d5c3",
    "object_format": "sha1",
    "root": "f934db89e0c73d71843d634b8ddbd53154732735",
    "root_sha256": "e1f63af56330549480003aea3c771abb754b202919c974ffe749e5329b175d12",
    "founder": "SHA256:q18VTrWDieC+Sc25wpbcIHm4/gUotkmUJpyFgDeOdyY"
  },
  "created_utc": "2026-09-25T12:00:00.000Z"
}
```

`policy_sha256` is the SHA-256 of a synthetic policy line (see Evidence below).

First vector (journey E1: the head that admitted a new member, height 18), particle
`119c4eb9684c068f432378f39da6ec2a277d7f4633fd8d1a47bffb0896698fa9`:

```json
{
  "schema": "rapp-work-folder-hive/1-vector",
  "organization_payload_hash": "b359b54abb163cc9e5e38d8eef573223eb393726f0946ade0728dfee9c509738",
  "observed_utc": "2026-09-25T12:05:00.000Z",
  "head": {
    "commit": "de4053fa2301ceccf8dca80d92d752b73eeb43f0",
    "commit_sha256": "7cfc2e471f3c8073cf58a404f732133be2dee66a6f9d9d7338136846c1c3f5dc",
    "height": 18,
    "rules_version": 2,
    "rules_sha256": "d1a024ae0b88ed6516dcd3da3a01780d0e12602cd4f4d72689b9a85d8cf211be"
  },
  "previous_vector_payload_hash": null
}
```

Successor vector (the model's last accepted commit, height 40), particle
`f2a870da47ee633a6b7c9c21a3eed45e5dec8d3e54ed2cdcf69cb025d10eb5f6`:

```json
{
  "schema": "rapp-work-folder-hive/1-vector",
  "organization_payload_hash": "b359b54abb163cc9e5e38d8eef573223eb393726f0946ade0728dfee9c509738",
  "observed_utc": "2026-09-25T12:10:00.000Z",
  "head": {
    "commit": "af4ea0caee5dc8840a254b4b3f0c0aa242a76c5a",
    "commit_sha256": "7f7351b896478c16aed965b8a61c37213f350f6fccbf3b25fe16219af8355322",
    "height": 40,
    "rules_version": 2,
    "rules_sha256": "d1a024ae0b88ed6516dcd3da3a01780d0e12602cd4f4d72689b9a85d8cf211be"
  },
  "previous_vector_payload_hash": "119c4eb9684c068f432378f39da6ec2a277d7f4633fd8d1a47bffb0896698fa9"
}
```

The successor is valid because height 40 is greater than 18, commit `de4053fa…` is
22 first-parent steps behind `af4ea0ca…`, and all 22 commits after it pass the
checker.

## Token and compatibility analysis

- **New tokens only.** `rapp-work-folder-hive/1`,
  `rapp-work-folder-hive/1-organization` and `rapp-work-folder-hive/1-vector` are
  new. No existing token is widened or reshaped (Art. 2). Every `rapp-work/1`
  artifact verifies exactly as before.
- **`rapp-work/1` untouched.** Its closed seven kinds, schemas, reference, index
  entry, anchor inputs, rev-16 record and the `RAPP_WORK_PIN.json` pin in
  `kody-w/rapp-work` are unchanged, so no chain revision and no re-pin is needed.
  The recorded adoption check shows the sibling kinds coexist with a valid
  `rapp-work/1` adoption.
- **RAPP/1 untouched (Art. 18).** Same canonicalization, hashes, RAPPID grammar and
  mint, eleven-key envelope, consumer checklist, wire and eggs. Registrations use
  only existing entry types (`protocol`, `kind`, `genesis`), and no endpoint is added
  (Art. 4).
- **Identity (Art. 7).** The organization's identity is minted. The Hive keeps its
  own convention name and gets no derived RAPP identity. The root and fingerprint
  are recorded as evidence.
- **Owner authority (Art. 6).** Evaluated against the owner in effect at each
  frame's `utc`, through the registry, exactly as `rapp-work/1` §2 does.
- **Convention versions.** A binding pins one convention version by exact bytes.
  The convention says: "The checker's rules change only with a new version of this
  convention, and then only tighten." Moving to a new version means a new
  organization genesis after the old one is deprecated. A convention version never
  changes under a pin.
- **Promotion path.** If the owner later chooses (a), a `rapp-work/2` would carry a
  tagged Hive member that includes this binding, and folder-Hive organizations would
  move by create-only migration to new identities. Accepted history stays readable
  under this token forever.
- **Intended release.** Newest release scope only, as an experiment. It is not part
  of RAPP/1 LTS.

## Security analysis

| Threat | Handling |
|---|---|
| Copycat Hive reusing the id | `root` and `root_sha256` pin the exact genesis. The same id under another root is another Hive. |
| Binding without the members' knowledge | The binding is the organization's own claim and grants nothing inside the Hive. Members are not asked, because the convention has no approval that names an organization (the companion G5 proposal raises this). A consumer never reads a binding as the members' consent. |
| Founder impersonation | The root must verify under its own key file's key, and that key's fingerprint must equal `founder`. People compare the fingerprint out of band, as invitations and Hive cards already do. |
| SHA-1 collisions | `sha1` object ids are paired with SHA-256 twins at the root and at every accepted head, and a collision-detecting SHA-1 is required. Residual risk: trees, blobs and parents between pinned points are still addressed by SHA-1. A `sha256` Hive removes it once hosting allows. This is an owner question. |
| History rewrite or force-push | High-water, first-parent ancestry at an exact depth, and fork refusal. The convention's devices refuse the same rewrite. |
| Withheld or stale objects | A missing object is refused, never assumed. A stale vector is reported with its age, and freshness is the consumer's policy, as in RAPP/1 §13.1. |
| Forged commits by non-members | The checker refuses them. The model's forged push is a refusal vector. |
| Compromised member key | A Hive-level limit that the convention documents ("whoever holds a member's only key acts as that member until removed"). The organization records what the Hive accepted and cannot fix it. |
| Compromised owner key | The attacker can sign vectors only for heads that verify, so cannot originate Hive state. It can bind a Hive unilaterally (the binding grants nothing inside it) or fork the stream (both branches refused, RAPP/1 §7.6). Tombstone and re-anchor per RAPP/1 §§10, 13.2 and 13.3, heeding the §14 note on backdated frames. |
| Checker substitution | `checker_sha256` plus the registry's pin of the spec bytes. |
| Instruction injection from Hive text | Verifiers treat Hive bytes as data. The checker parses markdown and never runs it, git hooks stay off, and nothing from the Hive is executed or loaded as instructions. |
| Denial of service by huge histories | A consumer may bound its work. Beyond the bound it reports "not verified", never "accepted". |
| Cross-organization or cross-world replay | `organization_payload_hash`, stream binding (RAPP/1 §7.5 step 1a), and one live binding per root per estate. |

## Privacy analysis

- The payloads carry identifiers, content addresses, counts and versions only: no
  names, member keys, notes, titles, paths or file content.
- `founder` is a public-key fingerprint. The convention makes one key per device per
  Hive, so it links nothing by default. A founder who imported an older key (the
  convention's migration path allows it) links this Hive to that key's other uses.
  Organizations are told so, and fresh keys are recommended.
- Vector cadence reveals activity, so streams are GODD by default.
- The examples use only public synthetic values: public test keys, `example.com`,
  `example-world`, and placeholder RAPPIDs.

## Migration

- No estate has activated canonical `rapp-work/1` yet (the organism's G16), and no
  folder-Hive organization exists. Nothing migrates.
- Existing folder Hives need no change. A binding reads their existing root, id and
  founder.
- An organization that moves to a new Hive, for example a stuck Hive's successor
  that carries its files, binds it with a new genesis. The profile does not link the
  two in `/1` (an owner question).

## Rollback

- For this proposal: delete the branch, or refuse it. Nothing else depends on it.
- For an adopting estate: deprecate the profile's `protocol` and `kind` entries and
  the organizations' `genesis` entries (append-only `deprecated: true`, RAPP/1
  §13.3). Accepted frames stay readable history. They are never deleted or re-signed.

## Conformance vectors to add (described; not implemented in the canonical suites)

A future `folder_hive_conformance.py` would run these against a replayed synthetic
model Hive. Nothing is added to `work_conformance.py`.

**Positive**
1. The model Hive's triple verifies: root, twin, root check, id and founder.
2. A genesis frame with the example payload is accepted, with the signer the owner in
   effect.
3. The first vector at height 18 is accepted after a full replay.
4. The successor at height 40 is accepted after an incremental replay from height 18.
5. An exact replay of the retained vector frame changes nothing.
6. The adoption check accepts `rapp-work/1` plus the two sibling kinds.

**Refusal**
1. `hive_id` differs from `HIVE.md` at the root.
2. A copycat root: the same id and a different founder key.
3. `founder` is not the root signer's fingerprint.
4. `root_sha256` mismatch.
5. The root has a parent, or an extra file.
6. The convention spec hash is not pinned, or the checker hash differs.
7. A second live binding of the same root in one estate refuses both.
8. A vector naming the retained head again.
9. A lower height (rollback).
10. The same height with a different commit (fork).
11. A higher height that does not descend (rewritten history).
12. A descending line that contains the model's forged push (refused commit).
13. `height` differs from the first-parent count.
14. `commit_sha256` mismatch.
15. `rules_version` or `rules_sha256` differs from `HIVE.md` at the head, or
    `rules_version` decreases.
16. Missing objects.
17. An unsigned frame, or a signer that is not the owner in effect (including an old
    key after rotation, and a tombstoned key).
18. A `folder-hive.*` frame on a `rapp-work/1` organization stream, or a `work.*`
    frame on a folder-Hive organization stream.
19. A closed payload with an extra member (for example a member name).
20. `observed_utc` differs from the frame's `utc`, or goes backwards.
21. Retained state reset to an older vector.

Each critical refusal would be proven to turn red under a controlled mutation before
it is committed (Constitution Art. 8: a red oracle is a finding, and a check is never
weakened to pass).

## Reference implementation and gating

None in this proposal. The gap is an idea, and ideas get a proposal only. A later
reference would be a stdlib-only `rapp_work_folder_hive.py` that imports `rapp.py`'s
canonicalizer (Art. 10) and takes the git replay as an injected verifier, so the
protocol validators stay stdlib-only. It would ship under its own token, off by
default. An estate turns it on only by adopting the profile, and without adoption
every frame of these kinds is refused. It is never part of `rapp-work/1`
conformance.

## Ready-to-file issue text (not filed)

The owner decides whether to file it. Proposed title: *rapp-work/1: how does an
organization bind a folder Hive (no RAPPID, git history, no owner inside)?*

> ## PII-free use case
>
> A group of co-equal people keeps its shared work in a folder Hive: markdown files
> in a git repository. Every change is an SSH-signed commit that the Hive's own rules
> accept or refuse, judged by the rules and membership at its parent commit. The
> Hive has no owner, no RAPPID, no Mother stream and no registry. Its identity under
> its convention is a 128-bit random id fixed by its first commit. Invitations and
> discovery cards name it by that id, its first commit and its founder's key
> fingerprint. The group wants a RAPP Work organization, with one accountable owner
> in one world, to bind this Hive and record which Hive states it accepted, without
> treating git as authority.
>
> ## Ambiguity
>
> Canonical `rapp-work/1` §2 binds "one sovereign `hive_rappid`", and §4 says
> `rapp-work/1-vector` "captures the authenticated `rapp-hive/1` checkpoint". §1
> closes the seven `work.*` kinds, and §9 says a Git commit is not authority. Both
> payload schemas are closed. The reference refuses any other live `work.*` kind and
> any other kind on the organization stream. Constitution Art. 2 forbids widening
> either payload in place, and Art. 7 forbids deriving an identity from the Hive's
> id or root.
>
> 1. Is binding a folder Hive in scope for `rapp-work/1` at all, or only for a
>    successor (`rapp-work/2`) or a sibling profile with its own kinds?
> 2. May a sibling profile declare an organization-shaped genesis (the §2 fields with
>    a folder-Hive binding in place of `hive_rappid`) on its own body stream?
> 3. Is the triple of Hive id, first commit and founder fingerprint, plus pinned
>    convention bytes, an acceptable binding, with the triple as evidence and the
>    signed genesis as the only authority?
> 4. May a signed record name an "accepted head" (a commit the Hive's own rules
>    accept from the pinned root), with high-water by height and first-parent
>    ancestry and with the consumer's own replay as proof?
> 5. Are SHA-1 Hives acceptable with SHA-256 twins at pinned points, or must bindable
>    Hives use SHA-256 object ids?
> 6. Should one estate be limited to one live binding per Hive?
>
> ## Proposed fail-closed status pending a ruling
>
> - A `rapp-work/1` organization binds only a `rapp-hive/1` Hive. No estate presents
>   a folder Hive as an organization's Hive.
> - No `work.vector` names a git commit. Any `rapp-work/1` payload whose Hive fields
>   name a folder Hive is refused.
> - Folder Hives stay experimental and outside every `rapp-work/1` or RAPP/1
>   conformance claim. Any organization statement about one is an unsigned draft.
> - Experiments use new, non-`work.*` kinds only, in the newest release scope, never
>   in RAPP/1 LTS.
>
> No names, handles, emails, hostnames, account ids, keys (other than public test
> keys), private repository names, paths or customer data are included.

## Open questions for the owner

1. Vehicle: accept (b), the sibling profile now, or go to (a), `rapp-work/2`, now?
2. The token name. `rapp-work-folder-hive/1` is a working name.
3. Where the profile's text lives while experimental: the frontier track beside the
   Part V.1 folder profile (recommended), an estate repository, or
   `protocols/rapp-work-folder-hive/1/` here (which needs a chain revision).
4. Require an active `rapp-work/1` adoption as a prerequisite (proposed), or allow a
   folder-only estate without it?
5. SHA-1 Hives with SHA-256 twins (proposed), or `sha256` object format only? Should
   a full tree digest also be pinned at accepted heads?
6. One live binding per root per estate (proposed)?
7. The registry name of the folder convention. It depends on Work Constitution
   Part V.1 giving the convention a real token.
8. Should `/1` link a successor organization (a new Hive, or a new convention
   version) to its predecessor's last vector, or leave that to a later version once
   real use asks for it (proposed)?
9. Graduation criteria: Work Constitution Article 16 (a real team, a real week), then
   the rings.

## Owner actions needed

- Decide the vehicle, the token name and the home (questions 1 to 3).
- If accepted as an experiment: publish the profile text at the chosen home, and
  have the adopting estate sign its `protocol`, `kind`, convention-pin and `genesis`
  entries. That is the estate owner's signature, not this proposal's.
- Keep RAPP/1 LTS and canonical `rapp-work/1` unchanged. No chain revision and no
  `RAPP_WORK_PIN.json` re-pin is needed unless (a) is chosen.
- Relay the gap status to the organism (G10: `proposed`). Its files are edited only
  by their own agent.

## Evidence: how the recorded values were produced

- The model Hive values come from running the story of
  `kody-w/rapp-model-hive@2bd7c95` `tools/build_example.py` in a scratch folder
  (Python 3.13, `cryptography` 50), then reading its shared copy with the model's own
  `agents/hive_agent.py` functions (`verify`, `check_root`, `fingerprint`, `Snap`)
  and hashing each commit's octets with SHA-1 (checked against the id) and SHA-256.
- The adoption, validator and frame evidence come from `rapp_work.py`,
  `rapp_registry.py` and `rapp.py` at `591e014`, on Python 3.9.6 and 3.13, with
  identical results.
- The policy digest in the example is `sha256("example folder-Hive organization
  policy\n")`.
- Nothing was written to any reference repository, and no scratch file is committed.

## References

- Canonical `rapp-work/1`: [`protocols/rapp-work/1/SPEC.md`](../SPEC.md) (SHA-256
  `283359355c3fe2858e28744368255683af3ed28a68e290e56c231e7d4b13c08e`) §§1, 2, 4, 9
  and 10; [`schema.json`](../schema.json) (SHA-256
  `ff30f9878f12fa4ad7d93c4c205eb1cb580137a7dee87aa9d23c88a93466d19e`);
  [`rapp_work.py`](../../../../rapp_work.py);
  [`work_conformance.py`](../../../../work_conformance.py);
  [`protocols/index.json`](../../../index.json).
- RAPP/1: [`SPEC.md`](../../../../SPEC.md) §§6.1, 6.1.1, 6.2, 6.3, 7.1, 7.2, 7.5, 7.6,
  10, 11.2, 12, 13.1 to 13.3 and 14;
  [`CONSTITUTION.md`](../../../../CONSTITUTION.md) Articles 2, 3, 4, 5, 6, 7, 8, 14
  and 18; [`EXTENDING.md`](../../../../EXTENDING.md);
  [`CONTRIBUTING.md`](../../../../CONTRIBUTING.md);
  [`rapp-backlog.md`](../../../../rapp-backlog.md).
- `rapp-hive/1` §§2, 9.1 and 12:
  <https://github.com/kody-w/rapp-work/blob/29ead23b21645f8d7682ee00414930ffa9ce0ca6/protocols/rapp-hive/1/SPEC.md>
  (SHA-256 `79aeef7bc5000f4a7b09483844b035c66adf817475540e583138f2e6b432c822`).
- `RAPP_WORK_PIN.json`:
  <https://github.com/kody-w/rapp-work/blob/29ead23b21645f8d7682ee00414930ffa9ce0ca6/RAPP_WORK_PIN.json>.
- The folder convention and its checker:
  <https://github.com/kody-w/rapp-model-hive/blob/2bd7c95152ede719b6418b80e2bdc2cd457bf711/HIVE-MD.md>
  (SHA-256 `f3186e0d88cc36e18582171fff4ed9a68feddc4ae316f66fb8acc2982892fd96`) and
  `agents/hive_agent.py` at the same commit (SHA-256
  `e9a2d7243da31fd2388f140bb8138c3d8d2db428ad09075530eb049a0355e8dd`).
- Hive Hub cards: `kody-w/hive-hub`, branch `experimental/organism-fit` (commit
  `d076f812f21dbf9cb9f813191f4f27c44d61b275`), `HUB.md` and `cards/`.
- The organism and the Work Constitution (read-only here): `kody-w/rapp-work`,
  branch `experimental/rapp-work-constitution`, commit
  `9e945f8ee532fb8a3e2e89e2c2c36f7fa778d7f7`: `organism/gaps/G10.md`, `G05.md`,
  `G08.md` and `G09.md`; `organism/crossings/folder-hive-organization.md`;
  `organism/parts/folder-hive.md`; `organism/journeys/E1.md` and `E3.md`;
  `CONSTITUTION.md` Part II, Article 16 and Part V.
- Companion G5 proposal: branch `experimental/gap-g5-owner-notary`,
  <https://github.com/kody-w/rapp-1/blob/experimental/gap-g5-owner-notary/protocols/rapp-work/1/proposals/0005-owner-as-hive-notary.md>.
- RFC 4253 §6.6 (SSH public key format), RFC 8709 (Ed25519 for SSH), RFC 8785 (JCS).
