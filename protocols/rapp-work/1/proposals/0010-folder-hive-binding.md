# Proposal 0010: bind a folder Hive through a folder-Hive organization

| | |
|---|---|
| **Status** | Draft, not accepted. Nothing here is in force. The owner decides. |
| **Gap** | G10: an organization cannot bind a folder Hive. |
| **Home spec** | Canonical `rapp-work/1` §§1, 2 and 4 ([`../SPEC.md`](../SPEC.md)) |
| **Proposed vehicle** | A new, additive sibling profile, `rapp-work-folder-hive/1` (working name), which adds a second, parallel organization type: the **folder-Hive organization**. `rapp-work/1` is not changed, and a `rapp-work/1` organization still binds only a `rapp-hive/1` Hive. |
| **Companion** | G5, the owner as the Hive's notary: branch `experimental/gap-g5-owner-notary`, file `protocols/rapp-work/1/proposals/0005-owner-as-hive-notary.md`. That proposal builds on this one. This one stands alone. |
| **Branch** | `experimental/gap-g10-folder-hive-binding` |

## Summary

A folder Hive is a git repository of markdown files with no owner inside. It has
no RAPPID, no Mother stream and no registry, so canonical `rapp-work/1` cannot bind
it. `work.organization` names one `rapp-hive/1` Hive by `hive_rappid`, and
`work.vector` records only an authenticated `rapp-hive/1` checkpoint. Both payloads
are closed, and the seven `work.*` kinds are closed.

This proposal leaves `rapp-work/1` exactly as it is. It meets G10 with a second,
parallel organization type, the **folder-Hive organization**, declared by one small
sibling profile with two kinds of its own on a body stream of its own:

1. **`folder-hive.organization`**: the folder-Hive organization's declaration. It
   has the accountable owner and the one hard world of `rapp-work/1` §2. In place of
   `hive_rappid` it has a **binding**, which names one folder Hive by its Hive id,
   its first (root) commit and its founder key fingerprint, under a convention
   version whose text and checker the adopting estate pins.
2. **`folder-hive.vector`**: the organization's signed record of an **accepted
   head**, a commit that the estate-pinned checker accepts on the one line from the
   root. Each vector names a head that comes strictly after the previous one, both
   by git ancestry and by the Hive's own acceptance of every commit in between, or it
   observes the previous head again, later.

A `rapp-work/1` organization still binds only a `rapp-hive/1` Hive, and no `work.*`
record names a folder Hive. In `/1` a folder-Hive organization has only a binding
and vectors: no releases, catalogs, migrations, receipts, observations or rollbacks.

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
  claim alone." It also binds "the RAPP CI/CD `release_scope`" and "an exact
  `policy_sha256`", which serve releases (below).
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
- `rapp_work.py` uses `release_scope` and `policy_sha256` only to qualify a release
  (`_qualified_release`: the release scope must equal the organization's, and the
  CI/CD qualification must bind its policy), for rollbacks, migrations and
  observations. `validate_organization` checks only their grammar.
- `rapp_work.advance_vector`, which `WorkLedger.accept_vector` applies, accepts a
  vector that names the retained Mother head again (same head, same catalog) with an
  `observed_utc` at least the retained one's, and needs no ancestry check for it.
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
- **Art. 7** and SPEC §6.2: a RAPPID tail is minted once, from entropy or a public
  key, and is never the hash of a name. SPEC §6.3: a tail that is not 64 lowercase
  hex (for example a 32-hex one) is provisional and "MUST NOT appear in any emitted
  frame, `stream_id`, egg, or registry entry".
- **Art. 10**: any copy of the reference primitives "must prove byte parity with
  `rapp.py` against shared vectors".
- **Art. 18**: canonicalization, hashes, the RAPPID grammar and mint, the eleven-key
  envelope, the consumer checklist and the wire never change under `rapp/1`.
- SPEC §6.1.1 and §7.2: a kind is `lclabel "." lclabel`, and the registry binds it to
  exactly one family. §13.3: every stream registers its creation `genesis`, and a
  `genesis` entry has exactly `type`, `stream_id`, `frame_hash`, `deprecated` and the
  optional `old_stream_id` and `new_stream_id`. A `protocol` entry has exactly `name`,
  `spec_repo`, `spec_path`, `spec_hash` and `deprecated`, and is "an estate adoption
  pin, never a power to redefine a protocol". §11.2 item 4: a profile is activated by
  a `protocol` entry pinning its exact repository, path and SHA-256.
- SPEC §11.1 item 1: if a release policy repeats the pinned `grail_id`, "that value is
  only a consistency assertion and MUST byte-equal the registry result; it cannot
  select or rebind the pin".
- SPEC §7.6: two valid frames at one stream position are a fork, refused past the
  fork point, and "only the owner resolves a fork (Art. X), by re-genesis (§12.1) if
  needed". §12.1: a re-genesis is a new owner-signed genesis of kind `body.re-genesis`
  (for a body stream) whose payload is only `migrated_from`. §14: after a compromise
  "the owner SHOULD advance affected stream heads (or re-genesis) past
  `revoked_utc`".
- `rapp-hive/1` §9.1 (in `kody-w/rapp-work` at `29ead23`) is the precedent for a
  separate stream: its receipts are "owner-signed on a separately registered body
  stream, not appended to the Mother as an alternative convergence".

### The folder Hive

The convention is `HIVE-MD.md` in `kody-w/rapp-model-hive`, branch
`experimental/hive-md`, commit `2bd7c95` (SHA-256 `f3186e0d…fd96`). Its checker and
Brainstem agent is one file, `agents/hive_agent.py` (SHA-256 `e9a2d724…e8dd`). Its
own docstring says it "Needs Python 3.11+, cryptography and git", unlike the
stdlib-only reference validators here, which CI runs on Python 3.9 and 3.13.

- `HIVE.md` holds `hive` ("a random id fixed by the first commit"), `version`,
  `approvals` (new Hives start at 2), and optional `fields` and `previous`.
- "Every commit after the pinned first commit has one parent and an SSH signature
  (namespace `git`) by a key that the tree at its parent lists under
  `members/<name>/keys/`, in that name." Each commit is judged by the rules as they
  stood at its parent. "History is one line". "`hive` and `.gitattributes` never
  change". "The first refused commit stops verification."
- Some rules read history, not only the tree at the parent: "A request that was ever
  admitted, even for a device retired since, is never filed again" (the checker's
  `admitted_ever` hashes every key file ever added on the first-parent line), and "A
  removal names the member's membership: the request moved in when their `keys/`
  folder was last created" (`Snap.admitted` walks the first-parent history).
- The text names its checker by path ("Verify it yourself": `python
  agents/hive_agent.py check`) and says "only the checker checks the rule". It does not
  name the checker's hash, and the text's hash does not fix the checker: at commits
  `5d1e4d8` and `0b780a5` `HIVE-MD.md` is the same (SHA-256 `38f0830c…1620`), while
  `agents/hive_agent.py` differs (`472afd82…` and `113a93e3…`).
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
  `experimental/rapp-work-constitution`, commit `71ef227`) says in Part II that the
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
  all family `body`, and the two convention pins `hive-md` and `hive-md/checker`,
  passes `rapp_work.validate_registry_adoption`. Adding `work.folder-vector` is
  refused: `rapp-work registry: unrecognized live work kinds ['work.folder-vector']`.
  So a sibling profile must not use the `work` label.
- `rapp_work.validate_organization` refuses a `hive` object in place of
  `hive_rappid` ("expected keys …"), refuses an extra `hive` member, and refuses a
  32-hex Hive id used as a RAPPID tail (`hive_rappid: expected RAPP/1 rappid`).
  `rapp.rappid_valid` is false for it.
- `rapp_work.validate_vector` refuses a git-commit checkpoint ("expected keys …") and
  a 40-hex commit id as `mother_head.frame_hash` ("expected 64 lowercase hex").
- `rapp_work.advance_vector` accepts a copy of the `work-lifecycle.json` vector that
  names the same Mother head again, with a later `observed_utc`, and no ancestry
  verifier.
- Frames of kinds `folder-hive.organization` and `folder-hive.vector` built with
  `rapp.build_frame` pass `rapp.verify_frame` steps 1 to 6 with a fixture signature
  verifier. They have exactly the eleven keys. The envelope does not change.

Run against the public synthetic model Hive (`tools/build_example.py`'s story at
`2bd7c95`, replayed in a scratch folder with Python 3.13 and `cryptography` 50):

- Root `f934db89e0c73d71843d634b8ddbd53154732735`, Hive id
  `185d0eb5d4b1247b260042d0d840d5c3` and founder
  `SHA256:q18VTrWDieC+Sc25wpbcIHm4/gUotkmUJpyFgDeOdyY`. These match its Hive Hub
  card. It has 41 accepted commits, and its forged push (`96c271b4bf`, journey J9) is
  refused. Its keys are public test keys, so they prove nothing.
- The SHA-256 tree digest of section 3, computed from the tree's own objects, equals
  the tree id that git 2.50.1 itself writes (`git mktree`) for the same files in a
  repository made with `--object-format=sha256`. This held for every accepted commit.
- Verdicts read history before the parent. On a scratch extension of the replay, a
  commit after height 40 that re-files the founder's own root request (its key was
  retired at journey J10, so no key file in the tree carries it) is refused by the
  pinned checker ("a request that was admitted once is never filed again"). The same
  judge with its history lookup (`admitted_ever`) disabled accepts it. A member's
  signed merge commit is refused ("history must stay one line"). A removal of the
  member `emery`, approved by every other member, is accepted, although its subject,
  emery's membership hash `3f9f786a…e417`, matches no key file in the judged tree.

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
| **(b) Sibling profile** (recommended) | `rapp-work-folder-hive/1`: a parallel folder-Hive organization type with its own two kinds (`folder-hive.*`, never `work.*`) and closed payloads, on its own body stream. It is subordinate to `rapp-work/1`: it reuses that profile's rules by reference, yields to it on any conflict, and is adopted by an estate's `protocol` entry. | Additive. Zero bytes change in `rapp-work/1`, its schema, its reference or the anchor, and it needs no SDK re-pin. It is growth by registration (Art. 4). The experiment stays in the newest scope and can be tried by one estate with one team. If real use says so, it can later be folded into (a). | A second, parallel organization type: the owner and world of §2, a binding in place of the Hive member, and no release members. A folder-Hive organization gets only a binding and vectors in `/1`, with no catalogs, migrations, receipts, observations or rollbacks. Those stay with `rapp-work/1` organizations. |
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
  which adds anchor inputs and needs an owner-ratified chain revision (Constitution
  Art. 14), or `rapp-work/2`.

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

> # RAPP Work folder-Hive organization
>
> **Protocol identifier:** `rapp-work-folder-hive/1`
> **Status:** Experimental additive profile (newest release scope only)
> **Parent:** `rapp-work/1` (canonical, `kody-w/rapp-1`), under `rapp/1`
> **Depends on:** a folder Hive convention whose text and checker the adopting
> estate pins
>
> The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD** and **MAY** are used
> as defined by RAPP/1 section 2.
>
> ## 1. Foundation and registration
>
> This profile defines the **folder-Hive organization**: a second, parallel
> organization type beside the `rapp-work/1` organization. A folder-Hive
> organization binds one folder Hive and records which states of that Hive it
> accepted. This profile changes no RAPP/1 byte and no `rapp-work/1` byte, kind,
> schema or rule. Every authoritative payload:
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
> 4. pin each folder Hive convention version that its folder-Hive organizations bind
>    with exactly two active `protocol` entries with the same `spec_repo`
>    (section 3):
>    - the **text pin**, whose `name` is the convention's registry name *N* and whose
>      `spec_hash` is the SHA-256 of the convention's text; and
>    - the **checker pin**, whose `name` is *N* followed by `/checker` and whose
>      `spec_hash` is the SHA-256 of the one checker file that the text names, taken
>      from the same commit as the text; and
> 5. register the creation `genesis` of every folder-Hive organization stream
>    (RAPP/1 §13.3), and never register a second live one whose binding names the
>    `root` of a live one (section 3).
>
> The kind set is closed for this profile. Its kinds never use the `work` label, so
> the closed `work.*` set of `rapp-work/1` is untouched. A folder-Hive organization
> body stream carries only these two kinds (section 4 covers forks and
> re-genesis). No new registry entry type, envelope, endpoint or `work.*` kind is
> implied. On any conflict, RAPP/1 wins, then `rapp-work/1`, then this profile.
>
> ## 2. The folder-Hive organization
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
> | `hive` | the binding (section 3) |
> | `created_utc` | RAPP/1 §7.4 form; equals the genesis frame's `utc` |
>
> Every grammar is the one `rapp-work/1/schema.json` uses for the same member. A
> folder-Hive organization has no releases in `/1`, so it carries neither
> `release_scope` nor `policy_sha256`, which serve releases in `rapp-work/1`. The
> organization identity is minted (RAPP/1 §6.2) and is never derived from the Hive,
> its id, its root, its founder, a repository, a URL or a path. Owner authority is
> evaluated through the adopting estate's signed registry and time-scoped signer
> rules, never from the declaration alone. The frame is signed by the owner in effect
> at its `utc`, with superseded and revoked keys refused as RAPP/1 §§6.3, 10 and 13.3
> require. A folder-Hive organization is not a `rapp-work/1` organization: it
> carries no `work.*` payload, and no `work.*` payload may name it.
>
> ## 3. The binding: one folder Hive under an estate-pinned convention
>
> `hive` has exactly these members:
>
> | Member | Grammar | Role |
> | --- | --- | --- |
> | `convention` | object: exactly `name` (text, 1 to 64 characters), `spec_sha256` and `checker_sha256` (each 64 lowercase hex) | Names the convention version. The estate's pins fix its bytes. |
> | `hive_id` | exactly 32 lowercase hex digits | The Hive's label under its convention: `HIVE.md` `hive:` |
> | `object_format` | `"sha1"` or `"sha256"` | The Hive repository's git object format |
> | `root` | 40 lowercase hex for `sha1`, 64 for `sha256` | The Hive's first commit |
> | `root_sha256` | 64 lowercase hex | The root's SHA-256 twin |
> | `root_tree_sha256` | 64 lowercase hex | The root's SHA-256 tree digest |
> | `founder` | `"SHA256:"` followed by exactly 43 characters of unpadded standard base64 | The founder key fingerprint: evidence |
>
> **Definitions.**
>
> - *Commit octets*: the octets git hashes to name a commit object, that is
>   `"commit " || decimal byte length of the content || 0x00 || content`, where
>   *content* is exactly what `git cat-file commit <id>` prints.
> - *SHA-256 twin*: `lowercase_hex(SHA-256(commit octets))`. It binds the commit
>   object alone: its headers (tree, parents, author, committer, signature) and its
>   message, in which the tree and the parents are named only by their object ids. For
>   `object_format` `"sha256"`, the twin **MUST** equal the object id itself.
> - *SHA-256 tree digest*: the object id that the commit's tree has in git's SHA-256
>   object format. It binds every file and folder of the tree by SHA-256, and it is
>   computed from the tree's own objects. A file's digest is `SHA-256("blob " ||
>   decimal byte length || 0x00 || content)`. A folder's digest is `SHA-256("tree " ||
>   decimal byte length || 0x00 || entries)`, where *entries* are the folder's own
>   entries in its own order, each `mode || " " || name || 0x00` followed by the 32
>   octets of that entry's digest. Only the modes `100644` (file) and `40000`
>   (folder) are allowed, and any other mode is refused. For `object_format`
>   `"sha256"`, the tree digest **MUST** equal the tree id that the commit names.
> - *Named commit*: this profile names every commit by three values: its object id in
>   the binding's `object_format`, its SHA-256 twin and its SHA-256 tree digest. To
>   check a named commit is to recompute all three from the commit's own objects.
>   Any mismatch is refused.
> - *Founder fingerprint*: OpenSSH's SHA-256 fingerprint of the founder's Ed25519
>   public key, that is `"SHA256:" || base64(SHA-256(key blob))` without `=` padding,
>   where the key blob is the SSH wire encoding `string("ssh-ed25519") ||
>   string(32-octet public key)` (RFC 4253 §6.6, RFC 8709).
>
> **What names the Hive, and what is evidence.** The folder Hive has no RAPP/1
> identity: it has no RAPPID, and this profile mints none for it, since a RAPPID is
> minted once and never derived (RAPP/1 §6.2).
>
> - Inside this profile, the root tells one Hive from another. `root`, `root_sha256`
>   and `root_tree_sha256` are content addresses of the Hive's first commit and of
>   every file in it. A different root is a different Hive, whatever id it carries.
> - `hive_id` is the Hive's label under its convention: 128 bits, drawn from fresh
>   randomness when the Hive is created, fixed by the root, and never changed. It is
>   carried only as this plain value. It is never a RAPPID, a RAPPID tail, a
>   `stream_id` or a `kid`, and it is never "upgraded" to one. On its own it is not
>   unique, since anyone can write any 32 hex digits into a new root.
> - `founder` is evidence. Derived from a public key, it shows that the root was
>   signed by the key the organization expected, and it is the value people compare
>   by voice or on a Hive card. It gives the founder no authority after the root.
> - `convention` names the rules, and the estate's text and checker pins fix their
>   bytes. The only authority in the binding is the signed genesis frame: the
>   organization's accountable claim that this is its Hive.
>
> **Verification against the Hive's own bytes.** Before accepting a genesis, a
> consumer **MUST**, in order, and **MUST** refuse (never repair) on any failure:
>
> 1. **Pins.** Find, in the authenticated adopting registry, exactly one active
>    `protocol` entry named `convention.name` (the text pin) and exactly one named
>    `convention.name` followed by `/checker` (the checker pin), both with the same
>    `spec_repo`. `convention.spec_sha256` and `convention.checker_sha256` **MUST**
>    byte-equal their `spec_hash` values. The two payload hashes are consistency
>    assertions only, as RAPP/1 §11.1 item 1 treats a repeated `grail_id`: they cannot
>    select, add or rebind a pin.
> 2. **Checker.** Judge only with checker bytes whose SHA-256 equals the checker pin,
>    which the consumer obtained and checked itself and runs itself, reading the
>    Hive's bytes only as data. A consumer never obtains or runs code because a
>    payload, a Hive or a locator names it. A verdict from any other code, a port
>    included, is not acceptance under this profile.
> 3. **Objects.** Obtain the Hive's objects by any transport into a repository the
>    consumer controls, with the convention's git hygiene: hooks, submodules,
>    alternates, remote helpers and filesystem monitors are off. Transport carries
>    bytes. It proves nothing. A missing object is refused, never assumed.
> 4. **Root commit.** Check `root` as a named commit (`root`, `root_sha256` and
>    `root_tree_sha256`). A SHA-1 implementation that detects collision attacks (git's
>    default, SHA-1DC) is **REQUIRED**, and an object it flags is refused.
> 5. **Root check.** Run the pinned checker's root check on `root`: no parent; a tree
>    with exactly `HIVE.md`, `.gitattributes` and the founder's one key file (plus the
>    convention's optional `MEMBER.md`); `HIVE.md` `version: 1`; signed in the `git`
>    namespace by the key in that key file, in the founder's name; the key file a valid
>    request of that key for this Hive.
> 6. **Id.** `HIVE.md` in the root tree names `hive: <hive_id>`.
> 7. **Founder.** The founder fingerprint of the key in the root's key file, which is
>    also the root's signing key, equals `founder`.
>
> A different root with the same `hive_id` is a different Hive and is refused.
>
> **One live binding per root in one estate.** An estate owner **MUST NOT** register
> the genesis of a folder-Hive organization whose binding names a `root` that a live
> folder-Hive organization of the same estate already binds. A consumer that finds
> two live folder-Hive organizations of one estate binding the same `root` **MUST**
> refuse both until the estate owner deprecates one (RAPP/1 §13.3), as for a fork
> (RAPP/1 §7.6). A `genesis` entry records only a `stream_id` and a `frame_hash`, so
> a consumer can prove that no second binding exists only by obtaining and verifying
> every live genesis frame of the estate. This profile does not require that proof,
> and nothing in it depends on one: a binding grants nothing inside the Hive, and
> every vector is bound to its own organization's genesis and stream. Across estates,
> bindings are independent.
>
> ## 4. Accepted-head vector
>
> **Accepted head.** A commit *H* is an *accepted head* of the bound Hive when the
> estate-pinned checker, run from `root`, judges every commit on the one line from
> `root` to *H* and refuses none. Each commit after `root` has exactly one parent, the
> commit that passed just before it, so a merge anywhere on the line is refused. Each
> commit is judged by the rules and membership in the tree at its parent **and** by
> the first-parent history before it, as the convention defines. Under `hive-md`, for
> example, a request that was admitted once is never filed again, and a removal names
> the membership fixed when the member's keys folder was last created. A verdict
> therefore depends on the whole line from `root`: a consumer **MUST** hold every
> object reachable from *H*, and a shallow copy cannot establish acceptance.
> `HIVE.md` at *H* must still name `hive_id`. Git ancestry alone is not acceptance: a
> descendant that contains one refused commit is not accepted. The proof is the
> consumer's own replay of the Hive's bytes. No payload, signature count, hosting
> badge or fetch result substitutes for it.
>
> `rapp-work-folder-hive/1-vector` has exactly these members:
>
> | Member | Grammar and meaning |
> | --- | --- |
> | `schema` | `"rapp-work-folder-hive/1-vector"` |
> | `organization_payload_hash` | particle hash of the organization genesis payload |
> | `observed_utc` | RAPP/1 §7.4 form; equals the frame's `utc` |
> | `head` | object with exactly `commit`, `commit_sha256`, `tree_sha256`, `height`, `rules_version` and `rules_sha256` |
> | `previous_vector_payload_hash` | `null` for the first vector; otherwise the particle hash of the retained vector |
>
> Within `head`:
>
> - `commit`, `commit_sha256` and `tree_sha256` name the accepted head (section 3).
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
> 3. check `head` as a named commit (section 3, step 4);
> 4. establish that `head.commit` is an accepted head at exactly `height`, and that
>    `rules_version` and `rules_sha256` match `HIVE.md` at it; and
> 5. for every vector after the first, against the retained vector *R*: require that
>    `previous_vector_payload_hash` equals *R*'s particle hash and `observed_utc` is at
>    least *R*'s, and that the vector is exactly one of:
>    - a **successor**: `height` is greater than *R*'s `height`; *R*'s commit is the
>      ancestor of `head.commit` exactly `height − R.height` first-parent steps back;
>      every commit after *R*'s commit up to `head.commit` is accepted (judging may
>      start after *R* because *R* was itself established from `root`, but each
>      judgment still reads the history before *R*); and `rules_version` is at least
>      *R*'s; or
>    - a **re-observation**: `head` equals *R*'s `head`, member for member. It records
>      that the organization observed the same accepted head again, later, as
>      `rapp-work/1` §4 lets a `work.vector` name the same Mother head again. Steps 3
>      and 4 hold because they held for *R*.
>
> The consumer persists the accepted vector as high-water, as `rapp-work/1` §4
> requires for `rapp-hive/1` vectors:
>
> - the same head again is a re-observation, never a successor, and an exact replay
>   of the retained frame changes nothing;
> - a lower `height` is rollback;
> - the same `height` with a different head is a fork;
> - a higher `height` that does not descend from the retained head is a fork of
>   rewritten history;
> - a descending line that contains a refused commit is refused; and
> - resetting or deleting retained vector state is not recovery.
>
> A fork of the Hive is surfaced as a drift finding and refused past the fork point.
> Only the Hive's members can repair their Hive, by resetting the shared copy to the
> last commit that verified. A stuck Hive's remedy is a new Hive, bound by a new
> folder-Hive organization.
>
> **Freshness, compromise and forks of the organization stream.** A vector's age is
> its `observed_utc`, and how old is too old is the consumer's policy (RAPP/1 §13.1).
> A re-observation renews it, and it lets the owner in effect advance the stream's
> head past a `revoked_utc` after a compromise (RAPP/1 §14). Two different frames at
> one position of the organization stream are a fork of that stream, and both are
> refused past the fork point (RAPP/1 §7.6). This profile defines no re-genesis: a
> consumer refuses a `body.re-genesis` frame on a folder-Hive organization stream, as
> it refuses every kind that is not one of this profile's two, so a RAPP/1 re-genesis
> (§12.1) ends the stream under this profile. A forked or bricked organization stream
> is replaced by a new folder-Hive organization, with a newly minted
> `organization_rappid`, after the estate owner deprecates the old genesis entry
> (RAPP/1 §13.3). The old stream's accepted frames stay readable history.
>
> ## 5. What a git commit does and does not authorize
>
> Inside the Hive, the convention decides. A signed commit by an admitted key
> authorizes effects inside that Hive only. For this profile, a commit, its signature,
> its ancestry, a fetch, a branch or tag, a hosting provider's mark, a commit time and
> an author name are evidence at most, never authority (`rapp-work/1` §9). Only a
> signed `folder-hive.vector` frame by the owner in effect records that the
> organization accepted a head, and only after the consumer has replayed it. A
> consumer that does not hold the Hive's bytes, or stops at a bound, cannot accept a
> vector. It may still verify the frame under RAPP/1, which shows only that the owner
> in effect signed the claim, and it reports the vector as not verified.
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
> deliberate act under another profile. An estate owner who keeps the one-binding
> rule of section 3 never binds one Hive into two worlds of that estate.
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
> kind bindings; the adoption prerequisites, both convention pins included; the
> binding against the Hive's bytes; accepted heads by a full-history replay under the
> estate-pinned checker; and vector high-water with re-observation, rollback and fork
> refusal. It passes the profile's positive and refusal vectors. It claims nothing
> about `rapp-work/1` conformance.

## Example payloads (non-normative)

These use synthetic values only. The RAPPIDs are placeholders, like
`protocols/examples/work-lifecycle.json` (a real organization mints its tails).
`hive-md` is only an example registry name. The Hive values come from the public
synthetic model Hive in `kody-w/rapp-model-hive` at `2bd7c95`, rebuilt with its own
`tools/build_example.py` story. Its keys are public test keys that prove nothing.
Particle hashes were computed with `rapp_profile.particle_hash` at `591e014`. The
companion G5 proposal repeats the four blocks from here to the successor vector,
byte for byte.

The adopting estate's two convention pins, as `protocol` entries (the pinned bytes
are `HIVE-MD.md` and `agents/hive_agent.py` at `2bd7c95`):

```json
[
  {
    "type": "protocol",
    "name": "hive-md",
    "spec_repo": "https://github.com/kody-w/rapp-model-hive",
    "spec_path": "HIVE-MD.md",
    "spec_hash": "f3186e0d88cc36e18582171fff4ed9a68feddc4ae316f66fb8acc2982892fd96",
    "deprecated": false
  },
  {
    "type": "protocol",
    "name": "hive-md/checker",
    "spec_repo": "https://github.com/kody-w/rapp-model-hive",
    "spec_path": "agents/hive_agent.py",
    "spec_hash": "e9a2d7243da31fd2388f140bb8138c3d8d2db428ad09075530eb049a0355e8dd",
    "deprecated": false
  }
]
```

Genesis, `folder-hive.organization`, particle
`0a2632ff92dfe251c2e78e94922ed0527ecb482e8a70bbde8dc01d0ef0e3d477`:

```json
{
  "schema": "rapp-work-folder-hive/1-organization",
  "organization_rappid": "rappid:@example/folder-hive-organization:4444444444444444444444444444444444444444444444444444444444444444",
  "owner_rappid": "rappid:@example/work-owner:5555555555555555555555555555555555555555555555555555555555555555",
  "world_id": "example-world",
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
    "root_tree_sha256": "fc9d58842eb027b7628259168d9fafc3fcf60d7b31f9eab6a21f4c6bee3035a6",
    "founder": "SHA256:q18VTrWDieC+Sc25wpbcIHm4/gUotkmUJpyFgDeOdyY"
  },
  "created_utc": "2026-09-25T12:00:00.000Z"
}
```

First vector (journey E1: the head that admitted a new member, height 18), particle
`9dcf878bad7186b081062a27922a1231eb33dd74c4951ea8e87589ca8728b0df`:

```json
{
  "schema": "rapp-work-folder-hive/1-vector",
  "organization_payload_hash": "0a2632ff92dfe251c2e78e94922ed0527ecb482e8a70bbde8dc01d0ef0e3d477",
  "observed_utc": "2026-09-25T12:05:00.000Z",
  "head": {
    "commit": "de4053fa2301ceccf8dca80d92d752b73eeb43f0",
    "commit_sha256": "7cfc2e471f3c8073cf58a404f732133be2dee66a6f9d9d7338136846c1c3f5dc",
    "tree_sha256": "ce0b110b05d24df5a180c03c9e3358e077f939438b0eefa0e118b607cf5b7822",
    "height": 18,
    "rules_version": 2,
    "rules_sha256": "d1a024ae0b88ed6516dcd3da3a01780d0e12602cd4f4d72689b9a85d8cf211be"
  },
  "previous_vector_payload_hash": null
}
```

Successor vector (the model's last accepted commit, height 40), particle
`aa75f7a805db81ec7ff80c603e542adff5c99fa0de7829ac5b538d04c6d5d1d3`:

```json
{
  "schema": "rapp-work-folder-hive/1-vector",
  "organization_payload_hash": "0a2632ff92dfe251c2e78e94922ed0527ecb482e8a70bbde8dc01d0ef0e3d477",
  "observed_utc": "2026-09-25T12:10:00.000Z",
  "head": {
    "commit": "af4ea0caee5dc8840a254b4b3f0c0aa242a76c5a",
    "commit_sha256": "7f7351b896478c16aed965b8a61c37213f350f6fccbf3b25fe16219af8355322",
    "tree_sha256": "207ef7ee0add56ae75d4034fb3b676da9bb9250ab58c21c5808e5cb89b4345cd",
    "height": 40,
    "rules_version": 2,
    "rules_sha256": "d1a024ae0b88ed6516dcd3da3a01780d0e12602cd4f4d72689b9a85d8cf211be"
  },
  "previous_vector_payload_hash": "9dcf878bad7186b081062a27922a1231eb33dd74c4951ea8e87589ca8728b0df"
}
```

The successor is valid because height 40 is greater than 18, commit `de4053fa…` is
22 first-parent steps behind `af4ea0ca…`, and all 22 commits after it pass the pinned
checker, which also reads the history before height 18.

A re-observation of that head an hour later (not repeated in G5), particle
`39862cd2f13f1cfe35c06516b841dc95e0fceff0833eb491e233a75a6657149d`:

```json
{
  "schema": "rapp-work-folder-hive/1-vector",
  "organization_payload_hash": "0a2632ff92dfe251c2e78e94922ed0527ecb482e8a70bbde8dc01d0ef0e3d477",
  "observed_utc": "2026-09-25T13:10:00.000Z",
  "head": {
    "commit": "af4ea0caee5dc8840a254b4b3f0c0aa242a76c5a",
    "commit_sha256": "7f7351b896478c16aed965b8a61c37213f350f6fccbf3b25fe16219af8355322",
    "tree_sha256": "207ef7ee0add56ae75d4034fb3b676da9bb9250ab58c21c5808e5cb89b4345cd",
    "height": 40,
    "rules_version": 2,
    "rules_sha256": "d1a024ae0b88ed6516dcd3da3a01780d0e12602cd4f4d72689b9a85d8cf211be"
  },
  "previous_vector_payload_hash": "aa75f7a805db81ec7ff80c603e542adff5c99fa0de7829ac5b538d04c6d5d1d3"
}
```

Its `head` equals the successor's member for member, so it adds no Hive state. It
only renews the age of the organization's latest observation.

## Token and compatibility analysis

- **New tokens only.** `rapp-work-folder-hive/1`,
  `rapp-work-folder-hive/1-organization` and `rapp-work-folder-hive/1-vector` are
  new. No existing token is widened or reshaped (Art. 2). Every `rapp-work/1`
  artifact verifies exactly as before.
- **`rapp-work/1` untouched.** Its closed seven kinds, schemas, reference, index
  entry, anchor inputs, rev-16 record and the `RAPP_WORK_PIN.json` pin in
  `kody-w/rapp-work` are unchanged, so no chain revision and no re-pin is needed.
  The recorded adoption check shows the sibling kinds and both convention pins
  coexist with a valid `rapp-work/1` adoption.
- **RAPP/1 untouched (Art. 18).** Same canonicalization, hashes, RAPPID grammar and
  mint, eleven-key envelope, consumer checklist, wire and eggs. Registrations use
  only existing entry types (`protocol`, `kind`, `genesis`), and no endpoint is added
  (Art. 4). The checker pin is an ordinary `protocol` entry: an exact repository,
  path and SHA-256 (RAPP/1 §§11.2 item 4 and 13.3), here for the convention's
  executable rules.
- **Identity (Art. 7).** The organization's RAPPID is minted. The Hive gets no
  RAPPID: inside this profile its root tells it apart, `hive_id` is its label, and
  `founder` is evidence.
- **Owner authority (Art. 6).** Evaluated against the owner in effect at each
  frame's `utc`, through the registry, exactly as `rapp-work/1` §2 does.
- **Convention versions.** A binding names one convention version, and the estate's
  two pins fix its text and checker bytes. The convention says: "The checker's rules
  change only with a new version of this convention, and then only tighten." Its
  checker bytes can still change under the same text (`5d1e4d8` and `0b780a5`),
  which is why the checker has its own pin. New bytes are pinned under a new
  convention name, and an organization moves to them by a new genesis after the old
  one is deprecated. A convention version never changes under a pin, and a binding
  whose hashes no longer match its live pins is refused.
- **Promotion path.** If the owner later chooses (a), a `rapp-work/2` would carry a
  tagged Hive member that includes this binding, and folder-Hive organizations would
  move by create-only migration to new identities. Accepted history stays readable
  under this token forever.
- **Not a rev-N+1 revision.** Nothing in `rapp/1` or `rapp-work/1` changes, and
  `EXTENDING.md` says: "Registered kinds, registry entries, vocabulary and
  subordinate profiles can grow under `rapp/1`." It becomes an amendment, carried by
  an owner-ratified chain append (Constitution Art. 14), only if the owner chooses
  (a), or publishes the profile in this repository's `protocols/index.json`.
- **Intended release.** Newest release scope only, as an experiment. It is not part
  of RAPP/1 LTS.

## Security analysis

| Threat | Handling |
|---|---|
| Copycat Hive reusing the id | `root`, `root_sha256` and `root_tree_sha256` pin the exact genesis. The same id under another root is another Hive. |
| Binding without the members' knowledge | The binding is the organization's own claim and grants nothing inside the Hive. Members are not asked, because the convention has no approval that names an organization (the companion G5 proposal raises this). A consumer never reads a binding as the members' consent. |
| Founder impersonation | The root must verify under its own key file's key, and that key's fingerprint must equal `founder`. People compare the fingerprint out of band, as invitations and Hive cards already do. |
| Checker substitution | The estate pins the checker in its own `protocol` entry, whose name follows from the text pin's and whose repository is the text pin's. The binding's two hashes are only consistency assertions, so neither the organization nor the Hive selects the judging code. A consumer runs only bytes equal to the checker pin, never code that a payload, a Hive or a locator names. Residual: the estate owner answers for pinning the checker the convention publishes with its text. |
| SHA-1 collisions | Every named commit (the root and each accepted head) is bound by SHA-256 twice: its commit octets by the twin, and its whole tree by the tree digest. A collision-detecting SHA-1 is required. Residual: the commits between named points, and the trees and blobs they name, are bound only by SHA-1 with collision detection, and verdicts depend on them. A `sha256` Hive removes that once hosting allows (open question 5). |
| History rewrite or force-push | High-water, first-parent ancestry at an exact depth, and fork refusal. The convention's devices refuse the same rewrite. |
| Shallow or partial copies | Verdicts read history before the parent, so a consumer must hold every object reachable from the head. A shallow copy gives "not verified", never "accepted". |
| Withheld or stale objects | A missing object is refused, never assumed. A stale vector is reported with its age, and freshness is the consumer's policy, as in RAPP/1 §13.1. A re-observation renews a quiet Hive's latest vector. |
| Forged commits by non-members | The checker refuses them. The model's forged push is a refusal vector. |
| Compromised member key | A Hive-level limit that the convention documents ("whoever holds a member's only key acts as that member until removed"). The organization records what the Hive accepted and cannot fix it. |
| Compromised owner key | The attacker can sign vectors only for heads that verify, so cannot originate Hive state. It can bind a Hive unilaterally (the binding grants nothing inside it) or fork the stream (both branches refused, RAPP/1 §7.6). Recovery is a tombstone and a re-anchor (RAPP/1 §§6.3, 10 and 13.3, and §13.2 when the owner is the estate owner), heeding the §14 note on backdated frames: the successor advances the stream past `revoked_utc` with a re-observation. A forked stream is replaced by a new organization (section 4). |
| Instruction injection from Hive text | Verifiers treat Hive bytes as data. The checker parses markdown and never runs it, git hooks stay off, and nothing from the Hive is executed or loaded as instructions. |
| Denial of service by huge histories | A consumer may bound its work. Beyond the bound it reports "not verified", never "accepted". |
| Cross-organization or cross-world replay | `organization_payload_hash` and stream binding (RAPP/1 §7.5 step 1a) tie every vector to one organization. The one-binding rule is an estate-owner duty, and a consumer that sees a duplicate refuses both. |

## Privacy analysis

- The payloads carry identifiers, content addresses, counts and versions only: no
  names, member keys, notes, titles, paths or file content.
- `founder` is a public-key fingerprint. The convention makes one key per device per
  Hive, so it links nothing by default. A founder who imported an older key (the
  convention's migration path allows it) links this Hive to that key's other uses.
  Organizations are told so, and fresh keys are recommended.
- The tree digests, like the commit ids, can confirm a copy that someone already
  holds. On their own they reveal nothing.
- Vector cadence reveals activity, so streams are GODD by default.
- The examples use only public synthetic values: public test keys, `example.com`,
  `example-world`, and placeholder RAPPIDs.

## Migration

- No estate has activated canonical `rapp-work/1` yet (the organism's G16), and no
  folder-Hive organization exists. Nothing migrates.
- Existing folder Hives need no change. A binding reads their existing root, id and
  founder.
- An organization that moves to a new Hive, for example a stuck Hive's successor
  that carries its files, binds it with a new genesis. So does an organization whose
  stream forked or bricked, or that moves to new convention bytes. The profile does
  not link the two in `/1` (an owner question).

## Rollback

- For this proposal: delete the branch, or refuse it. Nothing else depends on it.
- For an adopting estate: deprecate the profile's `protocol` and `kind` entries, the
  convention pins, and the organizations' `genesis` entries (append-only
  `deprecated: true`, RAPP/1 §13.3). Accepted frames stay readable history. They are
  never deleted or re-signed.

## Conformance vectors to add (described; not implemented in the canonical suites)

A future `folder_hive_conformance.py` would run these against a replayed synthetic
model Hive. Nothing is added to `work_conformance.py`.

**Positive**
1. The model Hive's binding verifies: both pins, the root as a named commit, the root
   check, the id and the founder.
2. A genesis frame with the example payload is accepted, with the signer the owner in
   effect.
3. The first vector at height 18 is accepted after a full replay.
4. The successor at height 40 is accepted after an incremental replay from height 18,
   which still reads history before height 18.
5. The re-observation of height 40 is accepted, and renews the vector's age.
6. An exact replay of the retained vector frame changes nothing.
7. The adoption check accepts `rapp-work/1` plus the two sibling kinds and both
   convention pins.

**Refusal**
1. `hive_id` differs from `HIVE.md` at the root.
2. A copycat root: the same id and a different founder key.
3. `founder` is not the root signer's fingerprint.
4. `root_sha256` or `root_tree_sha256` differs from the recomputed value.
5. The root has a parent, or an extra file.
6. The checker is not estate-pinned: no active entry named `hive-md/checker`, two of
   them, or one whose `spec_repo` differs from the text pin's.
7. `spec_sha256` or `checker_sha256` differs from the estate's pin.
8. A payload, a Hive file or a locator that offers checker bytes: the consumer fetches
   and runs nothing it names, and judges only with its own pinned bytes.
9. A second live binding of the same root in one estate refuses both.
10. A vector naming a different head at the retained height (fork).
11. A lower height (rollback).
12. A higher height that does not descend (rewritten history).
13. A descending line that contains the model's forged push (refused commit).
14. A signed merge commit on the line, even one whose parents both passed.
15. An incremental replay from *R* whose next commit re-files a request admitted
    before *R*: in the model, the founder's own root request re-filed after height
    40. Only a checker that reads history before *R* refuses it.
16. A shallow copy that lacks the history before *R*: not verified.
17. `height` differs from the first-parent count.
18. `commit_sha256` or `tree_sha256` differs from the recomputed value.
19. `rules_version` or `rules_sha256` differs from `HIVE.md` at the head, or
    `rules_version` decreases.
20. Missing objects.
21. An object that git's collision detection flags (for example a blob holding the
    public SHAttered collision prefix).
22. An unsigned frame, or a signer that is not the owner in effect (including an old
    key after rotation, and a tombstoned key).
23. A `folder-hive.*` frame on a `rapp-work/1` organization stream, a `work.*` frame
    on a folder-Hive organization stream, or a `body.re-genesis` on a folder-Hive
    organization stream.
24. A closed payload with an extra member (for example a member name, or
    `rapp-work/1`'s `release_scope`).
25. `observed_utc` differs from the frame's `utc`, or goes backwards.
26. Retained state reset to an older vector.

Each critical refusal would be proven to turn red under a controlled mutation before
it is committed (Constitution Art. 8: a red oracle is a finding, and a check is never
weakened to pass).

## Reference implementation and gating

None in this proposal. The gap is an idea, and ideas get a proposal only. A later
reference would be a stdlib-only `rapp_work_folder_hive.py` that imports `rapp.py`'s
canonicalizer (Art. 10) and takes the git replay as an injected verifier, so the
protocol validators stay stdlib-only. The verifier would run the checker only from
bytes equal to the estate's checker pin, with the checker's own runtime (Python 3.11
or later, `cryptography` and git). It would ship under its own token, off by
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
> accept or refuse, judged by the rules and membership at its parent commit and by
> the history before it. The Hive has no owner, no RAPPID, no Mother stream and no
> registry. Its identity under its convention is a 128-bit random id fixed by its
> first commit. Invitations and discovery cards name it by that id, its first commit
> and its founder's key fingerprint. The group wants a RAPP Work organization, with
> one accountable owner in one world, to bind this Hive and record which Hive states
> it accepted, without treating git as authority.
>
> ## Ambiguity
>
> Canonical `rapp-work/1` §2 binds "one sovereign `hive_rappid`", and §4 says
> `rapp-work/1-vector` "captures the authenticated `rapp-hive/1` checkpoint". §1
> closes the seven `work.*` kinds, and §9 says a Git commit is not authority. Both
> payload schemas are closed. The reference refuses any other live `work.*` kind and
> any other kind on the organization stream. Constitution Art. 2 forbids widening
> either payload in place, and Art. 7 forbids deriving a RAPPID from the Hive's id or
> root.
>
> 1. Is binding a folder Hive in scope for `rapp-work/1` at all, or only for a
>    successor (`rapp-work/2`) or a sibling profile with its own kinds and a second,
>    parallel organization type?
> 2. May a sibling profile declare an organization-shaped genesis (the owner and world
>    of §2, a folder-Hive binding in place of `hive_rappid`, and no release members)
>    on its own body stream?
> 3. Is the triple of Hive id, first commit and founder fingerprint, under a
>    convention whose text and checker the estate pins, an acceptable binding, with
>    the triple as evidence and the signed genesis as the only authority?
> 4. May a signed record name an "accepted head" (a commit the estate-pinned checker
>    accepts from the pinned root), with high-water by height and first-parent
>    ancestry, re-observation of the same head, and the consumer's own full-history
>    replay as proof?
> 5. Are SHA-1 Hives acceptable with SHA-256 twins and tree digests at named
>    commits, or must bindable Hives use SHA-256 object ids?
> 6. Should one estate be limited to one live binding per Hive, as an estate-owner
>    duty that consumers enforce when they see a duplicate?
> 7. May a `protocol` entry pin a convention's checker (its executable rules) the way
>    it pins a specification?
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
5. SHA-1: SHA-1 Hives with SHA-256 twins and tree digests at every named commit
   (proposed), or `sha256` object format only once hosting allows it? Should a
   SHA-256 chain over every commit on the line also be pinned, to cover the commits
   between named points?
6. One live binding per root per estate, as an estate-owner duty that consumers
   enforce when they see a duplicate (proposed), or must a consumer resolve every
   live genesis of the estate, and refuse folder-Hive bindings while one is
   unavailable?
7. The registry names of the convention and its checker pin (`N` and `N/checker`
   proposed). It depends on Work Constitution Part V.1 giving the convention a real
   token. Or should a later convention version name its checker's hash in its own
   text, so that the text pin alone fixes both?
8. Ports: only the pinned checker bytes decide in `/1` (proposed), or may a port
   decide once the convention publishes shared vectors it must pass, as Constitution
   Art. 10 does for copies of `rapp.py`?
9. Re-genesis: none in `/1`, so a forked or bricked organization stream is replaced
   by a new organization (proposed), or a re-genesis that carries the declaration
   forward?
10. Should `/1` link a successor organization (a new Hive, new convention bytes, or a
    replaced stream) to its predecessor's last vector, or leave that to a later
    version once real use asks for it (proposed)?
11. Graduation criteria: Work Constitution Article 16 (a real team, a real week), then
    the rings.

## Owner actions needed

- Decide the vehicle, the token name and the home (questions 1 to 3).
- If accepted as an experiment: publish the profile text at the chosen home, and
  have the adopting estate sign its `protocol`, `kind`, convention-pin and `genesis`
  entries. That is the estate owner's signature, not this proposal's.
- Keep RAPP/1 LTS and canonical `rapp-work/1` unchanged. No chain revision and no
  `RAPP_WORK_PIN.json` re-pin is needed unless (a) is chosen.
- Relay the gap status to the organism (G10: `proposed`). Its G10 fix text, journey
  E1 and the folder-Hive crossing still say that a `work.vector` would name the
  accepted head. Under this proposal it is a `folder-hive.vector` of a parallel
  folder-Hive organization, and `work.vector` stays `rapp-hive/1` only. The
  organism's files are edited only by their own agent.

## Evidence: how the recorded values were produced

- The model Hive values come from running the story of
  `kody-w/rapp-model-hive@2bd7c95` `tools/build_example.py` in a scratch folder
  (Python 3.13, `cryptography` 50), then reading its shared copy with the model's own
  `agents/hive_agent.py` functions (`verify`, `check_root`, `judge`, `fingerprint`,
  `Snap`, `admitted_ever`). Each commit's octets were hashed with SHA-1 (checked
  against the id) and SHA-256. Each tree digest was computed from the tree's own
  objects and compared with the tree id that `git mktree` writes for the same
  entries in a scratch repository made with `--object-format=sha256`.
- The history evidence was produced on a scratch clone of that shared copy, with
  commits signed by the model's public test keys: a re-filed root request, a merge,
  and two approvals plus the removal of `emery`, each judged with the model's `judge`
  and, for the re-filed request, once more with `admitted_ever` replaced by an empty
  lookup.
- The two checker hashes at `5d1e4d8` and `0b780a5` come from `git show
  <commit>:agents/hive_agent.py` in a read-only clone of `kody-w/rapp-model-hive`.
- The adoption, validator and frame evidence come from `rapp_work.py`,
  `rapp_registry.py` and `rapp.py` at `591e014`, on Python 3.9.6 and 3.13, with
  identical results.
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
  10, 11.1, 11.2, 12, 12.1, 13.1 to 13.3 and 14;
  [`CONSTITUTION.md`](../../../../CONSTITUTION.md) Articles 2, 3, 4, 5, 6, 7, 8, 10,
  14 and 18; [`EXTENDING.md`](../../../../EXTENDING.md);
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
  `e9a2d7243da31fd2388f140bb8138c3d8d2db428ad09075530eb049a0355e8dd`). The same
  repository at `5d1e4d8eaa577b25c230a0cdca27b5789d3cdb71` and
  `0b780a51788d9f2372e0f34a80c1cab370f9e9a7`: `HIVE-MD.md` SHA-256
  `38f0830caef10a8768198c52f7b94a8dc551180a432e94d52b875e8023cd1620` at both;
  `agents/hive_agent.py` SHA-256
  `472afd82a27db60aa063d55f00f4d1275d247243c2b9b998b29f5511c359c5a6` and
  `113a93e38ee036418208d93a7f8f551c123db04b7e6fa7941a578aaf8e9d55c1`.
- Hive Hub cards: `kody-w/hive-hub`, branch `experimental/organism-fit` (commit
  `d076f812f21dbf9cb9f813191f4f27c44d61b275`), `HUB.md` and `cards/`.
- The organism and the Work Constitution (read-only here): `kody-w/rapp-work`,
  branch `experimental/rapp-work-constitution`, commit
  `71ef227555ad565aaff20c549968c31dcd1d4778`: `organism/gaps/G10.md`, `G05.md`,
  `G08.md` and `G09.md`; `organism/crossings/folder-hive-organization.md`;
  `organism/parts/folder-hive.md`; `organism/journeys/E1.md` and `E3.md`;
  `CONSTITUTION.md` Part II, Article 16 and Part V.
- Companion G5 proposal: branch `experimental/gap-g5-owner-notary`,
  <https://github.com/kody-w/rapp-1/blob/experimental/gap-g5-owner-notary/protocols/rapp-work/1/proposals/0005-owner-as-hive-notary.md>.
- git's SHA-256 object format: the hash-function transition design,
  <https://git-scm.com/docs/hash-function-transition>; git's collision-detecting
  SHA-1 (SHA-1DC), reported by `git version --build-options`.
- RFC 4253 §6.6 (SSH public key format), RFC 8709 (Ed25519 for SSH), RFC 8785 (JCS).
