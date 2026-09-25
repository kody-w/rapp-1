# Proposal 0005: the owner as the Hive's notary

| | |
|---|---|
| **Status** | Draft, not accepted. Nothing here is in force. The owner decides. |
| **Gap** | G5: an organization has one owner only, so co-equal groups do not fit. |
| **Home spec** | Canonical `rapp-work/1` §2 ([`../SPEC.md`](../SPEC.md)) |
| **Proposed vehicle** | A new, additive sibling profile, `rapp-work-notary/1` (working name). `rapp-work/1` is not changed. |
| **Depends on** | G10, the folder-Hive binding (`rapp-work-folder-hive/1`, a draft on branch `experimental/gap-g10-folder-hive-binding`, file `protocols/rapp-work/1/proposals/0010-folder-hive-binding.md`). The parts used here are summarized below, so this document stands alone. |
| **Branch** | `experimental/gap-g5-owner-notary` |

## Summary

Canonical `rapp-work/1` gives an organization exactly one accountable owner. A
group of equals keeps its work in a folder Hive, which has no owner inside: its
members decide together, by approvals counted under the Hive's own rules. Outside
the Hive, though, only RAPP/1 signatures verify against a registry, and a RAPP/1
frame carries exactly one signature.

This proposal keeps the one accountable owner and changes what that owner may sign.
The owner becomes the **Hive's notary**: they sign at the edge only what the Hive
already approved, and every notarization names that approval exactly:

- **the approval's exact reference**: its kind, the subject hash the approvals
  name, the commit it was judged at, and the commit that applied it;
- **the threshold evidence**: how many members there were, how many approvals
  the rules required, and how many counted; and
- **the rule version it was judged under**: `HIVE.md`'s version and hash at that
  commit, under the convention bytes the binding pins.

Any verifier that holds the Hive's bytes can recompute every one of these values.
A notarization that does not match is refused, and it remains signed evidence
against the notary who signed it. The notary may refuse to sign. The notary may
never originate a decision, alter one, or sign without a matching approval.

## Context: what is true today

All references are to `kody-w/rapp-1` at `591e014` unless stated otherwise.

### Canonical `rapp-work/1` (`protocols/rapp-work/1/SPEC.md`)

SHA-256 `283359355c3fe2858e28744368255683af3ed28a68e290e56c231e7d4b13c08e`.

- **§2** binds "the accountable `owner_rappid`" and says: "Owner authority is
  evaluated through the adopting estate's signed registry and time-scoped signer
  rules, never from an organization claim alone."
- **§1** closes the seven `work.*` kinds: "No eighth `work.*` kind, new registry
  entry type, alternate envelope, or endpoint is implied." Every authoritative
  payload is signed, even where RAPP/1 would allow `sig:null`.
- **§9**: "Consequential effects require the signed RAPP/1 occurrence, authenticated
  registry, retained high-water, profile-specific evidence, and authorized signer."
- The schema (SHA-256
  `ff30f9878f12fa4ad7d93c4c205eb1cb580137a7dee87aa9d23c88a93466d19e`) and
  `rapp_work.py` close every payload. `policy_sha256` is the release qualification
  policy: `rapp_work.py` checks releases against it through `qualification_verifier`.

### RAPP/1 (`SPEC.md`, rev-16) and its Constitution

- **§10**: `sig` is one detached JWS whose protected header has exactly `alg`, `b64`,
  `crit` and `kid` (the signer's RAPPID). Key discovery goes through the §13
  registry. "A consumer MUST NOT infer authorship from an unsigned frame."
- **§10 and §6.3**: key rotation is a `re-anchor` record (the old key's continuity
  signature is required for `rotation`). A verifier refuses a superseded key on frames
  at or after the re-anchor's `utc`, and a tombstoned key on frames at or after its
  `revoked_utc`. Compromise is a `tombstone` plus a `compromise` re-anchor
  (§13.3). **§13.2** applies the same time-scoping to the estate owner:
  "owner-signed" means signed by the owner in effect at the artifact's `utc`. §14
  warns that a compromised key can backdate frames just below `revoked_utc`.
- **Constitution Art. 5**: the registry is the root of trust. **Art. 6**: authority
  is scoped in time. **Art. 18**: the eleven-key envelope and consumer checklist
  never change under `rapp/1`, so one frame cannot carry two signatures.
- **Art. 2**: a new key set moves the token. **Art. 4**: grow by registration.

### The folder Hive and its decisions

The convention is `HIVE-MD.md` in `kody-w/rapp-model-hive` at `2bd7c95` (SHA-256
`f3186e0d88cc36e18582171fff4ed9a68feddc4ae316f66fb8acc2982892fd96`). Its checker is
`agents/hive_agent.py` (SHA-256
`e9a2d7243da31fd2388f140bb8138c3d8d2db428ad09075530eb049a0355e8dd`).

- There is no owner inside. Every change is one signed commit, judged by the rules
  and membership as they stood at its parent ("The one rule").
- The approvals: "`approve: admit|remove|rules|publish`, the `sha256` of the exact
  subject, and `member` (remove) or `replaces` (rules). The approver's signed commit
  is its signature."
- The one rule sets the numbers. *threshold* = max(1, min(`approvals`, members)).
  Admit needs *threshold* approvals. Rules needs max(1, min(max(old, new
  `approvals`), members)) "approvals naming both hashes". Remove needs "every other
  member, at least two". "The signer counts once, and only current members'
  approvals of the exact hash count."
- Publishing: "A manifest in `members/<name>/publish/` names the public copy and
  lists `sha256  path` for files of one room. With *threshold* approvals, the
  Brainstem copies exactly those files into a separate repository with
  `PUBLISHED.md`". `check-public --hive` checks that the files, `to:` and `hive:` are
  "exactly those of a manifest the Hive approved".
- Known limit: "With `approvals: 1`, a member can admit a second identity of their
  own and outvote a lone co-member".

### The RAPP Work Constitution and the organism (read-only here)

These are in `kody-w/rapp-work`, branch `experimental/rapp-work-constitution`,
commit `9e945f8`.

- **Article 7**: signatures decide; transport carries. **Article 9**: a publication's
  "approval binds the exact files and the destination". **Article 15**: old records
  "are called RAPP/1-verified only where a signed registry holds their keys".
- **Part V.2** (proposed, G9): inside a Hive, a signed commit by an admitted key
  authorizes effects inside that Hive only, and "an effect that crosses a world
  boundary still needs one under `rapp-work/1`". **Part V.4** (proposed, G8):
  members are names bound to keys by the Hive's signed history.
- `organism/gaps/G05.md`: "One idea, not yet proposed to `rapp-work/1`, makes the
  owner the Hive's notary: they sign at the edge only what the Hive already approved,
  and name that approval. No specification provides notarizing today."
- `organism/crossings/folder-hive-organization.md`: "Nothing yet (idea: the owner
  notarizes the accepted head; G5, G10)". Journey E3: "the organization could later
  notarize the publication with RAPP/1".

## What this proposal builds on (G10, summarized)

G10 proposes `rapp-work-folder-hive/1`, a sibling profile with its own two kinds on
its own body stream. It leaves `rapp-work/1` unchanged.

- A **folder-Hive organization** genesis (`folder-hive.organization`) has the
  accountable-body fields of `rapp-work/1` §2 (`organization_rappid`,
  `owner_rappid`, `world_id`, `release_scope`, `policy_sha256`, `created_utc`), plus
  a `hive` binding in place of `hive_rappid`: pinned convention bytes, `hive_id`,
  `object_format`, `root` with its SHA-256 twin, and the `founder` key fingerprint.
  The Hive id is the convention's own name and never a RAPPID. The root and the
  fingerprint are evidence. The signed genesis is the only authority.
- An **accepted head** is a commit that the pinned convention, run from the root,
  judges on the one line with no refused commit.
- A **vector** (`folder-hive.vector`) is the owner's signed record of an accepted
  head (`commit`, SHA-256 twin, `height`, `rules_version`, `rules_sha256`). Each
  vector comes strictly after the previous one, by first-parent ancestry and by the
  Hive's own acceptance of every commit in between.

Under this proposal, every G10 vector is a **head notarization**. The approval it
names is the Hive's own acceptance of every commit up to the head, and the rule
version is `head.rules_version` and `head.rules_sha256`. This proposal adds no rule
to vectors. It adds the **decision notarization** below. If G10 is refused, this
proposal has nothing to bind to and waits.

## The problem, precisely

1. **One accountable owner.** `rapp-work/1` §2 has exactly one `owner_rappid`, and
   owner authority is evaluated through the registry. A group of equals has no one
   inside its Hive who may decide alone.
2. **Hive signatures do not verify outside.** Members sign with SSH keys that the
   Hive's own history binds to names. No RAPP/1 registry holds those keys (G8), so
   outside the Hive a member's approval is convention-level evidence, not a RAPP/1
   signature.
3. **One signature per frame.** RAPP/1 §10 gives a frame one `sig` with one `kid`,
   and Art. 18 freezes the envelope. The group cannot co-sign a frame.
4. **No notarizing.** No specification says how an owner may sign for a decision
   they did not make, or how anyone can check that they signed only what was
   decided.

## Vehicles considered

| Vehicle | What it is | For | Against |
|---|---|---|---|
| **(a) `rapp-work/2`** | A successor organization with an owner role (for example `owner_role: "notary"`) and decision records. | One organization model. | Moves the whole token (the G10 analysis applies). It still needs a folder-Hive binding first, and it puts an experiment into the organization profile before it graduates. |
| **(b) Sibling profile** (recommended) | `rapp-work-notary/1`: one kind, `notary.notarization`, on one notary stream per folder-Hive organization. It is subordinate to `rapp-work/1` and to G10's binding profile. | Additive and small: one kind and one closed payload. `rapp-work/1` is untouched. The owner stays the one accountable RAPPID. Every check is a recomputation of the Hive's own rules, so no new decision rule is invented. | Depends on G10. It notarizes only the decisions the convention can express today (the four approval kinds). |
| **(c1) A promise in the policy** | The owner promises, in a document pinned by `policy_sha256`, to sign only what the Hive approved. | No new records. | Refused. `policy_sha256` is the release qualification policy, so this would give it a second meaning. A promise is also not checkable. |
| **(c2) Register every member key** | Add each member's key to the registry as an `spki` entry, so members sign RAPP/1 frames themselves. | Members' signatures verify outside. | Refused for now. The estate owner would append and deprecate those entries, so one owner's registry would decide who is in. That goes against the convention (no owner inside) and Work Constitution Part V.4 (members are names bound to keys by the Hive's signed history). It duplicates the Hive's membership, links per-Hive device keys, and still gives no form for "k of n approved". |
| **(c3) Co-signed frames** | Several signatures on one frame. | Direct group signing. | Refused. It changes the frozen envelope (RAPP/1 §10, Art. 18), so it is a `rapp/2` conversation. |
| **(c4) `work.receipt`** | Record decisions as receipts. | No new kinds. | Refused. Receipt types are closed, and folder-Hive organizations are not `rapp-work/1` organizations. |

**Recommendation: (b), as an experiment in the newest release scope, beside G10.**
At graduation the owner decides whether it stays a subordinate profile or is folded
into a `rapp-work/2`.

## Proposed change

### Changes to canonical `rapp-work/1`

None. `protocols/rapp-work/1/SPEC.md`, `schema.json`, `rapp_work.py`,
`work_conformance.py`, `protocols/index.json`, `anchor/**` and the conformance
vectors stay byte for byte as they are. The owner of a `rapp-work/1` organization
signs exactly as today.

### Proposed normative text: a new profile document (insertion)

The quoted text below is the exact proposed text of a new document,
`protocols/rapp-work-notary/1/SPEC.md`, at the location the owner chooses (the G10
proposal discusses where). Here "this profile" means `rapp-work-notary/1`, and
"folder-Hive organization", "binding", "accepted head" and "vector" have their
meanings in `rapp-work-folder-hive/1`.

> # RAPP Work Hive notary
>
> **Protocol identifier:** `rapp-work-notary/1`
> **Status:** Experimental additive profile (newest release scope only)
> **Parent:** `rapp-work-folder-hive/1`, under `rapp-work/1` and `rapp/1`
>
> The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD** and **MAY** are used
> as defined by RAPP/1 section 2.
>
> ## 1. Foundation and registration
>
> This profile lets a group of equals keep one accountable owner, who notarizes the
> group's decisions and makes none. It changes no RAPP/1 byte, no `rapp-work/1` byte
> or rule, and no `rapp-work-folder-hive/1` rule. Every notarization is canonical
> RAPP/1 I-JSON, travels in the frozen eleven-key frame, is signed, and is accepted
> only after registry, signature, signer, stream and payload authorization.
>
> An adopting estate **MUST**:
>
> 1. hold active adoptions of canonical `rapp-work/1` and of
>    `rapp-work-folder-hive/1`;
> 2. append one `protocol` entry pinning this exact specification;
> 3. append exactly one `kind` entry, `notary.notarization`, bound to the `body`
>    family, whose only permitted payload schema is
>    `rapp-work-notary/1-notarization`; and
> 4. register the creation `genesis` of every notary stream (RAPP/1 §13.3).
>
> The kind set is closed. No new registry entry type, envelope, endpoint or `work.*`
> kind is implied. On any conflict, RAPP/1 wins, then `rapp-work/1`, then
> `rapp-work-folder-hive/1`, then this profile.
>
> ## 2. The notary
>
> In an adopting estate, every folder-Hive organization is **notary-bound**, and its
> owner in effect is its Hive's **notary**. The owner in effect is the organization's
> `owner_rappid` as the registry's re-anchor records carry it forward, with
> superseded and revoked keys refused as RAPP/1 §§6.3, 10 and 13.3 require (the
> time-scoped signer rules of `rapp-work/1` §2). The members decide inside the Hive.
> The notary signs at the edge.
>
> The notary's statements for the Hive are exactly two:
>
> - **head notarizations**: the organization's `folder-hive.vector` frames, unchanged.
>   The approval each one names is the Hive's own acceptance of every commit up to
>   its head, under the rules `head.rules_version` and `head.rules_sha256` name.
> - **decision notarizations**: `notary.notarization` frames (section 3).
>
> A consumer **MUST NOT** treat any other statement signed by the owner as a decision
> or state of the Hive.
>
> Each folder-Hive organization has at most one **notary stream**: a separately
> registered body stream whose `stream_id` is a RAPPID minted for it (RAPP/1 §6.2),
> carrying only `notary.notarization` frames, whose genesis frame is the
> organization's first notarization. Every frame on it is signed by the notary in
> effect at its `utc`, and by nobody else. There is no delegation.
>
> ## 3. The notary act
>
> A `rapp-work-notary/1-notarization` payload states that the Hive approved exactly
> one decision, and names that approval. It has exactly these members:
>
> | Member | Grammar and meaning |
> | --- | --- |
> | `schema` | `"rapp-work-notary/1-notarization"` |
> | `organization_payload_hash` | 64 lowercase hex: the folder-Hive organization's genesis payload particle |
> | `vector_payload_hash` | 64 lowercase hex: a vector of that organization that the consumer accepted |
> | `notarized_utc` | RAPP/1 §7.4 form; equals the frame's `utc` |
> | `approval` | the approval's exact reference (below) |
> | `threshold` | the threshold evidence: exactly `members`, `required` and `counted`, each a `uint53` of at least 1 |
> | `rules` | the rule version: exactly `version` (a whole number from 1 to 999999999) and `sha256` (64 lowercase hex), the convention's subject hash of `HIVE.md`, both at `approval.judged_at` |
> | `effect` | `null` for `admit`, `remove` and `rules`; for `publish`, the public-copy effect (below) |
> | `previous_notarization_payload_hash` | `null` at the notary stream's genesis; otherwise the particle of the previous notarization on the stream, equal to the frame's `prev` |
>
> `approval` has exactly these members:
>
> - `kind`: `"admit"`, `"remove"`, `"rules"` or `"publish"`, the convention's closed
>   approval kinds;
> - `subject_sha256`: the exact subject hash that the Hive's approvals name (their
>   `sha256:`);
> - `replaces_sha256`: for `rules`, the hash of the rules text it replaces (the
>   approvals' `replaces:`); otherwise `null`;
> - `judged_at`: exactly `commit` (an object id in the binding's `object_format`) and
>   `height` (`uint53`). This is the commit whose tree the decision is judged against.
>   For `admit`, `remove` and `rules` it is the parent of `effect_commit`. For
>   `publish` it is the named vector's head.
> - `effect_commit`: for `admit`, `remove` and `rules`, the Hive commit that applied
>   the decision, whose one parent is `judged_at.commit`; for `publish`, `null`.
>
> The public-copy `effect` has exactly these members:
>
> - `kind`: `"public-copy"`;
> - `to`: text of 1 to 64 characters, exactly the manifest's `to:` value (the
>   destination the Hive approved);
> - `object_format`: `"sha1"` or `"sha256"`, of the public copy;
> - `commit`: the public copy commit that carries the publication;
> - `commit_sha256`: its SHA-256 twin (as defined in `rapp-work-folder-hive/1`); and
> - `published_sha256`: the convention's subject hash of that commit's `PUBLISHED.md`.
>
> No member may carry a member name, a key or fingerprint, a request text, a note, a
> title, a path or file content.
>
> ## 4. Verification of a notarization
>
> Before accepting a notarization, a consumer **MUST**, in order, and **MUST** refuse
> (never repair) on any failure:
>
> 1. **Frame and stream.** Verify the frame under RAPP/1 §7.5 with a signature,
>    registered kind and body family. It must sit on the organization's one live
>    notary stream: two live notary streams naming one organization refuse every
>    notarization of it until the estate owner deprecates one (RAPP/1 §13.3).
>    `previous_notarization_payload_hash` must equal the frame's `prev` (and be
>    `null` only at genesis).
> 2. **Signer.** The signer is the organization's notary in effect at the frame's
>    `utc`, and `notarized_utc` equals that `utc`.
> 3. **Organization and vector.** `organization_payload_hash` names a folder-Hive
>    organization genesis the consumer accepted and that is still live.
>    `vector_payload_hash` names a vector of that organization the consumer accepted,
>    and `notarized_utc` is not earlier than its `observed_utc`.
> 4. **On the accepted line.** `judged_at.commit` is the vector head, or its ancestor
>    exactly `head.height − judged_at.height` first-parent steps back. For `publish`,
>    it is the vector head itself. `effect_commit`, when present, is the next commit on
>    that line, at height `judged_at.height + 1`, and not above the vector head.
>    Nothing is notarized before an accepted vector reaches it.
> 5. **Rule version.** `rules.version` and `rules.sha256` equal `HIVE.md` at
>    `judged_at.commit`.
> 6. **Approval and threshold.** Recompute, under the pinned convention and from the
>    tree at `judged_at.commit` alone (its members, rules and approval files):
>    - **admit**: `effect_commit` moves `requests/<name>/<device>.md` into
>      `members/<name>/keys/<device>.md` for a name that is not yet a member, and
>      `subject_sha256` is the subject hash of that request. A member adding their own
>      device is not an approval and is never notarized. `counted` = the signer of
>      `effect_commit`, plus the members whose approvals name `approve: admit` and
>      this hash, each once. `required` = max(1, min(`approvals`, `members`)).
>    - **remove**: `effect_commit` moves `members/<name>/` to `former/` for a member
>      other than its signer, and `subject_sha256` is that member's membership hash
>      as the convention defines it. `counted` = the signer, plus the other members
>      whose approvals name `approve: remove`, this hash and `member: <name>`.
>      `required` = `members` − 1, which must be at least 2, and `counted` must equal
>      `required`.
>    - **rules**: `effect_commit` changes `HIVE.md`, whose new text hashes to
>      `subject_sha256` while the old one hashes to `replaces_sha256`. The change is
>      judged under the old rules, so `replaces_sha256` equals `rules.sha256`.
>      `counted` = the signer, plus the members whose approvals name
>      `approve: rules`, both hashes. `required` = max(1, min(max(old, new
>      `approvals`), `members`)).
>    - **publish**: a manifest under `members/<name>/publish/` has subject hash
>      `subject_sha256`. `counted` = the members whose approvals name
>      `approve: publish` and this hash, plus the member whose key signed
>      `effect.commit`, each once. `required` = max(1, min(`approvals`, `members`)).
>
>    Only members at `judged_at.commit` count. `threshold.members`,
>    `threshold.required` and `threshold.counted` must equal the recomputed values,
>    and `counted` must be at least `required`. `effect_commit`, when present, must
>    itself be an accepted commit.
> 7. **Effect.** For `admit`, `remove` and `rules`, `effect` is `null`. For `publish`:
>    `to` equals the manifest's `to:`; `effect.commit` matches its octets
>    (`commit_sha256`); its committed tree holds only plain files, namely
>    `PUBLISHED.md`, an optional `.gitattributes` of exactly `* text eol=lf`, and
>    exactly the manifest's files with the room prefix removed, each with its listed
>    hash; `PUBLISHED.md` hashes to `published_sha256` and names `manifest:
>    <subject_sha256>` and `hive: <hive_id>`; and every commit of the public copy up
>    to `effect.commit` is signed by a key of a member at `judged_at.commit`. The
>    public copy is found by any transport. Its commit and files, not its location,
>    are what is notarized.
> 8. **Once.** No other accepted notarization of the organization names the same
>    `approval.kind` and `approval.subject_sha256`. An exact replay of an accepted
>    frame changes nothing. A different payload for the same approval is refused.
>
> The consumer persists accepted notarizations and the notary stream head as
> high-water (RAPP/1 §7.6). Resetting or deleting that state is not recovery.
>
> ## 5. What the notary may never do
>
> The notary **MUST NOT**:
>
> 1. **originate**: sign a notarization that no approval in accepted history
>    matches, or a vector for a head that is not accepted;
> 2. **alter**: notarize an effect that differs from what the approval names in any
>    byte, file, destination or commit, or "repair" a near match;
> 3. **pre-sign**: notarize a decision before an accepted vector of the organization
>    reaches it, or a publication before its public copy commit exists;
> 4. **re-use**: notarize one approval twice with different payloads;
> 5. **sign outside tenure**: sign when not the owner in effect at the frame's `utc`;
> 6. **split**: keep a second notary stream, or sign two different frames at one
>    position of the stream; or
> 7. **disclose**: put names, keys, texts, notes, titles, paths or content into a
>    notarization.
>
> ## 6. The right to refuse
>
> The notary **MAY** refuse any notarization, and **MUST** refuse when a check of
> section 4 would fail. A refusal writes nothing. The notary **MUST** refuse to
> notarize a publication they know or suspect would put personal data, secrets,
> credentials, private prompts or GODD into DOGG (`rapp-hive/1` §2). A notarization
> is never a DOGG verdict. The notary **SHOULD** refuse a decision judged under
> `approvals: 1` in a Hive of two or more members, following the convention's own
> advice.
>
> A refusal is not a veto. The Hive's decision stays valid inside the Hive, and the
> Hive's own evidence (such as `check-public`) stays checkable. Only the
> organization's RAPP/1 statement is withheld. No consumer may read a missing
> notarization as a refusal of the decision, or a notary's silence as consent.
>
> ## 7. Accountability
>
> The owner stays the one accountable RAPPID of the organization, in exactly the
> sense of `rapp-work/1` §2: authorized through the estate's signed registry, and
> scoped in time. The Hive's approvers make the decision, and their signed commits
> are its evidence. The notary attests it, and the notary's signature is evidence
> that they checked. Anyone with the Hive's bytes can recompute every value. A false
> notarization is refused by every consumer that checks, and it stays permanent,
> non-repudiable evidence against its signer.
>
> ## 8. Succession and key compromise
>
> - **Rotation.** The notary's key moves by a `rotation` re-anchor that the estate
>   owner signs, with the old key's continuity signature (RAPP/1 §§6.3 and 13.3).
>   Notarizations made before the re-anchor's `utc` stay valid, because a superseded
>   key is refused only on frames at or after it (§10). After the boundary, only the
>   successor signs.
> - **Compromise.** A `tombstone` and a `compromise` re-anchor (§§10 and 13.3). Frames
>   by the tombstoned key at or after `revoked_utc` are refused. A compromised key
>   still cannot originate a decision, because every notarization is recomputed from
>   the Hive's bytes. It can only notarize real approvals early or late, claim a
>   content-identical effect first, or fork the stream (both branches refused, §7.6).
>   After a compromise, the successor **SHOULD** re-verify the retained notarizations
>   against the Hive's bytes and advance the notary stream past `revoked_utc`
>   (RAPP/1 §14).
> - **A new notary.** In RAPP/1 terms, a different person takes over only through
>   re-anchor records that the estate owner signs. An estate owner **SHOULD** move a
>   notary only as the Hive decided. The convention cannot yet express that decision,
>   because no approval names an organization or a notary. Until a convention version
>   can, this remains the estate owner's own accountable act, recorded in the
>   registry. The members may instead bind their Hive to another organization, after
>   the old binding is deprecated.
>
> ## 9. Failure modes
>
> 1. **A notary who refuses to sign.** Nothing inside the Hive is blocked (section 6).
>    Remedies: ask again; the estate owner moves the notary (section 8); or the members
>    bind their Hive to another organization.
> 2. **A notary who is unavailable** (lost key). Recovery is a compromise re-anchor
>    (section 8). Implementations that refuse owner succession cannot recover and
>    fail closed.
> 3. **Two notaries.**
>    - Two notary streams for one organization: every notarization of it is refused
>      until one is deprecated (section 4, step 1).
>    - Two organizations in one estate binding one Hive: `rapp-work-folder-hive/1`
>      refuses both bindings, so neither can notarize.
>    - Organizations in two estates binding one Hive: two independent notaries. When
>      they agree, each corroborates the other. Incompatible accepted heads mean the
>      Hive forked, which is a drift finding for its members. Neither notary can
>      override the Hive's bytes.
>    - The old and new keys around a succession: the superseded key is refused on
>      every frame at or after the re-anchor's `utc` (RAPP/1 §10), so the two never
>      sign validly at the same time.
>    - Co-notaries (k of n owners): not provided. A frame carries one signature, and a
>      k-of-n rule would be a new profile.
> 4. **Equivocation.** Two different frames at one stream position are a fork. Both
>    are refused past the fork point (RAPP/1 §7.6).
> 5. **The Hive changes later.** An approver leaves, or a manifest is withdrawn. The
>    notarization stays a true statement about accepted history at `judged_at`. It is
>    never re-signed or deleted, and later vectors show the new state. A publication
>    cannot be recalled from anyone who already copied it.
>
> ## 10. World boundary and data classes
>
> A notarization is the RAPP/1 occurrence at the Hive's edge that an effect crossing
> a world boundary needs. Inside, the members' signed commits authorize effects inside
> the Hive only. Outside, the notary's signed notarization states exactly which
> decision the organization attests, in its one `world_id`. It moves no Hive content
> into that world: only hashes, counts, versions and, for a publication, the public
> copy commit and its approved destination name. It grants no membership in the
> organization, key release or effect in another world.
>
> A publication notarization points at a public copy, so it may itself be published
> (DOGG) when the organization chooses and the public copy is DOGG. Notarizations of
> `admit`, `remove` and `rules` disclose governance events, so they are GODD by
> default.
>
> ## 11. Conformance
>
> An implementation claiming this profile verifies the closed payload and its kind
> binding, the adoption prerequisites, the notary stream and signer, every check of
> section 4 by recomputation under the pinned convention, and the high-water, fork and
> once-only refusals. It passes the profile's positive and refusal vectors.

## Example payloads (non-normative)

These use synthetic values only. The notary is the example organization's owner
(`rappid:@example/work-owner:5555…`), and the notary stream is
`rappid:@example/folder-hive-notary:6666…`. Both are placeholder RAPPIDs, like
`protocols/examples/work-lifecycle.json`. The Hive is the public synthetic model Hive
in `kody-w/rapp-model-hive` at `2bd7c95`, rebuilt with its own
`tools/build_example.py` story. Its keys are public test keys that prove nothing.
Each value below was recomputed from that replay. Particles were computed with
`rapp_profile.particle_hash` at `591e014`. The organization and vectors they name
are G10's examples, repeated in the appendix so this document stands alone.

Notary stream genesis: the admission that the first vector carries (journey E1).
Particle `43b6599b75b7e396d980924fa2bb89554032a13f1d9f704c8075aca877921785`:

```json
{
  "schema": "rapp-work-notary/1-notarization",
  "organization_payload_hash": "b359b54abb163cc9e5e38d8eef573223eb393726f0946ade0728dfee9c509738",
  "vector_payload_hash": "119c4eb9684c068f432378f39da6ec2a277d7f4633fd8d1a47bffb0896698fa9",
  "notarized_utc": "2026-09-25T12:06:00.000Z",
  "approval": {
    "kind": "admit",
    "subject_sha256": "a1d5911486f23a2ee25c2e18edbc47527c28bcaf5594ff6804c438ac47c126ed",
    "replaces_sha256": null,
    "judged_at": {
      "commit": "9c1b77f28a024302646cb74d12c658a057e3d793",
      "height": 17
    },
    "effect_commit": "de4053fa2301ceccf8dca80d92d752b73eeb43f0"
  },
  "threshold": {
    "members": 3,
    "required": 2,
    "counted": 2
  },
  "rules": {
    "version": 2,
    "sha256": "d1a024ae0b88ed6516dcd3da3a01780d0e12602cd4f4d72689b9a85d8cf211be"
  },
  "effect": null,
  "previous_notarization_payload_hash": null
}
```

In the replay, the Hive at height 17 had 3 members and `approvals: 2`, so 2 were
required. The admission commit at height 18 was signed by one member, after one
other member's approval named the request's hash, so 2 counted. With a wrong subject
hash, only the signer counts (1), and the notarization is refused.

Second notarization: the publication (journey E3), judged at the last accepted head
(height 40). Particle
`31c71d89c0ccc9aae0809c9a48b63e69aa2b620f4c0d59802cbae0ecdd12206b`:

```json
{
  "schema": "rapp-work-notary/1-notarization",
  "organization_payload_hash": "b359b54abb163cc9e5e38d8eef573223eb393726f0946ade0728dfee9c509738",
  "vector_payload_hash": "f2a870da47ee633a6b7c9c21a3eed45e5dec8d3e54ed2cdcf69cb025d10eb5f6",
  "notarized_utc": "2026-09-25T12:11:00.000Z",
  "approval": {
    "kind": "publish",
    "subject_sha256": "1dcfa66f8a50e8158b98da5cdb6777f1b72afbf8a9446c0ed67fd18e2b63a4df",
    "replaces_sha256": null,
    "judged_at": {
      "commit": "af4ea0caee5dc8840a254b4b3f0c0aa242a76c5a",
      "height": 40
    },
    "effect_commit": null
  },
  "threshold": {
    "members": 4,
    "required": 2,
    "counted": 2
  },
  "rules": {
    "version": 2,
    "sha256": "d1a024ae0b88ed6516dcd3da3a01780d0e12602cd4f4d72689b9a85d8cf211be"
  },
  "effect": {
    "kind": "public-copy",
    "to": "contoso-onboarding-public",
    "object_format": "sha1",
    "commit": "655485aed56370b7191e49833cfa27c5f339cdc5",
    "commit_sha256": "22ec7db5e2c48a163c147c6c62dd8124892b0055a58232c87f416b32f614450e",
    "published_sha256": "320917451b91062de76cc9fed6d4ae0c26cf26f331b6b1a8be1526add6f12b8b"
  },
  "previous_notarization_payload_hash": "43b6599b75b7e396d980924fa2bb89554032a13f1d9f704c8075aca877921785"
}
```

At height 40, the commit in which one member left, the Hive had 4 members and
`approvals: 2`, so 2 were required. One member's approval named the manifest's
hash, and a member signed the public copy commit, so 2 counted. The public commit
holds exactly the manifest's one file with its hash, plus `PUBLISHED.md` and
`.gitattributes`. `PUBLISHED.md` names the manifest and the Hive id. The `to` value
is the model's own synthetic destination name.

## Token and compatibility analysis

- **New tokens only:** `rapp-work-notary/1` and `rapp-work-notary/1-notarization`,
  with one kind, `notary.notarization`, that does not use the `work` label. No
  existing token is widened (Art. 2). A reference run shows an adopting registry with
  the seven `work.*` kinds, G10's two kinds and this kind passes
  `rapp_work.validate_registry_adoption` at `591e014`, while an added `work.*` kind is
  refused.
- **`rapp-work/1` untouched:** the same seven kinds, schemas, reference, index
  entry, anchor inputs and SDK pin (`RAPP_WORK_PIN.json` in `kody-w/rapp-work`). No
  chain revision is needed.
- **RAPP/1 untouched (Art. 18):** one signature per frame, the same envelope and
  consumer checklist, and only existing registry entry types (`protocol`, `kind`,
  `genesis`). A notary frame built with `rapp.build_frame` passes `rapp.verify_frame`
  steps 1 to 6 with a fixture verifier.
- **Owner authority (Art. 6):** the owner in effect at each frame's `utc`, through
  the registry. **Identity (Art. 7):** the notary stream's RAPPID is minted, and
  nothing is derived from the Hive's id, root or members.
- **G10 unchanged:** vectors keep their exact shape and rules. This profile only
  names them head notarizations.
- **Not a rev-N+1 revision:** nothing in `rapp/1` or `rapp-work/1` changes, and
  `EXTENDING.md` says: "Registered kinds, registry entries, vocabulary and
  subordinate profiles can grow under `rapp/1`." It becomes an amendment, carried by
  an owner-ratified chain append (Constitution Art. 14), only if the owner chooses
  (a), or publishes the profile in this repository's `protocols/index.json`.
- **Intended release:** newest release scope only, as an experiment beside G10. It
  is not part of RAPP/1 LTS.

## Security analysis

| Threat | Handling |
|---|---|
| The notary invents a decision | Recomputation from the Hive's bytes finds no matching approval, so it is refused. The signed frame stays as evidence against the notary. |
| The notary alters an approved publication | The files, hashes, `PUBLISHED.md`, `to` and public commit are all checked, so any difference is refused. |
| Pre-signing or backdating | The decision must lie on an accepted vector's line, the time must be at or after that vector's observation, and the notary stream is hash-chained. |
| Replay across organizations or Hives | `organization_payload_hash`, the binding's root, stream binding (RAPP/1 §7.5 step 1a), and the once-only rule. |
| Threshold inflation | `members`, `required` and `counted` are recomputed, and only members at `judged_at` count. |
| Sock-puppet approvals under `approvals: 1` | A known convention limit. The notary SHOULD refuse, and consumers see `required` in every notarization. |
| Compromised owner key | It cannot originate decisions, only mistime real ones or fork the stream. Recovery by tombstone and re-anchor. |
| Compromised member key | A Hive-level limit: the notary faithfully attests what the Hive approved, and may refuse on knowledge. |
| Two notaries | Refused or independent, as in section 9. |
| Injection from Hive text | Verifiers read Hive bytes only as data, and never run or load them. |

## Privacy analysis

- Notarizations carry hashes, counts, versions and commit ids only. The one textual
  value is the destination name the Hive approved, and only for publications, which
  are public by nature.
- Subject hashes are over high-entropy texts that include keys and signatures, so
  they reveal nothing without the Hive's bytes.
- Governance notarizations reveal that an admission, removal or rules change
  happened, and when, so they are GODD by default.
- The examples contain only public synthetic values: public test keys, placeholder
  RAPPIDs, `example.com` and `example-world`.

## Migration

Nothing migrates. No estate has activated canonical `rapp-work/1` yet (the
organism's G16), and no folder-Hive organization or notary stream exists. Existing
folder Hives need no change: every value is recomputed from their existing bytes.

## Rollback

- For this proposal: delete the branch, or refuse it.
- For an adopting estate: deprecate the profile's `protocol` and `kind` entries and
  the notary streams' `genesis` entries (append-only, RAPP/1 §13.3). Accepted
  notarizations stay readable history. They are never deleted or re-signed.

## Conformance vectors to add (described; not implemented in the canonical suites)

These would be run against the replayed synthetic model Hive, beside G10's vectors.
Nothing is added to `work_conformance.py`.

**Positive**
1. The admission notarization above (judged at height 17, applied at 18, 3 members,
   2 required, 2 counted).
2. The publication notarization above (judged at height 40, 4 members, 2 required,
   2 counted, and an exact public tree).
3. An exact replay of an accepted notarization frame changes nothing.
4. A notarization after a key rotation, signed by the successor.

**Refusal**
1. A wrong subject hash (the replay counts 1 against 2 required).
2. Only a former member's approval.
3. `counted`, `required` or `members` differs from the recomputation.
4. `judged_at` is not the parent of `effect_commit`.
5. `effect_commit` is above the named vector's head (pre-signing).
6. A vector that was not accepted, or belongs to another organization.
7. `rules.version` or `rules.sha256` differs from `HIVE.md` at `judged_at`.
8. A publication judged anywhere but the vector head.
9. A public commit with an extra file, a changed byte, another `to`, a
   `PUBLISHED.md` naming another manifest or Hive, or a signature by a non-member.
10. A second notarization of the same approval with a different effect.
11. A member's own device addition presented as `admit`.
12. A removal without every other member, or with only one other member.
13. A rules change whose `replaces_sha256` is wrong.
14. A signer that is not the notary in effect: an old key after rotation, a
    tombstoned key, or another estate identity.
15. Two live notary streams for one organization.
16. `notarized_utc` differs from the frame's `utc`, or is earlier than the vector's
    `observed_utc`.
17. A payload with an extra member (for example a member name).
18. `effect` present for `admit`, or missing for `publish`.
19. Two different frames at one notary stream position.
20. A notarization for an organization whose binding was refused (two bindings of
    one root).

Each critical refusal would be proven to turn red under a controlled mutation before
it is committed (Constitution Art. 8: a red oracle is a finding, and a check is never
weakened to pass).

## Reference implementation and gating

None in this proposal. The gap is an idea, and ideas get a proposal only. A later
reference would sit beside G10's: stdlib-only payload validators that import
`rapp.py`'s canonicalizer (Art. 10), with the Hive replay and the recomputation of
section 4 as injected verifiers. It would ship under its own token, off by default.
Without adoption, every `notary.notarization` frame is refused. It is never part of
`rapp-work/1` conformance.

## Ready-to-file issue text (not filed)

The owner decides whether to file it. Proposed title: *rapp-work/1 §2: can a group
of equals keep one accountable owner who only notarizes the group's decisions?*

> ## PII-free use case
>
> A group of co-equal people keeps its work in a folder Hive, a git repository of
> markdown files with no owner inside. Its members decide by approvals, which the
> Hive's own rules count at each commit's parent: admissions, removals, rules
> changes and publications. They want their decisions to count outside the Hive, for
> example so that a reviewed public page can be relied on by people who trust a RAPP/1
> estate registry. Outside the Hive, only RAPP/1 signatures verify against a registry,
> the members' keys are in no registry, and a frame carries one signature. The group
> is willing to have one accountable owner, as long as that owner signs only what the
> group already approved, names that approval exactly, and can be checked by anyone
> who holds the Hive's bytes.
>
> ## Ambiguity
>
> Canonical `rapp-work/1` §2 binds one "accountable `owner_rappid`", with authority
> "evaluated through the adopting estate's signed registry and time-scoped signer
> rules". Nothing says whether an owner may sign for a decision they did not make, or
> constrains what the owner signs to decisions made elsewhere. RAPP/1 §10 gives a frame
> one signature, and Art. 18 freezes the envelope. §9 requires the signed RAPP/1
> occurrence for consequential effects.
>
> 1. Is it lawful for an organization's owner to act only as a notary, whose
>    statements are valid only when they name a matching approval of the
>    organization's Hive?
> 2. Is a sibling profile with its own kind (not `work.*`) the right vehicle, or
>    should this wait for a `rapp-work/2` owner role?
> 3. Which decisions may be notarized: publications only, or also admissions,
>    removals and rules changes?
> 4. Is "the approval's exact reference" the approval kind, subject hash, judging
>    commit and applying commit, with the threshold evidence and rule version
>    recomputable from the Hive's bytes?
> 5. May the notary refuse, and must a refusal never act as a veto inside the Hive?
> 6. Who decides a new notary: the estate owner through re-anchor records only, or
>    the Hive, once its convention can express it?
> 7. Should k-of-n co-notaries exist, given one signature per frame?
>
> ## Proposed fail-closed status pending a ruling
>
> - No organization says that its owner "notarizes" anything. Owners sign
>   `rapp-work/1` records exactly as today.
> - A folder Hive's decisions are never presented as RAPP/1-authorized outside the
>   Hive. A publication is checked with the convention's `check-public` and called
>   convention-verified, not RAPP/1-verified.
> - No member key is added to a registry to make Hive approvals look like RAPP/1
>   signatures.
> - Any experiment uses new, non-`work.*` kinds in the newest release scope only,
>   never in RAPP/1 LTS.
>
> No names, handles, emails, hostnames, account ids, keys (other than public test
> keys), private repository names, paths or customer data are included.

## Open questions for the owner

1. Vehicle: accept (b), the sibling profile beside G10, or wait for a `rapp-work/2`
   owner role?
2. The token and kind names. `rapp-work-notary/1` and `notary.notarization` are
   working names.
3. Scope: all four approval kinds (proposed), or publications only (the one decision
   that leaves the Hive today, journey E3)?
4. Judge publications at the named vector's head (proposed, as `check-public --hive`
   judges at the Hive's head), or at the commit where the threshold was first met?
5. Keep the explicit right to refuse, and the "refusal is not a veto" rule
   (proposed)?
6. `approvals: 1`: SHOULD refuse (proposed), MUST refuse, or no rule?
7. One notary stream per organization, refusing all when two appear (proposed)?
8. Notary succession: registry re-anchor only for now (proposed), with a
   Hive-approved notary as a later convention change (Work Constitution Part V.1 and
   V.4)?
9. Co-notaries: out of scope for `/1` (proposed)?
10. The dependency on G10: accept or refuse the two together?

## Owner actions needed

- Decide questions 1 to 3 and 10. The others can follow real use.
- If accepted as an experiment: publish the profile text beside G10's, and have the
  adopting estate sign its `protocol`, `kind` and notary-stream `genesis` entries.
  That is the estate owner's signature, not this proposal's.
- Keep RAPP/1 LTS and canonical `rapp-work/1` unchanged. No chain revision and no
  `RAPP_WORK_PIN.json` re-pin is needed.
- Relay the gap status to the organism (G5: `proposed`). Its files are edited only by
  their own agent.

## Evidence: how the recorded values were produced

- The Hive values come from running the story of
  `kody-w/rapp-model-hive@2bd7c95` `tools/build_example.py` in a scratch folder
  (Python 3.13, `cryptography` 50). They were then recomputed with the model's own
  `agents/hive_agent.py` functions: `Snap.members`, `threshold`, `approvers`,
  `judge`, `signer`, `front` and `sha`, the same logic `check-public --hive` uses, but
  judged at the named commit. Commit octets were hashed with SHA-1 (checked against
  the id) and SHA-256.
- The public copy's tree, `PUBLISHED.md` and signatures were checked the same way.
  The model's `check_public` reports no problems.
- The registry, validator and frame evidence come from `rapp_work.py`,
  `rapp_registry.py` and `rapp.py` at `591e014`, on Python 3.9.6 and 3.13, with
  identical results.
- Nothing was written to any reference repository, and no scratch file is committed.

## References

- Canonical `rapp-work/1`: [`protocols/rapp-work/1/SPEC.md`](../SPEC.md) §§1, 2, 9
  and 10; [`schema.json`](../schema.json);
  [`rapp_work.py`](../../../../rapp_work.py);
  [`work_conformance.py`](../../../../work_conformance.py).
- RAPP/1: [`SPEC.md`](../../../../SPEC.md) §§6.2, 6.3, 7.5, 7.6, 10, 13.1 to 13.3 and
  14; [`CONSTITUTION.md`](../../../../CONSTITUTION.md) Articles 2, 4, 5, 6, 7, 8, 14
  and 18; [`EXTENDING.md`](../../../../EXTENDING.md);
  [`CONTRIBUTING.md`](../../../../CONTRIBUTING.md);
  [`rapp-backlog.md`](../../../../rapp-backlog.md).
- G10, the binding this builds on: branch `experimental/gap-g10-folder-hive-binding`,
  <https://github.com/kody-w/rapp-1/blob/experimental/gap-g10-folder-hive-binding/protocols/rapp-work/1/proposals/0010-folder-hive-binding.md>.
- `rapp-hive/1` §2:
  <https://github.com/kody-w/rapp-work/blob/29ead23b21645f8d7682ee00414930ffa9ce0ca6/protocols/rapp-hive/1/SPEC.md>.
- The folder convention and its checker:
  <https://github.com/kody-w/rapp-model-hive/blob/2bd7c95152ede719b6418b80e2bdc2cd457bf711/HIVE-MD.md>
  and `agents/hive_agent.py` at the same commit.
- The organism and the Work Constitution (read-only here): `kody-w/rapp-work`,
  branch `experimental/rapp-work-constitution`, commit
  `9e945f8ee532fb8a3e2e89e2c2c36f7fa778d7f7`: `organism/gaps/G05.md`, `G08.md`,
  `G09.md` and `G10.md`; `organism/crossings/folder-hive-organization.md`;
  `organism/journeys/E1.md` and `E3.md`; `organism/glossary.md` ("notary (idea)");
  `CONSTITUTION.md` Articles 7, 9 and 15 and Part V.

## Appendix: the G10 examples this proposal names (non-normative)

These are G10's example payloads, byte for byte, so that the notarizations above
can be checked from this document alone.

Folder-Hive organization genesis, particle
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

First vector (height 18), particle
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

Successor vector (height 40), particle
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
