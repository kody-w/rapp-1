# Proposal 0005: the owner as the Hive's notary

| | |
|---|---|
| **Status** | Draft, not accepted. Nothing here is in force. The owner decides. |
| **Gap** | G5: an organization has one owner only, so co-equal groups do not fit. |
| **Home spec** | Canonical `rapp-work/1` §2 ([`../SPEC.md`](../SPEC.md)) |
| **Proposed vehicle** | A new, additive sibling profile, `rapp-work-notary/1` (working name). `rapp-work/1` is not changed. |
| **Depends on** | G10, the folder-Hive organization (`rapp-work-folder-hive/1`, a draft on branch `experimental/gap-g10-folder-hive-binding`, file `protocols/rapp-work/1/proposals/0010-folder-hive-binding.md`). The parts used here are summarized below, so this document stands alone. |
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
  commit, under the convention text and checker that the adopting estate pins.

Any verifier that holds the Hive's bytes can recompute every one of these values
with the estate-pinned checker. A notarization that does not match is refused, and
it remains signed evidence against the notary who signed it. A consumer without the
Hive's bytes can learn only that the notary attested it. The notary may refuse to
sign. The notary may never originate a decision, alter one, or sign without a
matching approval. And the notary appoints itself: no notarization says that the
Hive chose its notary.

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
- **§§6.2 and 6.3**: a re-anchor is lawful in exactly three cases: a provisional
  128→256-bit upgrade, §10 key rotation or compromise, and a pre-rev-3 keyed-tail
  migration. A `compromise` re-anchor waives the old key's signature, but only with a
  tombstone registered in the same append.
- **§7.5 step 6** is the one time-dependent check: a signature that passed may
  "flip pass→fail when a §10 tombstone with `revoked_utc` ≤ the frame's `utc` is
  later registered". `EXTENDING.md` ("Tombstone issuance time"): a tombstone carries
  only `revoked_utc`, not when it was issued, and "a current owner can discover an
  earlier compromise cutoff".
- **§13.3**: a `genesis` entry has exactly `type`, `stream_id`, `frame_hash`,
  `deprecated` and the optional `old_stream_id` and `new_stream_id`. It does not say
  what kind of stream it registers.
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
- The membership a removal names comes from history: "A removal names the member's
  membership: the request moved in when their `keys/` folder was last created. New or
  retired devices keep it; leaving and coming back changes it." The checker finds it
  by walking the first-parent history (`Snap.admitted`).
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
- What the checker does in detail: `check-public` accepts only plain files (mode
  `100644`, at most 1 MB), a `.gitattributes` only if it is exactly `* text eol=lf`,
  and each other file listed in `PUBLISHED.md` with its hash. With `--hive` it
  requires one room, compares `to:` with the public copy's folder name, and counts
  signers and approvals at the Hive's current head. The Brainstem writes
  `PUBLISHED.md` in one exact form (`_do_publish`), but `check-public` reads only its
  front matter and the lines shaped like listings. On a scratch copy of the model's
  public copy, it reports nothing for an added prose line, and it reports an added
  listing of a missing file as "listed but missing".
- Known limit: "With `approvals: 1`, a member can admit a second identity of their
  own and outvote a lone co-member".

### The RAPP Work Constitution and the organism (read-only here)

These are in `kody-w/rapp-work`, branch `experimental/rapp-work-constitution`,
commit `71ef227`.

- **Article 7**: signatures decide; transport carries. **Article 9**: a publication's
  "approval binds the exact files and the destination". **Article 15**: old records
  "are called RAPP/1-verified only where a signed registry holds their keys".
- Article 15's reasons also file "a single owner" under `rapp-hive/1` ("G1 and G5
  belong to `rapp-hive/1`: a roster that could never change, and a single owner"),
  while `organism/gaps/G05.md` homes G5 in canonical `rapp-work/1` §2. This proposal
  follows the gap file. The difference is the organism's to settle, and is reported,
  not changed, here.
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
- `organism/gaps/G06.md` (open): the references refuse owner succession, and "a lost
  or compromised owner root key needs a new trust anchor".

## What this proposal builds on (G10, summarized)

G10 proposes `rapp-work-folder-hive/1`, a sibling profile that adds a second,
parallel organization type with its own two kinds on its own body stream. It leaves
`rapp-work/1` unchanged.

- A **folder-Hive organization** genesis (`folder-hive.organization`) has the
  accountable owner and the one world of `rapp-work/1` §2 (`organization_rappid`,
  `owner_rappid`, `world_id`, `created_utc`), and a `hive` binding in place of
  `hive_rappid`: the convention version, `hive_id`, `object_format`, `root` with its
  SHA-256 twin and SHA-256 tree digest, and the `founder` key fingerprint. It has no
  releases, so no `release_scope` or `policy_sha256`. The Hive id is the Hive's label
  and never a RAPPID. The root tells the Hive apart, and the fingerprint is evidence.
  The signed genesis is the only authority.
- The adopting estate pins each convention version twice: a **text pin** (a
  `protocol` entry named *N*) and a **checker pin** (named *N*`/checker`). The
  binding's two hashes must equal those pins and cannot choose them, and a consumer
  judges only with checker bytes equal to the checker pin.
- Every commit is **named** by its object id, its SHA-256 twin (over the commit
  octets) and its SHA-256 tree digest (the tree's object id in git's SHA-256 object
  format).
- An **accepted head** is a commit that the estate-pinned checker, run from the
  root, judges on the one line with no refused commit. Verdicts also read the
  first-parent history before each parent, so a consumer holds every object reachable
  from the head.
- A **vector** (`folder-hive.vector`) is the owner's signed record of an accepted
  head (`commit`, `commit_sha256`, `tree_sha256`, `height`, `rules_version`,
  `rules_sha256`). Each vector comes strictly after the previous one, by first-parent
  ancestry and by the Hive's own acceptance of every commit in between, or observes
  the previous head again, later.
- An estate owner never registers two live bindings of one root, and a consumer that
  finds two refuses both.

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
| **(b) Sibling profile** (recommended) | `rapp-work-notary/1`: one kind, `notary.notarization`, on one live notary stream per folder-Hive organization. It is subordinate to `rapp-work/1` and to G10's profile. | Additive and small: one kind and one closed payload. `rapp-work/1` is untouched. The owner stays the one accountable RAPPID. Every check is a recomputation of the Hive's own rules under the estate-pinned checker, so no new decision rule is invented. | Depends on G10. It notarizes only the decisions the convention can express today (the four approval kinds). |
| **(c1) A promise in a policy** | The owner promises, in a pinned policy document, to sign only what the Hive approved. | No new records. | Refused. A folder-Hive organization carries no policy member, and reusing `rapp-work/1`'s `policy_sha256`, the release qualification policy, would give it a second meaning. A promise is also not checkable. |
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
"folder-Hive organization", "binding", "convention pins", "named commit", "accepted
head" and "vector" have their meanings in `rapp-work-folder-hive/1`.

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
>    `rapp-work-folder-hive/1`, with that profile's convention pins;
> 2. append one `protocol` entry pinning this exact specification;
> 3. append exactly one `kind` entry, `notary.notarization`, bound to the `body`
>    family, whose only permitted payload schema is
>    `rapp-work-notary/1-notarization`; and
> 4. register the creation `genesis` of every notary stream (RAPP/1 §13.3), and never
>    register a second live one for one folder-Hive organization (section 2).
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
> **A notary appoints itself.** The notary is its own organization's owner, and the
> binding that makes it the Hive's notary is that organization's own claim. The
> convention has no approval that names an organization or a notary, and anyone who
> holds a Hive's bytes, a former member's copy included, can bind the Hive from an
> estate they control and notarize its real decisions. A binding or a notarization
> **MUST NOT** be read as the Hive choosing, knowing of or consenting to its notary.
> It says nothing about whom the members would choose.
>
> The notary's statements for the Hive are exactly two:
>
> - **head notarizations**: the organization's `folder-hive.vector` frames,
>   unchanged, re-observations included. The approval each one names is the Hive's
>   own acceptance of every commit up to its head, under the rules
>   `head.rules_version` and `head.rules_sha256` name.
> - **decision notarizations**: `notary.notarization` frames (section 3).
>
> A consumer **MUST NOT** treat any other statement signed by the owner as a decision
> or state of the Hive.
>
> **The notary stream.** Each folder-Hive organization has at most one live **notary
> stream**: a separately registered body stream whose `stream_id` is a RAPPID minted
> for it (RAPP/1 §6.2), carrying only `notary.notarization` frames, whose genesis
> frame is a notarization of that organization. Every frame on it is signed by the
> notary in effect at its `utc`, and by nobody else. There is no delegation. A
> consumer learns a notary stream's `stream_id` from whoever presents a notarization.
> Transport carries it and proves nothing: the consumer checks that a live `genesis`
> entry registers the stream and that the stream's genesis frame names the
> organization. The estate owner **MUST NOT** register a second live notary stream
> for one organization, and a consumer that finds two **MUST** refuse every
> notarization of that organization until the estate owner deprecates one. As for
> bindings (`rapp-work-folder-hive/1` §3), a consumer can prove that no second stream
> exists only by verifying every live genesis frame of the estate, and this profile
> does not require that proof. A replacement stream, registered after the estate owner
> deprecates the old one's genesis entry, starts at a new genesis whose
> `previous_notarization_payload_hash` is `null`.
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
> - `judged_at`: exactly `commit`, `commit_sha256` and `tree_sha256`, which name a
>   commit of the Hive, and `height` (`uint53`). This is the commit whose tree and
>   history the decision is judged against. For `admit`, `remove` and `rules` it is
>   the parent of `effect_commit`. For `publish` it is the named vector's head.
> - `effect_commit`: for `admit`, `remove` and `rules`, exactly `commit`,
>   `commit_sha256` and `tree_sha256` of the Hive commit that applied the decision,
>   whose one parent is `judged_at.commit`; for `publish`, `null`.
>
> The public-copy `effect` has exactly these members:
>
> - `kind`: `"public-copy"`;
> - `to`: text of 1 to 64 characters, exactly the manifest's `to:` value (the
>   destination the Hive approved);
> - `object_format`: `"sha1"` or `"sha256"`, of the public copy;
> - `commit`, `commit_sha256` and `tree_sha256`: the public-copy commit that carries
>   the publication, named as `rapp-work-folder-hive/1` §3 names a commit; and
> - `published_sha256`: the SHA-256 of that commit's `PUBLISHED.md` bytes.
>
> No member may carry a member name, a key or fingerprint, a request text, a note, a
> title, a path or file content.
>
> ## 4. Verification of a notarization
>
> Before accepting a notarization, a consumer **MUST**, in order, and **MUST** refuse
> (never repair) on any failure. Every recomputation runs the checker that the
> adopting estate pins for the binding's convention, and reads the Hive's bytes only
> as data (`rapp-work-folder-hive/1` §3). Neither the notary nor a payload selects
> the checker or the rules.
>
> 1. **Frame and stream.** Verify the frame under RAPP/1 §7.5 with a signature,
>    registered kind and body family, on the organization's live notary stream
>    (section 2). `previous_notarization_payload_hash` must equal the frame's `prev`
>    (and be `null` only at genesis).
> 2. **Signer.** The signer is the organization's notary in effect at the frame's
>    `utc`, and `notarized_utc` equals that `utc`.
> 3. **Organization and vector.** `organization_payload_hash` names a folder-Hive
>    organization genesis the consumer accepted and that is still live.
>    `vector_payload_hash` names a vector of that organization the consumer accepted,
>    and `notarized_utc` is not earlier than its `observed_utc`.
> 4. **Named commits.** Check `judged_at`, `effect_commit` (when present) and, for
>    `publish`, the public-copy commit as named commits. A SHA-1 implementation that
>    detects collision attacks is **REQUIRED**, and an object it flags is refused.
> 5. **On the accepted line.** `judged_at.commit` is the vector head, or its ancestor
>    exactly `head.height − judged_at.height` first-parent steps back. For `publish`,
>    it is the vector head itself. `effect_commit`, when present, is the next commit on
>    that line, at height `judged_at.height + 1`, and not above the vector head.
>    Nothing is notarized before an accepted vector reaches it.
> 6. **Rule version.** `rules.version` and `rules.sha256` equal `HIVE.md` at
>    `judged_at.commit`.
> 7. **Approval and threshold.** Recompute, under the pinned checker's definitions,
>    from the accepted history up to `judged_at.commit` (its tree, and the first-parent
>    history before it, which the convention's membership rule reads), plus the tree at
>    `effect_commit` when present:
>    - **admit**: `effect_commit` moves `requests/<name>/<device>.md` into
>      `members/<name>/keys/<device>.md` for a name that is not yet a member, and
>      `subject_sha256` is the subject hash of that request in the tree at
>      `judged_at.commit`. A member adding their own device is not an approval and is
>      never notarized. `counted` = the signer of `effect_commit`, plus the members
>      whose approvals name `approve: admit` and this hash, each once. `required` =
>      max(1, min(`approvals`, `members`)).
>    - **remove**: `effect_commit` moves `members/<name>/` to `former/` for a member
>      other than its signer, and `subject_sha256` is that member's membership hash
>      as the convention defines it: the subject hash of the request that was moved in
>      when `members/<name>/keys/` was last created, found by walking the first-parent
>      history back from `judged_at.commit` (for the founder, the root's key file).
>      New and retired devices keep it, so it need not match any key file in the tree
>      at `judged_at.commit`. `counted` = the signer, plus the other members whose
>      approvals name `approve: remove`, this hash and `member: <name>`. `required` =
>      `members` − 1, which must be at least 2, and `counted` must equal `required`.
>    - **rules**: `effect_commit` changes `HIVE.md` and sets the next `version`. Its
>      new text, in the tree at `effect_commit`, hashes to `subject_sha256`, and the
>      old one hashes to `replaces_sha256`. The change is judged under the old rules,
>      so `replaces_sha256` equals `rules.sha256`. `counted` = the signer, plus the
>      members whose approvals name `approve: rules` and both hashes. `required` =
>      max(1, min(max(old `approvals`, new `approvals`), `members`)), with the new
>      `approvals` read from `HIVE.md` at `effect_commit`.
>    - **publish**: a manifest under `members/<name>/publish/` in the tree at
>      `judged_at.commit` has subject hash `subject_sha256` and lists files of exactly
>      one room under `shared/`. `counted` = the members whose approvals name
>      `approve: publish` and this hash, plus the member whose key signed
>      `effect.commit`, each once. `required` = max(1, min(`approvals`, `members`)).
>
>    Only members at `judged_at.commit` count. `threshold.members`,
>    `threshold.required` and `threshold.counted` must equal the recomputed values,
>    and `counted` must be at least `required`. `effect_commit`, when present, must
>    itself be an accepted commit.
> 8. **Effect.** For `admit`, `remove` and `rules`, `effect` is `null`. For
>    `publish`, every condition of the pinned checker's `check-public --hive`, judged
>    at `judged_at.commit` instead of the Hive's current head, and these exact forms:
>    - `to` equals the manifest's `to:`. The checker compares `to:` with the public
>      copy's folder name; here the notarization carries the name, and a location is
>      never evidence.
>    - The tree at `effect.commit` holds only plain files (mode `100644`) of at most
>      1 MB (1048576 octets): `PUBLISHED.md`, an optional `.gitattributes` of exactly
>      `* text eol=lf` and a line feed, and exactly the manifest's files with the room
>      prefix removed.
>    - Each of those files has the subject hash (the SHA-256 of its text after LF and
>      NFC normalization) that the manifest lists for it.
>    - `PUBLISHED.md` is byte for byte the form the pinned checker writes: the lines
>      `---`, `manifest: <subject_sha256>`, `hive: <hive_id>`, `---` and an empty line,
>      then one line `<sha256>  <path without the room prefix>` per manifest file, in
>      the manifest's order, each line ending in a line feed, and nothing else.
>      `published_sha256` equals the SHA-256 of those bytes.
>    - Every commit reachable from `effect.commit` is signed, in the `git` namespace,
>      by a key of a member at `judged_at.commit`.
>
>    The public copy is found by any transport. Its commit and files, not its
>    location, are what is notarized.
> 9. **One meaning per approval.** Every accepted notarization of the organization
>    that names the same `approval.kind` and `approval.subject_sha256`, on any of its
>    notary streams, carries the same `approval`, `threshold`, `rules` and `effect`,
>    byte for byte. A different one is refused. An exact replay of an accepted frame
>    changes nothing.
>
> The consumer persists accepted notarizations and the notary stream head as
> high-water (RAPP/1 §7.6). Resetting or deleting that state is not recovery.
>
> **Without the Hive's bytes.** Steps 3 and 5 to 8 need the Hive's own objects and
> an accepted vector. A consumer that does not hold them cannot accept a
> notarization, and **MUST NOT** treat one as the Hive's decision or as authority for
> any effect. It **MAY** check what needs none of the Hive's bytes: the frame, stream
> and signer (steps 1 and 2); the closed payload; and, for `publish`, a public copy it
> holds: `effect.commit` as a named commit, the plain-file tree, `PUBLISHED.md` in the
> checker's shape (front matter naming `subject_sha256` and the `hive_id` of the
> organization's genesis, then every file of the tree listed once with its hash, and
> nothing else), and `published_sha256`. If all of that holds, it may report the
> notarization as **attested**, never as accepted: the notary in effect signed exactly
> this statement about exactly these public bytes. An attestation is the notary's
> accountable claim. Anyone who later holds the Hive's bytes can check it, and a false
> one stays signed evidence against the notary (section 7).
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
> 6. **split**: keep a second live notary stream, or sign two different frames at one
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
> notarization is refused by every consumer that checks, and it stays signed evidence
> against its signer, with one limit. A later tombstone for the signer's key whose
> `revoked_utc` is at or before the frame's `utc` makes RAPP/1 refuse the signature
> (§7.5 step 6), and then the frame no longer shows that the notary signed it. The
> estate owner chooses `revoked_utc`, and a tombstone does not record when it was
> issued (`EXTENDING.md`). So the evidence lasts only while no declared compromise
> covers it. A consumer that needs the evidence keeps the frame and the registry it
> verified it against.
>
> ## 8. Succession and key compromise
>
> - **Rotation.** The same notary moves to a new key by a `rotation` re-anchor that
>   the estate owner signs, with the old key's continuity signature (RAPP/1 §§6.3 and
>   13.3). Notarizations made before the re-anchor's `utc` stay valid, because a
>   superseded key is refused only on frames at or after it (§10). After the boundary,
>   only the successor key signs.
> - **Compromise or loss.** A `tombstone` and a `compromise` re-anchor (§§10 and
>   13.3), to a new key of the same notary. Frames by the tombstoned key at or after
>   `revoked_utc` are refused, and `revoked_utc` **SHOULD** be the earliest time the
>   key may have left the notary's control, and no earlier. A compromised key still
>   cannot originate a decision, because every notarization is recomputed from the
>   Hive's bytes. It can only notarize real approvals early or late, claim a
>   content-identical effect first, or fork the stream (both branches refused, §7.6).
>   After a compromise, the successor **SHOULD** re-verify the retained notarizations
>   against the Hive's bytes and advance the organization's vector stream past
>   `revoked_utc` with a re-observation (`rapp-work-folder-hive/1` §4), as RAPP/1 §14
>   advises. The notary stream itself advances only with the next real notarization,
>   since only real approvals can be notarized. Until then a consumer treats notary
>   frames stamped just below `revoked_utc` with §14's caution.
> - **No handover.** `/1` has no lawful way to make a different person the notary of
>   an existing organization. RAPP/1 re-anchors an identity only for a provisional
>   upgrade, a key rotation or compromise, or a tag migration (§§6.2 and 6.3). A
>   rotation needs the old key's signature, which a notary who refuses will not give.
>   A compromise re-anchor declares a compromise, with a `revoked_utc` that the estate
>   owner chooses and may set in the past, which would void real earlier
>   notarizations (section 7). So an estate owner **MUST NOT** use a compromise
>   re-anchor to replace a notary whose key is neither compromised nor lost. A
>   different notary means a new folder-Hive organization with a new owner, binding
>   the same Hive after the estate owner deprecates the old binding
>   (`rapp-work-folder-hive/1` §3), or a binding in another estate. An explicit
>   succession record, perhaps one that the Hive approves, is an owner question.
>
> ## 9. Failure modes
>
> 1. **A notary who refuses to sign.** Nothing inside the Hive is blocked (section 6).
>    Remedies: ask again; a new folder-Hive organization with another owner, after the
>    estate owner deprecates the old binding; or a binding in another estate
>    (section 8). The members cannot bind their Hive themselves: only an organization
>    binds, and only its estate owner deprecates a binding.
> 2. **A notary who is unavailable** (lost key). Recovery is a compromise re-anchor to
>    a new key of the same notary (section 8). Implementations that refuse owner
>    succession cannot recover and fail closed (the organism's G6).
> 3. **Two notaries.**
>    - Two live notary streams for one organization: every notarization of it is
>      refused until one is deprecated (section 2).
>    - Two organizations in one estate binding one Hive: the estate owner must not
>      register them, and a consumer that finds both refuses both bindings
>      (`rapp-work-folder-hive/1` §3), so neither can notarize.
>    - Organizations in two estates binding one Hive: two independent, self-appointed
>      notaries (section 2). When they agree, each corroborates the other.
>      Incompatible accepted heads mean the Hive forked, which is a drift finding for
>      its members. Neither notary can override the Hive's bytes, and neither is the
>      Hive's choice.
>    - The old and new keys around a rotation: the superseded key is refused on every
>      frame at or after the re-anchor's `utc` (RAPP/1 §10), so the two never sign
>      validly at the same time.
>    - Co-notaries (k of n owners): not provided. A frame carries one signature, and a
>      k-of-n rule would be a new profile.
> 4. **Equivocation.** Two different frames at one stream position are a fork. Both
>    are refused past the fork point (RAPP/1 §7.6). The notary stream is then
>    replaced (section 2), and its accepted notarizations still bind the one-meaning
>    rule (section 4, step 9).
> 5. **The Hive changes later.** An approver leaves, or a manifest is withdrawn. The
>    notarization stays a true statement about accepted history at `judged_at`. It is
>    never re-signed or deleted, though a later tombstone can void its signature
>    (section 7), and later vectors show the new state. A publication cannot be
>    recalled from anyone who already copied it.
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
> Every notarization is GODD by default, a publication notarization included.
> Besides the public copy commit and its destination, a publication notarization
> carries Hive metadata that the public copy does not: `judged_at`'s commit and
> height, the member count, the rules version and hash, the vector it names, and its
> chain to the organization's other notarizations, whose member counts over time
> reveal admissions and removals. Publishing any notarization as DOGG is a separate
> decision that needs proven global-publication rights for every value it carries
> (`rapp-hive/1` §2, `rapp-work-folder-hive/1` §6). A DOGG public copy does not make
> its notarization DOGG. This profile defines no stripped public attestation in `/1`
> (an owner question).
>
> ## 11. Conformance
>
> An implementation claiming this profile verifies the closed payload and its kind
> binding, the adoption prerequisites, the notary stream and signer, every check of
> section 4 by recomputation under the estate-pinned checker, the attested level
> without the Hive's bytes, and the high-water, fork and one-meaning refusals. It
> passes the profile's positive and refusal vectors.

## Example payloads (non-normative)

These use synthetic values only. The notary is the example organization's owner
(`rappid:@example/work-owner:5555…`), and the notary stream is
`rappid:@example/folder-hive-notary:6666…`. Both are placeholder RAPPIDs, like
`protocols/examples/work-lifecycle.json`. The Hive is the public synthetic model Hive
in `kody-w/rapp-model-hive` at `2bd7c95`, rebuilt with its own
`tools/build_example.py` story. Its keys are public test keys that prove nothing.
Each value below was recomputed from that replay. Particles were computed with
`rapp_profile.particle_hash` at `591e014`. The convention pins, the organization and
the vectors they name are G10's examples, repeated byte for byte in the appendix so
this document stands alone.

Notary stream genesis: the admission that the first vector carries (journey E1).
Particle `65eb12b3b5189811f0b4c80fc8cf7367e5829eee4fda60f17c82c7b79057f06f`:

```json
{
  "schema": "rapp-work-notary/1-notarization",
  "organization_payload_hash": "0a2632ff92dfe251c2e78e94922ed0527ecb482e8a70bbde8dc01d0ef0e3d477",
  "vector_payload_hash": "9dcf878bad7186b081062a27922a1231eb33dd74c4951ea8e87589ca8728b0df",
  "notarized_utc": "2026-09-25T12:06:00.000Z",
  "approval": {
    "kind": "admit",
    "subject_sha256": "a1d5911486f23a2ee25c2e18edbc47527c28bcaf5594ff6804c438ac47c126ed",
    "replaces_sha256": null,
    "judged_at": {
      "commit": "9c1b77f28a024302646cb74d12c658a057e3d793",
      "commit_sha256": "cef4a0c7d1fee8f56846677e16a8c60a9ea7dbe68dd477f6052924368a7742a4",
      "tree_sha256": "a0901a1f32d7be8a7122913fb9284e862055089ee4e85c73205c2dc0d1fa423b",
      "height": 17
    },
    "effect_commit": {
      "commit": "de4053fa2301ceccf8dca80d92d752b73eeb43f0",
      "commit_sha256": "7cfc2e471f3c8073cf58a404f732133be2dee66a6f9d9d7338136846c1c3f5dc",
      "tree_sha256": "ce0b110b05d24df5a180c03c9e3358e077f939438b0eefa0e118b607cf5b7822"
    }
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
hash, only the signer counts (1), and the notarization is refused. The effect
commit is the first vector's head, so its three values equal that vector's `head`.

Second notarization: the publication (journey E3), judged at the last accepted head
(height 40). Particle
`376290208e57a0ac91f64b0bb9edb1d70020798d51f7f174a40b974cb78442c6`:

```json
{
  "schema": "rapp-work-notary/1-notarization",
  "organization_payload_hash": "0a2632ff92dfe251c2e78e94922ed0527ecb482e8a70bbde8dc01d0ef0e3d477",
  "vector_payload_hash": "aa75f7a805db81ec7ff80c603e542adff5c99fa0de7829ac5b538d04c6d5d1d3",
  "notarized_utc": "2026-09-25T12:11:00.000Z",
  "approval": {
    "kind": "publish",
    "subject_sha256": "1dcfa66f8a50e8158b98da5cdb6777f1b72afbf8a9446c0ed67fd18e2b63a4df",
    "replaces_sha256": null,
    "judged_at": {
      "commit": "af4ea0caee5dc8840a254b4b3f0c0aa242a76c5a",
      "commit_sha256": "7f7351b896478c16aed965b8a61c37213f350f6fccbf3b25fe16219af8355322",
      "tree_sha256": "207ef7ee0add56ae75d4034fb3b676da9bb9250ab58c21c5808e5cb89b4345cd",
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
    "tree_sha256": "72847b1cb36984090deebce9f7fc4018b9c6789f62b10f8f68140ad63df86f81",
    "published_sha256": "320917451b91062de76cc9fed6d4ae0c26cf26f331b6b1a8be1526add6f12b8b"
  },
  "previous_notarization_payload_hash": "65eb12b3b5189811f0b4c80fc8cf7367e5829eee4fda60f17c82c7b79057f06f"
}
```

At height 40, the commit in which one member left, the Hive had 4 members and
`approvals: 2`, so 2 were required. One member's approval named the manifest's
hash, and a member signed the public copy commit, so 2 counted. The public commit
holds exactly the manifest's one file with its hash, plus `PUBLISHED.md` and
`.gitattributes`. `PUBLISHED.md` is byte for byte the checker's form: it names the
manifest and the Hive id, and lists that one file. The `to` value is the model's own
synthetic destination name. Both notarizations are GODD by default (section 10).

## Token and compatibility analysis

- **New tokens only:** `rapp-work-notary/1` and `rapp-work-notary/1-notarization`,
  with one kind, `notary.notarization`, that does not use the `work` label. No
  existing token is widened (Art. 2). A reference run shows an adopting registry with
  the seven `work.*` kinds, G10's two kinds and its two convention pins, and this
  kind passes `rapp_work.validate_registry_adoption` at `591e014`, while an added
  `work.*` kind is refused.
- **`rapp-work/1` untouched:** the same seven kinds, schemas, reference, index
  entry, anchor inputs and SDK pin (`RAPP_WORK_PIN.json` in `kody-w/rapp-work`). No
  chain revision is needed.
- **RAPP/1 untouched (Art. 18):** one signature per frame, the same envelope and
  consumer checklist, and only existing registry entry types (`protocol`, `kind`,
  `genesis`). Notary frames built with `rapp.build_frame` pass `rapp.verify_frame`
  steps 1 to 6 with a fixture verifier, the second chained to the first.
- **Owner authority (Art. 6):** the owner in effect at each frame's `utc`, through
  the registry. **Identity (Art. 7):** the notary stream's RAPPID is minted, and
  nothing is derived from the Hive's id, root or members.
- **G10 unchanged:** vectors keep their exact shape and rules. This profile only
  names them head notarizations, and reuses G10's named commits and convention pins.
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
| The notary alters an approved publication | The public tree, each file's hash, `PUBLISHED.md` byte for byte, `to` and the public commit are all checked, so any difference is refused. |
| Pre-signing | The decision must lie on an accepted vector's line, at or below its head. |
| Backdating and times | `notarized_utc` and `observed_utc` are the signer's own claims (RAPP/1 §14). Only their order against the vector and along the stream is checked. A consumer that needs a trustworthy time records when it first saw the frame. |
| Replay across organizations or Hives | `organization_payload_hash`, the binding's root, stream binding (RAPP/1 §7.5 step 1a), and the one-meaning rule. |
| Threshold inflation | `members`, `required` and `counted` are recomputed, only members at `judged_at` count, and a removal's membership hash comes from history. |
| Sock-puppet approvals under `approvals: 1` | A known convention limit. The notary SHOULD refuse, and consumers see `required` in every notarization. |
| A self-appointed notary | Anyone who holds the Hive's bytes can bind it and notarize its real decisions from an estate they control. They cannot originate a decision, but their attestations could be mistaken for the Hive's choice. A notarization never says that the Hive chose its notary (section 2), and each consumer decides which estates' notaries it relies on. |
| Checker substitution | The estate pins the checker (`rapp-work-folder-hive/1` §§1 and 3). Neither the notary nor a payload selects the checker or the rules its notarizations are judged under. |
| SHA-1 collisions | Every commit a notarization names (`judged_at`, `effect_commit` and the public-copy commit) is a named commit, bound by its SHA-256 twin and SHA-256 tree digest, and a collision-detecting SHA-1 is required. The public files are also bound by the manifest's SHA-256 hashes and `PUBLISHED.md` by `published_sha256`. Residual: the history between named points, which the membership rule reads, and the public copy's earlier commits are bound only by SHA-1 with collision detection. |
| Compromised owner key | It cannot originate decisions, only mistime real ones or fork the stream. Recovery by tombstone and re-anchor, then a re-observation vector past `revoked_utc`. |
| Replacing a notary by a false compromise | Forbidden (section 8). A consumer cannot detect it, and a backdated `revoked_utc` would void real notarizations. Retained frames and the registry they were verified against keep what was checked. |
| Compromised member key | A Hive-level limit: the notary faithfully attests what the Hive approved, and may refuse on knowledge. |
| Two notaries | Refused or independent, as in section 9. |
| A consumer without the Hive's bytes | It can reach the attested level only, never acceptance (section 4). |
| Injection from Hive text | Verifiers read Hive bytes only as data, and never run or load them. |

## Privacy analysis

- Notarizations carry hashes, counts, versions and commit ids only. The one textual
  value is the destination name the Hive approved, and only for publications.
- Subject hashes are over high-entropy texts that include keys and signatures, so
  they reveal nothing without the Hive's bytes.
- Every notarization reveals governance metadata: when a decision happened, the
  height, the member count and the rules, and, along the stream, admissions and
  removals. So all of them are GODD by default, publications included, and a DOGG
  copy needs proven global-publication rights for every value it carries.
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
   2 counted, an exact public tree and an exact `PUBLISHED.md`).
3. A removal whose subject exists only in history: on a scratch extension of the
   model, the removal of `emery` (judged at height 42, 4 members, 3 required, 3
   counted), whose subject `3f9f786a…e417` matches no key file in the judged tree.
4. An exact replay of an accepted notarization frame changes nothing.
5. A notarization after a key rotation, signed by the successor.
6. A consumer that holds only the registry, the frames and the public copy reports
   the publication notarization as attested, never accepted.

**Refusal**
1. A wrong subject hash (the replay counts 1 against 2 required).
2. Only a former member's approval.
3. `counted`, `required` or `members` differs from the recomputation.
4. `judged_at` is not the parent of `effect_commit`.
5. `effect_commit` is above the named vector's head (pre-signing).
6. A vector that was not accepted, or belongs to another organization.
7. `rules.version` or `rules.sha256` differs from `HIVE.md` at `judged_at`.
8. A publication judged anywhere but the vector head.
9. A public commit with an extra file, a changed byte, a file over 1 MB, a link or an
   executable, another `to`, a `PUBLISHED.md` naming another manifest or Hive, or a
   signature by a non-member.
10. A `PUBLISHED.md` that is not the checker's exact form: an added prose line (which
    the checker's own `check-public` accepts), an added listing of a missing file,
    or its listings in another order.
11. A manifest whose files come from two rooms.
12. A second notarization of the same approval with a different `approval`,
    `threshold`, `rules` or `effect`, on the same stream or a replacement stream.
13. A member's own device addition presented as `admit`.
14. A removal without every other member, or with only one other member; or one whose
    subject is the hash of a key file in the judged tree instead of the membership
    hash from history (for `avery`, the hash of her first key file, retired since,
    `7cc3a71a…`, and not that of her current one).
15. A rules change whose `replaces_sha256` is wrong, or whose `required` ignores the
    new `approvals` value.
16. A signer that is not the notary in effect: an old key after rotation, a
    tombstoned key, or another estate identity.
17. Two live notary streams for one organization.
18. `notarized_utc` differs from the frame's `utc`, or is earlier than the vector's
    `observed_utc`.
19. A payload with an extra member (for example a member name).
20. `effect` present for `admit`, or missing for `publish`.
21. Two different frames at one notary stream position.
22. A notarization for an organization whose binding was refused (two bindings of
    one root).
23. A `judged_at`, `effect_commit` or public-copy commit whose `commit_sha256` or
    `tree_sha256` differs from the recomputed value.
24. A recomputation with a checker that is not the estate's checker pin.
25. A consumer without the Hive's bytes that reports a notarization as accepted.

Each critical refusal would be proven to turn red under a controlled mutation before
it is committed (Constitution Art. 8: a red oracle is a finding, and a check is never
weakened to pass).

## Reference implementation and gating

None in this proposal. The gap is an idea, and ideas get a proposal only. A later
reference would sit beside G10's: stdlib-only payload validators that import
`rapp.py`'s canonicalizer (Art. 10), with the Hive replay and the recomputation of
section 4 as injected verifiers that run the checker only from bytes equal to the
estate's checker pin. It would ship under its own token, off by default. Without
adoption, every `notary.notarization` frame is refused. It is never part of
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
> two audiences. People who hold the Hive's bytes, such as members or auditors, want
> to check a statement against the Hive themselves. People who hold only a RAPP/1
> estate registry and a public page want to know that the page is exactly the one the
> Hive approved, and can rely only on an accountable attestation. Outside the Hive,
> only RAPP/1 signatures verify against a registry, the members' keys are in no
> registry, and a frame carries one signature. The group is willing to have one
> accountable owner, as long as that owner signs only what the group already
> approved, names that approval exactly, and can be checked by anyone who holds the
> Hive's bytes.
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
>    recomputable from the Hive's bytes under the estate-pinned checker?
> 5. May the notary refuse, and must a refusal never act as a veto inside the Hive?
> 6. Who may make a different person the notary: nobody in `/1` (a new organization
>    instead), an explicit succession record, or the Hive, once its convention can
>    express it?
> 7. Should k-of-n co-notaries exist, given one signature per frame?
> 8. What may a consumer conclude without the Hive's bytes: nothing, or an "attested"
>    level that is never acceptance?
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
7. The notary stream: one live stream per organization, found by transport and
   checked against the registry, as an estate-owner duty that consumers enforce when
   they see two (proposed), or should a later version of the binding point at it?
8. Succession: no handover in `/1`, so a different notary means a new organization
   (proposed), or an explicit succession record, perhaps one the Hive approves (Work
   Constitution Part V.1 and V.4)?
9. Consent: should a later convention version add an approval that names the
   organization (and its estate) as the Hive's notary, so that a consumer can tell a
   chosen notary from a self-appointed one?
10. Outsiders: the "attested" level for a consumer without the Hive's bytes
    (proposed), or nothing at all?
11. A public attestation: none in `/1`, so every notarization is GODD by default
    (proposed), or a stripped, DOGG-ready record on its own stream that carries only
    the public copy commit and its destination?
12. Co-notaries: out of scope for `/1` (proposed)?
13. The dependency on G10: accept or refuse the two together?

## Owner actions needed

- Decide questions 1 to 3 and 13. The others can follow real use.
- If accepted as an experiment: publish the profile text beside G10's, and have the
  adopting estate sign its `protocol`, `kind` and notary-stream `genesis` entries.
  That is the estate owner's signature, not this proposal's.
- Keep RAPP/1 LTS and canonical `rapp-work/1` unchanged. No chain revision and no
  `RAPP_WORK_PIN.json` re-pin is needed.
- Relay the gap status to the organism (G5: `proposed`), and the difference between
  Work Constitution Article 15 (`rapp-hive/1`) and `G05.md` (`rapp-work/1` §2) on
  where G5 lives. The organism's files are edited only by their own agent.

## Evidence: how the recorded values were produced

- The Hive values come from running the story of
  `kody-w/rapp-model-hive@2bd7c95` `tools/build_example.py` in a scratch folder
  (Python 3.13, `cryptography` 50). They were then recomputed with the model's own
  `agents/hive_agent.py` functions: `Snap.members`, `threshold`, `approvers`,
  `admitted`, `judge`, `signer`, `front` and `sha`, the same logic `check-public
  --hive` uses, but judged at the named commit. Commit octets were hashed with SHA-1
  (checked against the id) and SHA-256. Each tree digest was computed from the tree's
  own objects and equals the tree id that `git mktree` writes for the same entries in
  a scratch repository made with `--object-format=sha256`.
- The public copy's tree, `PUBLISHED.md` and signatures were checked the same way.
  `PUBLISHED.md` equals, byte for byte, the form the model's `_do_publish` writes, so
  `published_sha256` is the SHA-256 of its raw bytes (and of its normalized text).
  The model's `check_public` reports no problems.
- The `check-public` probes changed a scratch copy of the public copy only: one
  commit signed by a public test key added a prose line to `PUBLISHED.md` (no
  problem reported), another added a listing of a missing file ("listed but
  missing").
- The removal of `emery` was made on a scratch clone of the replayed shared copy:
  two approvals and the move, signed by public test keys, each accepted by the
  model's `judge`, with `verify` from the root passing. Its subject is
  `Snap.admitted("emery")` at the judged commit.
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
- G10, the organization type this builds on: branch
  `experimental/gap-g10-folder-hive-binding`,
  <https://github.com/kody-w/rapp-1/blob/experimental/gap-g10-folder-hive-binding/protocols/rapp-work/1/proposals/0010-folder-hive-binding.md>.
- `rapp-hive/1` §2:
  <https://github.com/kody-w/rapp-work/blob/29ead23b21645f8d7682ee00414930ffa9ce0ca6/protocols/rapp-hive/1/SPEC.md>.
- The folder convention and its checker:
  <https://github.com/kody-w/rapp-model-hive/blob/2bd7c95152ede719b6418b80e2bdc2cd457bf711/HIVE-MD.md>
  and `agents/hive_agent.py` at the same commit.
- The organism and the Work Constitution (read-only here): `kody-w/rapp-work`,
  branch `experimental/rapp-work-constitution`, commit
  `71ef227555ad565aaff20c549968c31dcd1d4778`: `organism/gaps/G05.md`, `G06.md`,
  `G08.md`, `G09.md` and `G10.md`; `organism/crossings/folder-hive-organization.md`;
  `organism/journeys/E1.md` and `E3.md`; `organism/glossary.md` ("notary (idea)");
  `CONSTITUTION.md` Articles 7, 9 and 15 and Part V.

## Appendix: the G10 examples this proposal names (non-normative)

These are G10's example blocks, byte for byte, from the convention pins to the
successor vector, so that the notarizations above can be checked from this document
alone.

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
