# RAPP Private Hive
## Shared GODD, frame convergence, and multi-channel projection profile

**Protocol identifier:** `rapp-hive/1`  
**Status:** Normative RAPP/1 operational profile  
**Parent:** [`rapp/1`](../../../SPEC.md)  
**Schema:** [`schema.json`](schema.json)

RAPP Private Hive defines the access-restricted, off-device portion of a RAPP
workspace. It is a **GODD estate**, not a DOGG publication surface. A user
selects which local GODD material becomes Hive-shared GODD; authorized members
may then verify and assimilate that shared slice into their own local GODD.

The same Hive may be projected through private Git, SharePoint, NAS, LAN, or
other stores. These are channels for one authority, not independent Hives.
Dream Catcher convergence gathers immutable frames from temporary local
dimensions and produces one signed successor on the Mother Hive stream.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are
used as defined by RAPP/1 section 2.

## 1. RAPP/1 foundation

An implementation:

1. **MUST** use the exact eleven-key `rapp/1` frame envelope.
2. **MUST** canonicalize payloads with RAPP/1 section 4 and identify them with
   `H("rapp/1:particle", payload)`.
3. **MUST** register this profile and its exact kinds in the adopting estate's
   signed section 13 registry.
4. **MUST** carry every authoritative declaration, GODD slice, assimilation,
   convergence, and projection receipt in a signed frame. Unsigned documents
   are drafts or caches only.
5. **MUST NOT** add a transport endpoint beside `POST /chat`; Git, SharePoint,
   SMB, filesystem, and HTTP are artifact stores or frame logs.
6. **MUST** use RAPP/1 cross-stream Dream-Catcher order: ascending `utc`, then
   ascending `frame_hash`.
7. **MUST NOT** repair, reparent, mutate, or discard a received RAPP/1 frame.
8. **MUST** refuse in favor of RAPP/1 whenever this profile conflicts with the
   parent specification.

An adopting estate registers seven kinds, normally bound to the `body` family:
`hive.declaration`, `hive.object`, `hive.godd-slice`,
`hive.assimilation`, `hive.convergence`, `hive.projection`, and
`hive.template`. The profile requires signatures even when the selected RAPP/1
family would otherwise permit `sig:null`.

## 2. The three boundaries

1. **Local RAPP workspace** — the full on-device GODD. Material stays here
   unless its owner explicitly selects it.
2. **RAPP Private Hive** — the restricted collaborative workspace. It may
   contain both DOGG and explicitly shared GODD objects.
3. **DOGG** — a separately generated, globally public-facing projection. DOGG
   **MUST NOT** contain PII, secrets, credentials, private prompts, plaintext
   GODD, or data whose global-publication rights are unproven. Hive membership,
   a private repository push, or a Hive frame never authorizes DOGG publication.

The default transfer is copy. Moving or withdrawing a Hive slice **MUST NOT**
erase the owner's local source or rewrite accepted history.

DOGG and GODD classify data, not storage locations. A DOGG object remains
PII-free and globally safe even when it is held inside a restricted Hive. A
GODD object remains private data even when authorized Hive members share it.
Moving an object between local workspace and Hive does not change its data
class.

## 3. Declaration

`rapp-hive/1-declaration` names one Hive, its hard `world_id`, one owner, its
members, sealed rooms, channels, and policy. Members, rooms, and channels are
sorted by stable id. Exactly one channel has role `authority`; other channels
are writable contribution endpoints, mirrors, caches, or backups.

A member is a RAPP identity, not a human-only account. The protocol makes no
capability distinction between a person, AI, agent, service, or hybrid team
holding an authorized RAPPID. Roles, rooms, signatures, provenance, and policy
govern access. An implementation **MUST NOT** reduce collaboration rights merely
because an authorized member is non-human, and **MUST NOT** grant extra authority
merely because a member is human.

Supported channel kinds are `github`, `sharepoint`, `nas`, `lan`, `local`, and
`custom`. A locator is transport metadata, not identity. Changing a URL, mount,
tenant, repository, or server **MUST NOT** change the Hive rappid or any
artifact address.

The declaration policy is closed:

```json
{
  "godd_sharing": "explicit",
  "default_godd_scope": "local-only",
  "external_publication": "disabled",
  "conflict_mode": "explicit",
  "default_transfer": "copy"
}
```

`default_godd_scope:"local-only"` is load-bearing. The most sensitive GODD
never moves merely because a workspace joined a Hive. Each shared slice is a
separate affirmative act.

### 3.1 Sealed rooms

A room is a scoped area with a sorted member subset. `access:"repository"`
permits member-visible objects inside the repository's access boundary;
`access:"sealed"` additionally requires encrypted room objects. Rooms may
overlap. A four-member Hive may have a sealed room whose encrypted slices are
decryptable by only two named members.

All repository collaborators may be able to observe the sealed egg ciphertext,
hashes, room id, and non-sensitive routing metadata. That visibility grants no
plaintext access. The key service releases a slice DEK only to a recipient
whose keyed RAPPID is both:

1. a current member of the declared room; and
2. present in the slice's explicit audience.

Repository access, branch access, possession of ciphertext, or membership in a
different room is insufficient.

## 4. The Hive as an organic RAPP/1 workspace object

The Hive is itself a RAPP/1-identified workspace object that can present any
verified RAPP/1 object. `rapp-hive/1-object` is the generic membership record.
It names:

- the object's own RAPPID;
- one typed RAPP address (`rapp/1:particle`, `rapp/1:wave`, or
  `rapp/1:egg-manifest`);
- the object's registered or application kind;
- its target path in a member or shared area;
- its room and audience;
- its data class (`dogg`, `godd`, or `neutral`);
- its PII status and optional scan-evidence hash;
- its protection mode; and
- source frames and mutation keys for provenance and convergence.

Agents, skills, projects, frames, eggs, neighborhoods, rapplications, GODD
schemas, DOGG projections, tools, knowledge, media, and future registered RAPP
objects can all enter through this one rule. The profile does not prescribe a
fixed taxonomy. Members may reorganize their own areas and grow new structures
organically as long as RAPP identity, content addressing, world boundaries,
audience, provenance, and append-only history remain valid.

`protection:"member-visible"` is permitted in a repository-access room.
`protection:"sealed-room"` requires a sealed room and a signed RAPP/1 sealed
egg address. Unknown object kinds are not inferred; they must resolve through
the adopting estate's registry or remain untrusted application data.

A generic object classified `godd` **MUST** use `sealed-room` protection.
`rapp-hive/1-godd-slice` is the richer GODD specialization when assimilation,
plaintext schema, record count, and source-layer semantics are required. A
`dogg` object may be member-visible, but it still must satisfy the global
PII-free DOGG rule: `pii_status` is `none` and `pii_evidence_hash` binds the
sanitization or detection evidence used for that decision.

## 5. Hive-shared GODD slices

`rapp-hive/1-godd-slice` describes one immutable, owner-selected slice of GODD.
The frame contains only non-sensitive routing and verification metadata. The
actual GODD bytes **MUST** be a signed RAPP/1 `sealed` egg:

- `content.sealed_egg_hash` is its `rapp/1:egg-manifest` address;
- `content.artifact_rappid` is the keyed identity that signs the sealed egg;
- confidentiality uses RAPP/1 AES-256-GCM and scoped key release;
- the DEK, credentials, plaintext, and private source paths **MUST NOT** appear
  in the frame, Git history, channel locator, catalog, or projection receipt.

The slice classification is always `estate:"godd"` and
`scope:"hive-shared"`. Sharing does not turn GODD into DOGG. Every slice names
one room. Its audience is a sorted, non-empty subset of both current Hive
members and that room's members. Key release is authorized only for that
audience and may be narrower than repository read access.

`source_frames` preserves the RAPP/1 addresses from which the slice was
derived. `mutation_keys` declares the logical entities or invariants the slice
changes; Dream Catcher uses them to detect semantic conflicts.

## 6. Assimilation into another GODD

`rapp-hive/1-assimilation` records that an authorized recipient verified,
decrypted, and injected a Hive slice into a local workspace. Assimilation:

- **MUST** verify the slice frame, sealed egg, publisher signature, audience,
  key release, plaintext commitment, and world boundary before use;
- **MUST** mount the slice under an explicit local namespace;
- **MUST** preserve the source slice particle hash and resulting local layer
  hash;
- **MUST NOT** overwrite unrelated personal GODD;
- **MUST** use `overlay`, `copy`, or `materialize` mode with explicit
  precedence;
- **MUST NOT** imply that the recipient owns or may republish the source data.

A workspace may generate DOGG from its authorized GODD layers only when every
included slice independently allows DOGG projection and a separate publication
policy authorizes it. The projection pipeline **MUST** still remove and refuse
PII; `dogg_projection_allowed:true` is permission to evaluate a slice, not proof
that its raw fields are safe to publish.

## 7. Dimensions and the Mother Hive

A device, branch, contributor area, or access channel may evolve temporarily as
a **dimension** of one Hive. A dimension has its own RAPPID and immutable local
frames, but it is not a new authoritative Hive.

The **Mother Hive** is the one registered authority stream. Its signed
`hive.convergence` frame is the linearization point that accepts a new
canonical successor. Git may carry branches, commits, authorship, review, and
conflict evidence, but signed RAPP frames and the registered Mother Hive head
remain semantic authority.

## 8. Dream Catcher convergence

`rapp-hive/1-convergence` records a deterministic merge attempt:

1. Gather candidate frames from authorized dimensions and channels.
2. Verify each frame independently under RAPP/1 sections 7, 10, and 13.
3. Sort candidates by RAPP/1 section 7.4: `(utc, frame_hash)`.
4. Deduplicate identical `frame_hash` values.
5. Accept causally compatible frames additively.
6. Detect semantic conflicts through declared `mutation_keys`.
7. Preserve every conflicting branch; never use silent last-write-wins.
8. Resolve a conflict only with a signed reconciliation frame that names every
   conflicting frame.
9. Append one signed convergence frame to the Mother Hive stream.
10. Project that accepted head to every configured channel.

Decisions are `accepted`, `duplicate`, `conflict`, `quarantined`, or
`superseded`. Invalid, unauthorized, malformed, tampered, cross-world, or
lineage-breaking frames are quarantined. Quarantine of one frame **MUST NOT**
block independent valid frames.

`status:"partial"` is required while unresolved conflicts remain;
`status:"converged"` is permitted only when none remain. Convergence is
idempotent: repeating the same candidate set against the same base cannot
produce a different accepted set or catalog hash.

## 9. Multi-channel projection

`rapp-hive/1-projection` is a signed receipt for one channel. A current receipt
binds:

- the exact convergence payload hash;
- channel id;
- registry sequence;
- Mother Hive frame head;
- catalog hash; and
- complete artifact-manifest hash.

All current channels **MUST** expose the same verified identities and hashes.
A stale, partial, divergent, or tampered projection is surfaced and cannot
overwrite authority. A read-only mirror, cache, backup, or temporarily newer
local dimension never becomes authority by availability or timestamp.

## 10. Storage portability

The canonical Hive is ordinary verified bytes: frames, signed registries,
sealed eggs, manifests, and derived indexes. Backends are adapters.

A conformant export/import or migration:

1. verifies the source authority;
2. copies bytes without mutation;
3. verifies every destination byte and head;
4. records a projection receipt;
5. switches an authority locator only through an owner-signed declaration; and
6. leaves source retirement as a separate explicit action.

One Hive may project simultaneously through private GitHub, SharePoint, NAS,
LAN, and local caches. Members may use different channels and still verify the
same Hive.

## 11. Git contribution loop

Git is the default contribution and reconciliation substrate:

1. pull and verify the registered Mother Hive head;
2. make local changes and append dimension frames;
3. commit with attributable authorship;
4. push a branch or proposal to a writable channel;
5. run Dream Catcher;
6. review explicit conflicts or quarantines;
7. append the signed Mother Hive convergence frame; and
8. resynchronize every channel.

A Git merge alone does not authorize a Hive state. A signed convergence frame
does. Non-fast-forward history rewriting, force-push loss, or deletion of
accepted frames is nonconformant.

## 12. Privacy and access limits

- A Private Hive may contain DOGG, GODD, and neutral RAPP objects. The Hive's
  restricted location does not alter an object's data class.
- Hive GODD may contain sensitive data approved for the declared audience.
- The default GODD scope is local-only; only explicitly selected slices enter
  the Hive.
- Plaintext GODD **MUST NOT** be broadcast. Shared GODD uses sealed eggs and
  scoped key release.
- Rooms create cryptographic sub-audiences inside one Hive. Ciphertext
  visibility to other repository collaborators does not grant plaintext
  access.
- Repository, SharePoint, SMB, or LAN authorization is necessary but not
  sufficient; artifact key release enforces the slice audience.
- Revocation stops future key release but cannot erase plaintext already
  decrypted by an authorized member, as required by RAPP/1 section 9.2.1.
- External or globally public publication is outside this profile and disabled
  by declaration policy.
- DOGG is always PII-free. A DOGG projection that contains PII is
  nonconformant regardless of source consent or Hive membership.
- Cross-`world_id` assimilation is refused.

## 13. PII-free Hive template eggs

`rapp-hive/1-template` records a reusable Hive template packaged as a RAPP/1
egg. A template is a DOGG projection of Hive structure, not a backup or clone
of the live Private Hive.

A conformant template:

- receives a distinct template RAPPID rather than reusing the live Hive
  identity;
- includes only objects classified `dogg` or `neutral`;
- requires `pii_status:"none"` for every DOGG object;
- binds an aggregate `pii_evidence_hash`;
- excludes every GODD slice, sealed-room ciphertext, member-specific access
  grant, key-service secret, DEK, credential, personal memory, and live channel
  locator;
- may retain reusable workspace structure, schemas, agents, skills, tools,
  project templates, room definitions without live members, and DOGG content;
  and
- is packed and verified under the existing RAPP/1 egg specification.

The template egg can be shared globally because its selected bytes are DOGG or
neutral and PII-free. Hatching it creates a new Hive identity and empty local
GODD layers; it never joins the recipient to the source Hive or grants access
to source GODD.

## 14. Conformance

An implementation claiming `rapp-hive/1` conformance must:

1. validate all seven closed payload schemas;
2. reproduce every RAPP particle hash;
3. verify authoritative signed frames and signer authorization;
4. use sealed RAPP/1 eggs for Hive-shared GODD bytes;
5. preserve explicit member audience and world boundaries;
6. order candidate frames by `(utc, frame_hash)`;
7. preserve conflicts and require reconciliation frames;
8. maintain one Mother Hive head across all dimensions;
9. verify every current channel against the same accepted hashes;
10. pass `python3 hive_conformance.py`.

JSON Schema validation alone proves only shape. The Python validator enforces
cross-document membership, audience, convergence, and channel invariants.
