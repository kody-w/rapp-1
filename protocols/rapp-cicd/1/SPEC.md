# RAPP CI/CD
## Immutable qualification and promotion profile

**Protocol identifier:** `rapp-cicd/1`  
**Status:** Normative RAPP/1 operational profile  
**Parent:** [`rapp/1`](../../../SPEC.md)  
**Schema:** [`schema.json`](schema.json)

RAPP CI/CD defines how one immutable AI release candidate earns promotion. It
turns "production ready" into a candidate-bound, machine-verifiable statement.
It does not prescribe GitHub Actions, a cloud provider, a branch model, or a
particular list of ring names.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are
used as defined by RAPP/1 section 2.

## 1. Foundation

RAPP CI/CD is subordinate to RAPP/1. An implementation:

1. **MUST** use RAPP/1 canonical I-JSON for every protocol payload.
2. **MUST** identify a payload by
   `H("rapp/1:particle", payload)`.
3. **MUST** carry an authoritative payload in a signed RAPP/1 frame. A local
   unsigned file is a draft, fixture, or cache and cannot authorize promotion.
4. **MUST NOT** add a transport endpoint beside RAPP/1 `POST /chat`.
5. **MUST** resolve `release_scope` and the Grail binding from authenticated,
   owner-controlled policy as required by RAPP/1 section 11.1.
6. **MUST** refuse any conflict with RAPP/1 or its activated Grail declaration.

The profile defines four closed payload schemas:

| schema | purpose |
|---|---|
| `rapp-cicd/1-release` | immutable identity of one release candidate |
| `rapp-cicd/1-policy` | ordered promotion path and required evidence |
| `rapp-cicd/1-evidence` | result of one stage against that exact candidate |
| `rapp-cicd/1-promotion` | explicit decision to advance, hold, or reject |

Unknown keys are refused. Missing keys are refused. A changed payload has a new
particle hash and therefore is a different release, policy, evidence record, or
decision.

## 2. Release capsule

A `rapp-cicd/1-release` payload identifies the complete candidate before
qualification begins:

```json
{
  "schema": "rapp-cicd/1-release",
  "release_scope": "https://example.com/releases/product",
  "created_utc": "2026-08-30T12:54:20.000Z",
  "source": {
    "repository": "https://github.com/example/product",
    "object_format": "sha1",
    "commit": "0123456789012345678901234567890123456789",
    "tree": "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
  },
  "artifact": {
    "sha256": "<64 lowercase hex>",
    "size_bytes": 1234,
    "media_type": "application/zip",
    "entrypoint": "src/main.py"
  },
  "grail": {
    "grail_id": "grail:<64 lowercase hex>",
    "path": "rapp_brainstem/brainstem.py",
    "sha256": "<64 lowercase hex>",
    "size_bytes": 154059
  },
  "components": [
    {
      "kind": "kernel",
      "name": "grail-brainstem",
      "version": "v0.6.16",
      "sha256": "<same digest as grail.sha256>",
      "mutable": false
    }
  ],
  "lineage": {
    "mode": "seed",
    "parents": []
  }
}
```

The release identity is the payload's RAPP particle hash. Before it can enter
qualification, a trusted RAPP/1 registry verifier supplies the activated
`grail-kernel` entry. The release's scope, Grail identity, path, SHA-256, and
byte length **MUST** equal that authenticated binding. Comparing fields only
against other candidate-supplied fields is circular and nonconformant.

A release capsule:

- **MUST** identify an immutable source commit and tree.
- **MUST** bind the exact distributable artifact and runtime entry point.
- **MUST** contain exactly one immutable `kernel` component whose digest equals
  `grail.sha256`.
- **MUST** enumerate every behavior-affecting agent, adapter, model, policy,
  configuration, state schema, tool, and knowledge source. Component `kind`
  values are lowercase extension points; new kinds do not require a new
  protocol version.
- **MUST NOT** mark the kernel mutable. Any other component marked mutable is
  an external dependency, remains pinned by an identity descriptor hash, and
  requires continuously expiring behavioral evidence.
- **MUST** become a new release whenever any component, configuration, prompt,
  policy, model identity, tool contract, or artifact byte changes.
- **MUST** record `lineage.mode` as `seed`, `offspring`, or `cross`.
  `offspring` names one typed RAPP parent address; `cross` names two or more.
  Parents are sorted, unique, and informational only. The new organism receives
  a new identity and inherits no authority or ownership merely by naming them.

## 3. Promotion policy

A `rapp-cicd/1-policy` payload defines one ordered path. Stages have a stable
`id` and one semantic class:

`development -> test -> canary -> qualification+ -> preprod -> production`

`qualification` may repeat; every other class occurs exactly once. This lets an
estate use names such as Nightly, Alpha, and Beta without hard-coding those
names into the protocol.

Every stage declares:

- `required_checks`: exact lowercase identifiers;
- `minimum_soak_seconds`: the minimum measured observation interval;
- `maximum_evidence_age_seconds`: how long stage evidence may authorize a new
  promotion;
- `approval`: `automatic` or `owner`.

The Canary class **MUST** include `grail-kernel`, `product`, `autonomous`, and
`security-smoke`.
The Preprod class **MUST** include:

- `exact-candidate`
- `grail-kernel`
- `dependency-integrity`
- `supply-chain`
- `security`
- `privacy`
- `tenant-isolation`
- `state-compatibility`
- `model-behavior`
- `capacity`
- `failover`
- `authenticated-soak`
- `rollback-rehearsal`
- `restore-rehearsal`

Preprod **MUST** have a non-zero soak. Production **MUST** require owner
approval. A policy change creates a new policy particle hash and invalidates
promotion decisions made against the prior policy.

Preprod is a gate, not a mutable ring. It reconstructs the exact candidate in a
production-shaped environment; it does not accept patches or produce different
release bytes.

## 4. Evidence

A `rapp-cicd/1-evidence` payload binds:

- the release particle hash;
- the policy particle hash;
- the exact stage and semantic class;
- the environment digest;
- the artifact digest and Grail identity;
- start and completion timestamps;
- one content-addressed result per executed check;
- the previous stage's evidence particle hash.

Evidence forms an ordered hash-linked chain matching the policy. Every required
check must be present and pass, the measured interval must meet the stage's
minimum soak, and the previous stage must have passed. A missing predecessor,
stage skip, reordered stage, stale candidate, changed artifact, or changed
Grail is refusal.

Stage time is monotonic: each stage starts at or after its predecessor
completed, and every record in a promoted prefix completes no later than the
promotion decision and trusted verification time.

Evidence **MUST** be produced by a trusted evaluator outside candidate control.
Candidate code may emit observations but cannot decide that its own gate
passed. Secrets, credentials, and raw customer content **MUST NOT** appear in
evidence; store a digest or access-controlled reference instead.

Promotion authorization **MUST** resolve every evidence payload through a
signed evaluator frame or an authenticated evidence receipt. Validating bare
candidate-supplied evidence objects is payload validation only and cannot
authorize promotion.

## 5. Promotion

A `rapp-cicd/1-promotion` payload names the exact release, policy, evidence,
source stage, and immediately following target stage. Its decision is
`promote`, `hold`, or `reject`.

A `promote` decision is valid only when:

1. the referenced evidence is for the source stage;
2. the evidence result is `pass`;
3. the target is the next policy stage, with no skip;
4. all hashes resolve to the exact payloads under evaluation;
5. the decision is carried by a signer authorized for the target stage.
6. the complete evidence prefix from development through the source stage
   validates without a gap;
7. the source evidence remains within its declared maximum age at trusted
   verification time.

Approval never repairs failed evidence. An owner may hold or reject a passing
candidate, but cannot promote a failing one.

## 6. Supply chain and evaluator isolation

The following properties are mandatory:

- Build once; promote the same artifact digest everywhere.
- Resolve dependencies from exact locks and immutable sources.
- Produce provenance, SBOM, vulnerability, and license evidence.
- Separate runtime dependencies from test dependencies.
- Reconstruct sealed artifacts before execution and bind verification to the
  bytes actually consumed.
- Run evaluators with least privilege and without candidate-controlled policy.
- Treat an unavailable check as failed, never skipped-success.
- Treat externally mutable model or knowledge dependencies as changed when
  their observed behavior or identity leaves the qualified envelope.

## 7. State and user continuity

Qualification **MUST** prove that the candidate can read supported prior state,
that migrations are reversible or expand-contract safe, and that rollback does
not discard acknowledged user work. Destructive repair testing occurs only in
an isolated candidate environment with an explicit backup and restore proof.

An AI may grow in a candidate lineage. It **MUST NOT** rewrite the serving
lineage in place. Training, prompt optimization, tool acquisition, memory
schema changes, and policy changes all produce a new release capsule.

## 8. Failure and refusal

The following are release-blocking:

- `kernel-drift`
- `artifact-drift`
- `policy-drift`
- `environment-drift`
- `stage-skip`
- `missing-evidence`
- `failed-check`
- `stale-evidence`
- `untrusted-evaluator`
- `state-incompatible`
- `rollback-unproven`
- `restore-unproven`

A red gate is a finding. Bypassing, muting, retrying until green without
preserving failures, or changing the candidate under the same release identity
is nonconformant.

## 9. Conformance

The reference library exposes two deliberately different layers:

- payload validators return `payload-conformant`; this proves shape, hashes,
  ordering, and cross-document consistency but grants no authority;
- `authorize_promotion_frame` additionally verifies the enclosing RAPP frame,
  registered kind, stream continuity, signature, authenticated Grail binding,
  and signer authorization.

An implementation claiming **RAPP CI/CD conformance** must:

1. validate all four closed payload schemas;
2. reproduce their RAPP particle hashes;
3. enforce the cross-document rules in this specification;
4. verify the enclosing RAPP frame signature and signer authority;
5. retain the complete evidence and decision chain;
6. pass `python3 operations_conformance.py`.

JSON Schema validation alone is insufficient because it cannot prove artifact
identity, temporal ordering, stage continuity, signer authority, or exact
promotion.
