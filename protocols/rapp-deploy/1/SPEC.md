# RAPP Deploy
## Bounded rollout and continuous AI health profile

**Protocol identifier:** `rapp-deploy/1`  
**Status:** Normative RAPP/1 operational profile  
**Parent:** [`rapp/1`](../../../SPEC.md)  
**Depends on:** [`rapp-cicd/1`](../../rapp-cicd/1/SPEC.md)  
**Schema:** [`schema.json`](schema.json)

RAPP Deploy defines how a qualified release receives user traffic and how its
health remains continuously provable. The unit of safety is an isolated
deployment cell; the unit of change is an immutable RAPP CI/CD release.

## 1. Foundation

RAPP Deploy inherits every RAPP/1 and RAPP CI/CD refusal. It defines three
closed payload schemas:

| schema | purpose |
|---|---|
| `rapp-deploy/1-plan` | topology, waves, health budgets, state, data, and recovery |
| `rapp-deploy/1-health` | one candidate-bound observation window in one cell |
| `rapp-deploy/1-decision` | advance, complete, hold, rollback, or quarantine |

Each payload is canonical RAPP/1 I-JSON and is identified by its particle hash.
Authoritative plans, observations, and decisions travel in signed RAPP/1
frames. This profile adds no new endpoint.

Payload conformance alone never authorizes traffic. An authorized plan binds a
signed, fresh RAPP CI/CD promotion to Production, the complete evidence prefix,
the authenticated Grail declaration, and a resolvable previously authorized
rollback release.

The rollback release is verified against its own historical authenticated
Grail binding. A successor Grail therefore may retain a prior-Grail release as
its exact rollback target; candidate authority cannot rewrite the ancestor's
binding.

## 2. Serving and candidate lineages

An implementation **MUST** maintain two distinct lineages:

- **serving lineage**: the immutable release currently receiving user traffic;
- **candidate lineage**: an isolated release undergoing qualification or
  progressive exposure.

`candidate_isolated` **MUST** be true and `in_place_mutation` **MUST** be false.
Any behavior-affecting change creates a new RAPP CI/CD release particle hash.
The running service may append user state under its declared state contract,
but it cannot rewrite its code, model selection, agents, prompts, tools,
policies, or schemas under an existing release identity.

## 3. Cellular topology

Every deployment uses `topology.mode: "cellular"`. A cell is an independently
observable and isolatable failure domain with a declared region and tenant
scope.

Conformance classes:

| class | minimum topology |
|---|---|
| `single-cell` | one cell |
| `multi-cell` | two cells in two failure domains |
| `planetary` | three cells, two regions, three failure domains |

A planetary implementation **MUST** be able to stop routing to one cell without
stopping healthy cells. Shared control planes **MUST NOT** turn a cell-local
failure into a fleet-wide write outage.

## 4. Progressive exposure

Waves are ordered and traffic is expressed as integer basis points. They:

- begin with `shadow` at zero user traffic;
- increase traffic strictly;
- never remove a previously exposed cell;
- end with `global` at 10,000 basis points across every cell.

A planetary plan additionally includes:

- `canary` at no more than 100 basis points;
- `regional` at no more than 5,000 basis points.

Each wave declares a minimum observation duration and minimum healthy windows
per selected cell. A decision cannot advance until every selected cell meets
both requirements with fresh evidence.

## 5. Health contract

The plan defines a list of integer-valued objectives. Each objective names its
unit, comparison operator, and threshold. This list is the protocol's primary
extension point: deployments may add new objectives without changing the
envelope or asking RAPP/1 to understand the metric.

The minimum objective set covers:

- availability parts per million;
- error parts per million;
- p95 latency milliseconds;
- quality score parts per million;
- safety violations parts per million;
- tool success parts per million;
- resource saturation parts per million;
- knowledge age seconds;
- cost microunits per request.

Boolean invariants use integer values (`0` or `1`) and unit `boolean`. The core
also requires:

- exact artifact identity;
- exact Grail identity;
- state integrity;
- model identity;
- behavioral-baseline compatibility;
- tool-contract compatibility.

Every observation supplies exactly one measurement and evidence digest for
every declared objective. Health evidence expires after
`max_evidence_age_seconds`. A model provider, tool, knowledge source, policy, or
dependency may change without a repository commit; expired evidence therefore
cannot authorize continued rollout.

Every health record also carries the observed runtime artifact digest, Grail
identity/path/digest/size, model-set hash, tool-set hash, and state-schema hash.
Identity measurements are derived from those observed values. A record cannot
keep `artifact-match:1` while reporting different runtime bytes.

The health verdict and ordered reason codes are derived values. An observation
cannot label itself healthy when a budget or invariant failed.

## 6. State continuity

State uses one of:

- `none`: no schema migration;
- `expand-contract`: additive compatibility first, removal only after every
  reader has moved;
- `dual-read-write`: old and new representations coexist through migration.

State **MUST** remain backward compatible during rollout. Any migration requires
a content-addressed rollback snapshot. The plan binds both the prior and
candidate state-schema hashes plus the exact Preprod compatibility, rollback,
and restore evidence. `expand-contract` and `dual-read-write` may use different
schema hashes when that compatibility evidence passes; `none` requires equal
hashes. Restore time and recovery-point objectives are integer seconds in the
deployment plan and are proven in Preprod.

Acknowledged user work **MUST NOT** be discarded by rollback. If that cannot be
proven, rollout is refused.

## 7. Tenant and data safety

Every plan binds content-addressed residency, retention, deletion, and backup
policies. Tenant isolation is mandatory. A cell may process only tenants and
regions permitted by those policies.

Telemetry and evidence **MUST** minimize user content. Raw prompts, memories,
credentials, and regulated data are not deployment evidence. Store aggregate
metrics, digests, or access-controlled references.

## 8. Resilience controls

Every deployment carries a list of lowercase resilience controls. The list is
an extension point: a platform can add controls without changing the protocol.
Every deployment requires:

- circuit breakers;
- rate limits;
- load shedding;
- an independently operable kill switch;
- automatic pause;
- automatic rollback.

Planetary deployments additionally require regional failover. Provider failure
behavior is either:

- `fail-closed`: stop the affected capability and report unavailability; or
- `degrade-explicitly`: serve a declared reduced capability and tell the user.

A success-shaped silent fallback is forbidden.

## 9. Decisions

A `rapp-deploy/1-decision` references the exact plan, release, wave, and complete
set of health records used for the decision. Decisions form their own hash
chain. Health windows form a per-cell hash chain and must be monotonic and
non-overlapping; duplicate intervals cannot be counted twice.

For every cell already exposed in the predecessor wave, the first new health
window **MUST** link to the authenticated terminal health record named by the
predecessor decision. A later wave cannot restart a cell's health history at a
null predecessor.

A `hold` or `quarantine` is itself part of the decision ancestry. New evidence
for that same wave follows the hold/quarantine and may later authorize
advancement. A decision may not bypass it by pointing back to the older
wave-transition decision. The enclosing RAPP frame head and the payload's
`previous_decision_payload_hash` must identify the same predecessor.

Every decision publishes `health_heads`, the signed terminal payload hash and
window end for each cell observed so far. A partial hold updates only the cells
it observed and carries the other authenticated heads forward. This allows a
multi-cell wave to pause on one affected cell without losing continuity or
making the wave impossible to resume.

- `advance`: move to the next wave only after all selected cells satisfy the
  current wave.
- `complete`: finish only when the global wave satisfies the contract.
- `hold`: preserve current exposure while collecting evidence or awaiting an
  operator.
- `rollback`: route to the exact `rollback_release_payload_hash`.
- `quarantine`: remove the candidate or affected cell from traffic and retain
  evidence for diagnosis.

A decision that references any unhealthy or stale observation can never
authorize `advance` or `complete`, even if older healthy windows already met
the minimum count.
A rollback target is an exact release particle hash, never a mutable tag.
That hash must resolve to a previously authorized release with a state schema
compatible with the candidate and the plan's restore evidence.

## 10. Long-term health

Deployment health continues after global rollout. Implementations **MUST**:

1. emit recurring health windows from every serving cell;
2. requalify when evidence expires or a mutable dependency changes;
3. run scheduled rollback, restore, failover, and capacity drills;
4. retain append-only incident and decision evidence;
5. enforce error budgets and freeze promotion when exhausted;
6. keep a tested previous release available until the rollback window closes;
7. surface degraded operation to users and operators;
8. retire releases through an explicit migration, never silent abandonment.

Production is therefore a continuously renewed health claim, not a one-time
deployment event.

A global `complete` decision is not a terminal chain state. Subsequent global
health windows may produce another `complete`, or may `hold`, `quarantine`, or
`rollback` when the deployed organism or its environment changes.

## 11. Conformance

The reference library separates payload validation from authorization.
`validate_plan_payload`, `validate_health`, and `validate_decision` prove
content relationships. `authorize_plan_frame` and
`authorize_decision_frame` additionally require signed RAPP frames, registered
kinds, authenticated qualification, authorized health provenance, and signer
authority.

An implementation claiming **RAPP Deploy conformance** must:

1. accept only a release that passed the required RAPP CI/CD path;
2. validate all three closed payload schemas;
3. enforce topology, wave, health, state, data, resilience, and decision rules;
4. verify enclosing RAPP frame signatures and signer authority;
5. prove automatic pause, exact rollback, restore, and cell quarantine;
6. pass `python3 operations_conformance.py`.

An implementation may claim `single-cell` or `multi-cell` conformance without
claiming planetary conformance. It may claim **planetary** only when every
planetary requirement above is proven by current evidence.
