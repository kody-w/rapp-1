# Why RAPP
## The organism grows around the Grail

RAPP begins with one permanent idea:

> Plant the same sacred kernel in new ground, then let the organism grow around
> it without changing what made it the same organism.

The Grail is the seed. RAPP is the living structure that wraps it: identity,
agents, organs, tools, policy, memory, state, interfaces, deployment, and
experience. New capability grows outward as a new layer. It is not welded into
the kernel.

This is not merely an implementation pattern. It is the reason RAPP exists.

## The first question

Every RAPP begins with:

> **What should I do?**

The answer is not a monolithic program written all at once. The problem is
RAPPed up:

1. name the goal and its boundary;
2. add one capability layer;
3. record what happened in a frame;
4. test the result against evidence;
5. add, replace, or remove the next layer;
6. repeat until the organism reliably does what was asked.

Layer after layer, frame after frame, the problem becomes a bounded organism.
The history of how it learned to fulfill the goal remains inspectable instead
of disappearing inside the final build.

When the organism does what was asked, it **graduates**. Graduation is the
point where a RAPP leaves the protected nursery, enters the wild, and begins
fulfilling its RAPPed-up goal for real users. Graduation requires identity,
qualification, health limits, and a return path. It is not permission to mutate
silently after release.

## Offspring in the wild

A graduated organism remains portable and self-documented. When it encounters
a challenge its current body cannot meet, it does not erase itself. It records
the encounter, RAPPs the new problem in a candidate lineage, and may produce an
**offspring**:

- the ancestor remains immutable;
- the offspring receives a new identity;
- the offspring records the typed content addresses of its parent material;
- the new layers and frames belong to the offspring's own history.

Two or more RAPPed objects may also be **crossed**. Crossing does not blend
identities or silently transfer authority. It creates a new organism with a new
identity and explicit multi-parent lineage. Its parents remain intact. Their
self-documenting bodies give the offspring a chance to combine capabilities
and solve a challenge neither parent could satisfy alone.

This can continue indefinitely across generations. "Try forever" means an
unbounded lineage of inspectable, bounded attempts — never one uncontrolled
infinite loop consuming user trust or resources.

## Why it is called RAPP

RAPP is a name before it is an acronym, but its construction is deliberate:

- **R** is recursive. The same organism grammar repeats from one agent, to a
  rapplication, to a brainstem, to a neighborhood, to an estate.
- **APP** is application. The result is useful, runnable life rather than a
  passive model or a pile of infrastructure.
- Spoken aloud, RAPP carries the idea of **wrap**. Capability wraps the Grail
  instead of cutting into it.

A RAPP is therefore a recursive application organism: an immutable identity
and kernel surrounded by composable living layers.

RAPP is also a verb:

> To RAPP a problem is to wrap it in verifiable layers and frames until the
> resulting organism can be safely graduated to fulfill that goal in the wild.

The name is intentionally not expanded into a rigid marketing acronym. Its
meaning is architectural and testable.

## The growth model

```text
environment and skin
  deployment, health, and recovery
    policy, permissions, and human seams
      memory, state, and identity
        agents, tools, adapters, and organs
          RAPP/1 protocol membrane
            immutable Grail kernel
```

Each outer layer may specialize for a person, business, device, region, or
mission. The center remains the same.

This gives RAPP two properties that ordinary application stacks usually trade
against each other:

1. **Continuity.** The organism retains identity and lineage while its
   capabilities grow.
2. **Portability.** The same verified seed can be planted on new hardware, in a
   new region, for a new tenant, or inside a new product without silently
   becoming a different species.

## The Grail is a seed, not a feature backlog

The kernel owns only what every organism of the species must share. A request
that appears to require a kernel edit is first tested against the outer growth
surfaces:

- agent;
- adapter;
- organ;
- configuration;
- policy;
- frame;
- state schema;
- deployment control plane;
- user-facing skin.

If the capability can live in one of those layers, it belongs there. If it
cannot, the system reports an incompatibility rather than quietly changing the
Grail under an existing identity.

## New ground

"Planting" is literal architecture. A RAPP organism may be placed:

- on a person's local machine;
- in a business-controlled box;
- in an enterprise tenant;
- in an isolated regional cell;
- on a provider-neutral runtime;
- in a future substrate not known when the kernel was written.

The ground supplies resources and policy. It does not redefine the seed.
Environment-specific behavior is an outer layer with an address, owner, and
removal path.

## Growth without user disruption

The AI that serves users is a qualified release, not a live experiment.
Learning and mutation occur in an isolated candidate lineage. A candidate earns
its way outward through RAPP CI/CD and reaches users through RAPP Deploy.

The serving organism remains stable until the next organism version has:

- the same authenticated Grail;
- a complete content-addressed release capsule;
- passing, fresh qualification evidence;
- state compatibility and restore proof;
- bounded progressive exposure;
- a known exact rollback release.

Users experience continuity while the organism continues to grow.

## The RAPP test

A design belongs in RAPP when the answer to each question is yes:

1. Can the Grail remain byte-identical?
2. Can the capability be expressed as a removable outer layer?
3. Can its identity, inputs, and effects be verified?
4. Can the organism be replanted without losing lineage?
5. Can offspring or crosses name every parent without inheriting hidden
   authority?
6. Can a failed layer be isolated or rolled back without harming healthy
   users?
7. Can a stranger implement the same contract without private interpretation?

If not, the design is not finished.

## Open foundation, owned organisms

RAPP/1 is an open protocol intended for independent implementation. The
organisms grown with it may be personal, public, commercial, private, or
regulated. Openness of the seed does not erase ownership of an organism's
identity, memory, policy, data, brand, or authored experience.

That separation is the compact:

> One open seed. Infinitely many owned organisms. No hidden mutation of the
> root.

---

**Canonical philosophy:** this file in `kody-w/rapp-1`.  
**Operational law:** `CONSTITUTION.md`, RAPP CI/CD, and RAPP Deploy.  
**Company expression:** RapterBox LLC's Constitution and Ten Commandments at
`https://rapterbox.com/rapp`.
