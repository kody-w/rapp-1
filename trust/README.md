# RAPP/1 trust-registry candidate

This directory is a **proposal surface**, not the registry of record. The authority
described by SPEC section 13 remains:

```text
https://github.com/kody-w/RAPP
rapp-map/ecosystem-spec.json
```

That path was unavailable to this worktree's GitHub credentials when this candidate
was prepared, so `registry-candidate.json` records `retrieval_status:"unavailable"`
and does not guess its sequence, owner rappid, key, prior digest, or signature.
Nothing here becomes trusted because it merged into `kody-w/rapp-1`.

## Candidate contents

`registry-candidate.json` is pinned to `rapp-1@f75226e`, the rev-6 spec blob, and
anchor frame 6. It preserves the exact eleven-member `rapp/1` frame. It proposes:

| Proposal role | Candidate values |
|---|---|
| signed swarm kinds | `ms-rapp.factory-transform-request`, `ms-rapp.factory-output-wave` |
| body kind | `ms-rapp.factory-artifact` |
| egg variants | `ms-rapp-factory-transform-request`, `ms-rapp-factory-artifact`, `ms-rapp-factory-output-wave` |

The dot in each frame kind is required by SPEC section 6.1.1. The hyphen-only
names are valid egg-variant labels. These are proposed registrations only; the
closed registries in `rapp.py` and SPEC section 9.2 intentionally remain unchanged
until the owner ratifies them and the authoritative registry accepts them.

The schema also defines the fields needed for a prepared signing packet: owner
tenures, mint-once rappids, Ed25519 SPKI records, key validity, tombstones,
re-anchors, registry sequence and predecessor hash, provenance, and signature.
`grown_from` is retained only as immutable instance lineage. It grants no authority,
trust, or key material.

## Deterministic checks

Install the isolated trust dependency and run the committed candidate:

```text
python -m pip install -r trust/requirements.txt
python trust/rapp_trust.py verify trust/registry-candidate.json --allow-unsigned
python trust/rapp_trust.py digest trust/registry-candidate.json
python -m unittest -v trust.test_rapp_trust
```

The candidate digest is domain-separated in the proposal-only
`rapp/1:registry-candidate` space. It covers every candidate field except `sig`.
The expected digest is committed in `registry-candidate.digest`.

The verifier is fail-closed. It checks strict I-JSON with no floats, canonical bytes
through the repository's one canonicalizer, exact Frame shape, stream binding,
registry-bound kind families, detached Ed25519 JWS, SPKI-to-rappid binding, owner
tenure, key validity, tombstones, rotation continuity, rollback/equivocation, and
cross-estate replay. It never repairs, reparents, or mutates an input.

## Kody/Wildhaven owner signing ceremony

The following steps are human gates. Do not perform them in CI or in an agent session.

1. In a clean room, fetch the registry of record from its canonical source. Pin its
   exact commit and verify its existing owner signature, current `registry_seq`,
   predecessor digest, freshness, and sole non-deprecated `estate_owner`.
2. Review `registry-candidate.json` against the pinned SPEC and anchor. Confirm the
   three dot-form kind/family bindings and three hyphen-form egg variants are the
   intended append. Do not copy this candidate over the authoritative document.
3. Copy the candidate to an untracked working location. Set the canonical-source
   commit, next sequence, predecessor hash, owner tenure, owner rappid, owner SPKI,
   and validity interval from verified authority. The keyed rappid tail must equal
   `Hb("rapp/1:rappid", SPKI_DER)`.
4. Recompute the candidate digest twice in independent clean processes. Compare the
   canonical bytes and digest before authorizing any signature.
5. Keep the production Ed25519 private key outside this repository. The tool refuses
   a key path beneath the repository and never prints key bytes. Sign to an untracked
   output:

   ```text
   python trust/rapp_trust.py sign prepared-candidate.json \
     --private-key X:\offline\estate-owner.pem \
     --kid rappid:@owner/estate-owner:<verified-tail> \
     --registry-seq <verified-next-sequence> \
     --output X:\offline\signed-candidate.json
   ```

6. Verify the signed output using the estate-owner rappid distributed out of band,
   plus the previously persisted sequence and digest. A mismatch, rollback,
   equivocation, stale source, unknown key, or invalid lifecycle record is a refusal.
7. Translate the approved proposals into the exact append-only SPEC section 13.3
   entry shapes in `kody-w/RAPP/rapp-map/ecosystem-spec.json`. Run that repository's
   own synchronization and conformance flow. The authoritative append, owner
   signature, and merge happen there, not here.
8. Only after authoritative acceptance may consumers treat the new names as
   registered. Until then this directory remains unsigned candidate evidence.

The DOGG Atom feed at
`https://github.com/kody-w/rapp-1/commits/main/anchor.atom` is the official
token-free discovery stream for anchor ticks. A tick triggers a pull and chain
verification; feed entry IDs are never treated as frame hashes or trust evidence.
Estate tooling uses feeds over the GitHub API whenever a feed carries the answer.
