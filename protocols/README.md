# RAPP Operational Protocols

RAPP/1 defines the bytes, identities, frames, wire, packages, trust, and immutable
Grail. These profiles define how a RAPP organism reaches production and remains
healthy there without mutating the serving system underneath its users.

| Human name | Protocol identifier | Normative specification |
|---|---|---|
| RAPP CI/CD | `rapp-cicd/1` | [`rapp-cicd/1/SPEC.md`](rapp-cicd/1/SPEC.md) |
| RAPP Deploy | `rapp-deploy/1` | [`rapp-deploy/1/SPEC.md`](rapp-deploy/1/SPEC.md) |

The profiles are subordinate to RAPP/1:

- every payload is I-JSON canonicalized with RAPP/1 section 4;
- every payload is identified by its RAPP particle hash;
- authoritative payloads travel in signed RAPP/1 frames;
- neither profile adds an endpoint beside `POST /chat`;
- neither profile can weaken the immutable Grail rule;
- a profile conflict with `SPEC.md` is refused in favor of `SPEC.md`.

## Prove the profiles

```bash
python3 operations_conformance.py
```

The suite executes positive and negative vectors for exact-candidate promotion,
kernel drift, skipped stages, failed evidence, serving mutation, stale health,
cell isolation, progressive exposure, and exact rollback.

Validate the reusable examples directly:

```bash
python3 rapp_cicd.py release protocols/examples/release.json \
  --grail-binding protocols/examples/grail-binding.json
python3 rapp_cicd.py policy protocols/examples/policy.json
python3 rapp_deploy.py plan protocols/examples/deployment.json \
  --release protocols/examples/release.json
```

These commands report **payload conformance**, not authority. JSON Schemas
provide portable structural validation, and the Python payload validators
enforce cross-document and temporal rules. Promotion and traffic authorization
additionally require the signed-frame entry points, an authenticated RAPP/1
registry/Grail adapter, and signer authorization.

## Adoption rule

An estate adopts a profile by appending a signed RAPP/1 `protocol` registry
entry containing the protocol identifier, this repository, the normative path,
and the exact SHA-256 of that specification. A moving branch name is discovery,
not authority.

The profile index in [`index.json`](index.json) is generated from the committed
specifications and checked in CI. It is a publication aid, not a substitute for
the estate's signed registry.

## External subordinate profiles (registered by pointer)

Profiles that live in their own repository and pin this one, per [](../EXTENDING.md).
Listed here for discovery only; adoption is the estate's signed `protocol` entry.

| Human name | Protocol identifier | Normative specification | SHA-256 | Pinned commit |
|---|---|---|---|---|
| vbrainstem | `vbrainstem/1` | https://github.com/kody-w/vbrainstem/blob/078bb44b9ac28fda94ec4b13afcf88dc2fbcfc63/PROFILE.md | `b11228194d945f3de1f16c47b99ecb700334fbd90bf4cd6fc26e5e8e7a15e9cd` | `078bb44b9ac28fda94ec4b13afcf88dc2fbcfc63` |
