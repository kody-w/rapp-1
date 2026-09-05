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

Profiles that live in their own repository and pin this one, per [`EXTENDING.md`](../EXTENDING.md).
Listed here for discovery only; adoption is the estate's signed `protocol` entry.

| Human name | Protocol identifier | Normative specification | SHA-256 | Pinned commit |
|---|---|---|---|---|
| vbrainstem | `vbrainstem/1` (rev-2) | https://github.com/kody-w/vbrainstem/blob/511b79f6d2d930bcad62eb7079b3f1c38986b81f/PROFILE.md | `077f1b26ad83a94d8d44d70d377431237b4ab228692bb0e0a9cc389d042da08f` | `511b79f6d2d930bcad62eb7079b3f1c38986b81f` |

vbrainstem/1 rev-2 (2026-09-05): the host is a virtual machine. Any AI given a person's file runs the pinned Brainstem kernel, vendored in the skill with per-file SHA-256, as a Python virtual machine within its own reasoning, is also the model that kernel calls, keeps the machine's whole storage in the file, offers the kernel's factory tools from the first task, measures drift by running the code, and can plant a real kernel on a device with every memory mapped one to one. The skill any AI loads to do this: https://raw.githubusercontent.com/kody-w/vbrainstem/main/virtual-brainstem/SKILL.md
