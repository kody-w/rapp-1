# Operational profile examples

These files are deterministic conformance fixtures, not claims about a live
deployment:

- `grail-binding.json` - the trusted-binding shape supplied by a RAPP/1
  registry verifier;
- `release.json` - one immutable RAPP CI/CD release capsule;
- `rollback-release.json` - a separately resolved prior release with the
  previous state schema;
- `policy.json` - the Canary, Nightly, Alpha, Beta, Preprod, Production path;
- `deployment.json` - a planetary RAPP Deploy plan with isolated cells,
  progressive exposure, state recovery, data-policy pins, and extensible health
  objectives.

Their source and Grail identifiers intentionally match the 2026-08-30 pristine
RAPP release-train observation. The artifact, model, policy, backup, and prior
release digests are fixture values. They must be replaced with measured values
before use.

Run:

```bash
python3 rapp_cicd.py release protocols/examples/release.json \
  --grail-binding protocols/examples/grail-binding.json
python3 rapp_cicd.py policy protocols/examples/policy.json
python3 rapp_deploy.py plan protocols/examples/deployment.json \
  --release protocols/examples/release.json
```

The returned `payload_hash` is the RAPP particle address used by later
evidence and decisions.
