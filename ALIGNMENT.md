# Alignment and freshness

An accepted protocol checkpoint, a newer document, a valid artifact, and a
working consumer are different facts. These commands preserve that distinction.
Reports are dated observations, not permanent certificates or owner ratification.

## Canonical protocol views

```sh
python3 alignment_check.py
python3 alignment_check.py --live --output alignment-observation.json
```

The local check reuses the pinned bootstrap and chain resolver. It requires the
chain, immutable frame objects, index, beacon, materialized specification,
foundation/philosophy/constitution mirrors, operational profiles, and named
current front-door labels to agree. A missing current label fails rather than
passing an empty search. Historical revision mentions are not current labels.

Without `--live`, the result explicitly says freshness was not observed. With
`--live`, the canonical-main Atom feed supplies discovery; the beacon is then
read at the observed full commit. A stale checkout or different beacon fails,
even when its human revision label has not changed. An uncommitted candidate on
the current base remains a candidate, not an accepted publication. Discovery
and public HTTPS do not independently authenticate owner ratification.

The live mode needs Git and public network access, not a GitHub token. Transport
errors, malformed responses, and missing observations fail closed. Repeat the
observation before promotion and when the canonical feed changes.

## Local artifact linting

```sh
python3 rapp_check.py . --json
```

The linter reads original JSON bytes through the shared strict parser. It
discovers named/hash JSON frames, JSONL streams, identities, and eggs within
its stated limits. Counts distinguish occurrences, unique frame values, and
duplicate immutable copies; a repeated copy is not another sequence step.
Cross-stream splices, incompatible forks, malformed inputs, and missing
history cannot become a zero-evidence green result.

`COMPLIANT` is explicitly local structural/hash scope, not authenticated
Consumer conformance. The report lists unmeasured registry, signature,
stream-of-record, and persisted-head requirements. `DRIFT` or `INCOMPLETE`
exits nonzero; `NO_ARTIFACTS` and an unusable root exit 2.
Deduplication keeps the sequence field's lexical/type boundary: `seq: 0.0` or
`seq: 0e0` cannot borrow the result of a valid `seq: 0` copy, while equivalent
legal numeric payload spellings remain equivalent.

Registered kind-family bindings remain available for historical verification
after retirement. `Registry.family` and `check_frame_binding` preserve that
mapping; `Registry.producer_family` supplies the separate live-only
producer/discovery policy. Retirement does not erase old frame validity, and
none of these structural helpers authenticates a registry by itself.

The SDK's `check` action observes only a public `main/rappid.json`. Its success
is identity grammar/schema evidence, never a repository-wide verdict. Transport
failure, missing identity evidence, malformed JSON, and duplicate members do
not become `CLEAN`. The hatch aggregator likewise requires nonempty, counted,
locally compliant repository observations; missing or incomplete child results
cannot make its summary green.

## Live reference estate

```sh
python3 realcheck.py --output estate-observation.json
python3 realcheck.py --estate-root LOCAL-CACHES --no-sync --repo example --json
```

The default scope is exactly `twin`, `rapp-body`, `rapp-commons`, `rapp-map`, and
`RAR` under `kody-w`. Repeat `--repo` to select a different explicit scope;
`--owner` selects its public GitHub owner. Synchronization fetches the public
HEAD without resetting or pulling a working tree. Every inspected byte comes
from its recorded commit's Git objects. Dirty files, untracked files, symlinks,
and a nested directory pretending to be a repository cannot supply evidence.
Git replacement objects are disabled. Partial/promisor caches are refused so
an offline observation cannot lazily fetch missing objects.

The observation covers `rappid.json` records and numbered `frames/*.json`
directories, including nested chains. It does not claim coverage of arbitrary
embedded HTML frames, eggs, runtime behavior, or every repository under an
owner. The frozen-capture inventory is the wider discovery surface.

Exit 0 means the measured in-scope artifacts conform. Exit 1 means observed
drift; exit 2 means an incomplete observation. Zero artifacts is incomplete.
Old material is preserved and reported, not rewritten to make a check green.
No captured application is executed. `--no-sync` is explicitly a local-commit
observation and cannot claim live freshness.

## Frozen consumer inventory

`estate_inventory.py` reads the complete restored capture and its explicit
repository scope. Its matrix accounts for selected repositories and tracked
entries, including empty repositories and unavailable dependencies. Static
producer/reader references, revision pins, standalone artifact checks, chain
coverage, fixture/archive locations, and unmeasured areas remain separate
evidence categories. A version string is not a compatibility test, and a
fixture-looking path does not prove a refused artifact is safe.

The capture adapter currently requires POSIX no-follow, directory-relative
file access. A host without those primitives is explicitly refused rather
than silently using a weaker traversal path. Content-inspection limits and
opaque archives are reported separately from complete source-byte hashing.

Use its `--help` output for input, resource, and report-only options. Do not
reinterpret report-only collection as ecosystem acceptance. Source and
dependency bytes, raw paths, original identities, and immutable ancestry stay
unchanged by observation.

## Lawful updates

RAPP/1 rev-15 freezes its verification forms. Implementations, documentation,
vocabulary, registries, and subordinate profiles can improve compatibly.
Changing a frozen form requires a separate `rapp/2` token; existing `rapp/1`
artifacts keep their meaning. An old revision label or an unmerged proposal is
not authority to rewrite historical bytes.

Preserve a captured parent before proposing source changes. Record exact
allowed paths, before/after identities, regression evidence, and the base
checkpoint in a separate mutation proposal. A passed local gate does not
publish that proposal, ratify a revision, or activate an organism.
