# Grail conformance

This is the one shared test of the Grail `/chat` wire. The oracle is the
`kody-w/rapp-installer` kernel pinned in `kernel.json`, using the estate pin
keys `kernel`, `sha`, `version`, `path`, `kernel_blob`, and `pinned`. Every run
writes the ignored `report.json`.

## Three uses

**Version-bump gate:** compare a proposed Grail checkout with the pinned release.

```bash
GRAIL_DIR=/path/to/pinned/rapp_brainstem \
python3 conformance/grail/run.py --candidate grail:/path/to/candidate/rapp_brainstem
```

**Port check:** compare an implementation in-process.

```bash
GRAIL_DIR=/path/to/pinned/rapp_brainstem \
python3 conformance/grail/run.py --candidate module:my_adapter:create_candidate
```

`create_candidate(context)` receives fake-model URLs, the model name, fixture
agents, and a work directory. It returns a callable
`call(method, path, body)`. That callable returns `(status, body)` or an
HTTP-response-like object with `status_code` and `get_body()`.

**Any language, full suite:** start your own implementation from a shell command. The
suite passes it `PORT` to listen on, `FAKE_TOKEN_URL` and `FAKE_MODEL_URL` for the
deterministic model, `AGENTS_PATH` holding the fixture agents, and `GITHUB_MODEL`.
Answer `/health` on that port and all 25 scenarios run. Give the command as an **absolute path**: the
suite starts it from a temporary working directory. `expected.json` shows the pinned oracle's exact answer
for every scenario, so you never have to learn wording from a DIFF (`make_expected.py --check` keeps it current).

```bash
GRAIL_DIR=/path/to/pinned/rapp_brainstem \
python3 conformance/grail/run.py --candidate 'cmd:./my_brainstem serve'
```

**Hub join probe:** compare a live node without making model calls. This runs the
14 health, validation, version, and not-found scenarios.

```bash
GRAIL_DIR=/path/to/pinned/rapp_brainstem \
python3 conformance/grail/run.py --candidate http:https://node.example
```

HTTP errors always compare status and member names. Add `--same-version` to
compare the exact human-readable `error` text too. For `/health`, the live
probe compares only the HTTP status, the `status` value, and that `agents` is a
list of strings; a node's own agent names are not expected to match the oracle.

Use `--allow file.json` for declared bug fixes:

```json
[{"scenario": "blank input", "reason": "Improved error wording in 0.6.17"}]
```

An undeclared difference fails. The scenario unit check is:

```bash
python3 -m unittest discover -s conformance/grail -p 'test_*.py'
```

## Does the suite have teeth?

A suite that nothing can fail proves nothing. Two scripts answer that, and
their numbers are published rather than claimed.

**Mutants** (`mutants.py`) break a copy of the pinned kernel on purpose, one
exact edit at a time, and run the 25 scenarios against the break. Observed
2026-10-17 on the pinned kernel: **13 of 16 mutants caught**. The three
survivors are behavior the suite does not pin, listed on purpose:

- `model-502-text`: the wording when the model itself fails (the fake model never fails)
- `health-dir`: `/health` fields beyond `status` and `agents`
- `soul-ignored`: whether `soul.md` reaches the model (the fake model ignores system text)

**Coverage** (`coverage_run.py`) runs the kernel under branch coverage during
the suite. Observed 2026-10-17: **618 of 2029 statements, 139 of 706 branches**
of `brainstem.py`; **3 of 27 routes called** (`/chat`, `/health`, `/version`).
Untouched: `/chat/stream`, sign-in, `/models`, voice, `/agents` import, export and
delete, diagnostics. Those routes are outside this contract until a scenario
reaches them.

**Vectors** (`export_vectors.py`, `vectors.json`) are the 25 scenarios as plain
JSON in lesson order, so an implementer in any language can read the contract
without Python. CI fails if the file is stale.

Both measurements run in CI on every push (`.github/workflows/grail.yml`). Run
them yourself:

```bash
GRAIL_DIR=/path/to/pinned/rapp_brainstem python3 conformance/grail/mutants.py
GRAIL_DIR=/path/to/pinned/rapp_brainstem python3 conformance/grail/coverage_run.py
python3 conformance/grail/export_vectors.py --check
```

Known conformant implementations (each run yourself, numbers as observed):

| Implementation | Date | Result | Where |
|---|---|---|---|
| Pinned Grail, Python (oracle vs itself) | 2026-10-17 | 25 of 25 | this suite, macOS |
| `airaptr/star_agent`, Rust (private) | 2026-10-17 | 25 of 25 | its `conformance/grail_adapter.py` |
| [`kody-w/brainstem-go`](https://github.com/kody-w/brainstem-go), Go, built by an AI from the vectors alone | 2026-10-17 | 25 of 25 | `cmd:` candidate |
