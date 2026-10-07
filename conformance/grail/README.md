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
