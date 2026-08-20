---
layout: book
title: Selected Exercise Solutions
book_label: Appendix C
book_progress: 100
description: Selected worked solutions for The RAPP Programming Language
---

[← Appendix B: Glossary and Failure Atlas](B-glossary-and-failure-atlas.md) ·
[Book contents](README.md)

# Appendix C — Selected Exercise Solutions

These are selected solutions, not answer keys for every exercise. Try the exercise first. A good
RAPP solution is not merely code that prints the expected digest; it makes the addressed bytes,
refusal boundary, and authority assumptions visible.

## C.1 Exercise 1-2 — The Failure Atlas

Start from a fresh deep copy for every mutation. Otherwise an early payload edit may cause step 2
to hide the step 3 failure you intended to observe.

```python
cases = [
    ("missing-key", remove(frame, "prev_wave"), "1"),
    ("replay", frame, "1a", other_stream),
    ("payload", replace_payload(frame), "2"),
    ("envelope", replace_utc(frame), "3"),
    ("genesis", build_seq_one_without_head(), "4"),
    ("wire", build_body_with_prev_wave(), "5"),
    ("signature", build_unsigned_swarm(), "6"),
]
```

The runnable solution is [`examples/05_failure_atlas.py`](../examples/05_failure_atlas.py). The
important result is not seven error strings. It is proof that verification order is stable and
that each layer can be diagnosed independently.

## C.2 Exercise 2-2 — Canonical Byte Fixtures

Store the bytes as hex so the fixture cannot be changed by an editor’s encoding or newline rules:

```python
values = [
    {},
    {"b": 1, "a": [True, None, "café"]},
    {"nested": {"z": 0, "a": ""}},
]
for value in values:
    text = R.canonical(value)
    print(text)
    print(text.encode("utf-8").hex())
```

For the second value, construction order must disappear, array order must remain, and `é` must
appear as UTF-8 bytes `c3a9`, not as an ASCII `\u` escape. A cross-language fixture stores both the
value and the expected hex.

## C.3 Exercise 3-2 — Typed Addresses

Use an immutable pair:

```python
@dataclass(frozen=True)
class Address:
    space: str
    digest: str

class Store:
    def __init__(self):
        self.objects = {}

    def put(self, address, value):
        self.objects[address] = value

    def get(self, address):
        return self.objects[address]
```

Do not add `get_by_digest`. That convenience method would erase the property the type was created
to preserve. The complete runnable solution is
[`examples/04_typed_addresses.py`](../examples/04_typed_addresses.py).

## C.4 Exercise 4-2 — Name-Hash Audit

For each stored rappid:

1. validate and split the canonical grammar;
2. compute `sha256(f"{owner}/{slug}")`;
3. compare it with the full stored tail; and
4. report, never rewrite.

```python
match = R._RAPPID.fullmatch(rid)
owner, slug, tail = match.groups()
forbidden = hashlib.sha256(f"{owner}/{slug}".encode()).hexdigest()
if tail == forbidden:
    findings.append((path, "name-hash-mint"))
```

A non-matching tail is not proof that the mint was lawful; keyed identity still needs SPKI
binding, and keyless identity needs durable mint-once storage. This audit detects one known
forbidden derivation.

## C.5 Exercise 5-3 — Fork Detection

Group accepted candidates by `(stream_id, seq, prev)`. More than one distinct `frame_hash` in a
group is a fork:

```python
branches = {}
for frame in candidates:
    key = (frame["stream_id"], frame["seq"], frame["prev"])
    branches.setdefault(key, set()).add(frame["frame_hash"])

forks = {key: waves for key, waves in branches.items() if len(waves) > 1}
```

Do not pick the lexicographically smaller hash as current. Hash ordering is a deterministic merge
order across streams, not authority to resolve two branches of one stream. Surface the fork and
require owner-authorized convergence.

## C.6 Exercise 6-2 — Idempotent Chat Results

The stored value is the complete original result, not only a “seen” bit:

```python
key = (session_id, idempotency_key) if session_id else (None, idempotency_key)
if key in results:
    return results[key]

response = execute_once(request)
results[key] = response
return response
```

Session creation must store the generated `session_id` in that response. If a retry created a new
session before noticing the key, the operation was not idempotent.

Production storage needs an atomic insert-if-absent. Two workers racing on an in-memory
check-then-set can still execute twice.

## C.7 Exercise 7-2 — Safe Egg Paths

Validate names as data before extraction:

```python
def valid_path(path):
    if path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts)
```

Then require:

```text
set(archive entries) == set(contents paths) + {"manifest.json"}
```

Both checks are necessary. Safe-looking manifest paths do not help if the ZIP carries an unlisted
`../../escape`, and an exact entry set does not help if both manifest and ZIP agree on an unsafe
path.

## C.8 Exercise 8-3 — Construct the Signing Input

Given protected header `h` and frame `f`:

```python
header_octets = canonical(h).encode("utf-8")
payload_octets = canonical({k: v for k, v in f.items() if k != "sig"}).encode()
signing_input = base64url(header_octets) + b"." + payload_octets
```

The detached compact value stores:

```text
BASE64URL(header) .. BASE64URL(signature)
```

Do not base64url-encode the payload in the signing input: `b64:false` is the reason the exact
canonical frame bytes remain external and visible. Do not remove `frame_hash`; only `sig` is
removed for the signature input.

## C.9 Exercise 9-2 — Monotonic Registry State

Persist the highest accepted sequence beside the verified registry digest:

```python
def accept_registry(candidate, remembered):
    verify_owner_signature(candidate)
    if candidate["registry_seq"] < remembered.seq:
        raise Rollback
    if candidate["registry_seq"] == remembered.seq:
        if digest(candidate) != remembered.digest:
            raise Equivocation
        return remembered
    enforce_freshness(candidate)
    return Remembered(candidate["registry_seq"], digest(candidate))
```

Equal sequence with different bytes is not a newer registry; it is equivocation. A higher
sequence with an old timestamp may still violate the local freshness policy.

## C.10 Exercise 10-2 — Classify Synthetic Drift

Classify at the first normative boundary that fails:

| Mutation | Classification |
|---|---|
| reorder object keys before hashing | no drift if JCS output is unchanged |
| replace `payload_hash` with bare SHA-256 | address-space drift |
| rename `utc` to `ts` | frame shape, step 1 |
| replay a valid genesis under another path | stream binding, step 1a |
| change payload without changing hashes | particle integrity, step 2 |
| serve an older verified registry | registry rollback/freshness |

The first row matters: source-level difference is not protocol drift when canonical bytes are
identical. The others change the protocol claim or the authority state.

## C.11 Exercise 11-2 — Transactional Append

An in-memory compare-and-swap store can make the race explicit:

```python
class Heads:
    def __init__(self, genesis):
        self.current = genesis

    def compare_and_swap(self, expected_hash, replacement):
        if self.current["frame_hash"] != expected_hash:
            return False
        self.current = replacement
        return True
```

Each writer reads the same head and builds a different valid child. Both children may verify
against the observed head, and both may be stored by wave address. Only one call can replace the
remembered head:

```python
observed = heads.current
a = build_child(observed, {"writer": "a"})
b = build_child(observed, {"writer": "b"})

assert heads.compare_and_swap(observed["frame_hash"], a)
assert not heads.compare_and_swap(observed["frame_hash"], b)
```

The losing frame is an unreferenced immutable object, not a silently accepted second history. A
real store performs this comparison atomically and couples it to the idempotency result.

---

[← Appendix B: Glossary and Failure Atlas](B-glossary-and-failure-atlas.md) ·
[Book contents](README.md)
