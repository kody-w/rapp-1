# The rebuild seed

This folder holds exact source bytes for the Brainstem, the RAR catalog builder,
and the layer runtime. It lets you rebuild those pieces without their source
repositories. It is not a copy of every published agent, a package mirror, or a
ready-made operating system.

**The three source trees and `SEED.json` are generated. Never edit them.**
Change the source in its own repository, deliberately update the pins in
`refresh.py`, and regenerate. Work on disposable copies when building or running;
the seed itself should stay unchanged.

## What is pinned

`SEED.json` records each copied file's relative path, source repository, exact
source ref and path, SHA-256, and byte count. The Brainstem uses the
`brainstem-v0.6.16` tag and also checks its resolved commit and required engine
hash. RAR and the layer runtime use full commit hashes captured from main.
The source refs are also held in `refresh.py`; no branch is fetched implicitly.
An independent inventory fingerprint in `refresh.py` pins the complete file
list, provenance, fingerprints, exclusions, and executable-script list.
Removing a file and its manifest entry together is therefore still refused.

The manifest uses the new name **`rapp-seed/1`**. `FOUNDATION.json` is a
single-document pointer, and the existing indexes describe protocol objects;
neither is a per-file source inventory. The seed retains their explicit schema,
repository, pin, path, and SHA-256 approach without claiming either schema.

- `brainstem/`: the tracked `rapp_brainstem/` tree, flattened one level, plus
  the three root installers.
- `rar-builder/`: the requested Python entry points and their transitive local
  imports. `marketplaces.json` is a required static API input; `LAYERS.md` is
  the required input to `tools/sync_layers.py`. No full registry or site is copied.
- `layers/`: the installer, supervisor, pack manager, their local Python helpers,
  the easy-mode skill, and RAR's `stacks/grail-layers/` files.

The manifest lists every exclusion individually. Environment files (even
examples), credential files, credential-pattern matches, caches, dependency
environments, and files over 5,000,000 bytes are not admitted. Refresh refuses
to omit a required runtime or builder file silently. Source code is copied
unchanged, including its upstream documentation and metadata.

## Rebuild offline

Prerequisites: Python 3.11 or newer, a shell, and `curl`. The Brainstem needs
the packages listed in `brainstem/requirements.txt` already installed in your
chosen Python environment, or available as local wheels. Wheels, Python itself,
Git, and model weights are not part of this source seed. The catalog builder
uses only Python's standard library. Git is not needed for this offline build
when `SOURCE_DATE_EPOCH` is set.

Run these commands from the rapp-1 repository root. Do not run the copied
installers or `start.sh` offline: they download dependencies or source files.
The `.env` example is intentionally excluded; direct startup does not need it.

### 1. Verify and make working copies

```sh
python3 seed/refresh.py --check
export WORK="$(mktemp -d)"
export PYTHON="$(command -v python3)"
cp -R seed/brainstem "$WORK/brainstem"
cp -R seed/rar-builder "$WORK/rar"
cp -R seed/layers "$WORK/layers"
mkdir -p "$WORK/home" "$WORK/empty-bin"
```

Use an interpreter with the runtime requirements installed in its environment,
not only in a user-site folder tied to your usual home directory.

### 2. Start the Brainstem without signing in

Choose an unused loopback port. These examples use 17771, not 7071.
The empty command path hides `gh`, and the temporary home keeps your existing
sign-in and installed Brainstem out of the run. `env -i` also clears inherited
tokens and configuration.

```sh
env -i HOME="$WORK/home" PATH="$WORK/empty-bin" \
  PORT=17771 GITHUB_MODEL=gpt-4o BRAINSTEM_LAN_MODE=false \
  PYTHONDONTWRITEBYTECODE=1 \
  "$PYTHON" "$WORK/brainstem/brainstem.py" >"$WORK/plain.log" 2>&1 &
PLAIN_PID=$!
echo "Plain Brainstem PID: $PLAIN_PID"
curl --fail http://127.0.0.1:17771/health
```

Wait for the server to start before the health request. An HTTP 200 response
with `"status":"unauthenticated"` and `"version":"0.6.16"` is expected.
Health and local agents work without sign-in; remote model inference does not
become available just because the server is running.

```sh
kill "$PLAIN_PID"
wait "$PLAIN_PID" || test "$?" -eq 143
```

### 3. Build a catalog from agent files

Put your single-file agents under `$WORK/rar/agents/@publisher/`. Each needs
an embedded `__manifest__`; `template_agent.py` is the starting point. To prove
the build with two sample agents without downloading anything:

```sh
"$PYTHON" - <<'PY'
import os
from pathlib import Path
root = Path(os.environ["WORK"]) / "rar"
agents = root / "agents/@seed"
agents.mkdir(parents=True, exist_ok=True)
template = (root / "template_agent.py").read_text()
for slug, label in (("alpha_agent", "SeedAlpha"), ("beta_agent", "SeedBeta")):
    source = template.replace("@your_username/your_agent_name", "@seed/" + slug)
    source = source.replace("Your Agent Name", label).replace("YourAgentName", label)
    (agents / (slug + ".py")).write_text(source)
PY
(
  cd "$WORK/rar"
  export SOURCE_DATE_EPOCH=0 PYTHONDONTWRITEBYTECODE=1
  "$PYTHON" build_registry.py --registry-only
  "$PYTHON" scripts/build_static_api.py
  "$PYTHON" -c 'import json; print("registry.json agent count:", len(json.load(open("registry.json"))["agents"]))'
)
```

The count should be `2`. The result includes `registry.json`, agent ticket
pages, `manifest.json`, and `api/v1/catalog.json` with the audience and matching
endpoints. A fixed `SOURCE_DATE_EPOCH` makes timestamps independent of Git
history. Use a recorded source timestamp instead of `0` for your own release.

Use `--registry-only`: the bare upstream registry command also launches other
site generators outside this seed's catalog-building scope. The static API's
own `--check` computes a dry run, not a byte-for-byte drift check.

### 4. Apply layers from local, fingerprint-checked files

Stage the pack's default parts in the exact layout the unchanged supervisor
expects. Keep the published locators as provenance; with the pinned files
already present, the supervisor need not fetch them.

```sh
"$PYTHON" - <<'PY'
import hashlib
import json
import os
import shutil
from pathlib import Path
work = Path(os.environ["WORK"])
layers = work / "layers"
stack = layers / "stacks/grail-layers"
pack = json.loads((stack / "pack.json").read_bytes())
keys = ("id", "kind", "point", "file", "sha256", "locator")
parts = []
for entry in pack["install"]["parts"]:
    if entry["id"] not in pack["install"]["seed"]:
        continue
    part = {key: entry[key] for key in keys}
    body = (stack / part["file"]).read_bytes()
    if hashlib.sha256(body).hexdigest() != part["sha256"]:
        raise SystemExit("Part fingerprint mismatch: " + part["id"])
    publisher, name = part["id"][1:].split("/")
    target = layers / "parts" / publisher / name / part["file"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    parts.append(part)
(layers / "parts.json").write_text(json.dumps(parts) + "\n")
for name in ("journal_recall_agent.py", "fragments_agent.py"):
    shutil.copyfile(stack / name, work / "brainstem/agents" / name)
shutil.copyfile(layers / "brainstem_shape_agent.py",
                work / "brainstem/agents/brainstem_shape_agent.py")
PY
env -i HOME="$WORK/home" PATH="$WORK/empty-bin" \
  PORT=17771 GITHUB_MODEL=gpt-4o BRAINSTEM_LAN_MODE=false \
  BRAINSTEM_HOME="$WORK" GRAIL_LAYERS_HOME="$WORK/layers" \
  PYTHONDONTWRITEBYTECODE=1 \
  "$PYTHON" "$WORK/layers/grail_layers.py" \
  --kernel "$WORK/brainstem/brainstem.py" --python "$PYTHON" \
  --port 17771 --lab-port 17772 >"$WORK/supervisor.log" 2>&1 &
SUPERVISOR_PID=$!
echo "Layer supervisor PID: $SUPERVISOR_PID"
curl --fail http://127.0.0.1:17771/health
cat "$WORK/layers/applied.json"
cat "$WORK/layers/last-boot.json"
```

Wait for startup and the boot record before reading them. Expect
`providers_1_1`, `journal_tap`, and `senses_and_pages` in `applied`,
an empty `skipped` object, and `fallback: false`. Health alone is not proof
that layers loaded. Without sign-in the supervisor explicitly skips its
authenticated chat probe; this proves local startup, not remote inference.

```sh
GRAIL_LAYERS_HOME="$WORK/layers" "$PYTHON" "$WORK/layers/grail_layers.py" \
  --kernel "$WORK/brainstem/brainstem.py" --replay
kill "$SUPERVISOR_PID"
wait "$SUPERVISOR_PID"
```

The supervisor stops its own child. Do not kill by process name or stop an
existing service. `packs.py` is also preserved, but its normal catalog commands
use published endpoints; the local staging above is the offline path.

To regenerate layer facts and ticket pages in your working catalog:

```sh
cp -R "$WORK/layers/stacks" "$WORK/rar/stacks"
(
  cd "$WORK/rar"
  "$PYTHON" tools/sync_layers.py --write
  "$PYTHON" tools/sync_layers.py --check
)
```

Keep the generated output you need, then remove only this specific temporary
working directory when finished.

## Verify or regenerate the seed

```sh
python3 seed/refresh.py --check
python3 seed/refresh.py --check --scan
python3 seed/verify_refresh.py
```

`--check` never fetches or writes. It checks every manifest fingerprint and byte
count, the fixed Brainstem hash, safe regular-file paths, prohibited files, and
missing or unlisted files in the three generated trees. It also checks the
independently pinned complete inventory and, on POSIX, executable modes.
`--scan` prints the
credential-pattern scan, without printing matched values. Patterns cover private
keys, GitHub tokens, AWS access keys, service API keys, storage account keys,
and long literal credential assignments. A clean scan is not a mathematical
proof that arbitrary text contains no secret. One exact upstream test marker
for response redaction is reported as a reviewed non-secret fixture; other
matches in that file are still refused. Fingerprints prove consistency
with the committed manifest, not an upstream author's identity or a signature.

Regeneration needs network access and Git:

```sh
python3 seed/refresh.py
python3 seed/refresh.py
git diff -- seed/
```

Refresh fetches the exact recorded refs into temporary clones, verifies their
commits, checks the engine hash, follows local Python imports, copies exact
bytes, prunes stale generated files, and rewrites the manifest deterministically.
Running it again produces no additional changes. It never pushes or modifies
the source repositories. Updating to a newer main commit is a deliberate pin
change, not an automatic branch-following update. After changing source refs,
refresh reports a candidate inventory fingerprint and refuses writes until you
review the source selection and deliberately update `PINNED_INVENTORY_SHA256`.

CI checks the seed on every push and pull request. The weekly job and manual
workflow also reproduce the pinned sources, failing on any tracked or untracked
diff rather than committing generated changes.
