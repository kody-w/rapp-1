"""Run an unchanged Grail checkout WITH grail layers applied, against the suite's fake model.

Same wiring as run_grail.py; the only addition is grail_layers.apply_layers() before the kernel is
imported, so a layer is tested through the exact code path the supervisor uses. A layer must keep the
/chat wire identical (rapp/1 §11.1.6): any scenario difference is the layer's bug, not a new contract.
  usage: run_layered.py <kernel_dir> <port> <fake_port> <supervisor grail_layers.py> <layers_dir> <name,name>
"""

import hashlib
import importlib.util
import os
import sys


kernel_dir, port, fake_port, supervisor, layers_dir, names = sys.argv[1:7]
kernel_path = os.path.join(kernel_dir, "brainstem.py")
source = open(kernel_path, "rb").read()
blob = hashlib.sha1(b"blob %d\0" % len(source) + source).hexdigest()
expected = os.environ.get("GRAIL_BLOB")
if expected and blob != expected:
    sys.exit(
        f"grail brainstem.py blob {blob} != pinned {expected}; "
        "refusing to test a changed kernel"
    )

os.environ.update(
    PORT=port,
    GITHUB_TOKEN="ghu_fake",
    AGENTS_PATH=os.path.join(kernel_dir, "agents"),
)
spec = importlib.util.spec_from_file_location("grail_layers", supervisor)
grail_layers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grail_layers)
grail_sha, applied, skipped = grail_layers.apply_layers(
    source, layers_dir, [n for n in names.split(",") if n], report_dir=os.getcwd()
)
wanted = [n for n in names.split(",") if n]
if applied != wanted:
    sys.exit(f"layers not applied as requested: wanted {wanted}, applied {applied}, skipped {skipped}")

sys.path.insert(0, kernel_dir)
os.chdir(kernel_dir)

import brainstem  # noqa: E402


brainstem.COPILOT_TOKEN_URL = f"http://127.0.0.1:{fake_port}/token"
brainstem.MODEL = os.environ.get("GRAIL_MODEL", "gpt-4o")
brainstem.VOICE_MODE = False
brainstem.app.run(
    host="127.0.0.1",
    port=int(port),
    debug=False,
    threaded=True,
    use_reloader=False,
)
