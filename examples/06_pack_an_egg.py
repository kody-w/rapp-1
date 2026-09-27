"""06 — Pack an egg. Prove deterministic bytes, identity, and path refusal.

Run: python3 examples/06_pack_an_egg.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rapp as R


RID = "rappid:@reader/portable-agent:" + "a" * 64
UTC = "2026-08-20T12:00:00.000Z"
FILES = {
    "rappid.json": ('{"rappid":"' + RID + '"}').encode(),
    "soul.md": b"# A small, portable organism\n",
}

first = R.pack_egg("organism", RID, UTC, files=FILES)
second = R.pack_egg("organism", RID, UTC, files=FILES)
assert first == second

ok, step, why = R.verify_egg(first)
assert ok, (step, why)
manifest, unpacked = R.read_egg(first)
address = R.egg_address(manifest)

changed = R.pack_egg(
    "organism",
    RID,
    UTC,
    files={**FILES, "soul.md": b"# A changed organism\n"},
)
changed_manifest, _ = R.read_egg(changed)
assert R.egg_address(changed_manifest) != address

unsafe_files = {**FILES, "../escape": b"must never be extracted"}
try:
    R.pack_egg("organism", RID, UTC, files=unsafe_files)
except ValueError as exc:
    producer_refusal = str(exc)
else:
    raise AssertionError("a §9.3 producer must refuse a ../ path")

# What a hostile packer could still write by hand: the consumer refuses it too.
hostile_manifest = {**manifest, "contents": R._egg_contents(unsafe_files)}
unsafe = R._zip_pack(
    [("manifest.json", R.canonical(hostile_manifest).encode("utf-8"))]
    + [(c["path"], unsafe_files[c["path"]]) for c in hostile_manifest["contents"]]
)
ok, step, why = R.verify_egg(unsafe)
assert not ok and step == "§9.1", (ok, step, why)

print("deterministic bytes:", len(first))
print("egg address:        ", address)
print("files:              ", sorted(unpacked))
print("producer refused:   ", producer_refusal)
print("unsafe path refused:", why)
