"""04 — Typed addresses. Keep the RAPP space beside every digest.

The same value has a different address in each domain. A store keyed only by
64-hex digests discards that type information and invites address-space
confusion. Run: python3 examples/04_typed_addresses.py
"""
from dataclasses import dataclass
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rapp as R


SPACES = {
    "rapp/1:particle",
    "rapp/1:wave",
    "rapp/1:rappid",
    "rapp/1:egg",
    "rapp/1:egg-manifest",
    "rapp/1:seal",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Address:
    space: str
    digest: str

    def __post_init__(self):
        if self.space not in SPACES:
            raise ValueError(f"unknown RAPP address space: {self.space}")
        if not HEX64.fullmatch(self.digest):
            raise ValueError("digest must be 64 lowercase hex")


class AddressStore:
    def __init__(self):
        self._objects = {}

    def put(self, address, value):
        self._objects[address] = value

    def get(self, address):
        return self._objects[address]


value = {"message": "same value, different role"}
particle = Address("rapp/1:particle", R.H("rapp/1:particle", value))
wave = Address("rapp/1:wave", R.H("rapp/1:wave", value))

assert particle.digest != wave.digest

store = AddressStore()
store.put(particle, value)
assert store.get(particle) == value

wrong_role = Address("rapp/1:wave", particle.digest)
try:
    store.get(wrong_role)
except KeyError:
    print("cross-space lookup refused: the space is part of the key")
else:
    raise AssertionError("store accepted a particle digest as a wave")

print("particle:", particle)
print("wave:    ", wave)
