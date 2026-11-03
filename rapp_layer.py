#!/usr/bin/env python3
"""Stdlib reference for the device-local RAPP Layer shape-chain profile."""

from __future__ import annotations

import copy
import re
import warnings
from pathlib import Path
from typing import Optional, Sequence

import rapp as R
from rapp_profile import canonical_object, exact_keys, hex64, particle_hash, require

PROFILE = "rapp-layer/1"
SPEC_PATH = "protocols/rapp-layer/1/SPEC.md"
SCHEMA = "brainstem-shape/1"
KIND_SCHEMAS = {
    "shape.genesis": SCHEMA,
    "shape.tile": "shape.tile",
    "shape.gate": "shape.gate",
}
# The recorded historical identity and the supplied current source snapshot
# implement the same transitions on the published vectors, not identical bytes.
RECORDED_LENS_SHA256 = "91279ca0cc6f7bab461f96f8123046d3952e292d9cc7611c409d2d0d325a3a22"
SOURCE_LENS_SHA256 = "e404727c61a9d3e2afeeb4967a7283ecdcacc8ece36d5f23cb15a48b10ac8160"
SUPPORTED_LENSES = frozenset({RECORDED_LENS_SHA256, SOURCE_LENS_SHA256})
POINTS = ("provider", "auth", "storage", "agents", "transport", "kernel")
MAX_PARTS = 64
WARN_FRAMES = 50_000
PART_KEYS = {"id", "kind", "point", "file", "sha256", "locator"}
OBJECT_KEYS = {"schema", "grail", "safe_mode", "parts"}
TILE_KEYS = {"object", "derived_from", "lens", "params", "params_hash",
             "slush_in", "caller", "lease"}
GATE_KEYS = {"tile", "gate", "passed", "evidence"}
PART_ID = re.compile(r"@[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9_]+(?:[-.][a-z0-9_]+)*")
FILENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.py")


def validate_part(part: dict) -> dict:
    canonical_object(part, "part")
    exact_keys(part, PART_KEYS, "part")
    require(isinstance(part["id"], str) and bool(PART_ID.fullmatch(part["id"])),
            "part.id: expected publisher-scoped @publisher/name")
    require(part["kind"] in ("layer", "kernel"), "part.kind: unavailable kind")
    require(part["point"] in POINTS, "part.point: unknown extension point")
    require((part["kind"] == "kernel") == (part["point"] == "kernel"),
            "part: only a kernel occupies the kernel point")
    require(isinstance(part["file"], str) and bool(FILENAME.fullmatch(part["file"])),
            "part.file: expected one Python filename")
    hex64(part["sha256"], "part.sha256")
    require(isinstance(part["locator"], str) and part["locator"].startswith("https://"),
            "part.locator: expected https locator")
    return copy.deepcopy(part)


def _parts(parts: object) -> list:
    require(isinstance(parts, list), "shape.parts: expected array")
    require(len(parts) <= MAX_PARTS, "shape.parts: at most 64 parts")
    checked = [validate_part(part) for part in parts]
    for key in ("id", "point", "file"):
        require(len({part[key] for part in checked}) == len(checked),
                f"shape.parts: duplicate {key}")
    return checked


def validate_object(obj: dict) -> dict:
    """Return an independent, byte-equivalent shape; refuse, never repair."""
    canonical_object(obj, "shape")
    exact_keys(obj, OBJECT_KEYS, "shape")
    require(obj["schema"] == SCHEMA, "shape.schema: wrong protocol")
    grail = exact_keys(obj["grail"], {"sha256", "bytes"}, "shape.grail")
    hex64(grail["sha256"], "shape.grail.sha256")
    require(type(grail["bytes"]) is int and grail["bytes"] > 0,
            "shape.grail.bytes: expected positive integer")
    require(isinstance(obj["safe_mode"], bool), "shape.safe_mode: expected boolean")
    _parts(obj["parts"])
    return copy.deepcopy(obj)


def _params(params: dict) -> str:
    canonical_object(params, "params")
    action = params.get("action")
    require(action in ("add", "remove", "safe_mode", "set"),
            "params.action: expected add, remove, safe_mode, or set")
    if action == "add":
        validate_part(params.get("part"))
    elif action == "remove":
        require(isinstance(params.get("id"), str) and bool(PART_ID.fullmatch(params["id"])),
                "remove.id: expected publisher-scoped part id")
    elif action == "safe_mode":
        require(isinstance(params.get("on"), bool), "safe_mode: expected on boolean")
    else:
        _parts(params.get("parts"))
        require("safe_mode" not in params or isinstance(params["safe_mode"], bool),
                "set.safe_mode: expected boolean")
    return action


def perform(obj: dict, params: dict) -> dict:
    """Pure reference transitions; extra parameter data is retained in tiles."""
    current = validate_object(obj)
    action = _params(params)
    if action == "add":
        part = validate_part(params.get("part"))
        parts = [p for p in current["parts"] if p["id"] != part["id"]] + [part]
    elif action == "remove":
        identifier = params.get("id")
        require(identifier in {p["id"] for p in current["parts"]},
                "remove: no such part in the authorised shape")
        parts = [p for p in current["parts"] if p["id"] != identifier]
    elif action == "safe_mode":
        require(isinstance(params.get("on"), bool), "safe_mode: expected on boolean")
        return dict(current, safe_mode=params["on"])
    elif action == "set":
        parts = params.get("parts")
        safe_mode = params.get("safe_mode", current["safe_mode"])
        require(isinstance(safe_mode, bool), "set.safe_mode: expected boolean")
        return dict(current, parts=_parts(parts), safe_mode=safe_mode)
    return dict(current, parts=_parts(parts))


def validate_tile(payload: dict, base: Optional[dict] = None, *,
                  supported_lenses=SUPPORTED_LENSES) -> str:
    canonical_object(payload, "tile")
    exact_keys(payload, TILE_KEYS, "tile")
    validate_object(payload["object"])
    hex64(payload["derived_from"], "tile.derived_from")
    lens = exact_keys(payload["lens"], {"name", "sha256"}, "tile.lens")
    require(lens["name"] == "shape_lens", "tile.lens.name: unknown lens")
    hex64(lens["sha256"], "tile.lens.sha256")
    require(lens["sha256"] in supported_lenses, "tile.lens: unsupported source pin")
    _params(payload["params"])
    require(payload["params_hash"] == particle_hash(payload["params"]),
            "tile.params_hash: particle mismatch")
    require(payload["slush_in"] is None, "tile.slush_in: this lens has no carried state")
    require(payload["lease"] is None, "tile.lease: device-local stream is unleased")
    caller = exact_keys(payload["caller"], {"kind", "name"}, "tile.caller")
    require(caller["kind"] in ("person", "process"), "tile.caller.kind: unsupported caller")
    require(isinstance(caller["name"], str) and bool(caller["name"]),
            "tile.caller.name: expected nonempty string")
    if base is not None:
        expected = perform(base, payload["params"])
        require(R.canonical(expected) == R.canonical(payload["object"]),
                "tile: object does not replay")
    return particle_hash(payload)


def validate_gate(payload: dict) -> str:
    canonical_object(payload, "gate")
    exact_keys(payload, GATE_KEYS, "gate")
    hex64(payload["tile"], "gate.tile")
    require(payload["gate"] in ("lab", "live"), "gate.gate: expected lab or live")
    require(isinstance(payload["passed"], bool), "gate.passed: expected boolean")
    canonical_object(payload["evidence"], "gate.evidence")
    return particle_hash(payload)


class ShapeChain:
    """Verified chain and its distinct present and authorised projections."""

    def __init__(self, frames: Sequence[dict], *, supported_lenses=SUPPORTED_LENSES):
        require(bool(frames), "chain: genesis is required")
        self.frames = copy.deepcopy(list(frames))
        succession = None
        if any(isinstance(frame, dict)
               and isinstance(frame.get("kind"), str)
               and frame["kind"].startswith("succession.") for frame in self.frames):
            from rapp_succession import SuccessionChain

            succession = SuccessionChain(self.frames)
        tiles = {}
        head = None
        authorised_frame = None
        for position, frame in enumerate(self.frames):
            canonical_object(frame, f"frame {position}")
            ok, step, why = R.verify_frame(frame, head=head,
                                          stream_id_of_record=self.frames[0].get("stream_id"),
                                          signature_verifier=(succession.verify_signature
                                                              if succession else None))
            require(ok, f"frame {position}: RAPP refusal at step {step}: {why}")
            kind, payload = frame["kind"], frame["payload"]
            if position == 0:
                require(kind == "shape.genesis", "chain: first frame must be shape.genesis")
                genesis = validate_object(payload)
                require(not genesis["parts"] and not genesis["safe_mode"],
                        "genesis: plain Grail with safe_mode false required")
                authorised_frame = frame
            elif kind == "shape.tile":
                canonical_object(payload, f"tile {position}")
                require(payload.get("derived_from") == authorised_frame["frame_hash"],
                        f"tile {position}: must derive from authorised tile or genesis; failed tiles are dead ends")
                base = (authorised_frame["payload"] if authorised_frame["kind"] == "shape.genesis"
                        else authorised_frame["payload"]["object"])
                validate_tile(payload, base, supported_lenses=supported_lenses)
                tiles[frame["frame_hash"]] = frame
            elif kind == "shape.gate":
                validate_gate(payload)
                require(payload["tile"] in tiles, f"gate {position}: must name an earlier tile")
                if payload["passed"]:
                    authorised_frame = tiles[payload["tile"]]
            elif succession is not None and kind.startswith("succession."):
                pass
            else:
                raise ValueError(f"frame {position}: unexpected kind {kind!r}")
            head = frame
        self._authorised_frame = authorised_frame
        if len(self.frames) > WARN_FRAMES:
            warnings.warn("chain exceeds 50 000 frames; consider an owner-authorised checkpoint",
                          RuntimeWarning, stacklevel=2)

    @property
    def head(self) -> dict:
        return copy.deepcopy(self.frames[-1])

    @property
    def stream_id(self) -> str:
        return self.frames[0]["stream_id"]

    def present(self) -> dict:
        for frame in reversed(self.frames):
            if frame["kind"] == "shape.tile":
                return copy.deepcopy(frame["payload"]["object"])
        return copy.deepcopy(self.frames[0]["payload"])

    def authorised(self) -> tuple:
        frame = self._authorised_frame
        if frame["kind"] == "shape.genesis":
            return copy.deepcopy(frame["payload"]), None
        return copy.deepcopy(frame["payload"]["object"]), copy.deepcopy(frame)

    def live_failures_since_pass(self) -> int:
        failures = 0
        for frame in reversed(self.frames):
            if frame["kind"] == "shape.gate":
                if frame["payload"]["passed"]:
                    break
                failures += frame["payload"]["gate"] == "live"
        return failures

    def flap_fallback(self) -> dict:
        """Previous distinct passing tile, else genesis; no chain mutation."""
        _, current = self.authorised()
        if current is None or self.live_failures_since_pass() < 2:
            return self.authorised()[0]
        tiles = {f["frame_hash"]: f for f in self.frames if f["kind"] == "shape.tile"}
        for frame in reversed(self.frames):
            if (frame["kind"] == "shape.gate" and frame["payload"]["passed"]
                    and frame["payload"]["tile"] != current["frame_hash"]):
                return copy.deepcopy(tiles[frame["payload"]["tile"]]["payload"]["object"])
        return copy.deepcopy(self.frames[0]["payload"])


def load_chain(path: Path) -> ShapeChain:
    """Accept JSONL device streams or the committed JSON frame-array fixture."""
    raw = Path(path).read_bytes()
    if raw.lstrip().startswith(b"["):
        frames = R._strict_json(raw)
        require(isinstance(frames, list), "chain fixture: expected frame array")
    else:
        frames = [R._strict_json(line) for line in raw.splitlines() if line.strip()]
    return ShapeChain(frames)
