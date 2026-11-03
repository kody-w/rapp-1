"""Device-chain, lens replay, and adversarial vectors for RAPP Layer."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import rapp as R
import rapp_layer as L

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "protocols/examples/layer-lifecycle.json"


class RappLayerTests(unittest.TestCase):
    def setUp(self):
        self.frames = json.loads(FIXTURE.read_text())
        self.obj = copy.deepcopy(self.frames[0]["payload"])
        self.part = copy.deepcopy(self.frames[1]["payload"]["params"]["part"])

    def rebuild(self, frames):
        result = []
        aliases = {}
        for old in frames:
            payload = copy.deepcopy(old["payload"])
            if old["kind"] == "shape.tile":
                payload["derived_from"] = aliases.get(payload["derived_from"], payload["derived_from"])
            elif old["kind"] == "shape.gate":
                payload["tile"] = aliases.get(payload["tile"], payload["tile"])
            frame = R.build_frame(old["kind"], old["stream_id"], len(result), old["utc"],
                                  payload, result[-1]["payload_hash"] if result else None)
            aliases[old["frame_hash"]] = frame["frame_hash"]
            result.append(frame)
        return result

    def append(self, frames, kind, payload, utc=None):
        frames.append(R.build_frame(kind, frames[0]["stream_id"], len(frames),
                                   utc or frames[-1]["utc"], payload, frames[-1]["payload_hash"]))

    def test_real_chain_validates_without_changing_one_frame(self):
        chain = L.ShapeChain(self.frames)
        self.assertEqual(chain.frames, self.frames)
        self.assertEqual(len(chain.frames), 9)
        self.assertEqual(chain.authorised()[1]["seq"], 7)
        self.assertEqual(chain.head["seq"], 8)
        self.assertEqual(chain.present(), chain.authorised()[0])
        self.assertEqual(chain.frames[3]["payload"]["object"]["parts"][-1]["id"], "@kody-w/broken")
        self.assertNotIn("@kody-w/broken", [p["id"] for p in chain.authorised()[0]["parts"]])
        self.assertEqual(chain.stream_id,
                         "rappid:@kody-w/brainstem:883cff22dd5cf1248797f674d861c54658b79f9c07f305410bc668f94714d99d:mac")

    def test_present_is_not_authorised_until_gate_passes(self):
        chain = L.ShapeChain(self.frames[:2])
        self.assertTrue(chain.present()["parts"])
        self.assertEqual(chain.authorised(), (self.obj, None))
        failed = L.ShapeChain(self.frames[:5])
        self.assertEqual(len(failed.present()["parts"]), 2)
        self.assertEqual(failed.authorised()[1]["seq"], 1)

    def test_each_payload_and_nested_key_set_is_closed_and_required(self):
        cases = [
            (self.obj, L.validate_object),
            (self.part, L.validate_part),
            (self.obj["grail"], lambda value: L.validate_object(dict(self.obj, grail=value))),
            (self.frames[1]["payload"], L.validate_tile),
            (self.frames[2]["payload"], L.validate_gate),
            (self.frames[1]["payload"]["lens"],
             lambda value: L.validate_tile(dict(self.frames[1]["payload"], lens=value))),
            (self.frames[1]["payload"]["caller"],
             lambda value: L.validate_tile(dict(self.frames[1]["payload"], caller=value))),
        ]
        for value, validator in cases:
            with self.subTest(keys=tuple(value)):
                with self.assertRaises(ValueError):
                    validator(dict(value, extra=True))
                for key in value:
                    with self.subTest(missing=key), self.assertRaises(ValueError):
                        validator({k: v for k, v in value.items() if k != key})

    def test_dead_end_derivation_is_refused_even_when_it_replays(self):
        self.frames[5]["payload"]["derived_from"] = self.frames[3]["frame_hash"]
        self.frames[5]["payload"]["object"] = L.perform(
            self.frames[3]["payload"]["object"], self.frames[5]["payload"]["params"])
        with self.assertRaisesRegex(ValueError, "dead ends"):
            L.ShapeChain(self.rebuild(self.frames[:6]))

    def test_ungated_and_stale_derivations_are_refused(self):
        for target in (0, 3, 4):
            with self.subTest(target=target):
                frames = copy.deepcopy(self.frames)
                frames[5]["payload"]["derived_from"] = frames[target]["frame_hash"]
                with self.assertRaisesRegex(ValueError, "authorised"):
                    L.ShapeChain(self.rebuild(frames))

    def test_replay_refuses_rehashed_forgery(self):
        self.frames[1]["payload"]["object"]["safe_mode"] = True
        with self.assertRaisesRegex(ValueError, "does not replay"):
            L.ShapeChain(self.rebuild(self.frames))

    def test_params_hash_is_checked_independently_of_frame_hash(self):
        self.frames[1]["payload"]["params_hash"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "params_hash"):
            L.ShapeChain(self.rebuild(self.frames))

    def test_lens_pin_and_name_are_required(self):
        for lens in ({"name": "other", "sha256": L.RECORDED_LENS_SHA256},
                     {"name": "shape_lens", "sha256": "0" * 64}):
            with self.subTest(lens=lens), self.assertRaisesRegex(ValueError, "lens"):
                L.validate_tile(dict(self.frames[1]["payload"], lens=lens), self.obj)
        with self.assertRaisesRegex(ValueError, "source pin"):
            L.ShapeChain(self.frames, supported_lenses={L.SOURCE_LENS_SHA256})

    def test_gate_requires_earlier_tile_and_boolean_verdict(self):
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                L.validate_gate(dict(self.frames[2]["payload"], passed=value))
        for value in (self.frames[0]["frame_hash"], self.frames[7]["frame_hash"], "0" * 64):
            frames = copy.deepcopy(self.frames)
            frames[2]["payload"]["tile"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                L.ShapeChain(self.rebuild(frames))

    def test_newest_pass_is_chain_order_not_clock_or_later_failure(self):
        frames = copy.deepcopy(self.frames)
        payload = dict(frames[2]["payload"], tile=frames[1]["frame_hash"])
        self.append(frames, "shape.gate", payload, frames[-1]["utc"])
        self.assertEqual(L.ShapeChain(frames).authorised()[1]["seq"], 1)
        self.append(frames, "shape.gate", dict(payload, passed=False, gate="live"))
        self.assertEqual(L.ShapeChain(frames).authorised()[1]["seq"], 1)

    def test_flap_guard_counts_live_failures_since_any_pass(self):
        frames = copy.deepcopy(self.frames)
        payload = dict(frames[-1]["payload"], passed=False, gate="live")
        self.append(frames, "shape.gate", payload)
        first = L.ShapeChain(frames)
        self.assertEqual(first.live_failures_since_pass(), 1)
        self.assertEqual(first.flap_fallback(), first.authorised()[0])
        self.append(frames, "shape.gate", dict(payload, gate="lab"))
        self.append(frames, "shape.gate", payload)
        second = L.ShapeChain(frames)
        self.assertEqual(second.live_failures_since_pass(), 2)
        self.assertEqual(second.flap_fallback(), self.frames[5]["payload"]["object"])
        self.append(frames, "shape.gate", dict(payload, passed=True, gate="lab"))
        self.assertEqual(L.ShapeChain(frames).live_failures_since_pass(), 0)

    def test_flap_guard_without_previous_pass_returns_genesis(self):
        frames = copy.deepcopy(self.frames[:3])
        for _ in range(2):
            self.append(frames, "shape.gate", dict(frames[2]["payload"], passed=False, gate="live"))
        self.assertEqual(L.ShapeChain(frames).flap_fallback(), self.obj)

    def test_actions_are_pure_and_preserve_grail(self):
        original = copy.deepcopy(self.obj)
        added = L.perform(self.obj, {"action": "add", "part": self.part})
        self.assertEqual(self.obj, original)
        self.assertEqual(added["grail"], original["grail"])
        safe = L.perform(added, {"action": "safe_mode", "on": True})
        self.assertTrue(safe["safe_mode"])
        restored = L.perform(safe, {"action": "set", "parts": [], "safe_mode": False})
        self.assertEqual(restored, original)
        self.assertEqual(L.perform(added, {"action": "remove", "id": self.part["id"]}), original)
        self.assertEqual(L.perform(safe, {"action": "set", "parts": []})["safe_mode"], True)
        self.assertEqual(L.perform(self.obj, {"action": "add", "part": self.part, "extra": "kept"}), added)

    def test_add_existing_id_replaces_and_moves_it_to_end(self):
        other = dict(self.part, id="@kody-w/auth", point="auth", file="auth.py")
        obj = L.perform(self.obj, {"action": "set", "parts": [self.part, other]})
        result = L.perform(obj, {"action": "add", "part": dict(self.part, sha256="a" * 64)})
        self.assertEqual([p["id"] for p in result["parts"]], [other["id"], self.part["id"]])

    def test_one_occupant_and_unique_ids_and_filenames(self):
        variants = [dict(self.part), dict(self.part, id="@kody-w/other", file="other.py"),
                    dict(self.part, id="@kody-w/other", point="auth")]
        for other in variants:
            with self.subTest(other=other), self.assertRaisesRegex(ValueError, "duplicate"):
                L.perform(self.obj, {"action": "set", "parts": [self.part, other]})

    def test_part_pin_identity_kind_and_filename_refusals(self):
        for key, values in {
            "id": ["responses_models", "@a/b/c", "@A/b"],
            "kind": ["sidecar", "unknown"],
            "point": ["kernel", "other"],
            "file": ["../x.py", "/x.py", "x/y.py", "x.txt"],
            "sha256": ["b" * 63, "B" * 64],
            "locator": ["http://example.test/x", None],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    L.validate_part(dict(self.part, **{key: value}))
        kernel = dict(self.part, kind="kernel", point="kernel")
        L.validate_part(kernel)
        with self.assertRaises(ValueError):
            L.validate_part(dict(kernel, point="provider"))

    def test_shape_and_action_refusals(self):
        for obj in (dict(self.obj, schema="rapp/1"), dict(self.obj, safe_mode=1),
                    dict(self.obj, parts={}), dict(self.obj, grail={"sha256": "b" * 64, "bytes": True}),
                    dict(self.obj, grail={"sha256": "b" * 64, "bytes": 0})):
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                L.validate_object(obj)
        for params in ({"action": "remove", "id": "@a/missing"},
                       {"action": "safe_mode", "on": 1}, {"action": "set", "parts": None},
                       {"action": "set", "parts": [], "safe_mode": 1}, {"action": "unknown"}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                L.perform(self.obj, params)
        with self.assertRaisesRegex(ValueError, "64"):
            L.validate_object(dict(self.obj, parts=[self.part] * 65))

    def test_genesis_stream_link_unknown_kind_and_tamper_refusals(self):
        with self.assertRaises(ValueError):
            L.ShapeChain([])
        for key, value in (("kind", "unknown.kind"), ("stream_id", "rappid:@a/b:" + "a" * 64),
                           ("prev", "a" * 64)):
            frames = copy.deepcopy(self.frames)
            frames[1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                L.ShapeChain(frames)
        frames = copy.deepcopy(self.frames[:1])
        frames[0]["payload"]["parts"] = [self.part]
        with self.assertRaisesRegex(ValueError, "plain Grail"):
            L.ShapeChain(self.rebuild(frames))

    def test_only_null_slush_and_lease_and_host_callers(self):
        for key, value in (("slush_in", {}), ("lease", "claimed"),
                           ("caller", {"kind": "model", "name": "unverified"})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                L.validate_tile(dict(self.frames[1]["payload"], **{key: value}))

    def test_load_jsonl_and_strict_duplicate_key_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.jsonl"
            path.write_text("\n".join(R.canonical(f) for f in self.frames) + "\n")
            self.assertEqual(L.load_chain(path).frames, self.frames)
            path.write_text('{"kind":"shape.genesis","kind":"shape.tile"}\n')
            with self.assertRaises(ValueError):
                L.load_chain(path)

    def test_optional_supplied_runtime_matches_reference(self):
        source = ROOT / "_inputs/shape_lens.py"
        if not source.is_file():
            self.skipTest("external runtime source is not part of this repository")
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), L.SOURCE_LENS_SHA256)
        spec = importlib.util.spec_from_file_location("runtime_shape_lens", source)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        base = self.obj
        for params in ({"action": "add", "part": self.part},
                       {"action": "safe_mode", "on": True},
                       {"action": "set", "parts": [self.part], "safe_mode": False},
                       {"action": "remove", "id": self.part["id"]}):
            self.assertEqual(R.canonical(runtime.perform(base, params)),
                             R.canonical(L.perform(base, params)))
            base = L.perform(base, params)


if __name__ == "__main__":
    unittest.main()
