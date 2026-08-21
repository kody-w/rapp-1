#!/usr/bin/env python3
"""Generate or check the deterministic §7.10 RAPPID card fixture deck.

Run:
  python3 vectors/rappid-card/generate.py --check
  python3 vectors/rappid-card/generate.py --write
"""
import argparse
import base64
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import rapp as R


HERE = pathlib.Path(__file__).resolve().parent
PRIMARY_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
UNKNOWN_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PRIMARY_PUBLIC = R.ed25519_public_key(PRIMARY_SEED)
UNKNOWN_PUBLIC = R.ed25519_public_key(UNKNOWN_SEED)
PRIMARY_KID = R.ed25519_rappid("synthetic", "rappid-card-test", PRIMARY_PUBLIC)
UNKNOWN_KID = R.ed25519_rappid("synthetic", "unknown-card-test", UNKNOWN_PUBLIC)
SUBJECT = (
    "rappid:@synthetic/card-subject:"
    + R.Hb("rapp/1:rappid", bytes.fromhex("00112233445546778899aabbccddeeff"))
)

PARTS = {
    "soul": b"# Synthetic Card Soul\nFixture only. No private memory.\n",
    "engram": R.canonical({
        "root": "synthetic-engram-root",
        "entries": [{"seq": 0, "summary": "fixture"}],
    }).encode("utf-8"),
    "reflex-capability": R.canonical({
        "reflexes": ["answer"],
        "capabilities": ["memory-read", "reflex-run"],
    }).encode("utf-8"),
}
ISSUED_UTC = "2026-08-21T12:00:00.000Z"
NOW_UTC = "2026-08-21T12:30:00.000Z"
EXPIRES_UTC = "2026-09-21T12:00:00.000Z"
ENDPOINT = "https://fixtures.invalid/physical.rappid-card.json"
REVOCATION_URL = "https://fixtures.invalid/rappid-card-revocations.json"
BASE_COMPATIBILITY = {
    "protocol": R.SPEC,
    "runtime": "rapp-ref/1",
    "features": ["content-hydration/1", R.CARD_TEST_PROFILE],
}
BASE_ENVIRONMENT = {
    "protocol": R.SPEC,
    "runtime": "rapp-ref/1",
    "features": ["content-hydration/1", R.CARD_TEST_PROFILE],
    "max_classification": "internal",
    "granted_scope": ["memory-read", "reflex-run"],
}


def _b64(octets):
    return base64.b64encode(octets).decode("ascii")


def _card(nonce, *, profile=R.CARD_TEST_PROFILE, seed=PRIMARY_SEED,
          kid=PRIMARY_KID, issued=ISSUED_UTC, expires=EXPIRES_UTC,
          compatibility=None, classification="public", scopes=None,
          payload_mutator=None):
    manifest = R.build_card_manifest(
        profile,
        SUBJECT,
        kid,
        nonce,
        PARTS,
        compatibility or BASE_COMPATIBILITY,
        classification,
        scopes or ["memory-read"],
        expires,
        REVOCATION_URL,
    )
    if payload_mutator is not None:
        manifest = payload_mutator(dict(manifest))
    frame = R.build_card_frame(SUBJECT, 0, issued, manifest, seed)
    link = R.build_card_link(frame, ENDPOINT, nonce)
    return frame, link


def _vector(name, nonce, *, expected_ok=False, expected_step=None,
            frame=None, link=None, mode="test", now=NOW_UTC,
            revoked=None, environment=None, hydrated_parts=None,
            continuity=None, replay_seed=None, physical=False):
    if frame is None or link is None:
        frame, link = _card(nonce)
    return {
        "name": name,
        "frame": frame,
        "link": link,
        "mode": mode,
        "now_utc": now,
        "revoked": revoked or [],
        "environment": environment or dict(BASE_ENVIRONMENT),
        "connection_id": "fixture-connection",
        "hydrated_parts": hydrated_parts or sorted(PARTS),
        "continuity": continuity or R.card_continuity(frame["payload"], nonce),
        "replay_seed": replay_seed,
        "physical": physical,
        "expected": {"ok": expected_ok, "step": expected_step},
    }


def build_deck():
    vectors = []

    valid_nonce = "valid-card-nonce-0001"
    valid_frame, valid_link = _card(valid_nonce)
    vectors.append(_vector(
        "valid", valid_nonce, frame=valid_frame, link=valid_link, expected_ok=True))

    expired_nonce = "expired-card-nonce-01"
    expired_frame, expired_link = _card(
        expired_nonce,
        issued="2026-08-20T12:00:00.000Z",
        expires="2026-08-21T12:00:00.000Z",
    )
    vectors.append(_vector(
        "expired", expired_nonce, frame=expired_frame, link=expired_link,
        expected_step="expiry"))

    revoked_nonce = "revoked-card-nonce-01"
    revoked_frame, revoked_link = _card(revoked_nonce)
    vectors.append(_vector(
        "revoked", revoked_nonce, frame=revoked_frame, link=revoked_link,
        revoked=[revoked_frame["payload_hash"]], expected_step="revocation"))

    wrong_hash_nonce = "wrong-hash-nonce-0001"
    wrong_hash_frame, wrong_hash_link = _card(wrong_hash_nonce)
    wrong_hash_link = wrong_hash_link.replace(
        "m=" + wrong_hash_frame["payload_hash"], "m=" + "f" * 64)
    vectors.append(_vector(
        "wrong-manifest-hash", wrong_hash_nonce, frame=wrong_hash_frame,
        link=wrong_hash_link, expected_step="content-address"))

    unknown_nonce = "unknown-key-nonce-001"
    unknown_frame, unknown_link = _card(
        unknown_nonce, seed=UNKNOWN_SEED, kid=UNKNOWN_KID)
    vectors.append(_vector(
        "unknown-signing-key", unknown_nonce, frame=unknown_frame,
        link=unknown_link, expected_step="signature"))

    incompatible_nonce = "incompatible-nonce-01"
    incompatible_frame, incompatible_link = _card(
        incompatible_nonce,
        compatibility={
            "protocol": "rapp/2",
            "runtime": "rapp-ref/9",
            "features": ["content-hydration/1", R.CARD_TEST_PROFILE],
        },
    )
    vectors.append(_vector(
        "incompatible-runtime-protocol", incompatible_nonce,
        frame=incompatible_frame, link=incompatible_link,
        expected_step="compatibility"))

    classification_nonce = "classify-card-nonce-01"
    classification_frame, classification_link = _card(
        classification_nonce, classification="restricted")
    classification_environment = dict(BASE_ENVIRONMENT)
    classification_environment["max_classification"] = "public"
    vectors.append(_vector(
        "classification-violation", classification_nonce,
        frame=classification_frame, link=classification_link,
        environment=classification_environment,
        expected_step="classification-scope"))

    scope_nonce = "scope-card-nonce-0001"
    scope_frame, scope_link = _card(
        scope_nonce, scopes=["admin-wake", "memory-read"])
    scope_environment = dict(BASE_ENVIRONMENT)
    scope_environment["granted_scope"] = ["memory-read"]
    vectors.append(_vector(
        "insufficient-scope", scope_nonce, frame=scope_frame, link=scope_link,
        environment=scope_environment, expected_step="classification-scope"))

    missing_nonce = "missing-engram-nonce-1"
    missing_frame, missing_link = _card(missing_nonce)
    vectors.append(_vector(
        "missing-engram-part", missing_nonce, frame=missing_frame,
        link=missing_link, hydrated_parts=["reflex-capability", "soul"],
        expected_step="hydration"))

    continuity_nonce = "continuity-nonce-0001"
    continuity_frame, continuity_link = _card(continuity_nonce)
    bad_continuity = R.card_continuity(continuity_frame["payload"], continuity_nonce)
    bad_continuity["soul_hash"] = "0" * 64
    vectors.append(_vector(
        "continuity-challenge-failure", continuity_nonce,
        frame=continuity_frame, link=continuity_link,
        continuity=bad_continuity, expected_step="continuity"))

    reconnect_nonce = "reconnect-card-nonce-1"
    reconnect_frame, reconnect_link = _card(reconnect_nonce)
    vectors.append(_vector(
        "reconnect-during-hydration", reconnect_nonce,
        frame=reconnect_frame, link=reconnect_link,
        replay_seed={
            "nonce": reconnect_nonce,
            "connection_id": "fixture-original-connection",
            "state": "hydrating",
        },
        expected_step="replay-nonce"))

    replay_nonce = "duplicate-card-nonce-01"
    replay_frame, replay_link = _card(replay_nonce)
    vectors.append(_vector(
        "duplicate-replayed-nonce", replay_nonce,
        frame=replay_frame, link=replay_link,
        replay_seed={
            "nonce": replay_nonce,
            "connection_id": "fixture-connection",
            "state": "awake",
        },
        expected_step="replay-nonce"))

    physical_nonce = "physical-card-nonce-01"
    physical_frame, physical_link = _card(physical_nonce)
    vectors.append(_vector(
        "physical-payload-reproduction", physical_nonce,
        frame=physical_frame, link=physical_link, expected_ok=True, physical=True))

    prod_profile_nonce = "test-profile-prod-0001"
    prod_profile_frame, prod_profile_link = _card(prod_profile_nonce)
    vectors.append(_vector(
        "test-profile-refused-production", prod_profile_nonce,
        frame=prod_profile_frame, link=prod_profile_link, mode="production",
        expected_step="schema"))

    synthetic_prod_nonce = "synthetic-prod-nonce-01"
    synthetic_prod_frame, synthetic_prod_link = _card(
        synthetic_prod_nonce,
        profile=R.CARD_PROFILE,
        compatibility={
            "protocol": R.SPEC,
            "runtime": "rapp-ref/1",
            "features": ["content-hydration/1", R.CARD_PROFILE],
        },
    )
    synthetic_prod_environment = dict(BASE_ENVIRONMENT)
    synthetic_prod_environment["features"] = [
        "content-hydration/1", R.CARD_PROFILE]
    vectors.append(_vector(
        "synthetic-key-refused-production", synthetic_prod_nonce,
        frame=synthetic_prod_frame, link=synthetic_prod_link,
        mode="production", environment=synthetic_prod_environment,
        expected_step="signature"))

    forbidden_nonce = "forbidden-card-nonce-1"

    def add_instruction(payload):
        payload["requested_scope"] = ["auto-execute"]
        return payload

    forbidden_frame, forbidden_link = _card(
        forbidden_nonce, payload_mutator=add_instruction)
    vectors.append(_vector(
        "auto-execute-instruction-refused", forbidden_nonce,
        frame=forbidden_frame, link=forbidden_link, expected_step="schema"))

    return {
        "schema": "rappid-card-vectors/1",
        "production_profile": R.CARD_PROFILE,
        "test_profile": R.CARD_TEST_PROFILE,
        "virtual_suffix": R.CARD_VIRTUAL_SUFFIX,
        "subject_rappid": SUBJECT,
        "parts_b64": {part: _b64(PARTS[part]) for part in sorted(PARTS)},
        "trust": [{
            "kid": PRIMARY_KID,
            "spki_der_b64": _b64(R.ed25519_spki(PRIMARY_PUBLIC)),
            "synthetic": True,
        }],
        "vectors": vectors,
    }


def rendered_files():
    deck = build_deck()
    physical = next(vector for vector in deck["vectors"] if vector["physical"])
    return {
        HERE / "deck.json": (
            json.dumps(deck, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8"),
        HERE / "physical.rappid-card.json": R.canonical(physical["frame"]).encode("utf-8"),
        HERE / "physical-payload.txt": (physical["link"] + "\n").encode("utf-8"),
    }


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    failed = False
    for path, expected in rendered_files().items():
        if args.write:
            path.write_bytes(expected)
            print(f"wrote {path.relative_to(ROOT)} ({len(expected)} bytes)")
            continue
        actual = path.read_bytes() if path.exists() else None
        if actual != expected:
            print(f"DIFF {path.relative_to(ROOT)}", file=sys.stderr)
            failed = True
        else:
            print(f"OK   {path.relative_to(ROOT)} ({len(expected)} bytes)")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
