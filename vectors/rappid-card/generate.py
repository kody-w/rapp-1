#!/usr/bin/env python3
"""Generate or check the deterministic §7.10 RAPPID card fixture deck.

Run:
  python3 vectors/rappid-card/generate.py --check
  python3 vectors/rappid-card/generate.py --write
"""
import argparse
import base64
import hashlib
import json
import pathlib
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import rapp as R


HERE = pathlib.Path(__file__).resolve().parent
TEST_ISSUER_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
UNKNOWN_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
TEST_AUTHORITY_SEED = hashlib.sha256(b"rappid-card-test-authority").digest()
PROD_ISSUER_SEED = hashlib.sha256(b"rappid-card-production-issuer-vector").digest()
PROD_AUTHORITY_SEED = hashlib.sha256(b"rappid-card-production-authority-vector").digest()
ATTACKER_SEED = hashlib.sha256(b"rappid-card-trusted-attacker-vector").digest()


def _key(owner, slug, seed):
    public = R.ed25519_public_key(seed)
    return R.ed25519_rappid(owner, slug, public), R.ed25519_spki(public)


TEST_ISSUER, TEST_ISSUER_SPKI = _key(
    "synthetic", "rappid-card-test", TEST_ISSUER_SEED)
TEST_AUTHORITY, TEST_AUTHORITY_SPKI = _key(
    "synthetic", "card-policy-test", TEST_AUTHORITY_SEED)
PROD_ISSUER, PROD_ISSUER_SPKI = _key(
    "example", "card-issuer", PROD_ISSUER_SEED)
PROD_AUTHORITY, PROD_AUTHORITY_SPKI = _key(
    "example", "card-authority", PROD_AUTHORITY_SEED)
ATTACKER, ATTACKER_SPKI = _key(
    "synthetic", "trusted-attacker", ATTACKER_SEED)
UNKNOWN, _ = _key("synthetic", "unknown-card-test", UNKNOWN_SEED)

TRUST_KEYS = {
    TEST_ISSUER: TEST_ISSUER_SPKI,
    TEST_AUTHORITY: TEST_AUTHORITY_SPKI,
    PROD_ISSUER: PROD_ISSUER_SPKI,
    PROD_AUTHORITY: PROD_AUTHORITY_SPKI,
    ATTACKER: ATTACKER_SPKI,
}

TEST_SUBJECT = (
    "rappid:@synthetic/card-subject:"
    + R.Hb("rapp/1:rappid", bytes.fromhex("00112233445546778899aabbccddeeff"))
)
PROD_SUBJECT = (
    "rappid:@example/card-subject:"
    + R.Hb("rapp/1:rappid", bytes.fromhex("102132435465478798a9bacbdcedfe0f"))
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
VIEW_GENERATED_UTC = "2026-08-21T12:20:00.000Z"
VIEW_EFFECTIVE_UTC = "2026-08-21T00:00:00.000Z"
VIEW_EXPIRES_UTC = "2026-08-22T00:00:00.000Z"
GOOD_ORIGIN = "https://cards.example"
ATTACKER_ORIGIN = "https://attacker.example"
ENDPOINT = GOOD_ORIGIN + "/physical.rappid-card.json"
REVOCATION_URL = GOOD_ORIGIN + "/revocations.json"
PUBLIC_IP = "93.184.216.34"

MANDATORY_SCENARIOS = (
    "valid-test",
    "valid-production",
    "expired",
    "manifest-revoked",
    "key-revoked",
    "subject-revoked",
    "wrong-manifest-hash",
    "deep-payload",
    "oversized-payload",
    "newline-rappid",
    "newline-manifest-hash",
    "newline-lclabel",
    "newline-profile-token",
    "newline-connection-id",
    "unknown-signing-key",
    "attacker-key-impersonation",
    "delegation-expired",
    "delegation-revoked",
    "forged-revocation-view",
    "stale-revocation-view",
    "unavailable-revocation-view",
    "rollback-revocation-view",
    "protocol-incompatible",
    "runtime-incompatible",
    "unsupported-feature",
    "feature-superset",
    "classification-violation",
    "insufficient-scope",
    "missing-engram-part",
    "continuity-challenge-failure",
    "reconnect-during-hydration",
    "duplicate-replayed-nonce",
    "physical-payload-reproduction",
    "test-profile-production",
    "synthetic-key-production",
    "auto-execute",
    "endpoint-userinfo",
    "endpoint-empty-query",
    "endpoint-empty-fragment",
    "endpoint-space",
    "endpoint-backslash",
    "endpoint-bad-percent",
    "endpoint-double-encoding",
    "endpoint-numeric-127-1",
    "endpoint-numeric-octal",
    "endpoint-numeric-hex",
    "endpoint-numeric-short-private",
    "endpoint-loopback-literal",
    "endpoint-private-literal",
    "endpoint-link-local-literal",
    "endpoint-reserved-literal",
    "endpoint-unapproved-origin",
    "endpoint-redirect-origin",
    "endpoint-private-dns",
    "fetch-numeric-alias",
    "secret-endpoint-password",
    "secret-password",
    "secret-api-key",
    "secret-cookie",
    "secret-bearer",
    "secret-private-memory",
    "secret-unicode-latin-adjacency",
    "secret-unicode-cjk-adjacency",
)


def _b64(octets):
    return base64.b64encode(octets).decode("ascii")


def _clone(value):
    return json.loads(json.dumps(value))


def _profile_values(profile):
    if profile == R.CARD_TEST_PROFILE:
        return {
            "subject": TEST_SUBJECT,
            "issuer": TEST_ISSUER,
            "issuer_seed": TEST_ISSUER_SEED,
            "authority": TEST_AUTHORITY,
            "authority_seed": TEST_AUTHORITY_SEED,
        }
    return {
        "subject": PROD_SUBJECT,
        "issuer": PROD_ISSUER,
        "issuer_seed": PROD_ISSUER_SEED,
        "authority": PROD_AUTHORITY,
        "authority_seed": PROD_AUTHORITY_SEED,
    }


def _compatibility(profile, protocol=R.SPEC, runtime="rapp-ref/1", features=None):
    return {
        "protocol": protocol,
        "runtime": runtime,
        "features": sorted(features or ["content-hydration/1", profile]),
    }


def _provenance(source):
    return {"source": source, "channel": "canonical"}


def _runtime_policy(profile, *, protocol=R.SPEC, runtime="rapp-ref/1",
                    features=None, max_classification="internal",
                    granted_scope=None, generated=VIEW_GENERATED_UTC):
    values = _profile_values(profile)
    document = {
        "schema": R.CARD_RUNTIME_POLICY_SCHEMA,
        "policy_seq": 7,
        "generated_utc": generated,
        "effective_utc": VIEW_EFFECTIVE_UTC,
        "expires_utc": VIEW_EXPIRES_UTC,
        "authority_rappid": values["authority"],
        "signer_key_id": values["authority"],
        "provenance": _provenance(GOOD_ORIGIN + "/runtime-policy.json"),
        "card_authority": values["authority"],
        "protocol": protocol,
        "runtime": runtime,
        "features": sorted(features or [
            "content-hydration/1", profile, "safe-wake/1"]),
        "profiles": [profile],
        "max_classification": max_classification,
        "granted_scope": sorted(granted_scope or ["memory-read", "reflex-run"]),
        "max_registry_age_seconds": 3600,
        "sig": None,
    }
    return R.sign_card_document(
        document, values["authority"], values["authority_seed"])


def _authorization(issuer, subject, *, role="subject",
                   not_before="2026-08-01T00:00:00.000Z",
                   not_after="2026-09-21T00:00:00.000Z", revoked=None):
    return {
        "issuer_key_id": issuer,
        "subject_rappid": subject,
        "role": role,
        "not_before_utc": not_before,
        "not_after_utc": not_after,
        "revoked_utc": revoked,
    }


def _authority_view(profile, authorizations=None, approved_origins=None):
    values = _profile_values(profile)
    entries = authorizations
    if entries is None:
        if profile == R.CARD_PROFILE:
            entries = [_authorization(
                values["issuer"], None, role="card-issuer")]
        else:
            entries = [_authorization(
                values["issuer"], values["subject"], role="subject")]
    entries = sorted(entries, key=lambda entry: (
        entry["issuer_key_id"],
        "" if entry["subject_rappid"] is None else entry["subject_rappid"],
        entry["role"], entry["not_before_utc"], entry["not_after_utc"],
        "" if entry["revoked_utc"] is None else entry["revoked_utc"],
    ))
    document = {
        "schema": R.CARD_AUTHORITY_SCHEMA,
        "registry_seq": 11,
        "generated_utc": VIEW_GENERATED_UTC,
        "effective_utc": VIEW_EFFECTIVE_UTC,
        "expires_utc": VIEW_EXPIRES_UTC,
        "authority_rappid": values["authority"],
        "signer_key_id": values["authority"],
        "provenance": _provenance(GOOD_ORIGIN + "/authority.json"),
        "approved_origins": sorted(approved_origins or [GOOD_ORIGIN]),
        "authorizations": entries,
        "sig": None,
    }
    return R.sign_card_document(
        document, values["authority"], values["authority_seed"])


def _revocation(target_type, target, effective="2026-08-21T12:25:00.000Z"):
    return {
        "target_type": target_type,
        "target": target,
        "effective_utc": effective,
        "reason": "fixture",
    }


def _revocation_view(profile, source, entries=None, *, seq=13,
                     generated=VIEW_GENERATED_UTC,
                     effective=VIEW_EFFECTIVE_UTC,
                     expires=VIEW_EXPIRES_UTC):
    values = _profile_values(profile)
    entries = sorted(entries or [], key=lambda entry: (
        entry["target_type"], entry["target"], entry["effective_utc"], entry["reason"]))
    document = {
        "schema": R.CARD_REVOCATION_SCHEMA,
        "registry_seq": seq,
        "generated_utc": generated,
        "effective_utc": effective,
        "expires_utc": expires,
        "authority_rappid": values["authority"],
        "signer_key_id": values["authority"],
        "provenance": _provenance(source),
        "entries": entries,
        "sig": None,
    }
    return R.sign_card_document(
        document, values["authority"], values["authority_seed"])


def _raw_link(frame, endpoint, nonce, *, rappid=None, manifest_hash=None):
    return (
        "rappid://link/" + urllib.parse.quote(
            frame["payload"]["rappid"] if rappid is None else rappid, safe="")
        + "?m=" + (
            frame["payload_hash"] if manifest_hash is None else manifest_hash)
        + "&e=" + urllib.parse.quote(endpoint, safe="")
        + "&n=" + nonce
    )


def _card(nonce, *, profile=R.CARD_TEST_PROFILE, subject=None, issuer=None,
          issuer_seed=None, issued=ISSUED_UTC, expires=EXPIRES_UTC,
          compatibility=None, classification="public", scopes=None,
          endpoint=ENDPOINT, revocation_url=REVOCATION_URL, raw_link=False,
          payload_mutator=None):
    values = _profile_values(profile)
    subject = subject or values["subject"]
    issuer = issuer or values["issuer"]
    issuer_seed = issuer_seed or values["issuer_seed"]
    try:
        endpoint_origin = R._card_url_info(endpoint, R.CARD_VIRTUAL_SUFFIX)["origin"]
    except ValueError:
        endpoint_origin = GOOD_ORIGIN
    manifest = R.build_card_manifest(
        profile,
        subject,
        issuer,
        nonce,
        PARTS,
        compatibility or _compatibility(profile),
        classification,
        scopes or ["memory-read"],
        expires,
        revocation_url,
        endpoint_origin,
    )
    if payload_mutator is not None:
        manifest = payload_mutator(_clone(manifest))
    frame = R.build_card_frame(subject, 0, issued, manifest, issuer_seed)
    link = _raw_link(frame, endpoint, nonce) if raw_link else R.build_card_link(
        frame, endpoint, nonce)
    return frame, link


def _flip_signature(document):
    mutated = _clone(document)
    protected, detached, signature = mutated["sig"].split(".")
    signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    mutated["sig"] = ".".join((protected, detached, signature))
    return mutated


def _bundle(name, nonce, *, frame=None, link=None, profile=R.CARD_TEST_PROFILE,
            runtime_policy=None, authority_view=None, revocation_view=None,
            fetch_trace=None, hydrated_parts=None, continuity=None,
            state_seed=None, expected_ok=False, expected_step=None,
            reason_contains=None, physical=False, scanner_control=False,
            connection_id="fixture-connection", runtime_mutation=None):
    if frame is None or link is None:
        frame, link = _card(nonce, profile=profile)
    runtime_policy = runtime_policy or _runtime_policy(profile)
    authority_view = authority_view or _authority_view(profile)
    if revocation_view is None:
        revocation_view = _revocation_view(
            profile, frame["payload"]["revocation_url"])
    fetch_trace = fetch_trace or [{"url": urllib.parse.parse_qs(
        urllib.parse.urlsplit(link).query)["e"][0], "resolved_ip": PUBLIC_IP}]
    return {
        "name": name,
        "frame": frame,
        "link": link,
        "runtime_policy_authority": runtime_policy["authority_rappid"],
        "runtime_policy": runtime_policy,
        "authority_view": authority_view,
        "revocation_view": revocation_view,
        "now_utc": NOW_UTC,
        "connection_id": connection_id,
        "fetch_trace": fetch_trace,
        "hydrated_parts": hydrated_parts or sorted(PARTS),
        "continuity": continuity or R.card_continuity(frame["payload"], nonce),
        "state_seed": state_seed or {"nonces": [], "sequences": []},
        "physical": physical,
        "scanner_control": scanner_control,
        "runtime_mutation": runtime_mutation,
        "expected": {
            "ok": expected_ok,
            "step": expected_step,
            "reason_contains": reason_contains,
        },
    }


def build_deck():
    vectors = []

    test_nonce = "valid-test-card-0001"
    test_frame, test_link = _card(test_nonce)
    vectors.append(_bundle(
        "valid-test", test_nonce, frame=test_frame, link=test_link, expected_ok=True))

    prod_nonce = "valid-production-0001"
    prod_frame, prod_link = _card(prod_nonce, profile=R.CARD_PROFILE)
    vectors.append(_bundle(
        "valid-production", prod_nonce, profile=R.CARD_PROFILE,
        frame=prod_frame, link=prod_link, expected_ok=True))

    expired_nonce = "expired-card-nonce-01"
    expired_frame, expired_link = _card(
        expired_nonce, issued="2026-08-20T12:00:00.000Z",
        expires="2026-08-21T12:00:00.000Z")
    vectors.append(_bundle(
        "expired", expired_nonce, frame=expired_frame, link=expired_link,
        expected_step="expiry"))

    for name, target_type, target in (
            ("manifest-revoked", "manifest-hash", test_frame["payload_hash"]),
            ("key-revoked", "key-id", TEST_ISSUER),
            ("subject-revoked", "subject-rappid", TEST_SUBJECT)):
        nonce = name + "-0001"
        frame, link = _card(nonce)
        target_value = frame["payload_hash"] if target_type == "manifest-hash" else target
        view = _revocation_view(
            R.CARD_TEST_PROFILE, frame["payload"]["revocation_url"],
            [_revocation(target_type, target_value)])
        vectors.append(_bundle(
            name, nonce, frame=frame, link=link, revocation_view=view,
            expected_step="revocation"))

    wrong_hash_nonce = "wrong-hash-nonce-0001"
    wrong_hash_frame, wrong_hash_link = _card(wrong_hash_nonce)
    wrong_hash_link = wrong_hash_link.replace(
        "m=" + wrong_hash_frame["payload_hash"], "m=" + "f" * 64)
    vectors.append(_bundle(
        "wrong-manifest-hash", wrong_hash_nonce, frame=wrong_hash_frame,
        link=wrong_hash_link, expected_step="content-address"))

    deep_nonce = "deep-payload-nonce-001"
    deep_frame, deep_link = _card(deep_nonce)
    vectors.append(_bundle(
        "deep-payload", deep_nonce, frame=deep_frame, link=deep_link,
        runtime_mutation={"type": "deep-payload", "depth": 1100},
        expected_step="content-address", reason_contains="nesting depth"))

    oversized_nonce = "oversized-payload-001"
    oversized_frame, oversized_link = _card(oversized_nonce)
    vectors.append(_bundle(
        "oversized-payload", oversized_nonce,
        frame=oversized_frame, link=oversized_link,
        runtime_mutation={
            "type": "oversized-payload",
            "bytes": R.CANONICAL_MAX_BYTES + 1,
        },
        expected_step="content-address", reason_contains="exceeds 1048576"))

    newline_rappid_nonce = "newline-rappid-nonce-1"
    newline_rappid_frame, _ = _card(newline_rappid_nonce)
    vectors.append(_bundle(
        "newline-rappid", newline_rappid_nonce,
        frame=newline_rappid_frame,
        link=_raw_link(
            newline_rappid_frame, ENDPOINT, newline_rappid_nonce,
            rappid=newline_rappid_frame["payload"]["rappid"] + "\n"),
        expected_step="parse"))

    newline_hash_nonce = "newline-hash-nonce-001"
    newline_hash_frame, _ = _card(newline_hash_nonce)
    vectors.append(_bundle(
        "newline-manifest-hash", newline_hash_nonce,
        frame=newline_hash_frame,
        link=_raw_link(
            newline_hash_frame, ENDPOINT, newline_hash_nonce,
            manifest_hash=newline_hash_frame["payload_hash"] + "%0A"),
        expected_step="parse"))

    newline_lclabel_nonce = "newline-lclabel-0001"
    newline_lclabel_frame, newline_lclabel_link = _card(
        newline_lclabel_nonce,
        payload_mutator=lambda payload: dict(
            payload, requested_scope=["memory-read\n"]))
    vectors.append(_bundle(
        "newline-lclabel", newline_lclabel_nonce,
        frame=newline_lclabel_frame, link=newline_lclabel_link,
        expected_step="schema"))

    newline_profile_nonce = "newline-profile-0001"

    def newline_profile(payload):
        payload["compatibility"] = dict(
            payload["compatibility"], protocol="rapp/1\n")
        return payload

    newline_profile_frame, newline_profile_link = _card(
        newline_profile_nonce, payload_mutator=newline_profile)
    vectors.append(_bundle(
        "newline-profile-token", newline_profile_nonce,
        frame=newline_profile_frame, link=newline_profile_link,
        expected_step="schema"))

    newline_connection_nonce = "newline-connection-01"
    newline_connection_frame, newline_connection_link = _card(
        newline_connection_nonce)
    vectors.append(_bundle(
        "newline-connection-id", newline_connection_nonce,
        frame=newline_connection_frame, link=newline_connection_link,
        connection_id="fixture-connection\n", expected_step="replay-nonce"))

    unknown_nonce = "unknown-key-nonce-001"
    unknown_frame, unknown_link = _card(
        unknown_nonce, issuer=UNKNOWN, issuer_seed=UNKNOWN_SEED)
    vectors.append(_bundle(
        "unknown-signing-key", unknown_nonce, frame=unknown_frame,
        link=unknown_link, expected_step="signature"))

    attacker_nonce = "attacker-card-nonce-01"
    attacker_frame, attacker_link = _card(
        attacker_nonce, issuer=ATTACKER, issuer_seed=ATTACKER_SEED)
    vectors.append(_bundle(
        "attacker-key-impersonation", attacker_nonce,
        frame=attacker_frame, link=attacker_link,
        authority_view=_authority_view(R.CARD_TEST_PROFILE),
        expected_step="signature", reason_contains="no current signed authorization"))

    expired_delegation = _authorization(
        TEST_ISSUER, None, role="card-issuer",
        not_after="2026-08-21T12:15:00.000Z")
    delegation_nonce = "delegation-expired-001"
    delegation_frame, delegation_link = _card(delegation_nonce)
    vectors.append(_bundle(
        "delegation-expired", delegation_nonce,
        frame=delegation_frame, link=delegation_link,
        authority_view=_authority_view(
            R.CARD_TEST_PROFILE, [expired_delegation]),
        expected_step="signature"))

    revoked_delegation = _authorization(
        TEST_ISSUER, None, role="card-issuer",
        revoked="2026-08-21T12:20:00.000Z")
    revoked_delegation_nonce = "delegation-revoked-001"
    revoked_delegation_frame, revoked_delegation_link = _card(
        revoked_delegation_nonce)
    vectors.append(_bundle(
        "delegation-revoked", revoked_delegation_nonce,
        frame=revoked_delegation_frame, link=revoked_delegation_link,
        authority_view=_authority_view(
            R.CARD_TEST_PROFILE, [revoked_delegation]),
        expected_step="signature"))

    forged_nonce = "forged-revocation-001"
    forged_frame, forged_link = _card(forged_nonce)
    forged_view = _flip_signature(_revocation_view(
        R.CARD_TEST_PROFILE, forged_frame["payload"]["revocation_url"]))
    vectors.append(_bundle(
        "forged-revocation-view", forged_nonce,
        frame=forged_frame, link=forged_link, revocation_view=forged_view,
        expected_step="revocation"))

    stale_nonce = "stale-revocation-0001"
    stale_frame, stale_link = _card(stale_nonce)
    stale_view = _revocation_view(
        R.CARD_TEST_PROFILE, stale_frame["payload"]["revocation_url"],
        generated="2026-08-21T10:00:00.000Z",
        effective="2026-08-21T09:00:00.000Z")
    vectors.append(_bundle(
        "stale-revocation-view", stale_nonce,
        frame=stale_frame, link=stale_link, revocation_view=stale_view,
        expected_step="revocation", reason_contains="stale"))

    unavailable_nonce = "unavailable-revocation"
    unavailable_frame, unavailable_link = _card(unavailable_nonce)
    unavailable = _bundle(
        "unavailable-revocation-view", unavailable_nonce,
        frame=unavailable_frame, link=unavailable_link,
        expected_step="revocation", reason_contains="unavailable")
    unavailable["revocation_view"] = None
    vectors.append(unavailable)

    rollback_nonce = "rollback-revocation-01"
    rollback_frame, rollback_link = _card(rollback_nonce)
    rollback_view = _revocation_view(
        R.CARD_TEST_PROFILE, rollback_frame["payload"]["revocation_url"], seq=12)
    vectors.append(_bundle(
        "rollback-revocation-view", rollback_nonce,
        frame=rollback_frame, link=rollback_link, revocation_view=rollback_view,
        state_seed={"nonces": [], "sequences": [{
            "namespace": "card-revocation",
            "authority": TEST_AUTHORITY,
            "seq": 13,
            "view_hash": "0" * 64,
        }]},
        expected_step="revocation", reason_contains="rollback"))

    compatibility_cases = (
        ("protocol-incompatible", _compatibility(
            R.CARD_TEST_PROFILE, protocol="rapp/2"), False),
        ("runtime-incompatible", _compatibility(
            R.CARD_TEST_PROFILE, runtime="rapp-ref/9"), False),
        ("unsupported-feature", _compatibility(
            R.CARD_TEST_PROFILE,
            features=["content-hydration/1", R.CARD_TEST_PROFILE, "unsupported/1"]), False),
        ("feature-superset", _compatibility(R.CARD_TEST_PROFILE), True),
    )
    for name, compatibility, passes in compatibility_cases:
        nonce = name + "-0001"
        frame, link = _card(nonce, compatibility=compatibility)
        vectors.append(_bundle(
            name, nonce, frame=frame, link=link,
            expected_ok=passes, expected_step=None if passes else "compatibility"))

    classification_nonce = "classification-nonce-01"
    classification_frame, classification_link = _card(
        classification_nonce, classification="restricted")
    vectors.append(_bundle(
        "classification-violation", classification_nonce,
        frame=classification_frame, link=classification_link,
        expected_step="classification-scope"))

    scope_nonce = "scope-card-nonce-0001"
    scope_frame, scope_link = _card(
        scope_nonce, scopes=["admin-wake", "memory-read"])
    vectors.append(_bundle(
        "insufficient-scope", scope_nonce, frame=scope_frame, link=scope_link,
        expected_step="classification-scope"))

    missing_nonce = "missing-engram-nonce-1"
    missing_frame, missing_link = _card(missing_nonce)
    vectors.append(_bundle(
        "missing-engram-part", missing_nonce, frame=missing_frame,
        link=missing_link, hydrated_parts=["reflex-capability", "soul"],
        expected_step="hydration"))

    continuity_nonce = "continuity-nonce-0001"
    continuity_frame, continuity_link = _card(continuity_nonce)
    bad_continuity = R.card_continuity(continuity_frame["payload"], continuity_nonce)
    bad_continuity["soul_hash"] = "0" * 64
    vectors.append(_bundle(
        "continuity-challenge-failure", continuity_nonce,
        frame=continuity_frame, link=continuity_link,
        continuity=bad_continuity, expected_step="continuity"))

    reconnect_nonce = "reconnect-card-nonce-1"
    reconnect_frame, reconnect_link = _card(reconnect_nonce)
    vectors.append(_bundle(
        "reconnect-during-hydration", reconnect_nonce,
        frame=reconnect_frame, link=reconnect_link,
        state_seed={"nonces": [{
            "nonce": reconnect_nonce,
            "connection_id": "fixture-original-connection",
            "state": "hydrating",
            "utc": NOW_UTC,
        }], "sequences": []},
        expected_step="replay-nonce"))

    replay_nonce = "duplicate-card-nonce-01"
    replay_frame, replay_link = _card(replay_nonce)
    vectors.append(_bundle(
        "duplicate-replayed-nonce", replay_nonce,
        frame=replay_frame, link=replay_link,
        state_seed={"nonces": [{
            "nonce": replay_nonce,
            "connection_id": "fixture-connection",
            "state": "awake",
            "utc": NOW_UTC,
        }], "sequences": []},
        expected_step="replay-nonce"))

    physical_nonce = "physical-card-nonce-01"
    physical_frame, physical_link = _card(physical_nonce)
    vectors.append(_bundle(
        "physical-payload-reproduction", physical_nonce,
        frame=physical_frame, link=physical_link, expected_ok=True, physical=True))

    test_prod_nonce = "test-profile-prod-0001"
    test_prod_frame, test_prod_link = _card(test_prod_nonce)
    vectors.append(_bundle(
        "test-profile-production", test_prod_nonce,
        profile=R.CARD_PROFILE, frame=test_prod_frame, link=test_prod_link,
        runtime_policy=_runtime_policy(R.CARD_PROFILE),
        authority_view=_authority_view(R.CARD_PROFILE),
        revocation_view=_revocation_view(
            R.CARD_PROFILE, test_prod_frame["payload"]["revocation_url"]),
        expected_step="signature"))

    synthetic_prod_nonce = "synthetic-prod-nonce-01"
    synthetic_prod_frame, synthetic_prod_link = _card(
        synthetic_prod_nonce, profile=R.CARD_PROFILE,
        issuer=TEST_ISSUER, issuer_seed=TEST_ISSUER_SEED)
    vectors.append(_bundle(
        "synthetic-key-production", synthetic_prod_nonce,
        profile=R.CARD_PROFILE, frame=synthetic_prod_frame, link=synthetic_prod_link,
        expected_step="signature"))

    auto_nonce = "auto-execute-nonce-001"
    auto_frame, auto_link = _card(
        auto_nonce,
        payload_mutator=lambda payload: dict(
            payload, requested_scope=["auto-execute"]))
    vectors.append(_bundle(
        "auto-execute", auto_nonce, frame=auto_frame, link=auto_link,
        runtime_policy=_runtime_policy(
            R.CARD_TEST_PROFILE,
            granted_scope=["auto-execute", "memory-read", "reflex-run"]),
        expected_step="schema", reason_contains="secret",
        scanner_control=True))

    endpoint_mutations = (
        ("endpoint-userinfo", "https://user@cards.example/x.rappid-card.json"),
        ("endpoint-empty-query", ENDPOINT + "?"),
        ("endpoint-empty-fragment", ENDPOINT + "#"),
        ("endpoint-space", "https://cards.example/a b.rappid-card.json"),
        ("endpoint-backslash", "https://cards.example/a\\b.rappid-card.json"),
        ("endpoint-bad-percent", "https://cards.example/%ZZ.rappid-card.json"),
        ("endpoint-double-encoding",
         "https://cards.example/password%2520fixture/x.rappid-card.json"),
        ("endpoint-numeric-127-1", "https://127.1/x.rappid-card.json"),
        ("endpoint-numeric-octal", "https://0177.0.0.1/x.rappid-card.json"),
        ("endpoint-numeric-hex", "https://0x7f.0.0.1/x.rappid-card.json"),
        ("endpoint-numeric-short-private", "https://192.168.1/x.rappid-card.json"),
        ("endpoint-loopback-literal", "https://127.0.0.1/x.rappid-card.json"),
        ("endpoint-private-literal", "https://10.0.0.1/x.rappid-card.json"),
        ("endpoint-link-local-literal", "https://169.254.1.1/x.rappid-card.json"),
        ("endpoint-reserved-literal", "https://192.0.2.1/x.rappid-card.json"),
    )
    for name, endpoint in endpoint_mutations:
        nonce = name + "-01"
        frame, _ = _card(nonce)
        vectors.append(_bundle(
            name, nonce, frame=frame, link=_raw_link(frame, endpoint, nonce),
            expected_step="parse"))

    unapproved_nonce = "unapproved-origin-0001"
    unapproved_endpoint = ATTACKER_ORIGIN + "/x.rappid-card.json"
    unapproved_frame, unapproved_link = _card(
        unapproved_nonce, endpoint=unapproved_endpoint)
    vectors.append(_bundle(
        "endpoint-unapproved-origin", unapproved_nonce,
        frame=unapproved_frame, link=unapproved_link,
        fetch_trace=[{"url": unapproved_endpoint, "resolved_ip": PUBLIC_IP}],
        expected_step="signature"))

    redirect_nonce = "redirect-origin-nonce-1"
    redirect_frame, redirect_link = _card(redirect_nonce)
    vectors.append(_bundle(
        "endpoint-redirect-origin", redirect_nonce,
        frame=redirect_frame, link=redirect_link,
        fetch_trace=[
            {"url": ENDPOINT, "resolved_ip": PUBLIC_IP},
            {"url": ATTACKER_ORIGIN + "/redirected.rappid-card.json",
             "resolved_ip": PUBLIC_IP},
        ],
        expected_step="signature"))

    private_dns_nonce = "private-dns-nonce-0001"
    private_dns_frame, private_dns_link = _card(private_dns_nonce)
    vectors.append(_bundle(
        "endpoint-private-dns", private_dns_nonce,
        frame=private_dns_frame, link=private_dns_link,
        fetch_trace=[{"url": ENDPOINT, "resolved_ip": "10.0.0.1"}],
        expected_step="signature"))

    fetch_alias_nonce = "fetch-numeric-alias-01"
    fetch_alias_frame, fetch_alias_link = _card(fetch_alias_nonce)
    vectors.append(_bundle(
        "fetch-numeric-alias", fetch_alias_nonce,
        frame=fetch_alias_frame, link=fetch_alias_link,
        fetch_trace=[
            {"url": ENDPOINT, "resolved_ip": PUBLIC_IP},
            {"url": "https://127.1/redirected.rappid-card.json",
             "resolved_ip": "127.0.0.1"},
        ],
        expected_step="signature", reason_contains="numeric-looking"))

    endpoint_secret_nonce = "secret-endpoint-0001"
    secret_endpoint = GOOD_ORIGIN + "/password%3Dfixture/physical.rappid-card.json"
    endpoint_secret_frame, endpoint_secret_link = _card(
        endpoint_secret_nonce, endpoint=secret_endpoint, raw_link=True)
    vectors.append(_bundle(
        "secret-endpoint-password", endpoint_secret_nonce,
        frame=endpoint_secret_frame, link=endpoint_secret_link,
        fetch_trace=[{"url": secret_endpoint, "resolved_ip": PUBLIC_IP}],
        expected_step="parse", reason_contains="prohibited",
        scanner_control=True))

    secret_urls = (
        ("secret-password", "password%3Dfixture"),
        ("secret-api-key", "api-key%3Dfixture"),
        ("secret-cookie", "cookie%3Dfixture"),
        ("secret-bearer", "bearer%20fixture"),
        ("secret-private-memory", "private-memory%3Dfixture"),
        ("secret-unicode-latin-adjacency",
         "%C3%A9password%C3%A9"),
        ("secret-unicode-cjk-adjacency",
         "%E6%BC%A2password%E6%BC%A2"),
    )
    for name, segment in secret_urls:
        nonce = name + "-0001"
        revocation_url = GOOD_ORIGIN + "/" + segment + "/revocations.json"
        frame, link = _card(
            nonce,
            payload_mutator=lambda payload, url=revocation_url: dict(
                payload, revocation_url=url))
        vectors.append(_bundle(
            name, nonce, frame=frame, link=link,
            revocation_view=_revocation_view(
                R.CARD_TEST_PROFILE, revocation_url),
            expected_step="schema",
            reason_contains=(
                "prohibited"
                if name == "secret-bearer" or name.startswith("secret-unicode-")
                else "secret"
            ),
            scanner_control=True))

    assert tuple(vector["name"] for vector in vectors) == MANDATORY_SCENARIOS
    return {
        "schema": "rappid-card-vectors/3",
        "production_profile": R.CARD_PROFILE,
        "test_profile": R.CARD_TEST_PROFILE,
        "virtual_suffix": R.CARD_VIRTUAL_SUFFIX,
        "mandatory_scenarios": list(MANDATORY_SCENARIOS),
        "parts_b64": {part: _b64(PARTS[part]) for part in sorted(PARTS)},
        "trust": [{
            "kid": kid,
            "spki_der_b64": _b64(TRUST_KEYS[kid]),
        } for kid in sorted(TRUST_KEYS)],
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
