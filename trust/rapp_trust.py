#!/usr/bin/env python3
"""Unsigned-candidate trust tooling for the RAPP/1 registry.

This module is deliberately outside the stdlib-only teaching core. It uses
cryptography's Ed25519 implementation and never generates or persists keys.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import rapp as R


CANDIDATE_SCHEMA = "rapp/1-registry-candidate"
CANDIDATE_VERSION = 1
CANDIDATE_HASH_SPACE = "rapp/1:registry-candidate"
FRAME_KEYS = [
    "spec",
    "kind",
    "stream_id",
    "seq",
    "utc",
    "payload",
    "payload_hash",
    "prev",
    "prev_wave",
    "sig",
    "frame_hash",
]
TOP_LEVEL_KEYS = {
    "schema",
    "registry_version",
    "status",
    "estate",
    "issued_utc",
    "registry_seq",
    "previous_registry_hash",
    "canonical_source",
    "provenance",
    "frame",
    "algorithms",
    "owners",
    "rappids",
    "keys",
    "kinds",
    "egg_variants",
    "tombstones",
    "re_anchors",
    "sig",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KIND = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*$")
LABEL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
UTC_MILLIS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class TrustRefusal(ValueError):
    """A fail-closed trust decision. Inputs are never repaired."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VerifiedRegistry:
    document: Mapping[str, Any]
    digest: str
    trust_anchor: str


def _refuse(code: str, detail: str) -> None:
    raise TrustRefusal(code, detail)


def _reject_float(_: str) -> None:
    _refuse("non-ijson", "floating-point numbers are outside this tooling profile")


def _parse_int(token: str) -> int:
    value = int(token)
    if abs(value) > 2**53 - 1:
        _refuse("non-ijson", f"integer outside exact binary64 range: {token}")
    return value


def _pairs_no_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate-key", key)
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_pairs_no_duplicates,
        parse_float=_reject_float,
        parse_int=_parse_int,
        parse_constant=lambda token: _refuse("non-ijson", token),
    )


def validate_ijson(value: Any, depth: int = 1) -> None:
    if depth > 64:
        _refuse("non-ijson", "nesting depth exceeds 64")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            _refuse("non-ijson", "integer outside exact binary64 range")
        return
    if isinstance(value, float):
        _refuse("non-ijson", "floating-point numbers are forbidden")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            _refuse("non-ijson", "unpaired surrogate")
        return
    if isinstance(value, list):
        for item in value:
            validate_ijson(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _refuse("non-ijson", "object member name is not a string")
            validate_ijson(key, depth + 1)
            validate_ijson(item, depth + 1)
        return
    _refuse("non-ijson", f"unsupported value type: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Use the repository's one reference canonicalizer after strict I-JSON checks."""
    validate_ijson(value)
    octets = R.canonical(value).encode("utf-8")
    if len(octets) > 1024 * 1024:
        _refuse("non-ijson", "canonical form exceeds 1 MiB")
    return octets


def hash_value(space: str, value: Any) -> str:
    return hashlib.sha256(space.encode("ascii") + b"\n" + canonicalize(value)).hexdigest()


def candidate_digest(document: Mapping[str, Any]) -> str:
    return hash_value(CANDIDATE_HASH_SPACE, _without(document, "sig"))


def _without(value: Mapping[str, Any], *names: str) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in names}


def _b64url(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        _refuse("bad-jws", "non-canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        _refuse("bad-jws", "invalid base64url")
    if _b64url(decoded) != value:
        _refuse("bad-jws", "non-canonical base64url")
    return decoded


def public_spki_der(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def keyed_rappid(owner: str, slug: str, key: Ed25519PublicKey) -> str:
    if not LABEL.fullmatch(owner) or not LABEL.fullmatch(slug):
        _refuse("bad-rappid", "owner and slug must be lowercase labels")
    return f"rappid:@{owner}/{slug}:{R.Hb('rapp/1:rappid', public_spki_der(key))}"


def sign_value(
    value: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    kid: str,
    excluded: tuple[str, ...] = ("sig",),
) -> str:
    if not R.rappid_valid(kid):
        _refuse("bad-rappid", kid)
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": kid}
    protected = _b64url(canonicalize(header))
    payload = canonicalize(_without(value, *excluded))
    signature = private_key.sign(protected.encode("ascii") + b"." + payload)
    return protected + ".." + _b64url(signature)


def sign_document(
    value: Mapping[str, Any], private_key: Ed25519PrivateKey, kid: str
) -> dict[str, Any]:
    signed = copy.deepcopy(dict(value))
    signed["sig"] = sign_value(signed, private_key, kid)
    return signed


def _parse_jws(signature: str) -> tuple[dict[str, Any], str, bytes]:
    if not isinstance(signature, str):
        _refuse("bad-jws", "signature is not a string")
    parts = signature.split(".")
    if len(parts) != 3 or parts[1] != "":
        _refuse("bad-jws", "expected detached compact serialization")
    protected_octets = _b64url_decode(parts[0])
    try:
        header = json.loads(
            protected_octets,
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=_reject_float,
            parse_int=_parse_int,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _refuse("bad-jws", str(exc))
    expected = {"alg", "b64", "crit", "kid"}
    if not isinstance(header, dict) or set(header) != expected:
        _refuse("bad-jws", "protected header must have exactly alg,b64,crit,kid")
    if header["alg"] != "EdDSA" or header["b64"] is not False or header["crit"] != ["b64"]:
        _refuse("unsupported-jws", "only detached EdDSA with b64=false is supported")
    if canonicalize(header) != protected_octets:
        _refuse("bad-jws", "protected header is not canonical JCS")
    return header, parts[0], _b64url_decode(parts[2])


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or not UTC_MILLIS.fullmatch(value):
        _refuse("bad-utc", str(value))
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _refuse("bad-utc", value)


def _key_record(document: Mapping[str, Any], kid: str) -> Mapping[str, Any]:
    matches = [record for record in document["keys"] if record["kid"] == kid]
    if len(matches) != 1:
        _refuse("unknown-authority", f"no unique key record for {kid}")
    return matches[0]


def _public_key(record: Mapping[str, Any]) -> Ed25519PublicKey:
    if record["alg"] != "EdDSA":
        _refuse("unsupported-jws", str(record["alg"]))
    try:
        spki = base64.b64decode(record["spki_der_b64"], validate=True)
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError):
        _refuse("bad-key", "invalid SPKI DER")
    if not isinstance(key, Ed25519PublicKey):
        _refuse("bad-key", "SPKI is not Ed25519")
    if R.Hb("rapp/1:rappid", spki) != record["kid"].rsplit(":", 1)[-1]:
        _refuse("key-binding", "SPKI does not match keyed rappid tail")
    return key


def _key_valid_at(
    document: Mapping[str, Any],
    record: Mapping[str, Any],
    utc: str,
    apply_lifecycle: bool = True,
) -> None:
    instant = _utc(utc)
    if instant < _utc(record["not_before_utc"]):
        _refuse("key-not-yet-valid", record["kid"])
    if record["not_after_utc"] is not None and instant >= _utc(record["not_after_utc"]):
        _refuse("key-expired", record["kid"])
    anchors = [
        anchor for anchor in document["re_anchors"] if anchor["old_rappid"] == record["kid"]
    ]
    if record["deprecated"] and not anchors:
        _refuse("key-deprecated", record["kid"])
    if not apply_lifecycle:
        return
    for tombstone in document["tombstones"]:
        if tombstone["rappid"] == record["kid"] and instant >= _utc(tombstone["revoked_utc"]):
            _refuse("key-revoked", record["kid"])
    for anchor in anchors:
        if instant >= _utc(anchor["utc"]):
            _refuse("key-superseded", record["kid"])


def verify_value_signature(
    value: Mapping[str, Any],
    signature: str,
    document: Mapping[str, Any],
    artifact_utc: str,
    expected_kid: str | None = None,
    excluded: tuple[str, ...] = ("sig",),
    apply_lifecycle: bool = True,
) -> str:
    header, protected, signature_octets = _parse_jws(signature)
    kid = header["kid"]
    if expected_kid is not None and kid != expected_kid:
        _refuse("wrong-owner", f"expected {expected_kid}, got {kid}")
    record = _key_record(document, kid)
    _key_valid_at(document, record, artifact_utc, apply_lifecycle=apply_lifecycle)
    signing_input = protected.encode("ascii") + b"." + canonicalize(_without(value, *excluded))
    try:
        _public_key(record).verify(signature_octets, signing_input)
    except InvalidSignature:
        _refuse("bad-signature", kid)
    return kid


def _owner_at(document: Mapping[str, Any], utc: str) -> str:
    instant = _utc(utc)
    matches = []
    for owner in document["owners"]:
        start = _utc(owner["valid_from_utc"])
        end = _utc(owner["valid_until_utc"]) if owner["valid_until_utc"] is not None else None
        if start <= instant and (end is None or instant < end):
            matches.append(owner["rappid"])
    if len(matches) != 1:
        _refuse("unknown-authority", f"expected one estate owner at {utc}, found {len(matches)}")
    return matches[0]


def _stream_family(stream_id: str) -> str:
    if stream_id.startswith("net:") and LABEL.fullmatch(stream_id[4:]):
        return "swarm"
    if R.rappid_valid(stream_id):
        return "body"
    if ":" in stream_id:
        base, instance = stream_id.rsplit(":", 1)
        if R.rappid_valid(base) and LABEL.fullmatch(instance) and len(instance) <= 64:
            return "memory"
    _refuse("bad-stream", stream_id)


def validate_candidate(document: Mapping[str, Any]) -> None:
    original = copy.deepcopy(document)
    validate_ijson(document)
    if set(document) != TOP_LEVEL_KEYS:
        _refuse("candidate-shape", f"unexpected keys: {sorted(set(document) ^ TOP_LEVEL_KEYS)}")
    if document["schema"] != CANDIDATE_SCHEMA or document["registry_version"] != CANDIDATE_VERSION:
        _refuse("candidate-version", "unsupported schema or registry_version")
    if document["status"] not in {"unsigned-candidate", "owner-signed"}:
        _refuse("candidate-status", str(document["status"]))
    _utc(document["issued_utc"])
    if document["frame"]["spec"] != "rapp/1" or document["frame"]["keys"] != FRAME_KEYS:
        _refuse("frame-profile", "candidate must preserve the exact rapp/1 eleven-key frame")
    if document["frame"]["hash_space"] != "rapp/1:wave":
        _refuse("frame-profile", "wrong wave hash space")
    if document["algorithms"] != ["EdDSA"]:
        _refuse("algorithm-profile", "candidate tooling profile is exactly EdDSA")
    if not re.fullmatch(r"[0-9a-f]{40}", document["provenance"]["base_tree"]):
        _refuse("provenance", "base_tree")
    for name in ("spec_sha256", "anchor_frame_hash"):
        if not HEX64.fullmatch(document["provenance"][name]):
            _refuse("provenance", name)
    if document["status"] == "unsigned-candidate":
        if document["registry_seq"] is not None or document["sig"] is not None:
            _refuse("unsigned-candidate", "unsigned candidate must not claim sequence or signature")
    else:
        if not isinstance(document["registry_seq"], int) or isinstance(document["registry_seq"], bool):
            _refuse("registry-seq", "signed candidate requires uint53 registry_seq")
        if not 0 <= document["registry_seq"] <= 2**53 - 1 or not isinstance(document["sig"], str):
            _refuse("registry-seq", "invalid signed candidate sequence/signature")
    if document["previous_registry_hash"] is not None and not HEX64.fullmatch(document["previous_registry_hash"]):
        _refuse("registry-chain", "previous_registry_hash must be null or 64hex")
    rappids = [record["rappid"] for record in document["rappids"]]
    if len(rappids) != len(set(rappids)) or any(not R.rappid_valid(rappid) for rappid in rappids):
        _refuse("mint-once", "rappids must be unique and canonical")
    for record in document["rappids"]:
        _utc(record["minted_utc"])
        if record["grown_from"] is not None and not HEX64.fullmatch(record["grown_from"]):
            _refuse("grown-from", "lineage must be an egg address or null")
    owner_ids = [owner["rappid"] for owner in document["owners"]]
    if len(owner_ids) != len(set(owner_ids)) or any(owner not in rappids for owner in owner_ids):
        _refuse("owner-record", "owners must be unique registered rappids")
    key_ids = [key["kid"] for key in document["keys"]]
    if len(key_ids) != len(set(key_ids)) or any(kid not in rappids for kid in key_ids):
        _refuse("key-record", "keys must be unique registered rappids")
    kind_names = [entry["kind"] for entry in document["kinds"]]
    if len(kind_names) != len(set(kind_names)):
        _refuse("kind-registry", "duplicate kind")
    for entry in document["kinds"]:
        if not KIND.fullmatch(entry["kind"]) or entry["family"] not in {"memory", "body", "swarm"}:
            _refuse("kind-registry", str(entry))
    variants = [entry["variant"] for entry in document["egg_variants"]]
    if len(variants) != len(set(variants)) or any(not LABEL.fullmatch(item) for item in variants):
        _refuse("egg-registry", "egg variants must be unique lowercase labels")
    if document != original:
        _refuse("repair-attempt", "validation changed the input")


def _verify_lifecycle(document: Mapping[str, Any]) -> None:
    for tombstone in document["tombstones"]:
        owner = _owner_at(document, tombstone["revoked_utc"])
        verify_value_signature(
            tombstone, tombstone["sig"], document, tombstone["revoked_utc"], expected_kid=owner
        )
    tombstoned = {entry["rappid"] for entry in document["tombstones"]}
    for anchor in document["re_anchors"]:
        owner = _owner_at(document, anchor["utc"])
        verify_value_signature(anchor, anchor["sig"], document, anchor["utc"], expected_kid=owner)
        if anchor["case"] == "rotation":
            if anchor["old_key_sig"] is None:
                _refuse("re-anchor", "rotation requires old_key_sig")
            verify_value_signature(
                anchor,
                anchor["old_key_sig"],
                document,
                anchor["utc"],
                expected_kid=anchor["old_rappid"],
                excluded=("sig", "old_key_sig"),
                apply_lifecycle=False,
            )
        if anchor["case"] == "compromise" and anchor["old_rappid"] not in tombstoned:
            _refuse("re-anchor", "compromise requires same-registry tombstone")


def verify_candidate(
    document: Mapping[str, Any],
    trust_anchor: str | None = None,
    highest_registry_seq: int | None = None,
    highest_registry_digest: str | None = None,
    allow_unsigned: bool = False,
) -> VerifiedRegistry | None:
    validate_candidate(document)
    digest = candidate_digest(document)
    if document["status"] == "unsigned-candidate":
        if allow_unsigned:
            return None
        _refuse("unsigned-registry", "candidate is proposal material, not trust authority")
    if trust_anchor is None or not R.rappid_valid(trust_anchor):
        _refuse("unknown-authority", "an out-of-band estate_owner rappid is required")
    sequence = document["registry_seq"]
    if highest_registry_seq is not None and sequence < highest_registry_seq:
        _refuse("registry-rollback", f"{sequence} < {highest_registry_seq}")
    if (
        highest_registry_seq is not None
        and sequence == highest_registry_seq
        and highest_registry_digest is not None
        and digest != highest_registry_digest
    ):
        _refuse("registry-equivocation", "same registry_seq has different digest")
    owner = _owner_at(document, document["issued_utc"])
    if owner != trust_anchor:
        _refuse("cross-estate-replay", f"registry owner {owner} does not match trust anchor")
    verify_value_signature(
        document, document["sig"], document, document["issued_utc"], expected_kid=owner
    )
    _verify_lifecycle(document)
    return VerifiedRegistry(copy.deepcopy(document), digest, trust_anchor)


def verify_frame(
    frame: Mapping[str, Any],
    registry: VerifiedRegistry,
    stream_id_of_record: str,
    head: Mapping[str, Any] | None = None,
) -> None:
    original = copy.deepcopy(frame)
    validate_ijson(frame)
    _utc(frame.get("utc"))
    family = _stream_family(stream_id_of_record)
    kinds = {
        entry["kind"]: entry["family"]
        for entry in registry.document["kinds"]
        if not entry["deprecated"]
    }
    if frame.get("kind") not in kinds:
        _refuse("unknown-kind", str(frame.get("kind")))
    if kinds[frame["kind"]] != family:
        _refuse("kind-family", f"{frame['kind']} is not registered for {family}")
    ok, step, detail = R.verify_frame(
        dict(frame), head=dict(head) if head is not None else None, stream_id_of_record=stream_id_of_record
    )
    if not ok:
        _refuse(f"frame-step-{step}", detail)
    if frame["sig"] is not None:
        verify_value_signature(frame, frame["sig"], registry.document, frame["utc"])
    if frame != original:
        _refuse("repair-attempt", "verification changed the frame")


def verify_local_pins(document: Mapping[str, Any], repo_root: Path) -> None:
    provenance = document["provenance"]
    base_commit = provenance["base_commit"]
    tree = subprocess.check_output(
        ["git", "-C", str(repo_root), "show", "-s", "--format=%T", base_commit], text=True
    ).strip()
    if tree != provenance["base_tree"]:
        _refuse("base-drift", f"{tree} != {provenance['base_tree']}")
    spec = subprocess.check_output(
        ["git", "-C", str(repo_root), "cat-file", "blob", f"{provenance['spec_commit']}:{provenance['spec_path']}"]
    )
    if hashlib.sha256(spec).hexdigest() != provenance["spec_sha256"]:
        _refuse("spec-drift", "pinned spec hash mismatch")
    chain = subprocess.check_output(
        ["git", "-C", str(repo_root), "cat-file", "blob", f"{base_commit}:{provenance['anchor_path']}"]
    )
    last = json.loads(chain.decode("utf-8").splitlines()[-1])
    if (
        last["seq"] != provenance["anchor_seq"]
        or last["frame_hash"] != provenance["anchor_frame_hash"]
        or last["payload"]["normative_sha256"] != provenance["spec_sha256"]
    ):
        _refuse("anchor-drift", "anchor head does not bind the pinned spec")


def _private_key_from_external_path(path: Path) -> Ed25519PrivateKey:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        pass
    else:
        _refuse("private-key-location", "private keys must remain outside the repository")
    key = serialization.load_pem_private_key(resolved.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        _refuse("bad-key", "private key is not Ed25519")
    return key


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_bytes(canonicalize(value) + b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    digest_parser = sub.add_parser("digest")
    digest_parser.add_argument("candidate", type=Path)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("candidate", type=Path)
    verify_parser.add_argument("--trust-anchor")
    verify_parser.add_argument("--highest-seq", type=int)
    verify_parser.add_argument("--highest-digest")
    verify_parser.add_argument("--allow-unsigned", action="store_true")
    verify_parser.add_argument("--repo-root", type=Path, default=ROOT)
    sign_parser = sub.add_parser("sign")
    sign_parser.add_argument("candidate", type=Path)
    sign_parser.add_argument("--private-key", type=Path, required=True)
    sign_parser.add_argument("--kid", required=True)
    sign_parser.add_argument("--registry-seq", type=int, required=True)
    sign_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    document = load_json(args.candidate)
    if args.command == "digest":
        validate_candidate(document)
        print(candidate_digest(document))
        return 0
    if args.command == "verify":
        verify_local_pins(document, args.repo_root)
        verified = verify_candidate(
            document,
            trust_anchor=args.trust_anchor,
            highest_registry_seq=args.highest_seq,
            highest_registry_digest=args.highest_digest,
            allow_unsigned=args.allow_unsigned,
        )
        print(
            json.dumps(
                {
                    "digest": candidate_digest(document),
                    "status": "trusted" if verified is not None else "unsigned-candidate",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    validate_candidate(document)
    if document["status"] != "unsigned-candidate":
        _refuse("candidate-status", "sign only accepts an unsigned candidate")
    prepared = copy.deepcopy(document)
    prepared["status"] = "owner-signed"
    prepared["registry_seq"] = args.registry_seq
    prepared["sig"] = sign_value(prepared, _private_key_from_external_path(args.private_key), args.kid)
    verify_candidate(prepared, trust_anchor=args.kid)
    _write_json(args.output, prepared)
    print(candidate_digest(prepared))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TrustRefusal as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
