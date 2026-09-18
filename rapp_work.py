#!/usr/bin/env python3
"""Reference validator for the additive RAPP Work protocol profile."""

from __future__ import annotations

import copy
from typing import Callable, Optional

import rapp as R
import rapp_cicd as C
import rapp_deploy as D
from rapp_profile import (
    authoritative_frame_payload,
    bounded_int,
    canonical_object,
    exact_keys,
    grail_id,
    hex64,
    https_uri,
    label,
    object_id,
    particle_hash,
    relative_path,
    require,
    text,
    utc,
)

PROFILE = "rapp-work/1"
CANONICAL_REPOSITORY = "https://github.com/kody-w/rapp-1"
SPEC_PATH = "protocols/rapp-work/1/SPEC.md"

ORGANIZATION_SCHEMA = "rapp-work/1-organization"
CATALOG_SCHEMA = "rapp-work/1-catalog"
VECTOR_SCHEMA = "rapp-work/1-vector"
MIGRATION_SCHEMA = "rapp-work/1-migration"
RECEIPT_SCHEMA = "rapp-work/1-receipt"
OBSERVATION_SCHEMA = "rapp-work/1-observation"
ROLLBACK_SCHEMA = "rapp-work/1-rollback"

KIND_SCHEMAS = {
    "work.organization": ORGANIZATION_SCHEMA,
    "work.catalog": CATALOG_SCHEMA,
    "work.vector": VECTOR_SCHEMA,
    "work.migration": MIGRATION_SCHEMA,
    "work.receipt": RECEIPT_SCHEMA,
    "work.observation": OBSERVATION_SCHEMA,
    "work.rollback": ROLLBACK_SCHEMA,
}
WORK_KINDS = frozenset(KIND_SCHEMAS)
DEPENDENCY_PROTOCOLS = frozenset(
    {"rapp/1", "rapp-hive/1", "rapp-cicd/1", "rapp-deploy/1"}
)

MAX_CATALOG_ITEMS = 256
MAX_EVIDENCE_ITEMS = 128
MAX_RELEASE_OBSERVATIONS = 128
UINT53_MAX = 2**53 - 1

ORGANIZATION_KEYS = {
    "schema",
    "organization_rappid",
    "owner_rappid",
    "world_id",
    "hive_rappid",
    "release_scope",
    "policy_sha256",
    "created_utc",
}
CATALOG_KEYS = {
    "schema",
    "organization_payload_hash",
    "created_utc",
    "previous_catalog_payload_hash",
    "items",
}
VECTOR_KEYS = {
    "schema",
    "organization_payload_hash",
    "observed_utc",
    "hive_checkpoint",
    "mother_head",
    "previous_vector_payload_hash",
}
ROLLBACK_KEYS = {
    "schema",
    "organization_payload_hash",
    "created_utc",
    "release_payload_hash",
    "artifact_sha256",
    "grail_id",
    "state_schema_sha256",
    "snapshot",
    "restore_evidence_sha256",
    "locator",
}
MIGRATION_KEYS = {
    "schema",
    "organization_payload_hash",
    "migration_id",
    "created_utc",
    "mode",
    "source",
    "target",
    "catalog_item_ids",
    "rollback_payload_hash",
}
RECEIPT_KEYS = {
    "schema",
    "organization_payload_hash",
    "receipt_type",
    "subject",
    "issued_utc",
    "result",
    "evidence",
    "migration",
    "custody",
}
OBSERVATION_KEYS = {
    "schema",
    "organization_payload_hash",
    "release_payload_hash",
    "deployment_payload_hash",
    "vector_payload_hash",
    "observed_utc",
    "verdict",
    "evidence",
    "previous_observation_payload_hash",
}

ADDRESS_SPACES = {
    "rapp/1:particle",
    "rapp/1:wave",
    "rapp/1:egg-manifest",
}
CATALOG_ITEM_KINDS = {"plugin", "skill", "static-api", "portable-neuron"}
PORTABLE_NEURON_FORMATS = {
    "portable-neuron/2",
    "portable-neuron-catalog/2",
    "portable-neuron-packet/2",
    "portable-neuron-request/2",
}
RECEIPT_TYPES = {"migration-completed", "catalog-verified", "release-verified"}
RECEIPT_SUBJECT_KINDS = CATALOG_ITEM_KINDS | {
    "catalog",
    "migration",
    "release",
    "rollback",
    "vector",
}


def _rappid(value: object, where: str) -> str:
    require(R.rappid_valid(value), f"{where}: expected RAPP/1 rappid")
    return value  # type: ignore[return-value]


def _optional_hex64(value: object, where: str) -> Optional[str]:
    if value is None:
        return None
    return hex64(value, where)


def _same(left: object, right: object) -> bool:
    return R.canonical(left) == R.canonical(right)


def _address(value: object, where: str) -> dict:
    value = exact_keys(value, {"space", "hash"}, where)
    require(value["space"] in ADDRESS_SPACES, f"{where}.space: unsupported RAPP address")
    hex64(value["hash"], f"{where}.hash")
    return value


def _addresses(values: object, where: str, *, nonempty: bool = False) -> list:
    require(isinstance(values, list), f"{where}: expected array")
    require(len(values) <= MAX_EVIDENCE_ITEMS, f"{where}: too many addresses")
    checked = [_address(value, f"{where}[{index}]") for index, value in enumerate(values)]
    ordered = [(value["space"], value["hash"]) for value in checked]
    require(ordered == sorted(set(ordered)), f"{where}: must be unique and sorted")
    if nonempty:
        require(bool(checked), f"{where}: at least one address is required")
    return checked


def _head(value: object, where: str) -> dict:
    value = exact_keys(
        value,
        {"stream_id", "seq", "utc", "payload_hash", "frame_hash"},
        where,
    )
    text(value["stream_id"], f"{where}.stream_id", maximum=512)
    bounded_int(value["seq"], f"{where}.seq", 0, UINT53_MAX)
    utc(value["utc"], f"{where}.utc")
    hex64(value["payload_hash"], f"{where}.payload_hash")
    hex64(value["frame_hash"], f"{where}.frame_hash")
    return value


def _catalog_locator(value: object, where: str) -> dict:
    value = exact_keys(value, {"kind", "uri", "path"}, where)
    require(value["kind"] in {"git", "raw", "static"}, f"{where}.kind: unsupported locator")
    https_uri(value["uri"], f"{where}.uri")
    relative_path(value["path"], f"{where}.path")
    return value


def _immutable_locator(value: object, where: str) -> dict:
    value = exact_keys(
        value,
        {"repository", "object_format", "commit", "path"},
        where,
    )
    https_uri(value["repository"], f"{where}.repository")
    require(
        value["object_format"] in ("sha1", "sha256"),
        f"{where}.object_format: unsupported",
    )
    try:
        object_id(value["commit"], value["object_format"], f"{where}.commit")
    except ValueError as error:
        raise ValueError(f"{where}.commit: immutable commit object id required") from error
    relative_path(value["path"], f"{where}.path")
    return value


def validate_organization(payload: dict) -> str:
    canonical_object(payload, "work organization")
    exact_keys(payload, ORGANIZATION_KEYS, "work organization")
    require(
        payload["schema"] == ORGANIZATION_SCHEMA,
        "work organization.schema: wrong protocol",
    )
    organization = _rappid(
        payload["organization_rappid"],
        "work organization.organization_rappid",
    )
    _rappid(payload["owner_rappid"], "work organization.owner_rappid")
    hive = _rappid(payload["hive_rappid"], "work organization.hive_rappid")
    require(organization != hive, "work organization: organization and Hive identities must differ")
    label(payload["world_id"], "work organization.world_id")
    https_uri(payload["release_scope"], "work organization.release_scope")
    hex64(payload["policy_sha256"], "work organization.policy_sha256")
    utc(payload["created_utc"], "work organization.created_utc")
    return particle_hash(payload)


def _catalog_item(value: object, where: str) -> dict:
    value = exact_keys(
        value,
        {"id", "kind", "address", "locator", "authority", "compatibility"},
        where,
    )
    label(value["id"], f"{where}.id")
    require(value["kind"] in CATALOG_ITEM_KINDS, f"{where}.kind: unsupported")
    _address(value["address"], f"{where}.address")
    _catalog_locator(value["locator"], f"{where}.locator")
    require(
        value["authority"] == "discovery-only",
        f"{where}.authority: catalog entries never grant authority",
    )
    compatibility = value["compatibility"]
    if value["kind"] == "portable-neuron":
        compatibility = exact_keys(
            compatibility,
            {"format", "mode", "verdict", "evidence_sha256"},
            f"{where}.compatibility",
        )
        require(
            compatibility["format"] in PORTABLE_NEURON_FORMATS,
            f"{where}.compatibility.format: unsupported Portable Neuron format",
        )
        require(
            compatibility["mode"] == "inert-data",
            f"{where}.compatibility.mode: Portable Neurons are inert typed data",
        )
        require(
            compatibility["verdict"] == "compatible",
            f"{where}.compatibility.verdict: incompatible Portable Neuron",
        )
        hex64(
            compatibility["evidence_sha256"],
            f"{where}.compatibility.evidence_sha256",
        )
    else:
        require(
            compatibility is None,
            f"{where}.compatibility: only Portable Neurons carry compatibility data",
        )
    return value


def _catalog_shape(payload: dict, organization_hash: str) -> str:
    canonical_object(payload, "work catalog")
    exact_keys(payload, CATALOG_KEYS, "work catalog")
    require(payload["schema"] == CATALOG_SCHEMA, "work catalog.schema: wrong protocol")
    require(
        payload["organization_payload_hash"] == organization_hash,
        "work catalog: organization binding mismatch",
    )
    utc(payload["created_utc"], "work catalog.created_utc")
    _optional_hex64(
        payload["previous_catalog_payload_hash"],
        "work catalog.previous_catalog_payload_hash",
    )
    items = payload["items"]
    require(isinstance(items, list), "work catalog.items: expected array")
    require(len(items) <= MAX_CATALOG_ITEMS, "work catalog.items: catalog is out of bounds")
    checked = [_catalog_item(item, f"work catalog.items[{index}]") for index, item in enumerate(items)]
    ids = [item["id"] for item in checked]
    require(ids == sorted(set(ids)), "work catalog.items: duplicate catalog item or unsorted id")
    addresses = [
        (item["kind"], item["address"]["space"], item["address"]["hash"])
        for item in checked
    ]
    require(
        len(addresses) == len(set(addresses)),
        "work catalog.items: duplicate catalog item address",
    )
    return particle_hash(payload)


def validate_catalog(
    payload: dict,
    organization: dict,
    previous_catalog: Optional[dict] = None,
) -> str:
    organization_hash = validate_organization(organization)
    catalog_hash = _catalog_shape(payload, organization_hash)
    previous_hash = payload["previous_catalog_payload_hash"]
    if previous_catalog is None:
        require(previous_hash is None, "work catalog: genesis catalog requires null predecessor")
    else:
        retained_hash = _catalog_shape(previous_catalog, organization_hash)
        require(
            previous_hash == retained_hash,
            "work catalog: predecessor binding mismatch",
        )
        require(
            utc(payload["created_utc"], "work catalog.created_utc")
            >= utc(previous_catalog["created_utc"], "previous work catalog.created_utc"),
            "work catalog: timestamp precedes predecessor",
        )
    return catalog_hash


def validate_vector(payload: dict, organization: dict) -> str:
    organization_hash = validate_organization(organization)
    canonical_object(payload, "work vector")
    exact_keys(payload, VECTOR_KEYS, "work vector")
    require(payload["schema"] == VECTOR_SCHEMA, "work vector.schema: wrong protocol")
    require(
        payload["organization_payload_hash"] == organization_hash,
        "work vector: organization binding mismatch",
    )
    observed = utc(payload["observed_utc"], "work vector.observed_utc")
    checkpoint = exact_keys(
        payload["hive_checkpoint"],
        {
            "registry_seq",
            "registry_hash",
            "hive_rappid",
            "mother_head_frame_hash",
            "catalog_hash",
        },
        "work vector.hive_checkpoint",
    )
    bounded_int(
        checkpoint["registry_seq"],
        "work vector.hive_checkpoint.registry_seq",
        0,
        UINT53_MAX,
    )
    hex64(checkpoint["registry_hash"], "work vector.hive_checkpoint.registry_hash")
    _rappid(checkpoint["hive_rappid"], "work vector.hive_checkpoint.hive_rappid")
    hex64(
        checkpoint["mother_head_frame_hash"],
        "work vector.hive_checkpoint.mother_head_frame_hash",
    )
    hex64(checkpoint["catalog_hash"], "work vector.hive_checkpoint.catalog_hash")
    require(
        checkpoint["hive_rappid"] == organization["hive_rappid"],
        "work vector: Hive binding mismatch",
    )
    head = _head(payload["mother_head"], "work vector.mother_head")
    require(
        head["stream_id"] == checkpoint["hive_rappid"],
        "work vector: Mother stream must equal the Hive RAPPID",
    )
    require(
        head["frame_hash"] == checkpoint["mother_head_frame_hash"],
        "work vector: checkpoint and Mother head differ",
    )
    require(
        observed >= utc(head["utc"], "work vector.mother_head.utc"),
        "work vector: observation precedes the signed Hive head",
    )
    _optional_hex64(
        payload["previous_vector_payload_hash"],
        "work vector.previous_vector_payload_hash",
    )
    return particle_hash(payload)


def advance_vector(
    retained: dict,
    current: dict,
    organization: dict,
    *,
    ancestry_verifier: Optional[Callable[[dict, dict], bool]],
) -> str:
    retained_hash = validate_vector(retained, organization)
    current_hash = validate_vector(current, organization)
    require(
        current["previous_vector_payload_hash"] == retained_hash,
        "work vector: retained high-water predecessor mismatch",
    )
    require(
        utc(current["observed_utc"], "work vector.observed_utc")
        >= utc(retained["observed_utc"], "retained work vector.observed_utc"),
        "work vector: observation time rollback",
    )

    old_checkpoint = retained["hive_checkpoint"]
    new_checkpoint = current["hive_checkpoint"]
    old_registry_seq = old_checkpoint["registry_seq"]
    new_registry_seq = new_checkpoint["registry_seq"]
    require(new_registry_seq >= old_registry_seq, "work vector: Hive registry rollback")
    if new_registry_seq == old_registry_seq:
        require(
            new_checkpoint["registry_hash"] == old_checkpoint["registry_hash"],
            "work vector: Hive registry same-sequence fork",
        )

    old_head = retained["mother_head"]
    new_head = current["mother_head"]
    require(new_head["seq"] >= old_head["seq"], "work vector: signed Hive head rollback")
    if new_head["seq"] == old_head["seq"]:
        require(
            _same(new_head, old_head),
            "work vector: signed Hive head same-sequence fork",
        )
        require(
            new_checkpoint["catalog_hash"] == old_checkpoint["catalog_hash"],
            "work vector: catalog fork at the retained Hive head",
        )
    else:
        require(
            callable(ancestry_verifier)
            and bool(ancestry_verifier(old_head, new_head)),
            "work vector: signed Hive ancestry does not extend the retained high-water",
        )
    return current_hash


def _rollback_shape(payload: dict, organization: dict) -> str:
    organization_hash = validate_organization(organization)
    canonical_object(payload, "work rollback")
    exact_keys(payload, ROLLBACK_KEYS, "work rollback")
    require(payload["schema"] == ROLLBACK_SCHEMA, "work rollback.schema: wrong protocol")
    require(
        payload["organization_payload_hash"] == organization_hash,
        "work rollback: organization binding mismatch",
    )
    utc(payload["created_utc"], "work rollback.created_utc")
    hex64(payload["release_payload_hash"], "work rollback.release_payload_hash")
    hex64(payload["artifact_sha256"], "work rollback.artifact_sha256")
    grail_id(payload["grail_id"], "work rollback.grail_id")
    hex64(payload["state_schema_sha256"], "work rollback.state_schema_sha256")
    _address(payload["snapshot"], "work rollback.snapshot")
    hex64(payload["restore_evidence_sha256"], "work rollback.restore_evidence_sha256")
    _immutable_locator(payload["locator"], "work rollback.locator")
    return particle_hash(payload)


def _state_schema(release: dict) -> dict:
    components = [
        component
        for component in release["components"]
        if component["kind"] == "state-schema"
    ]
    require(
        len(components) == 1,
        "work rollback: release requires exactly one state-schema component",
    )
    return components[0]


def _qualified_release(
    payload: dict,
    organization: dict,
    qualification_verifier: Optional[Callable[[dict, str], bool]],
    where: str,
) -> str:
    release_hash = C.validate_release_payload(payload)
    require(
        payload["release_scope"] == organization["release_scope"],
        f"{where}: release scope differs from the organization",
    )
    require(
        callable(qualification_verifier)
        and bool(qualification_verifier(payload, organization["policy_sha256"])),
        f"{where}: authenticated CI/CD qualification does not bind the organization policy",
    )
    return release_hash


def validate_rollback(
    payload: dict,
    organization: dict,
    rollback_release: dict,
    *,
    deployment: Optional[dict] = None,
    candidate_release: Optional[dict] = None,
    qualification_verifier: Optional[Callable[[dict, str], bool]] = None,
) -> str:
    rollback_hash = _rollback_shape(payload, organization)
    release_hash = _qualified_release(
        rollback_release,
        organization,
        qualification_verifier,
        "work rollback",
    )
    require(
        payload["release_payload_hash"] == release_hash,
        "work rollback: release binding mismatch",
    )
    require(
        payload["artifact_sha256"] == rollback_release["artifact"]["sha256"],
        "work rollback: artifact binding mismatch",
    )
    require(
        payload["grail_id"] == rollback_release["grail"]["grail_id"],
        "work rollback: Grail binding mismatch",
    )
    require(
        payload["state_schema_sha256"] == _state_schema(rollback_release)["sha256"],
        "work rollback: state-schema binding mismatch",
    )
    locator = payload["locator"]
    source = rollback_release["source"]
    require(
        locator["repository"] == source["repository"]
        and locator["object_format"] == source["object_format"]
        and locator["commit"] == source["commit"]
        and locator["path"] == rollback_release["artifact"]["entrypoint"],
        "work rollback: locator differs from the immutable release source",
    )
    if deployment is not None:
        require(candidate_release is not None, "work rollback: candidate release is required")
        _qualified_release(
            candidate_release,
            organization,
            qualification_verifier,
            "work rollback candidate",
        )
        D.validate_plan_payload(candidate_release, deployment)
        require(
            deployment["rollback_release_payload_hash"] == release_hash,
            "work rollback: deployment selects another rollback release",
        )
        require(
            deployment["state"]["previous_schema_sha256"]
            == payload["state_schema_sha256"],
            "work rollback: deployment state schema mismatch",
        )
        require(
            deployment["state"]["restore_evidence_sha256"]
            == payload["restore_evidence_sha256"],
            "work rollback: deployment restore evidence mismatch",
        )
    return rollback_hash


def migration_identifier(
    organization_payload_hash: str,
    source_workspace_rappid: str,
    target_workspace_rappid: str,
    target_release_payload_hash: str,
) -> str:
    hex64(organization_payload_hash, "migration identity.organization_payload_hash")
    _rappid(source_workspace_rappid, "migration identity.source_workspace_rappid")
    _rappid(target_workspace_rappid, "migration identity.target_workspace_rappid")
    hex64(target_release_payload_hash, "migration identity.target_release_payload_hash")
    return particle_hash(
        {
            "schema": "rapp-work/1-migration-identity",
            "organization_payload_hash": organization_payload_hash,
            "source_workspace_rappid": source_workspace_rappid,
            "target_workspace_rappid": target_workspace_rappid,
            "target_release_payload_hash": target_release_payload_hash,
        }
    )


def _migration_shape(payload: dict, organization: dict) -> str:
    organization_hash = validate_organization(organization)
    canonical_object(payload, "work migration")
    exact_keys(payload, MIGRATION_KEYS, "work migration")
    require(payload["schema"] == MIGRATION_SCHEMA, "work migration.schema: wrong protocol")
    require(
        payload["organization_payload_hash"] == organization_hash,
        "work migration: organization binding mismatch",
    )
    hex64(payload["migration_id"], "work migration.migration_id")
    created = utc(payload["created_utc"], "work migration.created_utc")
    require(payload["mode"] == "create-only", "work migration.mode: must be create-only")

    source = exact_keys(
        payload["source"],
        {"workspace_rappid", "world_id", "snapshot", "head"},
        "work migration.source",
    )
    source_rappid = _rappid(
        source["workspace_rappid"],
        "work migration.source.workspace_rappid",
    )
    require(
        source["world_id"] == organization["world_id"],
        "work migration: source crossed the organization world",
    )
    _address(source["snapshot"], "work migration.source.snapshot")
    source_head = _head(source["head"], "work migration.source.head")
    require(
        source_head["stream_id"] == source_rappid,
        "work migration: source head belongs to another workspace",
    )
    require(
        created >= utc(source_head["utc"], "work migration.source.head.utc"),
        "work migration: creation precedes source head",
    )

    target = exact_keys(
        payload["target"],
        {"workspace_rappid", "release_payload_hash", "vector_payload_hash"},
        "work migration.target",
    )
    target_rappid = _rappid(
        target["workspace_rappid"],
        "work migration.target.workspace_rappid",
    )
    require(
        target_rappid != source_rappid,
        "work migration: create-only target must have a fresh RAPPID",
    )
    hex64(
        target["release_payload_hash"],
        "work migration.target.release_payload_hash",
    )
    hex64(target["vector_payload_hash"], "work migration.target.vector_payload_hash")
    require(
        payload["migration_id"]
        == migration_identifier(
            organization_hash,
            source_rappid,
            target_rappid,
            target["release_payload_hash"],
        ),
        "work migration: migration_id does not reproduce",
    )

    item_ids = payload["catalog_item_ids"]
    require(isinstance(item_ids, list), "work migration.catalog_item_ids: expected array")
    require(
        len(item_ids) <= MAX_CATALOG_ITEMS,
        "work migration.catalog_item_ids: selection is out of bounds",
    )
    checked_ids = [
        label(value, f"work migration.catalog_item_ids[{index}]")
        for index, value in enumerate(item_ids)
    ]
    require(
        checked_ids == sorted(set(checked_ids)),
        "work migration.catalog_item_ids: must be unique and sorted",
    )
    hex64(payload["rollback_payload_hash"], "work migration.rollback_payload_hash")
    return particle_hash(payload)


def validate_migration(
    payload: dict,
    organization: dict,
    catalog: dict,
    vector: dict,
    target_release: dict,
    rollback: dict,
    *,
    source_head_verifier: Optional[Callable[[dict], bool]] = None,
    qualification_verifier: Optional[Callable[[dict, str], bool]] = None,
) -> str:
    migration_hash = _migration_shape(payload, organization)
    require(
        callable(source_head_verifier)
        and bool(source_head_verifier(payload["source"])),
        "work migration: source signed frame head was not authenticated",
    )
    catalog_hash = _catalog_shape(catalog, validate_organization(organization))
    del catalog_hash
    vector_hash = validate_vector(vector, organization)
    target_release_hash = _qualified_release(
        target_release,
        organization,
        qualification_verifier,
        "work migration target",
    )
    rollback_hash = _rollback_shape(rollback, organization)
    require(
        payload["target"]["release_payload_hash"] == target_release_hash,
        "work migration: target release binding mismatch",
    )
    require(
        payload["target"]["vector_payload_hash"] == vector_hash,
        "work migration: target Hive vector binding mismatch",
    )
    require(
        payload["rollback_payload_hash"] == rollback_hash,
        "work migration: rollback binding mismatch",
    )
    require(
        _same(payload["source"]["snapshot"], rollback["snapshot"]),
        "work migration: rollback snapshot does not preserve the source",
    )
    catalog_ids = {item["id"] for item in catalog["items"]}
    require(
        set(payload["catalog_item_ids"]) <= catalog_ids,
        "work migration: unknown catalog item",
    )
    return migration_hash


def _custody(value: object, where: str) -> dict:
    value = exact_keys(
        value,
        {"holder_rappid", "key_rappid", "evidence_sha256"},
        where,
    )
    _rappid(value["holder_rappid"], f"{where}.holder_rappid")
    _rappid(value["key_rappid"], f"{where}.key_rappid")
    hex64(value["evidence_sha256"], f"{where}.evidence_sha256")
    return value


def validate_receipt(payload: dict, organization: dict) -> str:
    organization_hash = validate_organization(organization)
    canonical_object(payload, "work receipt")
    exact_keys(payload, RECEIPT_KEYS, "work receipt")
    require(payload["schema"] == RECEIPT_SCHEMA, "work receipt.schema: wrong protocol")
    require(
        payload["organization_payload_hash"] == organization_hash,
        "work receipt: organization binding mismatch",
    )
    require(payload["receipt_type"] in RECEIPT_TYPES, "work receipt.receipt_type: unsupported")
    subject = exact_keys(payload["subject"], {"kind", "address"}, "work receipt.subject")
    require(subject["kind"] in RECEIPT_SUBJECT_KINDS, "work receipt.subject.kind: unsupported")
    _address(subject["address"], "work receipt.subject.address")
    utc(payload["issued_utc"], "work receipt.issued_utc")
    require(payload["result"] in {"verified", "failed"}, "work receipt.result: unsupported")
    _addresses(
        payload["evidence"],
        "work receipt.evidence",
        nonempty=payload["result"] == "verified",
    )

    if payload["receipt_type"] == "migration-completed":
        require(
            subject["kind"] == "migration"
            and subject["address"]["space"] == "rapp/1:particle"
            and payload["result"] == "verified",
            "work receipt: completed migration subject/result mismatch",
        )
        migration = exact_keys(
            payload["migration"],
            {
                "migration_id",
                "source_snapshot_hash",
                "source_head_frame_hash",
                "target_workspace_rappid",
                "target_release_payload_hash",
                "target_vector_payload_hash",
                "rollback_payload_hash",
            },
            "work receipt.migration",
        )
        for key in (
            "migration_id",
            "source_snapshot_hash",
            "source_head_frame_hash",
            "target_release_payload_hash",
            "target_vector_payload_hash",
            "rollback_payload_hash",
        ):
            hex64(migration[key], f"work receipt.migration.{key}")
        _rappid(
            migration["target_workspace_rappid"],
            "work receipt.migration.target_workspace_rappid",
        )
        _custody(payload["custody"], "work receipt.custody")
    else:
        require(
            payload["migration"] is None and payload["custody"] is None,
            "work receipt: non-migration receipt cannot claim migration custody",
        )
        if payload["receipt_type"] == "catalog-verified":
            require(
                subject["kind"] in CATALOG_ITEM_KINDS | {"catalog"},
                "work receipt: catalog receipt has the wrong subject",
            )
        else:
            require(
                subject["kind"] == "release",
                "work receipt: release receipt has the wrong subject",
            )
    return particle_hash(payload)


def validate_migration_receipt(
    receipt: dict,
    migration: dict,
    organization: dict,
    *,
    custody_verifier: Optional[Callable[[dict], bool]],
) -> str:
    receipt_hash = validate_receipt(receipt, organization)
    migration_hash = _migration_shape(migration, organization)
    require(
        receipt["receipt_type"] == "migration-completed"
        and receipt["subject"]["address"]
        == {"space": "rapp/1:particle", "hash": migration_hash},
        "work receipt: completed migration binding mismatch",
    )
    details = receipt["migration"]
    require(
        details
        == {
            "migration_id": migration["migration_id"],
            "source_snapshot_hash": migration["source"]["snapshot"]["hash"],
            "source_head_frame_hash": migration["source"]["head"]["frame_hash"],
            "target_workspace_rappid": migration["target"]["workspace_rappid"],
            "target_release_payload_hash": migration["target"]["release_payload_hash"],
            "target_vector_payload_hash": migration["target"]["vector_payload_hash"],
            "rollback_payload_hash": migration["rollback_payload_hash"],
        },
        "work receipt: completed migration evidence changed",
    )
    require(
        utc(receipt["issued_utc"], "work receipt.issued_utc")
        >= utc(migration["created_utc"], "work migration.created_utc"),
        "work receipt: completion precedes migration creation",
    )
    require(
        callable(custody_verifier)
        and bool(custody_verifier(receipt["custody"])),
        "work receipt: completed migration custody is missing or unverified",
    )
    return receipt_hash


def validate_observation(
    payload: dict,
    organization: dict,
    release: dict,
    deployment: dict,
    vector: dict,
    *,
    previous_observation: Optional[dict] = None,
    health_verifier: Optional[Callable[[dict], bool]] = None,
    qualification_verifier: Optional[Callable[[dict, str], bool]] = None,
) -> str:
    organization_hash = validate_organization(organization)
    release_hash = _qualified_release(
        release,
        organization,
        qualification_verifier,
        "work observation",
    )
    deployment_hash = D.validate_plan_payload(release, deployment)
    vector_hash = validate_vector(vector, organization)
    canonical_object(payload, "work observation")
    exact_keys(payload, OBSERVATION_KEYS, "work observation")
    require(
        payload["schema"] == OBSERVATION_SCHEMA,
        "work observation.schema: wrong protocol",
    )
    require(
        payload["organization_payload_hash"] == organization_hash,
        "work observation: organization binding mismatch",
    )
    require(
        payload["release_payload_hash"] == release_hash,
        "work observation: release binding mismatch",
    )
    require(
        payload["deployment_payload_hash"] == deployment_hash,
        "work observation: deployment binding mismatch",
    )
    require(
        payload["vector_payload_hash"] == vector_hash,
        "work observation: Hive vector binding mismatch",
    )
    observed = utc(payload["observed_utc"], "work observation.observed_utc")
    require(
        observed >= utc(vector["observed_utc"], "work vector.observed_utc"),
        "work observation: release observation predates the Hive vector",
    )
    require(
        payload["verdict"] in {"healthy", "unhealthy", "indeterminate"},
        "work observation.verdict: unsupported",
    )
    _addresses(payload["evidence"], "work observation.evidence", nonempty=True)
    previous_hash = _optional_hex64(
        payload["previous_observation_payload_hash"],
        "work observation.previous_observation_payload_hash",
    )
    if previous_observation is None:
        require(
            previous_hash is None,
            "work observation: first retained observation requires null predecessor",
        )
    else:
        require(
            previous_hash == particle_hash(previous_observation),
            "work observation: predecessor binding mismatch",
        )
        require(
            observed
            >= utc(
                previous_observation["observed_utc"],
                "previous work observation.observed_utc",
            ),
            "work observation: timestamp precedes predecessor",
        )
    if payload["verdict"] == "healthy":
        require(
            callable(health_verifier) and bool(health_verifier(payload)),
            "work observation: healthy verdict lacks authorized RAPP Deploy health",
        )
    return particle_hash(payload)


def authorize_frame(
    frame: dict,
    *,
    expected_kind: Optional[str],
    head: Optional[dict],
    stream_id: str,
    registered_kinds: set,
    signature_verifier,
    authorization_verifier,
    organization: Optional[dict] = None,
) -> dict:
    kind = frame.get("kind")
    require(kind in KIND_SCHEMAS, "rapp-work frame: kind is not one of the closed work kinds")
    if expected_kind is not None:
        require(kind == expected_kind, "rapp-work frame: unexpected work kind")
    require(
        WORK_KINDS <= set(registered_kinds),
        "rapp-work frame: adopting registry did not register the complete closed kind set",
    )
    require(frame.get("sig") is not None, "rapp-work frame: authoritative payload must be signed")
    if head is None:
        require(
            kind == "work.organization",
            "rapp-work frame: organization declaration must be the body-stream genesis",
        )
    else:
        require(
            kind != "work.organization",
            "rapp-work frame: organization declaration cannot be appended twice",
        )
    if organization is not None:
        organization_hash = validate_organization(organization)
        require(
            stream_id == organization["organization_rappid"],
            "rapp-work frame: stream is not the organization body",
        )
    payload = authoritative_frame_payload(
        frame,
        expected_schema=KIND_SCHEMAS[kind],
        purpose=f"rapp-work-{kind}",
        head=head,
        stream_id=stream_id,
        registered_kinds=registered_kinds,
        signature_verifier=signature_verifier,
        authorization_verifier=authorization_verifier,
    )
    if organization is not None:
        if kind == "work.organization":
            require(
                payload["organization_rappid"] == stream_id
                and _same(payload, organization),
                "rapp-work frame: organization genesis binding mismatch",
            )
        else:
            require(
                payload.get("organization_payload_hash") == organization_hash,
                "rapp-work frame: payload belongs to another organization",
            )
    return payload


def required_registry_entries(spec_hash: str) -> list:
    hex64(spec_hash, "rapp-work spec hash")
    entries = [
        {
            "type": "protocol",
            "name": PROFILE,
            "spec_repo": CANONICAL_REPOSITORY,
            "spec_path": SPEC_PATH,
            "spec_hash": spec_hash,
            "deprecated": False,
        }
    ]
    entries.extend(
        {
            "type": "kind",
            "kind": kind,
            "family": "body",
            "deprecated": False,
        }
        for kind in sorted(WORK_KINDS)
    )
    return entries


def validate_registry_adoption(
    registry,
    spec_hash: str,
    *,
    dependency_verifier: Optional[Callable[[str, dict], bool]] = None,
) -> bool:
    required = required_registry_entries(spec_hash)
    active_protocols = [
        entry
        for entry in registry.entries
        if entry.get("type") == "protocol" and entry.get("deprecated") is False
    ]
    work_entries = [entry for entry in active_protocols if entry.get("name") == PROFILE]
    require(
        len(work_entries) == 1 and work_entries[0] == required[0],
        "rapp-work registry: canonical protocol pin is absent or differs",
    )
    require(
        callable(dependency_verifier),
        "rapp-work registry: authenticated dependency verifier is required",
    )
    for name in sorted(DEPENDENCY_PROTOCOLS):
        matches = [entry for entry in active_protocols if entry.get("name") == name]
        require(
            len(matches) == 1,
            f"rapp-work registry: exactly one active {name} pin is required",
        )
        require(
            bool(dependency_verifier(name, matches[0])),
            f"rapp-work registry: {name} pin does not match authenticated canonical authority",
        )
    for kind in WORK_KINDS:
        require(
            registry.family(kind) == "body",
            f"rapp-work registry: {kind} is not a live body kind",
        )
    unknown_work_kinds = {
        entry["kind"]
        for entry in registry.entries
        if entry.get("type") == "kind"
        and entry.get("deprecated") is False
        and isinstance(entry.get("kind"), str)
        and entry["kind"].startswith("work.")
        and entry["kind"] not in WORK_KINDS
    }
    require(
        not unknown_work_kinds,
        f"rapp-work registry: unrecognized live work kinds {sorted(unknown_work_kinds)}",
    )
    return True


class WorkLedger:
    """Small stateful gate for high-water, create-only, and bounded-history rules."""

    def __init__(self, organization: dict):
        self.organization = copy.deepcopy(organization)
        self.organization_payload_hash = validate_organization(organization)
        self.vector = None
        self.rollbacks = {}
        self.migrations = {}
        self.targets = {}
        self.completed = {}
        self.observations = []

    def accept_vector(
        self,
        payload: dict,
        *,
        hive_verifier: Optional[Callable[[dict, dict], bool]],
        ancestry_verifier: Optional[Callable[[dict, dict], bool]] = None,
    ) -> str:
        vector_hash = validate_vector(payload, self.organization)
        require(
            callable(hive_verifier)
            and bool(hive_verifier(payload["hive_checkpoint"], payload["mother_head"])),
            "work vector: signed rapp-hive/1 checkpoint was not authenticated",
        )
        if self.vector is not None:
            advance_vector(
                self.vector,
                payload,
                self.organization,
                ancestry_verifier=ancestry_verifier,
            )
        self.vector = copy.deepcopy(payload)
        return vector_hash

    def register_rollback(
        self,
        payload: dict,
        rollback_release: dict,
        *,
        deployment: Optional[dict] = None,
        candidate_release: Optional[dict] = None,
        qualification_verifier: Optional[Callable[[dict, str], bool]] = None,
    ) -> str:
        rollback_hash = validate_rollback(
            payload,
            self.organization,
            rollback_release,
            deployment=deployment,
            candidate_release=candidate_release,
            qualification_verifier=qualification_verifier,
        )
        release_hash = payload["release_payload_hash"]
        previous = self.rollbacks.get(release_hash)
        require(
            previous is None or previous == rollback_hash,
            "work rollback: immutable rollback target was rebound",
        )
        self.rollbacks[release_hash] = rollback_hash
        return rollback_hash

    def register_migration(
        self,
        payload: dict,
        catalog: dict,
        vector: dict,
        target_release: dict,
        rollback: dict,
        *,
        source_head_verifier: Optional[Callable[[dict], bool]] = None,
        target_absence_verifier: Optional[Callable[[str], bool]] = None,
        qualification_verifier: Optional[Callable[[dict, str], bool]] = None,
    ) -> str:
        migration_hash = validate_migration(
            payload,
            self.organization,
            catalog,
            vector,
            target_release,
            rollback,
            source_head_verifier=source_head_verifier,
            qualification_verifier=qualification_verifier,
        )
        require(
            self.vector is not None
            and particle_hash(self.vector) == payload["target"]["vector_payload_hash"],
            "work migration: target vector is not the accepted Hive high-water",
        )
        require(
            self.rollbacks.get(rollback["release_payload_hash"])
            == payload["rollback_payload_hash"],
            "work migration: rollback target is not retained and immutable",
        )
        migration_id = payload["migration_id"]
        previous = self.migrations.get(migration_id)
        require(
            previous is None or previous["hash"] == migration_hash,
            "work migration: create-only migration changed under one migration_id",
        )
        target_rappid = payload["target"]["workspace_rappid"]
        target_owner = self.targets.get(target_rappid)
        require(
            target_owner is None or target_owner == migration_id,
            "work migration: create-only target identity was reused",
        )
        if previous is None:
            require(
                callable(target_absence_verifier)
                and bool(target_absence_verifier(target_rappid)),
                "work migration: target identity already exists",
            )
            self.migrations[migration_id] = {
                "hash": migration_hash,
                "payload": copy.deepcopy(payload),
            }
            self.targets[target_rappid] = migration_id
        return migration_hash

    def record_observation(
        self,
        payload: dict,
        release: dict,
        deployment: dict,
        vector: dict,
        *,
        health_verifier: Optional[Callable[[dict], bool]] = None,
        qualification_verifier: Optional[Callable[[dict, str], bool]] = None,
    ) -> str:
        previous = self.observations[-1] if self.observations else None
        observation_hash = validate_observation(
            payload,
            self.organization,
            release,
            deployment,
            vector,
            previous_observation=previous,
            health_verifier=health_verifier,
            qualification_verifier=qualification_verifier,
        )
        require(
            self.vector is not None
            and particle_hash(self.vector) == payload["vector_payload_hash"],
            "work observation: vector is not the accepted Hive high-water",
        )
        if any(particle_hash(item) == observation_hash for item in self.observations):
            return observation_hash
        require(
            len(self.observations) < MAX_RELEASE_OBSERVATIONS,
            "work observation: retained release observations exceed the bounded profile",
        )
        self.observations.append(copy.deepcopy(payload))
        return observation_hash

    def recover_completed_migration(
        self,
        *,
        migration: dict,
        catalog: dict,
        vector: dict,
        target_release: dict,
        rollback: dict,
        receipt_frame: dict,
        frame_head: Optional[dict],
        observed_source: dict,
        registered_kinds: set,
        signature_verifier,
        authorization_verifier,
        evidence_verifier: Optional[Callable[[dict], bool]],
        custody_verifier: Optional[Callable[[dict], bool]],
        source_head_verifier: Optional[Callable[[dict], bool]],
        target_absence_verifier: Optional[Callable[[str], bool]],
        qualification_verifier: Optional[Callable[[dict, str], bool]],
        mutate: Callable[[dict], object],
    ) -> object:
        migration_hash = validate_migration(
            migration,
            self.organization,
            catalog,
            vector,
            target_release,
            rollback,
            source_head_verifier=source_head_verifier,
            qualification_verifier=qualification_verifier,
        )
        retained = self.migrations.get(migration["migration_id"])
        require(
            retained is not None and retained["hash"] == migration_hash,
            "work migration: completed migration has no retained create-only intent",
        )
        require(
            self.vector is not None
            and particle_hash(self.vector) == migration["target"]["vector_payload_hash"],
            "work migration: retained Hive high-water changed before completion",
        )
        require(
            self.rollbacks.get(rollback["release_payload_hash"])
            == migration["rollback_payload_hash"],
            "work migration: retained rollback target changed before completion",
        )
        receipt = authorize_frame(
            receipt_frame,
            expected_kind="work.receipt",
            head=frame_head,
            stream_id=self.organization["organization_rappid"],
            registered_kinds=registered_kinds,
            signature_verifier=signature_verifier,
            authorization_verifier=authorization_verifier,
            organization=self.organization,
        )
        receipt_hash = validate_migration_receipt(
            receipt,
            migration,
            self.organization,
            custody_verifier=custody_verifier,
        )
        require(
            _same(observed_source, migration["source"]),
            "work migration: source changed during completed-migration recovery",
        )
        require(
            callable(source_head_verifier)
            and bool(source_head_verifier(observed_source)),
            "work migration: source signed frame head was not reauthenticated",
        )
        require(
            callable(evidence_verifier)
            and all(bool(evidence_verifier(item)) for item in receipt["evidence"]),
            "work migration: completed evidence is missing or unverified",
        )
        prior = self.completed.get(migration["migration_id"])
        require(
            prior is None or prior == receipt_hash,
            "work migration: completed receipt changed",
        )
        if prior is not None:
            return {"status": "replayed", "receipt_payload_hash": receipt_hash}
        target_rappid = migration["target"]["workspace_rappid"]
        require(
            self.targets.get(target_rappid) == migration["migration_id"],
            "work migration: target identity binding changed",
        )
        require(
            callable(target_absence_verifier)
            and bool(target_absence_verifier(target_rappid)),
            "work migration: target identity exists before create-only mutation",
        )
        result = mutate(
            {
                "migration_payload_hash": migration_hash,
                "receipt_payload_hash": receipt_hash,
                "target_workspace_rappid": migration["target"]["workspace_rappid"],
                "target_release_payload_hash": migration["target"]["release_payload_hash"],
            }
        )
        self.completed[migration["migration_id"]] = receipt_hash
        return result
