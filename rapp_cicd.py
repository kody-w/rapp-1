#!/usr/bin/env python3
"""Reference validator for the RAPP CI/CD protocol profile."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

import rapp as R
from rapp_profile import (
    authoritative_frame_payload,
    boolean,
    canonical_object,
    exact_keys,
    grail_id,
    hex64,
    https_uri,
    label,
    load_json,
    object_id,
    particle_hash,
    positive_int,
    relative_path,
    require,
    text,
    unique_strings,
    utc,
)


RELEASE_SCHEMA = "rapp-cicd/1-release"
POLICY_SCHEMA = "rapp-cicd/1-policy"
EVIDENCE_SCHEMA = "rapp-cicd/1-evidence"
PROMOTION_SCHEMA = "rapp-cicd/1-promotion"

RELEASE_KEYS = {
    "schema",
    "release_scope",
    "created_utc",
    "source",
    "artifact",
    "grail",
    "components",
    "lineage",
}
POLICY_KEYS = {"schema", "release_scope", "created_utc", "stages"}
EVIDENCE_KEYS = {
    "schema",
    "release_payload_hash",
    "policy_payload_hash",
    "stage_id",
    "stage_class",
    "environment_sha256",
    "started_utc",
    "completed_utc",
    "artifact_sha256",
    "grail_id",
    "checks",
    "result",
    "previous_evidence_payload_hash",
}
PROMOTION_KEYS = {
    "schema",
    "release_payload_hash",
    "policy_payload_hash",
    "from_stage_id",
    "to_stage_id",
    "evidence_payload_hash",
    "decision",
    "reason_code",
    "decided_utc",
}
GRAIL_BINDING_KEYS = {
    "type",
    "release_scope",
    "grail_id",
    "repository",
    "immutable_ref",
    "object_format",
    "commit",
    "path",
    "mode",
    "blob",
    "sha256",
    "size_bytes",
    "activated_utc",
    "predecessor",
    "declared_by",
    "sig",
}

STAGE_CLASS_ORDER = {
    "development": 0,
    "test": 1,
    "canary": 2,
    "qualification": 3,
    "preprod": 4,
    "production": 5,
}
PREPROD_CHECKS = {
    "exact-candidate",
    "grail-kernel",
    "dependency-integrity",
    "supply-chain",
    "security",
    "privacy",
    "tenant-isolation",
    "model-behavior",
    "capacity",
    "failover",
    "authenticated-soak",
    "rollback-rehearsal",
    "restore-rehearsal",
    "state-compatibility",
}
CANARY_CHECKS = {"grail-kernel", "product", "autonomous", "security-smoke"}


def validate_grail_binding(payload: dict) -> dict:
    canonical_object(payload, "grail binding")
    exact_keys(payload, GRAIL_BINDING_KEYS, "grail binding")
    require(payload["type"] == "grail-kernel", "grail binding.type: expected grail-kernel")
    https_uri(payload["release_scope"], "grail binding.release_scope")
    grail_id(payload["grail_id"], "grail binding.grail_id")
    https_uri(payload["repository"], "grail binding.repository")
    require(
        isinstance(payload["immutable_ref"], str) and payload["immutable_ref"].startswith("refs/tags/"),
        "grail binding.immutable_ref: expected full tag ref",
    )
    require(payload["object_format"] in ("sha1", "sha256"), "grail binding.object_format: unsupported")
    object_id(payload["commit"], payload["object_format"], "grail binding.commit")
    relative_path(payload["path"], "grail binding.path")
    require(payload["mode"] in ("100644", "100755"), "grail binding.mode: unsupported")
    object_id(payload["blob"], payload["object_format"], "grail binding.blob")
    hex64(payload["sha256"], "grail binding.sha256")
    positive_int(payload["size_bytes"], "grail binding.size_bytes")
    utc(payload["activated_utc"], "grail binding.activated_utc")
    if payload["predecessor"] is not None:
        grail_id(payload["predecessor"], "grail binding.predecessor")
    require(R.rappid_valid(payload["declared_by"]), "grail binding.declared_by: invalid rappid")
    text(payload["sig"], "grail binding.sig", maximum=8192)
    return payload


def validate_release_payload(payload: dict) -> str:
    canonical_object(payload, "release")
    exact_keys(payload, RELEASE_KEYS, "release")
    require(payload["schema"] == RELEASE_SCHEMA, "release.schema: wrong protocol")
    https_uri(payload["release_scope"], "release.release_scope")
    utc(payload["created_utc"], "release.created_utc")

    source = exact_keys(
        payload["source"],
        {"repository", "object_format", "commit", "tree"},
        "release.source",
    )
    https_uri(source["repository"], "release.source.repository")
    require(source["object_format"] in ("sha1", "sha256"), "release.source.object_format: unsupported")
    object_id(source["commit"], source["object_format"], "release.source.commit")
    object_id(source["tree"], source["object_format"], "release.source.tree")

    artifact = exact_keys(
        payload["artifact"],
        {"sha256", "size_bytes", "media_type", "entrypoint"},
        "release.artifact",
    )
    hex64(artifact["sha256"], "release.artifact.sha256")
    positive_int(artifact["size_bytes"], "release.artifact.size_bytes")
    text(artifact["media_type"], "release.artifact.media_type", maximum=128)
    relative_path(artifact["entrypoint"], "release.artifact.entrypoint")

    grail = exact_keys(
        payload["grail"],
        {"grail_id", "path", "sha256", "size_bytes"},
        "release.grail",
    )
    grail_id(grail["grail_id"], "release.grail.grail_id")
    relative_path(grail["path"], "release.grail.path")
    hex64(grail["sha256"], "release.grail.sha256")
    positive_int(grail["size_bytes"], "release.grail.size_bytes")

    components = payload["components"]
    require(isinstance(components, list) and components, "release.components: expected non-empty array")
    identities = set()
    kernels = []
    for index, component in enumerate(components):
        where = f"release.components[{index}]"
        component = exact_keys(component, {"kind", "name", "version", "sha256", "mutable"}, where)
        label(component["kind"], f"{where}.kind")
        text(component["name"], f"{where}.name", maximum=128)
        text(component["version"], f"{where}.version", maximum=128)
        hex64(component["sha256"], f"{where}.sha256")
        boolean(component["mutable"], f"{where}.mutable")
        identity = (component["kind"], component["name"])
        require(identity not in identities, f"{where}: duplicate component identity")
        identities.add(identity)
        if component["kind"] == "kernel":
            kernels.append(component)
    require(len(kernels) == 1, "release.components: exactly one kernel component is required")
    require(kernels[0]["sha256"] == grail["sha256"], "release.components: kernel digest must equal Grail digest")
    require(not kernels[0]["mutable"], "release.components: kernel must be immutable")

    lineage = exact_keys(payload["lineage"], {"mode", "parents"}, "release.lineage")
    require(lineage["mode"] in ("seed", "offspring", "cross"), "release.lineage.mode: unsupported")
    parents = lineage["parents"]
    require(isinstance(parents, list), "release.lineage.parents: expected array")
    checked_parents = []
    for index, parent in enumerate(parents):
        where = f"release.lineage.parents[{index}]"
        parent = exact_keys(parent, {"space", "hash"}, where)
        require(
            parent["space"] in ("rapp/1:particle", "rapp/1:egg-manifest"),
            f"{where}.space: unsupported",
        )
        hex64(parent["hash"], f"{where}.hash")
        checked_parents.append((parent["space"], parent["hash"]))
    require(checked_parents == sorted(set(checked_parents)), "release.lineage.parents: must be unique and sorted")
    expected_count = {"seed": 0, "offspring": 1}.get(lineage["mode"])
    if expected_count is not None:
        require(len(parents) == expected_count, f"release.lineage: {lineage['mode']} requires {expected_count} parents")
    else:
        require(len(parents) >= 2, "release.lineage: cross requires at least two parents")
    return particle_hash(payload)


def validate_release(payload: dict, grail_binding: dict) -> str:
    release_hash = validate_release_payload(payload)
    binding = validate_grail_binding(grail_binding)
    require(payload["release_scope"] == binding["release_scope"], "release: Grail release scope mismatch")
    require(payload["grail"]["grail_id"] == binding["grail_id"], "release: authenticated Grail identity mismatch")
    require(payload["grail"]["path"] == binding["path"], "release: authenticated Grail path mismatch")
    require(payload["grail"]["sha256"] == binding["sha256"], "release: authenticated Grail digest mismatch")
    require(payload["grail"]["size_bytes"] == binding["size_bytes"], "release: authenticated Grail size mismatch")
    return release_hash


def validate_policy(payload: dict) -> str:
    canonical_object(payload, "policy")
    exact_keys(payload, POLICY_KEYS, "policy")
    require(payload["schema"] == POLICY_SCHEMA, "policy.schema: wrong protocol")
    https_uri(payload["release_scope"], "policy.release_scope")
    utc(payload["created_utc"], "policy.created_utc")
    stages = payload["stages"]
    require(isinstance(stages, list) and stages, "policy.stages: expected non-empty array")

    seen_ids = set()
    classes = []
    for index, stage in enumerate(stages):
        where = f"policy.stages[{index}]"
        stage = exact_keys(
            stage,
            {
                "id",
                "class",
                "required_checks",
                "minimum_soak_seconds",
                "maximum_evidence_age_seconds",
                "approval",
            },
            where,
        )
        stage_id = label(stage["id"], f"{where}.id")
        require(stage_id not in seen_ids, f"{where}.id: duplicate stage")
        seen_ids.add(stage_id)
        require(stage["class"] in STAGE_CLASS_ORDER, f"{where}.class: unsupported")
        classes.append(stage["class"])
        checks = unique_strings(stage["required_checks"], f"{where}.required_checks", labels=True)
        require(checks, f"{where}.required_checks: at least one check is required")
        positive_int(stage["minimum_soak_seconds"], f"{where}.minimum_soak_seconds", allow_zero=True)
        positive_int(stage["maximum_evidence_age_seconds"], f"{where}.maximum_evidence_age_seconds")
        require(stage["approval"] in ("automatic", "owner"), f"{where}.approval: unsupported")

    orders = [STAGE_CLASS_ORDER[value] for value in classes]
    require(orders == sorted(orders), "policy.stages: stage classes must be monotonic")
    require(classes[0] == "development", "policy.stages: first stage must be development")
    require(classes[-1] == "production", "policy.stages: last stage must be production")
    for required in ("test", "canary", "qualification", "preprod"):
        require(required in classes, f"policy.stages: missing required {required} class")
    require(
        all(classes.count(value) == 1 for value in ("development", "test", "canary", "preprod", "production")),
        "policy.stages: only qualification may repeat",
    )

    canary = next(stage for stage in stages if stage["class"] == "canary")
    require(
        CANARY_CHECKS <= set(canary["required_checks"]),
        f"policy canary: missing checks {sorted(CANARY_CHECKS - set(canary['required_checks']))}",
    )
    preprod = next(stage for stage in stages if stage["class"] == "preprod")
    require(
        PREPROD_CHECKS <= set(preprod["required_checks"]),
        f"policy preprod: missing checks {sorted(PREPROD_CHECKS - set(preprod['required_checks']))}",
    )
    require(preprod["minimum_soak_seconds"] > 0, "policy preprod: soak must be non-zero")
    require(stages[-1]["approval"] == "owner", "policy production: owner approval is required")
    return particle_hash(payload)


def _evidence_shape(payload: dict) -> tuple[dict[str, str], object, object]:
    canonical_object(payload, "evidence")
    exact_keys(payload, EVIDENCE_KEYS, "evidence")
    require(payload["schema"] == EVIDENCE_SCHEMA, "evidence.schema: wrong protocol")
    hex64(payload["release_payload_hash"], "evidence.release_payload_hash")
    hex64(payload["policy_payload_hash"], "evidence.policy_payload_hash")
    label(payload["stage_id"], "evidence.stage_id")
    require(payload["stage_class"] in STAGE_CLASS_ORDER, "evidence.stage_class: unsupported")
    hex64(payload["environment_sha256"], "evidence.environment_sha256")
    started = utc(payload["started_utc"], "evidence.started_utc")
    completed = utc(payload["completed_utc"], "evidence.completed_utc")
    require(completed >= started, "evidence: completed_utc precedes started_utc")
    hex64(payload["artifact_sha256"], "evidence.artifact_sha256")
    grail_id(payload["grail_id"], "evidence.grail_id")
    require(payload["result"] in ("pass", "fail"), "evidence.result: expected pass or fail")
    previous = payload["previous_evidence_payload_hash"]
    if previous is not None:
        hex64(previous, "evidence.previous_evidence_payload_hash")

    checks = payload["checks"]
    require(isinstance(checks, list), "evidence.checks: expected array")
    statuses = {}
    for index, check in enumerate(checks):
        where = f"evidence.checks[{index}]"
        check = exact_keys(check, {"id", "status", "evidence_sha256"}, where)
        check_id = label(check["id"], f"{where}.id")
        require(check_id not in statuses, f"{where}.id: duplicate check")
        require(check["status"] in ("pass", "fail"), f"{where}.status: expected pass or fail")
        hex64(check["evidence_sha256"], f"{where}.evidence_sha256")
        statuses[check_id] = check["status"]
    return statuses, started, completed


def validate_evidence(
    release: dict,
    grail_binding: dict,
    policy: dict,
    payload: dict,
    previous: dict | None = None,
) -> str:
    release_hash = validate_release(release, grail_binding)
    policy_hash = validate_policy(policy)
    statuses, started, completed = _evidence_shape(payload)
    require(payload["release_payload_hash"] == release_hash, "evidence: release binding mismatch")
    require(payload["policy_payload_hash"] == policy_hash, "evidence: policy binding mismatch")
    require(payload["artifact_sha256"] == release["artifact"]["sha256"], "evidence: artifact drift")
    require(payload["grail_id"] == release["grail"]["grail_id"], "evidence: kernel-drift")
    require(policy["release_scope"] == release["release_scope"], "evidence: release scope mismatch")

    stage_index = next(
        (index for index, stage in enumerate(policy["stages"]) if stage["id"] == payload["stage_id"]),
        None,
    )
    require(stage_index is not None, "evidence.stage_id: not present in policy")
    stage = policy["stages"][stage_index]
    require(payload["stage_class"] == stage["class"], "evidence.stage_class: policy mismatch")
    required_checks = set(stage["required_checks"])
    checks_pass = required_checks <= set(statuses) and all(value == "pass" for value in statuses.values())
    soak_pass = (completed - started).total_seconds() >= stage["minimum_soak_seconds"]
    expected_result = "pass" if checks_pass and soak_pass else "fail"
    require(payload["result"] == expected_result, f"evidence.result: must be {expected_result}")

    if stage_index == 0:
        require(previous is None, "evidence: development stage cannot have predecessor input")
        require(payload["previous_evidence_payload_hash"] is None, "evidence: development predecessor must be null")
    else:
        require(previous is not None, "evidence: previous stage evidence is required")
        _, _, previous_completed = _evidence_shape(previous)
        prior_stage = policy["stages"][stage_index - 1]
        require(previous["stage_id"] == prior_stage["id"], "evidence: skipped or reordered stage")
        require(previous["stage_class"] == prior_stage["class"], "evidence: predecessor class mismatch")
        require(previous["release_payload_hash"] == release_hash, "evidence: predecessor release mismatch")
        require(previous["policy_payload_hash"] == policy_hash, "evidence: predecessor policy mismatch")
        require(previous["result"] == "pass", "evidence: predecessor did not pass")
        require(started >= previous_completed, "evidence: stage started before predecessor completed")
        require(
            payload["previous_evidence_payload_hash"] == particle_hash(previous),
            "evidence: predecessor hash mismatch",
        )
    return particle_hash(payload)


def validate_evidence_chain(
    release: dict,
    grail_binding: dict,
    policy: dict,
    evidences: list[dict],
    *,
    terminal_stage_id: str | None = None,
) -> list[str]:
    validate_release(release, grail_binding)
    validate_policy(policy)
    require(evidences, "evidence chain: at least one record is required")
    require(len(evidences) <= len(policy["stages"]), "evidence chain: too many records")
    if terminal_stage_id is not None:
        terminal_index = next(
            (index for index, stage in enumerate(policy["stages"]) if stage["id"] == terminal_stage_id),
            None,
        )
        require(terminal_index is not None, "evidence chain: terminal stage not in policy")
        require(len(evidences) == terminal_index + 1, "evidence chain: incomplete or excessive prefix")
    hashes = []
    previous = None
    for index, evidence in enumerate(evidences):
        require(
            evidence["stage_id"] == policy["stages"][index]["id"],
            "evidence chain: stage does not match policy position",
        )
        hashes.append(validate_evidence(release, grail_binding, policy, evidence, previous))
        previous = evidence
    return hashes


def validate_promotion(
    release: dict,
    grail_binding: dict,
    policy: dict,
    evidence_chain: list[dict],
    payload: dict,
    *,
    verification_time: datetime,
) -> str:
    release_hash = validate_release(release, grail_binding)
    policy_hash = validate_policy(policy)
    canonical_object(payload, "promotion")
    exact_keys(payload, PROMOTION_KEYS, "promotion")
    require(payload["schema"] == PROMOTION_SCHEMA, "promotion.schema: wrong protocol")
    require(payload["release_payload_hash"] == release_hash, "promotion: release binding mismatch")
    require(payload["policy_payload_hash"] == policy_hash, "promotion: policy binding mismatch")
    label(payload["from_stage_id"], "promotion.from_stage_id")
    label(payload["to_stage_id"], "promotion.to_stage_id")
    require(payload["decision"] in ("promote", "hold", "reject"), "promotion.decision: unsupported")
    label(payload["reason_code"], "promotion.reason_code")
    utc(payload["decided_utc"], "promotion.decided_utc")

    stages = policy["stages"]
    from_index = next((index for index, stage in enumerate(stages) if stage["id"] == payload["from_stage_id"]), None)
    require(from_index is not None and from_index + 1 < len(stages), "promotion.from_stage_id: no next stage")
    require(payload["to_stage_id"] == stages[from_index + 1]["id"], "promotion: stage skip or reorder")
    validate_evidence_chain(
        release,
        grail_binding,
        policy,
        evidence_chain,
        terminal_stage_id=payload["from_stage_id"],
    )
    evidence = evidence_chain[-1]
    require(evidence["stage_id"] == payload["from_stage_id"], "promotion: evidence is for another stage")
    require(evidence["release_payload_hash"] == release_hash, "promotion: evidence release mismatch")
    require(evidence["policy_payload_hash"] == policy_hash, "promotion: evidence policy mismatch")
    require(payload["evidence_payload_hash"] == particle_hash(evidence), "promotion: evidence binding mismatch")
    require(verification_time.tzinfo is not None, "promotion: verification time must be timezone-aware")
    decided = utc(payload["decided_utc"], "promotion.decided_utc")
    completed = utc(evidence["completed_utc"], "evidence.completed_utc")
    require(completed <= decided <= verification_time, "promotion: future or pre-evidence decision time")
    require(
        all(
            utc(record["completed_utc"], "evidence.completed_utc") <= decided
            for record in evidence_chain
        ),
        "promotion: evidence completes after the decision",
    )
    require(
        (verification_time - completed).total_seconds() <= stages[from_index]["maximum_evidence_age_seconds"],
        "promotion: stale evidence",
    )
    if payload["decision"] == "promote":
        require(evidence["result"] == "pass", "promotion: failed evidence cannot promote")
        require(payload["reason_code"] == "all-gates-passed", "promotion: promote reason must be all-gates-passed")
    return particle_hash(payload)


def authorize_promotion_frame(
    *,
    release: dict,
    grail_binding: dict,
    policy: dict,
    evidence_chain: list[dict],
    frame: dict,
    head: dict | None,
    stream_id: str,
    registered_kinds: set[str],
    signature_verifier,
    authorization_verifier,
    evidence_authorization_verifier,
    grail_binding_verifier,
    verification_time: datetime,
) -> str:
    require(
        grail_binding_verifier is not None and bool(grail_binding_verifier(grail_binding)),
        "rapp-cicd-promotion: Grail binding is not authenticated",
    )
    require(
        evidence_authorization_verifier is not None
        and all(bool(evidence_authorization_verifier(evidence)) for evidence in evidence_chain),
        "rapp-cicd-promotion: evidence is not from an authorized evaluator",
    )
    payload = authoritative_frame_payload(
        frame,
        expected_schema=PROMOTION_SCHEMA,
        purpose="rapp-cicd-promotion",
        head=head,
        stream_id=stream_id,
        registered_kinds=registered_kinds,
        signature_verifier=signature_verifier,
        authorization_verifier=authorization_verifier,
    )
    return validate_promotion(
        release,
        grail_binding,
        policy,
        evidence_chain,
        payload,
        verification_time=verification_time,
    )


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("release", "policy", "evidence", "promotion"))
    parser.add_argument("document")
    parser.add_argument("--release")
    parser.add_argument("--grail-binding")
    parser.add_argument("--policy")
    parser.add_argument("--evidence", action="append", default=[])
    parser.add_argument("--previous")
    args = parser.parse_args()
    document = load_json(args.document)
    if args.kind == "release":
        require(args.grail_binding, "release requires --grail-binding")
        digest = validate_release(document, load_json(args.grail_binding))
    elif args.kind == "policy":
        digest = validate_policy(document)
    elif args.kind == "evidence":
        require(
            args.release and args.grail_binding and args.policy,
            "evidence requires --release, --grail-binding, and --policy",
        )
        digest = validate_evidence(
            load_json(args.release),
            load_json(args.grail_binding),
            load_json(args.policy),
            document,
            load_json(args.previous) if args.previous else None,
        )
    else:
        require(
            args.release and args.grail_binding and args.policy and args.evidence,
            "promotion requires release, Grail binding, policy, and evidence",
        )
        digest = validate_promotion(
            load_json(args.release),
            load_json(args.grail_binding),
            load_json(args.policy),
            [load_json(path) for path in args.evidence],
            document,
            verification_time=utc(document["decided_utc"], "promotion.decided_utc"),
        )
    print(json.dumps({"status": "payload-conformant", "payload_hash": digest}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "refused", "detail": str(error)}))
        sys.exit(1)
