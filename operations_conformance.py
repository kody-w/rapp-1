#!/usr/bin/env python3
"""Controlled conformance vectors for RAPP CI/CD and RAPP Deploy."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import rapp as R
import rapp_cicd as C
import rapp_deploy as D
from rapp_profile import load_json, particle_hash


ROOT = Path(__file__).resolve().parent
EXAMPLES = ROOT / "protocols" / "examples"
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
results = []


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append(condition)
    suffix = f" - {detail}" if detail and not condition else ""
    print(f"  [{PASS if condition else FAIL}] {name}{suffix}")


def refused(name: str, action, contains: str) -> None:
    try:
        action()
    except ValueError as error:
        check(name, contains in str(error), str(error))
    else:
        check(name, False, "accepted a document that must be refused")


def stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def release_fixture() -> dict:
    return {
        "schema": C.RELEASE_SCHEMA,
        "release_scope": "https://github.com/kody-w/rapp-installer/releases/grail",
        "created_utc": "2026-08-30T12:54:20.000Z",
        "source": {
            "repository": "https://github.com/kody-w/rapp-canary",
            "object_format": "sha1",
            "commit": "62ba2ee8efa2d44f6ed32c017f28be926027a57e",
            "tree": "620f5a3750f0dd26d0cbb584ca39c0406ffbeec8",
        },
        "artifact": {
            "sha256": digest("rapp-cicd/1 example release artifact"),
            "size_bytes": 1048576,
            "media_type": "application/zip",
            "entrypoint": "rapp_brainstem/brainstem.py",
        },
        "grail": {
            "grail_id": "grail:1a501dd7a01f05698abcf5f9bbe0273ebb9d09f5d6ec444aa71edccff947c8c7",
            "path": "rapp_brainstem/brainstem.py",
            "sha256": "bd55a7f0bcf5efd3f7966ca39bb146da3c25fda9a0b1ce5ba587919d3c3775f4",
            "size_bytes": 154059,
        },
        "components": [
            {
                "kind": "kernel",
                "name": "grail-brainstem",
                "version": "v0.6.16",
                "sha256": "bd55a7f0bcf5efd3f7966ca39bb146da3c25fda9a0b1ce5ba587919d3c3775f4",
                "mutable": False,
            },
            {
                "kind": "agent",
                "name": "release-controller",
                "version": "1.0.0",
                "sha256": digest("release-controller 1.0.0"),
                "mutable": False,
            },
            {
                "kind": "model",
                "name": "qualified-model-route",
                "version": "2026-08-30",
                "sha256": digest("qualified-model-route 2026-08-30"),
                "mutable": True,
            },
            {
                "kind": "state-schema",
                "name": "rapp-state",
                "version": "1",
                "sha256": digest("rapp-state/1 schema"),
                "mutable": False,
            },
            {
                "kind": "tool",
                "name": "runtime-tool-contract",
                "version": "1",
                "sha256": digest("runtime-tool-contract 1"),
                "mutable": False,
            },
        ],
        "lineage": {
            "mode": "seed",
            "parents": [],
        },
    }


def rollback_release_fixture() -> dict:
    release = copy.deepcopy(release_fixture())
    release["created_utc"] = "2026-08-29T20:00:00.000Z"
    release["source"] = {
        "repository": "https://github.com/kody-w/rapp-installer",
        "object_format": "sha1",
        "commit": "49db80c8c6b6caa7647369beaf477d374a8f293c",
        "tree": "94b85084b1dee1183a5c21c45e97e955cd688d8a",
    }
    release["artifact"]["sha256"] = digest("previous release artifact")
    release["components"][1]["version"] = "0.9.0"
    release["components"][1]["sha256"] = digest("release-controller 0.9.0")
    release["components"][3]["version"] = "0"
    release["components"][3]["sha256"] = digest("rapp-state/0 schema")
    return release


def grail_binding_fixture() -> dict:
    return {
        "type": "grail-kernel",
        "release_scope": "https://github.com/kody-w/rapp-installer/releases/grail",
        "grail_id": "grail:1a501dd7a01f05698abcf5f9bbe0273ebb9d09f5d6ec444aa71edccff947c8c7",
        "repository": "https://github.com/kody-w/rapp-installer",
        "immutable_ref": "refs/tags/brainstem-v0.6.16",
        "object_format": "sha1",
        "commit": "5fbde1776a72715935c3d597a9ddfce28a04032b",
        "path": "rapp_brainstem/brainstem.py",
        "mode": "100644",
        "blob": "3f7102ff508c813bb6494511fc32a421a633e418",
        "sha256": "bd55a7f0bcf5efd3f7966ca39bb146da3c25fda9a0b1ce5ba587919d3c3775f4",
        "size_bytes": 154059,
        "activated_utc": "2026-08-29T20:00:00.000Z",
        "predecessor": None,
        "declared_by": "rappid:@kody-w/estate-owner:" + "9" * 64,
        "sig": "fixture-detached-jws",
    }


def policy_fixture() -> dict:
    return {
        "schema": C.POLICY_SCHEMA,
        "release_scope": "https://github.com/kody-w/rapp-installer/releases/grail",
        "created_utc": "2026-08-30T12:54:20.000Z",
        "stages": [
            {
                "id": "development",
                "class": "development",
                "required_checks": ["unit"],
                "minimum_soak_seconds": 0,
                "maximum_evidence_age_seconds": 86400,
                "approval": "automatic",
            },
            {
                "id": "test",
                "class": "test",
                "required_checks": ["integration"],
                "minimum_soak_seconds": 0,
                "maximum_evidence_age_seconds": 86400,
                "approval": "automatic",
            },
            {
                "id": "canary",
                "class": "canary",
                "required_checks": ["grail-kernel", "product", "autonomous", "security-smoke"],
                "minimum_soak_seconds": 60,
                "maximum_evidence_age_seconds": 3600,
                "approval": "automatic",
            },
            {
                "id": "nightly",
                "class": "qualification",
                "required_checks": ["mirror-integrity"],
                "minimum_soak_seconds": 60,
                "maximum_evidence_age_seconds": 21600,
                "approval": "automatic",
            },
            {
                "id": "alpha",
                "class": "qualification",
                "required_checks": ["cross-platform"],
                "minimum_soak_seconds": 60,
                "maximum_evidence_age_seconds": 21600,
                "approval": "automatic",
            },
            {
                "id": "beta",
                "class": "qualification",
                "required_checks": ["release-candidate"],
                "minimum_soak_seconds": 60,
                "maximum_evidence_age_seconds": 21600,
                "approval": "automatic",
            },
            {
                "id": "preprod",
                "class": "preprod",
                "required_checks": sorted(C.PREPROD_CHECKS),
                "minimum_soak_seconds": 3600,
                "maximum_evidence_age_seconds": 7200,
                "approval": "automatic",
            },
            {
                "id": "production",
                "class": "production",
                "required_checks": ["owner-approval"],
                "minimum_soak_seconds": 0,
                "maximum_evidence_age_seconds": 3600,
                "approval": "owner",
            },
        ],
    }


def evidence_chain(release: dict, policy: dict) -> list[dict]:
    release_hash = particle_hash(release)
    policy_hash = particle_hash(policy)
    cursor = datetime(2026, 8, 30, 13, 0, tzinfo=timezone.utc)
    previous = None
    records = []
    for stage in policy["stages"]:
        completed = cursor + timedelta(seconds=stage["minimum_soak_seconds"])
        evidence = {
            "schema": C.EVIDENCE_SCHEMA,
            "release_payload_hash": release_hash,
            "policy_payload_hash": policy_hash,
            "stage_id": stage["id"],
            "stage_class": stage["class"],
            "environment_sha256": digest(f"environment {stage['id']}"),
            "started_utc": stamp(cursor),
            "completed_utc": stamp(completed),
            "artifact_sha256": release["artifact"]["sha256"],
            "grail_id": release["grail"]["grail_id"],
            "checks": [
                {
                    "id": check_id,
                    "status": "pass",
                    "evidence_sha256": digest(f"{stage['id']} {check_id}"),
                }
                for check_id in stage["required_checks"]
            ],
            "result": "pass",
            "previous_evidence_payload_hash": particle_hash(previous) if previous else None,
        }
        records.append(evidence)
        previous = evidence
        cursor = completed + timedelta(seconds=1)
    return records


def plan_fixture(
    release: dict,
    promotion: dict,
    rollback_release: dict,
    preprod_evidence: dict,
) -> dict:
    objectives = [
        {"id": "artifact-match", "unit": "boolean", "operator": "eq", "threshold": 1},
        {"id": "grail-match", "unit": "boolean", "operator": "eq", "threshold": 1},
        {"id": "state-integrity", "unit": "boolean", "operator": "eq", "threshold": 1},
        {"id": "model-identity", "unit": "boolean", "operator": "eq", "threshold": 1},
        {"id": "behavior-baseline", "unit": "boolean", "operator": "eq", "threshold": 1},
        {"id": "tool-contract", "unit": "boolean", "operator": "eq", "threshold": 1},
        {"id": "serving-mutated", "unit": "boolean", "operator": "eq", "threshold": 0},
        {"id": "availability", "unit": "ppm", "operator": "gte", "threshold": 999000},
        {"id": "error-rate", "unit": "ppm", "operator": "lte", "threshold": 1000},
        {"id": "latency-p95", "unit": "milliseconds", "operator": "lte", "threshold": 2000},
        {"id": "quality", "unit": "ppm", "operator": "gte", "threshold": 950000},
        {"id": "safety-violations", "unit": "ppm", "operator": "lte", "threshold": 0},
        {"id": "tool-success", "unit": "ppm", "operator": "gte", "threshold": 990000},
        {"id": "cost-per-request", "unit": "microunits", "operator": "lte", "threshold": 50000},
        {"id": "saturation", "unit": "ppm", "operator": "lte", "threshold": 800000},
        {"id": "knowledge-age", "unit": "seconds", "operator": "lte", "threshold": 86400},
    ]
    return {
        "schema": D.PLAN_SCHEMA,
        "release_payload_hash": particle_hash(release),
        "release_scope": release["release_scope"],
        "created_utc": "2026-08-30T14:06:00.000Z",
        "deployment_class": "planetary",
        "promotion_payload_hash": particle_hash(promotion),
        "serving": {
            "candidate_isolated": True,
            "in_place_mutation": False,
            "current_release_payload_hash": particle_hash(rollback_release),
        },
        "topology": {
            "mode": "cellular",
            "cells": [
                {
                    "cell_id": "us-east-a",
                    "region": "us-east",
                    "failure_domain": "us-east-1a",
                    "tenant_scope": "policy:us-east",
                },
                {
                    "cell_id": "us-west-a",
                    "region": "us-west",
                    "failure_domain": "us-west-2a",
                    "tenant_scope": "policy:us-west",
                },
                {
                    "cell_id": "eu-west-a",
                    "region": "eu-west",
                    "failure_domain": "eu-west-1a",
                    "tenant_scope": "policy:eu-west",
                },
            ],
        },
        "waves": [
            {
                "id": "shadow",
                "traffic_basis_points": 0,
                "minimum_observation_seconds": 60,
                "minimum_healthy_windows": 1,
                "cell_ids": ["us-east-a"],
            },
            {
                "id": "canary",
                "traffic_basis_points": 100,
                "minimum_observation_seconds": 300,
                "minimum_healthy_windows": 2,
                "cell_ids": ["us-east-a"],
            },
            {
                "id": "regional",
                "traffic_basis_points": 2500,
                "minimum_observation_seconds": 900,
                "minimum_healthy_windows": 3,
                "cell_ids": ["us-east-a", "us-west-a"],
            },
            {
                "id": "global",
                "traffic_basis_points": 10000,
                "minimum_observation_seconds": 1800,
                "minimum_healthy_windows": 3,
                "cell_ids": ["us-east-a", "us-west-a", "eu-west-a"],
            },
        ],
        "health_contract": {
            "max_evidence_age_seconds": 900,
            "objectives": objectives,
        },
        "state": {
            "schema": "rapp-state/1",
            "schema_sha256": digest("rapp-state/1 schema"),
            "previous_schema_sha256": digest("rapp-state/0 schema"),
            "compatibility_evidence_sha256": next(
                check["evidence_sha256"]
                for check in preprod_evidence["checks"]
                if check["id"] == "state-compatibility"
            ),
            "migration": "expand-contract",
            "backward_compatible": True,
            "rollback_snapshot_sha256": digest("rollback snapshot"),
            "rollback_evidence_sha256": next(
                check["evidence_sha256"]
                for check in preprod_evidence["checks"]
                if check["id"] == "rollback-rehearsal"
            ),
            "restore_evidence_sha256": next(
                check["evidence_sha256"]
                for check in preprod_evidence["checks"]
                if check["id"] == "restore-rehearsal"
            ),
            "recovery_point_objective_seconds": 60,
            "recovery_time_objective_seconds": 300,
        },
        "data": {
            "tenant_isolation": True,
            "residency_policy_sha256": digest("residency policy"),
            "retention_policy_sha256": digest("retention policy"),
            "deletion_policy_sha256": digest("deletion policy"),
            "backup_policy_sha256": digest("backup policy"),
        },
        "resilience": {
            "controls": [
                "circuit-breaker",
                "kill-switch",
                "load-shedding",
                "rate-limit",
                "regional-failover",
            ],
            "provider_failure_mode": "degrade-explicitly",
        },
        "rollback_release_payload_hash": particle_hash(rollback_release),
        "automatic_pause": True,
        "automatic_rollback": True,
    }


def health_fixture(
    release: dict,
    plan: dict,
    *,
    wave_id: str = "canary",
    cell_id: str = "us-east-a",
    window_start: str = "2026-08-30T21:00:00.000Z",
    window_end: str = "2026-08-30T21:05:00.000Z",
    previous: dict | None = None,
) -> dict:
    values = {
        "artifact-match": 1,
        "grail-match": 1,
        "state-integrity": 1,
        "model-identity": 1,
        "behavior-baseline": 1,
        "tool-contract": 1,
        "serving-mutated": 0,
        "availability": 999900,
        "error-rate": 100,
        "latency-p95": 800,
        "quality": 980000,
        "safety-violations": 0,
        "tool-success": 999000,
        "cost-per-request": 20000,
        "saturation": 300000,
        "knowledge-age": 3600,
    }
    objectives = {objective["id"]: objective for objective in plan["health_contract"]["objectives"]}
    return {
        "schema": D.HEALTH_SCHEMA,
        "deployment_payload_hash": particle_hash(plan),
        "release_payload_hash": particle_hash(release),
        "cell_id": cell_id,
        "wave_id": wave_id,
        "window_start_utc": window_start,
        "window_end_utc": window_end,
        "observed": {
            "artifact_sha256": release["artifact"]["sha256"],
            "grail_id": release["grail"]["grail_id"],
            "grail_path": release["grail"]["path"],
            "grail_sha256": release["grail"]["sha256"],
            "grail_size_bytes": release["grail"]["size_bytes"],
            "model_set_payload_hash": D._components_hash(release, "model"),
            "tool_set_payload_hash": D._components_hash(release, "tool"),
            "state_schema_sha256": D._state_schema_component(release)["sha256"],
        },
        "measurements": [
            {
                "id": objective_id,
                "unit": objectives[objective_id]["unit"],
                "value": value,
                "evidence_sha256": digest(f"measurement {objective_id} {value}"),
            }
            for objective_id, value in values.items()
        ],
        "verdict": "healthy",
        "reason_codes": [],
        "previous_health_payload_hash": particle_hash(previous) if previous else None,
    }


def health_heads(previous: dict[str, dict] | None, records: list[dict]) -> dict[str, dict]:
    heads = copy.deepcopy(previous or {})
    for record in records:
        heads[record["cell_id"]] = {
            "payload_hash": particle_hash(record),
            "window_end_utc": record["window_end_utc"],
        }
    return heads


def load_example(name: str) -> dict:
    with (EXAMPLES / name).open(encoding="utf-8") as stream:
        return json.load(stream)


print("=" * 72)
print("RAPP operational profiles - controlled conformance vectors")
print("=" * 72)

release = release_fixture()
rollback_release = rollback_release_fixture()
grail_binding = grail_binding_fixture()
policy = policy_fixture()
evidences = evidence_chain(release, policy)

check(
    "O1 release capsule binds to the authenticated Grail declaration",
    C.validate_release(release, grail_binding) == particle_hash(release),
)
check("O2 promotion policy defines an ordered complete path", C.validate_policy(policy) == particle_hash(policy))
check(
    "O3 evidence chain covers every stage without skips",
    len(C.validate_evidence_chain(release, grail_binding, policy, evidences)) == len(policy["stages"]),
)

counterfeit_release = copy.deepcopy(release)
counterfeit_release["grail"]["grail_id"] = "grail:" + digest("counterfeit grail")
counterfeit_release["grail"]["sha256"] = digest("counterfeit kernel")
counterfeit_release["components"][0]["sha256"] = counterfeit_release["grail"]["sha256"]
refused(
    "O4 coordinated candidate-side Grail substitution is refused",
    lambda: C.validate_release(counterfeit_release, grail_binding),
    "authenticated Grail identity mismatch",
)

artifact_drift = copy.deepcopy(evidences[2])
artifact_drift["artifact_sha256"] = digest("different artifact")
refused(
    "O5 evidence for different artifact bytes is refused",
    lambda: C.validate_evidence(release, grail_binding, policy, artifact_drift, evidences[1]),
    "artifact drift",
)

kernel_drift = copy.deepcopy(evidences[2])
kernel_drift["grail_id"] = "grail:" + digest("different kernel")
refused(
    "O6 evidence for a different Grail is refused",
    lambda: C.validate_evidence(release, grail_binding, policy, kernel_drift, evidences[1]),
    "kernel-drift",
)

missing_check = copy.deepcopy(evidences[2])
missing_check["checks"] = [
    check_record for check_record in missing_check["checks"] if check_record["id"] != "autonomous"
]
refused(
    "O7 a missing required check cannot report pass",
    lambda: C.validate_evidence(release, grail_binding, policy, missing_check, evidences[1]),
    "must be fail",
)

refused(
    "O8 stage skipping is refused",
    lambda: C.validate_evidence(release, grail_binding, policy, evidences[4], evidences[2]),
    "skipped or reordered",
)

reordered_time_chain = copy.deepcopy(evidences[:-1])
reordered_time_chain[0]["started_utc"] = "2027-01-01T00:00:00.000Z"
reordered_time_chain[0]["completed_utc"] = "2027-01-01T00:00:01.000Z"
for index in range(1, len(reordered_time_chain)):
    reordered_time_chain[index]["previous_evidence_payload_hash"] = particle_hash(
        reordered_time_chain[index - 1]
    )
refused(
    "O8b evidence stages cannot move backward in time",
    lambda: C.validate_evidence_chain(
        release,
        grail_binding,
        policy,
        reordered_time_chain,
        terminal_stage_id="preprod",
    ),
    "stage started before predecessor completed",
)

preprod = evidences[-2]
promotion = {
    "schema": C.PROMOTION_SCHEMA,
    "release_payload_hash": particle_hash(release),
    "policy_payload_hash": particle_hash(policy),
    "from_stage_id": "preprod",
    "to_stage_id": "production",
    "evidence_payload_hash": particle_hash(preprod),
    "decision": "promote",
    "reason_code": "all-gates-passed",
    "decided_utc": "2026-08-30T14:05:00.000Z",
}
check(
    "O9 complete passing Preprod evidence authorizes only the next stage",
    C.validate_promotion(
        release,
        grail_binding,
        policy,
        evidences[:-1],
        promotion,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
    )
    == particle_hash(promotion),
)

failed_preprod = copy.deepcopy(preprod)
failed_preprod["checks"][0]["status"] = "fail"
failed_preprod["result"] = "fail"
bad_promotion = copy.deepcopy(promotion)
bad_promotion["evidence_payload_hash"] = particle_hash(failed_preprod)
refused(
    "O10 failed evidence cannot promote",
    lambda: C.validate_promotion(
        release,
        grail_binding,
        policy,
        [*evidences[:-2], failed_preprod],
        bad_promotion,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
    ),
    "failed evidence",
)

fabricated_preprod = copy.deepcopy(preprod)
fabricated_preprod["checks"] = []
fabricated_preprod["result"] = "pass"
fabricated_promotion = copy.deepcopy(promotion)
fabricated_promotion["evidence_payload_hash"] = particle_hash(fabricated_preprod)
refused(
    "O11 fabricated Preprod pass cannot authorize production",
    lambda: C.validate_promotion(
        release,
        grail_binding,
        policy,
        [*evidences[:-2], fabricated_preprod],
        fabricated_promotion,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
    ),
    "must be fail",
)

stale_promotion = copy.deepcopy(promotion)
refused(
    "O12 stale CI/CD evidence cannot authorize promotion",
    lambda: C.validate_promotion(
        release,
        grail_binding,
        policy,
        evidences[:-1],
        stale_promotion,
        verification_time=datetime(2026, 8, 31, 14, 6, tzinfo=timezone.utc),
    ),
    "stale evidence",
)

crossed_release = copy.deepcopy(release)
crossed_release["lineage"] = {
    "mode": "cross",
    "parents": [
        {"space": "rapp/1:egg-manifest", "hash": digest("parent egg")},
        {"space": "rapp/1:particle", "hash": digest("parent document")},
    ],
}
crossed_release["lineage"]["parents"].sort(key=lambda parent: (parent["space"], parent["hash"]))
check(
    "O13 crossed offspring receives a distinct identity with typed parents",
    C.validate_release(crossed_release, grail_binding) != particle_hash(release),
)

controller = "rappid:@kody-w/release-controller:" + "a" * 64
promotion_frame = R.build_frame(
    "body.pulse",
    controller,
    0,
    promotion["decided_utc"],
    promotion,
    None,
    sig="fixture-signature",
)
signature_verifier = lambda _unsigned, signature: (signature == "fixture-signature", "bad fixture signature")
check(
    "O14 signed authorized promotion frame is accepted",
    C.authorize_promotion_frame(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        frame=promotion_frame,
        head=None,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: True,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        grail_binding_verifier=lambda binding: binding == grail_binding,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
    )
    == particle_hash(promotion),
)
refused(
    "O15 unauthorized promotion signer is refused",
    lambda: C.authorize_promotion_frame(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        frame=promotion_frame,
        head=None,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: False,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        grail_binding_verifier=lambda binding: binding == grail_binding,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
    ),
    "signer is not authorized",
)
refused(
    "O16 unauthenticated Grail registry binding cannot authorize promotion",
    lambda: C.authorize_promotion_frame(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        frame=promotion_frame,
        head=None,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: True,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        grail_binding_verifier=lambda _binding: False,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
    ),
    "Grail binding is not authenticated",
)
refused(
    "O16b unauthenticated evaluator evidence cannot authorize promotion",
    lambda: C.authorize_promotion_frame(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        frame=promotion_frame,
        head=None,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: True,
        evidence_authorization_verifier=lambda _evidence: False,
        grail_binding_verifier=lambda binding: binding == grail_binding,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
    ),
    "evidence is not from an authorized evaluator",
)

plan = plan_fixture(release, promotion, rollback_release, preprod)
check(
    "O17 planetary deployment payload is bounded and cellular",
    D.validate_plan_payload(release, plan) == particle_hash(plan),
)
check(
    "O18 deployment authorization resolves qualification and rollback releases",
    D.authorize_plan(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        promotion=promotion,
        rollback_release=rollback_release,
        rollback_grail_binding=grail_binding,
        plan=plan,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
        promotion_authorization_verifier=lambda value: value == promotion,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        rollback_authorization_verifier=lambda value: value == rollback_release,
        grail_binding_verifier=lambda value: value == grail_binding,
        rollback_grail_binding_verifier=lambda value: value == grail_binding,
    )
    == particle_hash(plan),
)
plan_frame = R.build_frame(
    "body.pulse",
    controller,
    1,
    plan["created_utc"],
    plan,
    promotion_frame["payload_hash"],
    sig="fixture-signature",
)
check(
    "O19 signed deployment plan frame binds the qualified release",
    D.authorize_plan_frame(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        promotion=promotion,
        rollback_release=rollback_release,
        rollback_grail_binding=grail_binding,
        frame=plan_frame,
        head=promotion_frame,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: True,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
        promotion_authorization_verifier=lambda value: value == promotion,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        rollback_authorization_verifier=lambda value: value == rollback_release,
        grail_binding_verifier=lambda value: value == grail_binding,
        rollback_grail_binding_verifier=lambda value: value == grail_binding,
    )
    == particle_hash(plan),
)

old_grail_binding = copy.deepcopy(grail_binding)
old_grail_binding.update(
    {
        "release_scope": "https://github.com/kody-w/rapp-installer/releases/grail-v0",
        "grail_id": "grail:" + digest("older grail"),
        "immutable_ref": "refs/tags/brainstem-v0.5.0",
        "commit": "1" * 40,
        "blob": "2" * 40,
        "sha256": digest("older kernel bytes"),
        "size_bytes": 150000,
        "activated_utc": "2026-01-01T00:00:00.000Z",
        "predecessor": None,
    }
)
old_grail_release = copy.deepcopy(rollback_release)
old_grail_release["release_scope"] = old_grail_binding["release_scope"]
old_grail_release["grail"] = {
    "grail_id": old_grail_binding["grail_id"],
    "path": old_grail_binding["path"],
    "sha256": old_grail_binding["sha256"],
    "size_bytes": old_grail_binding["size_bytes"],
}
old_grail_release["components"][0]["sha256"] = old_grail_binding["sha256"]
old_grail_plan = copy.deepcopy(plan)
old_grail_plan["serving"]["current_release_payload_hash"] = particle_hash(old_grail_release)
old_grail_plan["rollback_release_payload_hash"] = particle_hash(old_grail_release)
check(
    "O19b a successor Grail can roll back through the ancestor's own binding",
    D.authorize_plan(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        promotion=promotion,
        rollback_release=old_grail_release,
        rollback_grail_binding=old_grail_binding,
        plan=old_grail_plan,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
        promotion_authorization_verifier=lambda value: value == promotion,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        rollback_authorization_verifier=lambda value: value == old_grail_release,
        grail_binding_verifier=lambda value: value == grail_binding,
        rollback_grail_binding_verifier=lambda value: value == old_grail_binding,
    )
    == particle_hash(old_grail_plan),
)

unpromoted = copy.deepcopy(promotion)
unpromoted["decision"] = "hold"
unpromoted["reason_code"] = "operator-hold"
unpromoted_plan = copy.deepcopy(plan)
unpromoted_plan["promotion_payload_hash"] = particle_hash(unpromoted)
refused(
    "O20 an unpromoted release cannot enter deployment",
    lambda: D.authorize_plan(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        promotion=unpromoted,
        rollback_release=rollback_release,
        rollback_grail_binding=grail_binding,
        plan=unpromoted_plan,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
        promotion_authorization_verifier=lambda _value: True,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        rollback_authorization_verifier=lambda _value: True,
        grail_binding_verifier=lambda _value: True,
        rollback_grail_binding_verifier=lambda _value: True,
    ),
    "release was not promoted",
)

unresolved_rollback = copy.deepcopy(plan)
unresolved_rollback["rollback_release_payload_hash"] = digest("missing rollback release")
unresolved_rollback["serving"]["current_release_payload_hash"] = unresolved_rollback["rollback_release_payload_hash"]
refused(
    "O21 rollback must resolve to the supplied authorized release",
    lambda: D.authorize_plan(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidences[:-1],
        promotion=promotion,
        rollback_release=rollback_release,
        rollback_grail_binding=grail_binding,
        plan=unresolved_rollback,
        verification_time=datetime(2026, 8, 30, 14, 6, tzinfo=timezone.utc),
        promotion_authorization_verifier=lambda _value: True,
        evidence_authorization_verifier=lambda evidence: evidence in evidences[:-1],
        rollback_authorization_verifier=lambda _value: True,
        grail_binding_verifier=lambda _value: True,
        rollback_grail_binding_verifier=lambda _value: True,
    ),
    "rollback release does not resolve",
)

mutating_plan = copy.deepcopy(plan)
mutating_plan["serving"]["in_place_mutation"] = True
refused(
    "O22 in-place mutation of the serving AI is refused",
    lambda: D.validate_plan_payload(release, mutating_plan),
    "in-place serving mutation",
)

missing_control = copy.deepcopy(plan)
missing_control["resilience"]["controls"].remove("kill-switch")
refused(
    "O23 missing planetary resilience control is refused",
    lambda: D.validate_plan_payload(release, missing_control),
    "missing controls",
)

shadow_health = health_fixture(
    release,
    plan,
    wave_id="shadow",
    window_start="2026-08-30T15:00:00.000Z",
    window_end="2026-08-30T15:01:00.000Z",
)
shadow_decision = {
    "schema": D.DECISION_SCHEMA,
    "deployment_payload_hash": particle_hash(plan),
    "release_payload_hash": particle_hash(release),
    "wave_id": "shadow",
    "action": "advance",
    "health_payload_hashes": [particle_hash(shadow_health)],
    "health_heads": health_heads(None, [shadow_health]),
    "target_release_payload_hash": None,
    "previous_decision_payload_hash": None,
    "decided_utc": "2026-08-30T15:01:10.000Z",
}
check(
    "O24 shadow health and first-wave decision are contiguous",
    D.validate_decision(
        release,
        plan,
        [shadow_health],
        shadow_decision,
        verification_time=datetime(2026, 8, 30, 15, 1, 20, tzinfo=timezone.utc),
    )
    == particle_hash(shadow_decision),
)
shadow_decision_frame = R.build_frame(
    "body.pulse",
    controller,
    2,
    shadow_decision["decided_utc"],
    shadow_decision,
    plan_frame["payload_hash"],
    sig="fixture-signature",
)
check(
    "O25 signed shadow decision starts the rollout chain",
    D.authorize_decision_frame(
        release=release,
        plan=plan,
        health_records=[shadow_health],
        frame=shadow_decision_frame,
        head=plan_frame,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: True,
        plan_authorization_verifier=lambda value: value == plan,
        health_authorization_verifier=lambda value: value == shadow_health,
        previous_decision_authorization_verifier=lambda _value: False,
        verification_time=datetime(2026, 8, 30, 15, 1, 20, tzinfo=timezone.utc),
    )
    == particle_hash(shadow_decision),
)

health1 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:02:00.000Z",
    window_end="2026-08-30T15:07:00.000Z",
    previous=shadow_health,
)
health2 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:07:01.000Z",
    window_end="2026-08-30T15:12:01.000Z",
    previous=health1,
)
check(
    "O26 fresh health binds observed runtime identity to the qualified release",
    D.validate_health(
        release,
        plan,
        health2,
        verification_time=datetime(2026, 8, 30, 15, 12, 30, tzinfo=timezone.utc),
    )
    == particle_hash(health2),
)

runtime_drift = copy.deepcopy(health1)
runtime_drift["observed"]["artifact_sha256"] = digest("wrong runtime artifact")
refused(
    "O27 a claimed artifact match cannot hide observed runtime drift",
    lambda: D.validate_health(
        release,
        plan,
        runtime_drift,
        verification_time=datetime(2026, 8, 30, 15, 7, 30, tzinfo=timezone.utc),
    ),
    "contradicts observed runtime identity",
)

unsafe_health = copy.deepcopy(health1)
for measurement in unsafe_health["measurements"]:
    if measurement["id"] == "safety-violations":
        measurement["value"] = 1
unsafe_health["verdict"] = "unhealthy"
unsafe_health["reason_codes"] = ["safety-violations"]
unsafe_health2 = copy.deepcopy(health2)
unsafe_health2["previous_health_payload_hash"] = particle_hash(unsafe_health)
check(
    "O28 AI safety regression produces an unhealthy verdict",
    D.validate_health(
        release,
        plan,
        unsafe_health,
        verification_time=datetime(2026, 8, 30, 15, 7, 30, tzinfo=timezone.utc),
    )
    == particle_hash(unsafe_health),
)

stale_health = copy.deepcopy(health1)
stale_health["verdict"] = "unhealthy"
stale_health["reason_codes"] = ["stale"]
check(
    "O29 expired health evidence cannot remain healthy",
    D.validate_health(
        release,
        plan,
        stale_health,
        verification_time=datetime(2026, 8, 30, 16, 0, tzinfo=timezone.utc),
    )
    == particle_hash(stale_health),
)

decision = {
    "schema": D.DECISION_SCHEMA,
    "deployment_payload_hash": particle_hash(plan),
    "release_payload_hash": particle_hash(release),
    "wave_id": "canary",
    "action": "advance",
    "health_payload_hashes": [particle_hash(health1), particle_hash(health2)],
    "health_heads": health_heads(shadow_decision["health_heads"], [health1, health2]),
    "target_release_payload_hash": None,
    "previous_decision_payload_hash": particle_hash(shadow_decision),
    "decided_utc": "2026-08-30T15:12:30.000Z",
}
check(
    "O30 two chained healthy Canary windows authorize the next wave",
    D.validate_decision(
        release,
        plan,
        [health1, health2],
        decision,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    )
    == particle_hash(decision),
)

restarted_health1 = copy.deepcopy(health1)
restarted_health1["previous_health_payload_hash"] = None
restarted_health2 = copy.deepcopy(health2)
restarted_health2["previous_health_payload_hash"] = particle_hash(restarted_health1)
restart_decision = copy.deepcopy(decision)
restart_decision["health_payload_hashes"] = [
    particle_hash(restarted_health1),
    particle_hash(restarted_health2),
]
restart_decision["health_heads"] = health_heads(
    shadow_decision["health_heads"],
    [restarted_health1, restarted_health2],
)
refused(
    "O30b a later wave cannot restart a cell health chain",
    lambda: D.validate_decision(
        release,
        plan,
        [restarted_health1, restarted_health2],
        restart_decision,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    ),
    "broken health predecessor chain",
)

shadow_health2 = health_fixture(
    release,
    plan,
    wave_id="shadow",
    window_start="2026-08-30T15:01:01.000Z",
    window_end="2026-08-30T15:02:01.000Z",
    previous=shadow_health,
)
shadow_decision2 = copy.deepcopy(shadow_decision)
shadow_decision2["health_payload_hashes"] = [
    particle_hash(shadow_health),
    particle_hash(shadow_health2),
]
shadow_decision2["health_heads"] = health_heads(None, [shadow_health, shadow_health2])
shadow_decision2["decided_utc"] = "2026-08-30T15:02:10.000Z"
forked_health1 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:03:00.000Z",
    window_end="2026-08-30T15:08:00.000Z",
    previous=shadow_health,
)
forked_health2 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:08:01.000Z",
    window_end="2026-08-30T15:13:01.000Z",
    previous=forked_health1,
)
forked_decision = copy.deepcopy(decision)
forked_decision["previous_decision_payload_hash"] = particle_hash(shadow_decision2)
forked_decision["health_payload_hashes"] = [
    particle_hash(forked_health1),
    particle_hash(forked_health2),
]
forked_decision["health_heads"] = health_heads(
    shadow_decision2["health_heads"],
    [forked_health1, forked_health2],
)
forked_decision["decided_utc"] = "2026-08-30T15:13:30.000Z"
refused(
    "O30c a new wave cannot fork from a nonterminal prior health record",
    lambda: D.validate_decision(
        release,
        plan,
        [forked_health1, forked_health2],
        forked_decision,
        verification_time=datetime(2026, 8, 30, 15, 14, tzinfo=timezone.utc),
        previous_decision=shadow_decision2,
    ),
    "broken health predecessor chain",
)

early_health1 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:02:02.000Z",
    window_end="2026-08-30T15:07:02.000Z",
    previous=shadow_health2,
)
early_health2 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:07:03.000Z",
    window_end="2026-08-30T15:12:03.000Z",
    previous=early_health1,
)
early_decision = copy.deepcopy(forked_decision)
early_decision["health_payload_hashes"] = [
    particle_hash(early_health1),
    particle_hash(early_health2),
]
early_decision["health_heads"] = health_heads(
    shadow_decision2["health_heads"],
    [early_health1, early_health2],
)
refused(
    "O30d health collected before wave authorization cannot qualify it",
    lambda: D.validate_decision(
        release,
        plan,
        [early_health1, early_health2],
        early_decision,
        verification_time=datetime(2026, 8, 30, 15, 14, tzinfo=timezone.utc),
        previous_decision=shadow_decision2,
    ),
    "health predates wave authorization",
)

unsafe_decision = copy.deepcopy(decision)
unsafe_decision["health_payload_hashes"] = [particle_hash(unsafe_health), particle_hash(unsafe_health2)]
unsafe_decision["health_heads"] = health_heads(
    shadow_decision["health_heads"],
    [unsafe_health, unsafe_health2],
)
refused(
    "O31 unhealthy evidence cannot advance",
    lambda: D.validate_decision(
        release,
        plan,
        [unsafe_health, unsafe_health2],
        unsafe_decision,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    ),
    "unhealthy evidence cannot advance",
)

late_unhealthy = copy.deepcopy(health2)
late_unhealthy["window_start_utc"] = "2026-08-30T15:12:02.000Z"
late_unhealthy["window_end_utc"] = "2026-08-30T15:17:02.000Z"
late_unhealthy["previous_health_payload_hash"] = particle_hash(health2)
for measurement in late_unhealthy["measurements"]:
    if measurement["id"] == "safety-violations":
        measurement["value"] = 1
late_unhealthy["verdict"] = "unhealthy"
late_unhealthy["reason_codes"] = ["safety-violations"]
mixed_decision = copy.deepcopy(decision)
mixed_decision["health_payload_hashes"] = [
    particle_hash(health1),
    particle_hash(health2),
    particle_hash(late_unhealthy),
]
mixed_decision["health_heads"] = health_heads(
    shadow_decision["health_heads"],
    [health1, health2, late_unhealthy],
)
mixed_decision["decided_utc"] = "2026-08-30T15:17:30.000Z"
refused(
    "O31b a later unhealthy window blocks older healthy windows",
    lambda: D.validate_decision(
        release,
        plan,
        [health1, health2, late_unhealthy],
        mixed_decision,
        verification_time=datetime(2026, 8, 30, 15, 18, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    ),
    "unhealthy evidence cannot advance",
)

rollback = copy.deepcopy(unsafe_decision)
rollback["action"] = "rollback"
rollback["target_release_payload_hash"] = plan["rollback_release_payload_hash"]
check(
    "O32 unhealthy evidence can select only the resolved rollback release",
    D.validate_decision(
        release,
        plan,
        [unsafe_health, unsafe_health2],
        rollback,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    )
    == particle_hash(rollback),
)

duplicate_window = copy.deepcopy(health2)
duplicate_window["window_start_utc"] = health1["window_start_utc"]
duplicate_window["window_end_utc"] = health1["window_end_utc"]
duplicate_window["previous_health_payload_hash"] = particle_hash(health1)
duplicate_decision = copy.deepcopy(decision)
duplicate_decision["health_payload_hashes"] = [particle_hash(health1), particle_hash(duplicate_window)]
duplicate_decision["health_heads"] = health_heads(
    shadow_decision["health_heads"],
    [health1, duplicate_window],
)
refused(
    "O33 overlapping health windows cannot be counted twice",
    lambda: D.validate_decision(
        release,
        plan,
        [health1, duplicate_window],
        duplicate_decision,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    ),
    "overlapping or reordered",
)

global_direct = copy.deepcopy(decision)
global_direct["wave_id"] = "global"
global_direct["action"] = "complete"
refused(
    "O34 direct global completion without prior waves is refused",
    lambda: D.validate_decision(
        release,
        plan,
        [health1, health2],
        global_direct,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    ),
    "skipped or forked decision chain",
)

decision_frame = R.build_frame(
    "body.pulse",
    controller,
    3,
    decision["decided_utc"],
    decision,
    shadow_decision_frame["payload_hash"],
    sig="fixture-signature",
)
check(
    "O35 signed authorized deployment decision is accepted",
    D.authorize_decision_frame(
        release=release,
        plan=plan,
        health_records=[health1, health2],
        frame=decision_frame,
        head=shadow_decision_frame,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: True,
        plan_authorization_verifier=lambda value: value == plan,
        health_authorization_verifier=lambda value: value in (health1, health2),
        previous_decision_authorization_verifier=lambda value: value == shadow_decision,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    )
    == particle_hash(decision),
)

hold_decision = {
    "schema": D.DECISION_SCHEMA,
    "deployment_payload_hash": particle_hash(plan),
    "release_payload_hash": particle_hash(release),
    "wave_id": "canary",
    "action": "hold",
    "health_payload_hashes": [particle_hash(health1)],
    "health_heads": health_heads(shadow_decision["health_heads"], [health1]),
    "target_release_payload_hash": None,
    "previous_decision_payload_hash": particle_hash(shadow_decision),
    "decided_utc": "2026-08-30T15:07:30.000Z",
}
check(
    "O35b a same-wave hold becomes the latest decision ancestor",
    D.validate_decision(
        release,
        plan,
        [health1],
        hold_decision,
        verification_time=datetime(2026, 8, 30, 15, 8, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    )
    == particle_hash(hold_decision),
)
hold_frame = R.build_frame(
    "body.pulse",
    controller,
    3,
    hold_decision["decided_utc"],
    hold_decision,
    shadow_decision_frame["payload_hash"],
    sig="fixture-signature",
)
bypass_frame = R.build_frame(
    "body.pulse",
    controller,
    4,
    decision["decided_utc"],
    decision,
    hold_frame["payload_hash"],
    sig="fixture-signature",
)
refused(
    "O35c a later advance cannot bypass a hold in the frame ancestry",
    lambda: D.authorize_decision_frame(
        release=release,
        plan=plan,
        health_records=[health1, health2],
        frame=bypass_frame,
        head=hold_frame,
        stream_id=controller,
        registered_kinds={"body.pulse"},
        signature_verifier=signature_verifier,
        authorization_verifier=lambda _frame, _purpose: True,
        plan_authorization_verifier=lambda value: value == plan,
        health_authorization_verifier=lambda value: value in (health1, health2),
        previous_decision_authorization_verifier=lambda value: value == shadow_decision,
        verification_time=datetime(2026, 8, 30, 15, 13, tzinfo=timezone.utc),
        previous_decision=shadow_decision,
    ),
    "frame head does not match decision predecessor",
)

resumed_health1 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:08:00.000Z",
    window_end="2026-08-30T15:13:00.000Z",
    previous=health1,
)
resumed_health2 = health_fixture(
    release,
    plan,
    window_start="2026-08-30T15:13:01.000Z",
    window_end="2026-08-30T15:18:01.000Z",
    previous=resumed_health1,
)
resumed_decision = copy.deepcopy(decision)
resumed_decision["health_payload_hashes"] = [
    particle_hash(resumed_health1),
    particle_hash(resumed_health2),
]
resumed_decision["health_heads"] = health_heads(
    hold_decision["health_heads"],
    [resumed_health1, resumed_health2],
)
resumed_decision["previous_decision_payload_hash"] = particle_hash(hold_decision)
resumed_decision["decided_utc"] = "2026-08-30T15:18:30.000Z"
check(
    "O35d fresh same-wave evidence can resume from the recorded hold",
    D.validate_decision(
        release,
        plan,
        [resumed_health1, resumed_health2],
        resumed_decision,
        verification_time=datetime(2026, 8, 30, 15, 19, tzinfo=timezone.utc),
        previous_decision=hold_decision,
    )
    == particle_hash(resumed_decision),
)

regional_east1 = health_fixture(
    release,
    plan,
    wave_id="regional",
    cell_id="us-east-a",
    window_start="2026-08-30T15:13:00.000Z",
    window_end="2026-08-30T15:28:00.000Z",
    previous=health2,
)
regional_hold1 = {
    "schema": D.DECISION_SCHEMA,
    "deployment_payload_hash": particle_hash(plan),
    "release_payload_hash": particle_hash(release),
    "wave_id": "regional",
    "action": "hold",
    "health_payload_hashes": [particle_hash(regional_east1)],
    "health_heads": health_heads(decision["health_heads"], [regional_east1]),
    "target_release_payload_hash": None,
    "previous_decision_payload_hash": particle_hash(decision),
    "decided_utc": "2026-08-30T15:28:15.000Z",
}
check(
    "O35e a multi-cell wave may hold on evidence from one affected cell",
    D.validate_decision(
        release,
        plan,
        [regional_east1],
        regional_hold1,
        verification_time=datetime(2026, 8, 30, 15, 29, tzinfo=timezone.utc),
        previous_decision=decision,
    )
    == particle_hash(regional_hold1),
)
regional_east2 = health_fixture(
    release,
    plan,
    wave_id="regional",
    cell_id="us-east-a",
    window_start="2026-08-30T15:28:16.000Z",
    window_end="2026-08-30T15:43:16.000Z",
    previous=regional_east1,
)
regional_west1 = health_fixture(
    release,
    plan,
    wave_id="regional",
    cell_id="us-west-a",
    window_start="2026-08-30T15:28:16.000Z",
    window_end="2026-08-30T15:43:16.000Z",
)
regional_hold2 = copy.deepcopy(regional_hold1)
regional_hold2["health_payload_hashes"] = [
    particle_hash(regional_east2),
    particle_hash(regional_west1),
]
regional_hold2["health_heads"] = health_heads(
    regional_hold1["health_heads"],
    [regional_east2, regional_west1],
)
regional_hold2["previous_decision_payload_hash"] = particle_hash(regional_hold1)
regional_hold2["decided_utc"] = "2026-08-30T15:43:30.000Z"
check(
    "O35f a partial multi-cell hold preserves inherited heads and can resume",
    D.validate_decision(
        release,
        plan,
        [regional_east2, regional_west1],
        regional_hold2,
        verification_time=datetime(2026, 8, 30, 15, 44, tzinfo=timezone.utc),
        previous_decision=regional_hold1,
    )
    == particle_hash(regional_hold2),
)

global_prior_health = [
    health_fixture(
        release,
        plan,
        wave_id="global",
        cell_id=cell_id,
        window_start="2026-08-30T16:00:00.000Z",
        window_end="2026-08-30T16:30:00.000Z",
    )
    for cell_id in ("us-east-a", "us-west-a", "eu-west-a")
]
global_complete = {
    "schema": D.DECISION_SCHEMA,
    "deployment_payload_hash": particle_hash(plan),
    "release_payload_hash": particle_hash(release),
    "wave_id": "global",
    "action": "complete",
    "health_payload_hashes": [particle_hash(health) for health in global_prior_health],
    "health_heads": health_heads(None, global_prior_health),
    "target_release_payload_hash": None,
    "previous_decision_payload_hash": digest("authorized regional advance"),
    "decided_utc": "2026-08-30T16:30:30.000Z",
}
post_complete_failure = health_fixture(
    release,
    plan,
    wave_id="global",
    cell_id="eu-west-a",
    window_start="2026-08-30T16:31:00.000Z",
    window_end="2026-08-30T17:01:00.000Z",
    previous=global_prior_health[2],
)
for measurement in post_complete_failure["measurements"]:
    if measurement["id"] == "safety-violations":
        measurement["value"] = 1
post_complete_failure["verdict"] = "unhealthy"
post_complete_failure["reason_codes"] = ["safety-violations"]
post_complete_rollback = {
    "schema": D.DECISION_SCHEMA,
    "deployment_payload_hash": particle_hash(plan),
    "release_payload_hash": particle_hash(release),
    "wave_id": "global",
    "action": "rollback",
    "health_payload_hashes": [particle_hash(post_complete_failure)],
    "health_heads": health_heads(
        global_complete["health_heads"],
        [post_complete_failure],
    ),
    "target_release_payload_hash": plan["rollback_release_payload_hash"],
    "previous_decision_payload_hash": particle_hash(global_complete),
    "decided_utc": "2026-08-30T17:01:30.000Z",
}
check(
    "O35g global completion remains live and can roll back on later degradation",
    D.validate_decision(
        release,
        plan,
        [post_complete_failure],
        post_complete_rollback,
        verification_time=datetime(2026, 8, 30, 17, 2, tzinfo=timezone.utc),
        previous_decision=global_complete,
    )
    == particle_hash(post_complete_rollback),
)

with tempfile.NamedTemporaryFile("wb", delete=True) as duplicate_json:
    duplicate_json.write(b'{"schema":"rapp-cicd/1-release","schema":"forged"}')
    duplicate_json.flush()
    refused(
        "O36 duplicate JSON members are refused before normalization",
        lambda: load_json(duplicate_json.name),
        "duplicate JSON member",
    )

if EXAMPLES.exists():
    example_release = load_example("release.json")
    example_policy = load_example("policy.json")
    example_deployment = load_example("deployment.json")
    example_grail_binding = load_example("grail-binding.json")
    check(
        "O37 published release example conforms",
        C.validate_release(example_release, example_grail_binding) == particle_hash(example_release),
    )
    check("O38 published policy example conforms", C.validate_policy(example_policy) == particle_hash(example_policy))
    check(
        "O39 published deployment example conforms",
        D.validate_plan_payload(example_release, example_deployment) == particle_hash(example_deployment),
    )

profile_index = load_example("../index.json")
schema_paths = [
    ROOT / "protocols" / "rapp-cicd" / "1" / "schema.json",
    ROOT / "protocols" / "rapp-deploy" / "1" / "schema.json",
]
schemas_parse = all(isinstance(json.loads(path.read_text(encoding="utf-8")), dict) for path in schema_paths)
check("O40 published JSON Schemas parse as canonical JSON objects", schemas_parse)

index_ok = profile_index.get("schema") == "rapp/1-operational-profile-index"
for profile in profile_index.get("profiles", []):
    spec_path = ROOT / profile["spec_path"]
    schema_path = ROOT / profile["schema_path"]
    index_ok = index_ok and hashlib.sha256(spec_path.read_bytes()).hexdigest() == profile["spec_sha256"]
    index_ok = index_ok and hashlib.sha256(schema_path.read_bytes()).hexdigest() == profile["schema_sha256"]
    index_ok = index_ok and profile["parent"] == "rapp/1"
check("O41 profile index pins the exact public specifications and schemas", index_ok)

print("-" * 72)
passed = sum(results)
print(f"{len(results)} operational checks | {passed} PASS | {len(results) - passed} FAIL")
raise SystemExit(0 if passed == len(results) else 1)
