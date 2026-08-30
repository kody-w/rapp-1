#!/usr/bin/env python3
"""Reference validator for the RAPP Deploy protocol profile."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime

import rapp_cicd as C
from rapp_profile import (
    authoritative_frame_payload,
    boolean,
    bounded_int,
    canonical_object,
    exact_keys,
    grail_id,
    hex64,
    https_uri,
    label,
    load_json,
    particle_hash,
    positive_int,
    relative_path,
    require,
    text,
    unique_strings,
    utc,
)


PLAN_SCHEMA = "rapp-deploy/1-plan"
HEALTH_SCHEMA = "rapp-deploy/1-health"
DECISION_SCHEMA = "rapp-deploy/1-decision"

PLAN_KEYS = {
    "schema",
    "release_payload_hash",
    "release_scope",
    "created_utc",
    "deployment_class",
    "promotion_payload_hash",
    "serving",
    "topology",
    "waves",
    "health_contract",
    "state",
    "data",
    "resilience",
    "rollback_release_payload_hash",
    "automatic_pause",
    "automatic_rollback",
}
HEALTH_KEYS = {
    "schema",
    "deployment_payload_hash",
    "release_payload_hash",
    "cell_id",
    "wave_id",
    "window_start_utc",
    "window_end_utc",
    "measurements",
    "observed",
    "verdict",
    "reason_codes",
    "previous_health_payload_hash",
}
DECISION_KEYS = {
    "schema",
    "deployment_payload_hash",
    "release_payload_hash",
    "wave_id",
    "action",
    "health_payload_hashes",
    "health_heads",
    "target_release_payload_hash",
    "previous_decision_payload_hash",
    "decided_utc",
}

# The core is intentionally small. Plans may add objectives and controls without
# changing the protocol; these are the minimum claims needed for safe AI service.
CORE_OBJECTIVES = {
    "artifact-match": ("boolean", "eq", 1),
    "grail-match": ("boolean", "eq", 1),
    "state-integrity": ("boolean", "eq", 1),
    "model-identity": ("boolean", "eq", 1),
    "behavior-baseline": ("boolean", "eq", 1),
    "tool-contract": ("boolean", "eq", 1),
    "serving-mutated": ("boolean", "eq", 0),
    "availability": ("ppm", "gte", None),
    "error-rate": ("ppm", "lte", None),
    "latency-p95": ("milliseconds", "lte", None),
    "quality": ("ppm", "gte", None),
    "safety-violations": ("ppm", "lte", None),
    "tool-success": ("ppm", "gte", None),
    "cost-per-request": ("microunits", "lte", None),
}
PLANETARY_OBJECTIVES = {
    "saturation": ("ppm", "lte", None),
    "knowledge-age": ("seconds", "lte", None),
}
CORE_CONTROLS = {
    "circuit-breaker",
    "kill-switch",
    "load-shedding",
    "rate-limit",
}
PLANETARY_CONTROLS = {"regional-failover"}
OBSERVED_KEYS = {
    "artifact_sha256",
    "grail_id",
    "grail_path",
    "grail_sha256",
    "grail_size_bytes",
    "model_set_payload_hash",
    "tool_set_payload_hash",
    "state_schema_sha256",
}


def _objective_map(plan: dict) -> dict[str, dict]:
    return {objective["id"]: objective for objective in plan["health_contract"]["objectives"]}


def _components_hash(release: dict, kind: str) -> str:
    components = [
        component for component in release["components"] if component["kind"] == kind
    ]
    return particle_hash({"kind": kind, "components": components})


def _state_schema_component(release: dict) -> dict:
    components = [
        component for component in release["components"]
        if component["kind"] == "state-schema"
    ]
    require(len(components) == 1, "deployment: release requires exactly one state-schema component")
    return components[0]


def validate_plan_payload(release: dict, payload: dict) -> str:
    release_hash = C.validate_release_payload(release)
    canonical_object(payload, "deployment")
    exact_keys(payload, PLAN_KEYS, "deployment")
    require(payload["schema"] == PLAN_SCHEMA, "deployment.schema: wrong protocol")
    require(payload["release_payload_hash"] == release_hash, "deployment: release binding mismatch")
    hex64(payload["promotion_payload_hash"], "deployment.promotion_payload_hash")
    https_uri(payload["release_scope"], "deployment.release_scope")
    require(payload["release_scope"] == release["release_scope"], "deployment: release scope mismatch")
    utc(payload["created_utc"], "deployment.created_utc")
    require(
        payload["deployment_class"] in ("single-cell", "multi-cell", "planetary"),
        "deployment.deployment_class: unsupported",
    )

    serving = exact_keys(
        payload["serving"],
        {"candidate_isolated", "in_place_mutation", "current_release_payload_hash"},
        "deployment.serving",
    )
    require(
        boolean(serving["candidate_isolated"], "deployment.serving.candidate_isolated"),
        "deployment: candidate must be isolated",
    )
    require(
        not boolean(serving["in_place_mutation"], "deployment.serving.in_place_mutation"),
        "deployment: in-place serving mutation forbidden",
    )
    current_release = serving["current_release_payload_hash"]
    if current_release is not None:
        hex64(current_release, "deployment.serving.current_release_payload_hash")
        require(current_release != release_hash, "deployment: current and candidate release must differ")

    topology = exact_keys(payload["topology"], {"mode", "cells"}, "deployment.topology")
    require(topology["mode"] == "cellular", "deployment.topology.mode: must be cellular")
    cells = topology["cells"]
    require(isinstance(cells, list) and cells, "deployment.topology.cells: expected non-empty array")
    cell_ids = []
    regions = set()
    failure_domains = set()
    for index, cell in enumerate(cells):
        where = f"deployment.topology.cells[{index}]"
        cell = exact_keys(cell, {"cell_id", "region", "failure_domain", "tenant_scope"}, where)
        cell_ids.append(label(cell["cell_id"], f"{where}.cell_id"))
        regions.add(text(cell["region"], f"{where}.region", maximum=64))
        failure_domains.add(text(cell["failure_domain"], f"{where}.failure_domain", maximum=128))
        text(cell["tenant_scope"], f"{where}.tenant_scope", maximum=256)
    require(len(cell_ids) == len(set(cell_ids)), "deployment.topology.cells: duplicate cell_id")
    if payload["deployment_class"] == "multi-cell":
        require(len(cells) >= 2 and len(failure_domains) >= 2, "deployment: multi-cell requires two failure domains")
    if payload["deployment_class"] == "planetary":
        require(len(cells) >= 3, "deployment: planetary requires at least three cells")
        require(len(regions) >= 2, "deployment: planetary requires at least two regions")
        require(len(failure_domains) >= 3, "deployment: planetary requires at least three failure domains")

    waves = payload["waves"]
    require(isinstance(waves, list) and len(waves) >= 3, "deployment.waves: expected at least three waves")
    wave_ids = []
    traffic = []
    prior_cells = set()
    for index, wave in enumerate(waves):
        where = f"deployment.waves[{index}]"
        wave = exact_keys(
            wave,
            {"id", "traffic_basis_points", "minimum_observation_seconds", "minimum_healthy_windows", "cell_ids"},
            where,
        )
        wave_id = label(wave["id"], f"{where}.id")
        require(wave_id not in wave_ids, f"{where}.id: duplicate wave")
        wave_ids.append(wave_id)
        traffic.append(bounded_int(wave["traffic_basis_points"], f"{where}.traffic_basis_points", 0, 10000))
        positive_int(wave["minimum_observation_seconds"], f"{where}.minimum_observation_seconds")
        positive_int(wave["minimum_healthy_windows"], f"{where}.minimum_healthy_windows")
        selected_cells = set(unique_strings(wave["cell_ids"], f"{where}.cell_ids", labels=True))
        require(selected_cells, f"{where}.cell_ids: expected at least one cell")
        require(selected_cells <= set(cell_ids), f"{where}.cell_ids: unknown cell")
        require(prior_cells <= selected_cells, f"{where}.cell_ids: exposure cannot drop cells")
        prior_cells = selected_cells
    require(wave_ids[0] == "shadow" and traffic[0] == 0, "deployment.waves: first wave must be zero-traffic shadow")
    require(wave_ids[-1] == "global" and traffic[-1] == 10000, "deployment.waves: last wave must be global at 10000 basis points")
    require(traffic == sorted(set(traffic)), "deployment.waves: traffic must increase strictly")
    require(set(waves[-1]["cell_ids"]) == set(cell_ids), "deployment.waves: global must include every cell")
    if payload["deployment_class"] == "planetary":
        require("canary" in wave_ids and "regional" in wave_ids, "deployment: planetary requires canary and regional waves")
        canary = waves[wave_ids.index("canary")]
        regional = waves[wave_ids.index("regional")]
        require(canary["traffic_basis_points"] <= 100, "deployment: planetary canary cannot exceed one percent")
        require(regional["traffic_basis_points"] <= 5000, "deployment: regional wave cannot exceed fifty percent")

    contract = exact_keys(
        payload["health_contract"],
        {"max_evidence_age_seconds", "objectives"},
        "deployment.health_contract",
    )
    positive_int(contract["max_evidence_age_seconds"], "deployment.health_contract.max_evidence_age_seconds")
    objectives = contract["objectives"]
    require(isinstance(objectives, list) and objectives, "deployment.health_contract.objectives: expected array")
    objective_ids = set()
    for index, objective in enumerate(objectives):
        where = f"deployment.health_contract.objectives[{index}]"
        objective = exact_keys(objective, {"id", "unit", "operator", "threshold"}, where)
        objective_id = label(objective["id"], f"{where}.id")
        require(objective_id not in objective_ids, f"{where}.id: duplicate objective")
        objective_ids.add(objective_id)
        label(objective["unit"], f"{where}.unit")
        require(objective["operator"] in ("eq", "gte", "lte"), f"{where}.operator: unsupported")
        positive_int(objective["threshold"], f"{where}.threshold", allow_zero=True)
    required_objectives = dict(CORE_OBJECTIVES)
    if payload["deployment_class"] == "planetary":
        required_objectives.update(PLANETARY_OBJECTIVES)
    require(
        set(required_objectives) <= objective_ids,
        f"deployment.health_contract: missing objectives {sorted(set(required_objectives) - objective_ids)}",
    )
    by_id = _objective_map(payload)
    for objective_id, (unit, operator, exact_threshold) in required_objectives.items():
        objective = by_id[objective_id]
        require(objective["unit"] == unit, f"deployment objective {objective_id}: wrong unit")
        require(objective["operator"] == operator, f"deployment objective {objective_id}: wrong operator")
        if exact_threshold is not None:
            require(
                objective["threshold"] == exact_threshold,
                f"deployment objective {objective_id}: threshold must be {exact_threshold}",
            )

    state = exact_keys(
        payload["state"],
        {
            "schema",
            "migration",
            "backward_compatible",
            "rollback_snapshot_sha256",
            "rollback_evidence_sha256",
            "restore_evidence_sha256",
            "schema_sha256",
            "previous_schema_sha256",
            "compatibility_evidence_sha256",
            "recovery_point_objective_seconds",
            "recovery_time_objective_seconds",
        },
        "deployment.state",
    )
    text(state["schema"], "deployment.state.schema", maximum=128)
    hex64(state["schema_sha256"], "deployment.state.schema_sha256")
    hex64(state["previous_schema_sha256"], "deployment.state.previous_schema_sha256")
    hex64(
        state["compatibility_evidence_sha256"],
        "deployment.state.compatibility_evidence_sha256",
    )
    require(state["migration"] in ("none", "expand-contract", "dual-read-write"), "deployment.state.migration: unsupported")
    require(
        boolean(state["backward_compatible"], "deployment.state.backward_compatible"),
        "deployment.state: backward compatibility required",
    )
    snapshot = state["rollback_snapshot_sha256"]
    if snapshot is not None:
        hex64(snapshot, "deployment.state.rollback_snapshot_sha256")
    if state["migration"] != "none" or payload["deployment_class"] in ("multi-cell", "planetary"):
        require(snapshot is not None, "deployment.state: this plan requires a rollback snapshot")
    positive_int(state["recovery_point_objective_seconds"], "deployment.state.recovery_point_objective_seconds")
    positive_int(state["recovery_time_objective_seconds"], "deployment.state.recovery_time_objective_seconds")
    hex64(state["rollback_evidence_sha256"], "deployment.state.rollback_evidence_sha256")
    hex64(state["restore_evidence_sha256"], "deployment.state.restore_evidence_sha256")

    data = exact_keys(
        payload["data"],
        {
            "tenant_isolation",
            "residency_policy_sha256",
            "retention_policy_sha256",
            "deletion_policy_sha256",
            "backup_policy_sha256",
        },
        "deployment.data",
    )
    require(boolean(data["tenant_isolation"], "deployment.data.tenant_isolation"), "deployment.data: tenant isolation required")
    for key in (
        "residency_policy_sha256",
        "retention_policy_sha256",
        "deletion_policy_sha256",
        "backup_policy_sha256",
    ):
        hex64(data[key], f"deployment.data.{key}")

    resilience = exact_keys(
        payload["resilience"],
        {"controls", "provider_failure_mode"},
        "deployment.resilience",
    )
    controls = set(unique_strings(resilience["controls"], "deployment.resilience.controls", labels=True))
    required_controls = set(CORE_CONTROLS)
    if payload["deployment_class"] == "planetary":
        required_controls |= PLANETARY_CONTROLS
    require(
        required_controls <= controls,
        f"deployment.resilience: missing controls {sorted(required_controls - controls)}",
    )
    require(
        resilience["provider_failure_mode"] in ("fail-closed", "degrade-explicitly"),
        "deployment.resilience.provider_failure_mode: unsupported",
    )

    rollback = payload["rollback_release_payload_hash"]
    if rollback is not None:
        hex64(rollback, "deployment.rollback_release_payload_hash")
        require(rollback != release_hash, "deployment: rollback target cannot be candidate")
    if payload["deployment_class"] in ("multi-cell", "planetary"):
        require(rollback is not None, "deployment: multi-cell and planetary plans require rollback target")
        if current_release is not None:
            require(rollback == current_release, "deployment: rollback target must equal current serving release")
    require(boolean(payload["automatic_pause"], "deployment.automatic_pause"), "deployment: automatic pause required")
    require(boolean(payload["automatic_rollback"], "deployment.automatic_rollback"), "deployment: automatic rollback required")
    return particle_hash(payload)


def authorize_plan(
    *,
    release: dict,
    grail_binding: dict,
    policy: dict,
    evidence_chain: list[dict],
    promotion: dict,
    rollback_release: dict,
    rollback_grail_binding: dict,
    plan: dict,
    verification_time: datetime,
    promotion_authorization_verifier,
    evidence_authorization_verifier,
    rollback_authorization_verifier,
    grail_binding_verifier,
    rollback_grail_binding_verifier,
) -> str:
    require(
        grail_binding_verifier is not None and bool(grail_binding_verifier(grail_binding)),
        "deployment authorization: Grail binding is not authenticated",
    )
    release_hash = C.validate_release(release, grail_binding)
    plan_hash = validate_plan_payload(release, plan)
    promotion_hash = C.validate_promotion(
        release,
        grail_binding,
        policy,
        evidence_chain,
        promotion,
        verification_time=verification_time,
    )
    require(promotion["decision"] == "promote", "deployment authorization: release was not promoted")
    require(promotion["to_stage_id"] == policy["stages"][-1]["id"], "deployment authorization: promotion is not to production")
    require(
        promotion_authorization_verifier is not None
        and bool(promotion_authorization_verifier(promotion)),
        "deployment authorization: promotion is not authorized",
    )
    require(
        evidence_authorization_verifier is not None
        and all(bool(evidence_authorization_verifier(evidence)) for evidence in evidence_chain),
        "deployment authorization: qualification evidence is not authorized",
    )
    require(plan["promotion_payload_hash"] == promotion_hash, "deployment authorization: promotion binding mismatch")
    require(plan["release_payload_hash"] == release_hash, "deployment authorization: release binding mismatch")

    require(
        rollback_grail_binding_verifier is not None
        and bool(rollback_grail_binding_verifier(rollback_grail_binding)),
        "deployment authorization: rollback Grail binding is not authenticated",
    )
    rollback_hash = C.validate_release(rollback_release, rollback_grail_binding)
    require(
        plan["rollback_release_payload_hash"] == rollback_hash,
        "deployment authorization: rollback release does not resolve",
    )
    require(
        rollback_authorization_verifier is not None
        and bool(rollback_authorization_verifier(rollback_release)),
        "deployment authorization: rollback release is not previously authorized",
    )
    candidate_state = _state_schema_component(release)
    rollback_state = _state_schema_component(rollback_release)
    require(
        plan["state"]["schema_sha256"] == candidate_state["sha256"],
        "deployment authorization: candidate state schema mismatch",
    )
    require(
        plan["state"]["previous_schema_sha256"] == rollback_state["sha256"],
        "deployment authorization: rollback state schema mismatch",
    )
    if plan["state"]["migration"] == "none":
        require(
            rollback_state["sha256"] == candidate_state["sha256"],
            "deployment authorization: no-migration plan changed state schema",
        )
    preprod = evidence_chain[-1]
    checks = {check["id"]: check for check in preprod["checks"]}
    require(
        checks["rollback-rehearsal"]["evidence_sha256"] == plan["state"]["rollback_evidence_sha256"],
        "deployment authorization: rollback rehearsal evidence mismatch",
    )
    require(
        checks["restore-rehearsal"]["evidence_sha256"] == plan["state"]["restore_evidence_sha256"],
        "deployment authorization: restore rehearsal evidence mismatch",
    )
    require(
        checks["state-compatibility"]["evidence_sha256"]
        == plan["state"]["compatibility_evidence_sha256"],
        "deployment authorization: state compatibility evidence mismatch",
    )
    created = utc(plan["created_utc"], "deployment.created_utc")
    decided = utc(promotion["decided_utc"], "promotion.decided_utc")
    require(decided <= created <= verification_time, "deployment authorization: invalid plan creation time")
    return plan_hash


def _health_shape(payload: dict) -> tuple[datetime, datetime]:
    canonical_object(payload, "health")
    exact_keys(payload, HEALTH_KEYS, "health")
    require(payload["schema"] == HEALTH_SCHEMA, "health.schema: wrong protocol")
    hex64(payload["deployment_payload_hash"], "health.deployment_payload_hash")
    hex64(payload["release_payload_hash"], "health.release_payload_hash")
    label(payload["cell_id"], "health.cell_id")
    label(payload["wave_id"], "health.wave_id")
    started = utc(payload["window_start_utc"], "health.window_start_utc")
    ended = utc(payload["window_end_utc"], "health.window_end_utc")
    require(ended >= started, "health: window ends before it starts")
    observed = exact_keys(payload["observed"], OBSERVED_KEYS, "health.observed")
    hex64(observed["artifact_sha256"], "health.observed.artifact_sha256")
    grail_id(observed["grail_id"], "health.observed.grail_id")
    relative_path(observed["grail_path"], "health.observed.grail_path")
    hex64(observed["grail_sha256"], "health.observed.grail_sha256")
    positive_int(observed["grail_size_bytes"], "health.observed.grail_size_bytes")
    hex64(observed["model_set_payload_hash"], "health.observed.model_set_payload_hash")
    hex64(observed["tool_set_payload_hash"], "health.observed.tool_set_payload_hash")
    hex64(observed["state_schema_sha256"], "health.observed.state_schema_sha256")
    measurements = payload["measurements"]
    require(isinstance(measurements, list) and measurements, "health.measurements: expected array")
    ids = set()
    for index, measurement in enumerate(measurements):
        where = f"health.measurements[{index}]"
        measurement = exact_keys(measurement, {"id", "unit", "value", "evidence_sha256"}, where)
        measurement_id = label(measurement["id"], f"{where}.id")
        require(measurement_id not in ids, f"{where}.id: duplicate measurement")
        ids.add(measurement_id)
        label(measurement["unit"], f"{where}.unit")
        positive_int(measurement["value"], f"{where}.value", allow_zero=True)
        hex64(measurement["evidence_sha256"], f"{where}.evidence_sha256")
    require(payload["verdict"] in ("healthy", "unhealthy"), "health.verdict: unsupported")
    unique_strings(payload["reason_codes"], "health.reason_codes", labels=True)
    previous = payload["previous_health_payload_hash"]
    if previous is not None:
        hex64(previous, "health.previous_health_payload_hash")
    return started, ended


def health_failures(
    release: dict,
    plan: dict,
    health: dict,
    verification_time: datetime,
) -> list[str]:
    _, ended = _health_shape(health)
    objectives = _objective_map(plan)
    measurements = {measurement["id"]: measurement for measurement in health["measurements"]}
    observed = health["observed"]
    derived = {
        "artifact-match": int(observed["artifact_sha256"] == release["artifact"]["sha256"]),
        "grail-match": int(
            observed["grail_id"] == release["grail"]["grail_id"]
            and observed["grail_path"] == release["grail"]["path"]
            and observed["grail_sha256"] == release["grail"]["sha256"]
            and observed["grail_size_bytes"] == release["grail"]["size_bytes"]
        ),
        "model-identity": int(
            observed["model_set_payload_hash"] == _components_hash(release, "model")
        ),
        "tool-contract": int(
            observed["tool_set_payload_hash"] == _components_hash(release, "tool")
        ),
    }
    state_schema = _state_schema_component(release)
    if observed["state_schema_sha256"] != state_schema["sha256"]:
        derived["state-integrity"] = 0
    failures = []
    for objective_id, objective in objectives.items():
        measurement = measurements.get(objective_id)
        if measurement is None or measurement["unit"] != objective["unit"]:
            failures.append(objective_id)
            continue
        value = measurement["value"]
        if objective_id in derived:
            require(
                value == derived[objective_id],
                f"health measurement {objective_id}: contradicts observed runtime identity",
            )
        if objective_id == "state-integrity" and "state-integrity" in derived:
            require(value == 0, "health measurement state-integrity: schema drift must report zero")
        threshold = objective["threshold"]
        passed = {
            "eq": value == threshold,
            "gte": value >= threshold,
            "lte": value <= threshold,
        }[objective["operator"]]
        if not passed:
            failures.append(objective_id)
    for unexpected in set(measurements) - set(objectives):
        failures.append(f"undeclared-{unexpected}")
    require(verification_time.tzinfo is not None, "health: verification time must be timezone-aware")
    require(ended <= verification_time, "health: observation ends in the future")
    if (verification_time - ended).total_seconds() > plan["health_contract"]["max_evidence_age_seconds"]:
        failures.append("stale")
    return sorted(failures)


def validate_health(
    release: dict,
    plan: dict,
    payload: dict,
    *,
    verification_time: datetime,
) -> str:
    release_hash = C.validate_release_payload(release)
    plan_hash = validate_plan_payload(release, plan)
    started, ended = _health_shape(payload)
    require(payload["deployment_payload_hash"] == plan_hash, "health: deployment binding mismatch")
    require(payload["release_payload_hash"] == release_hash, "health: release binding mismatch")
    cells = {cell["cell_id"] for cell in plan["topology"]["cells"]}
    require(payload["cell_id"] in cells, "health.cell_id: not present in plan")
    wave = next((wave for wave in plan["waves"] if wave["id"] == payload["wave_id"]), None)
    require(wave is not None, "health.wave_id: not present in plan")
    require(payload["cell_id"] in wave["cell_ids"], "health: cell not selected for wave")
    require(
        (ended - started).total_seconds() >= wave["minimum_observation_seconds"],
        "health: observation window shorter than plan minimum",
    )
    failures = health_failures(release, plan, payload, verification_time)
    expected = "healthy" if not failures else "unhealthy"
    require(payload["verdict"] == expected, f"health.verdict: must be {expected}")
    require(payload["reason_codes"] == failures, "health.reason_codes: must exactly describe computed failures")
    return particle_hash(payload)


def validate_decision(
    release: dict,
    plan: dict,
    health_records: list[dict],
    payload: dict,
    *,
    verification_time: datetime,
    previous_decision: dict | None = None,
) -> str:
    release_hash = C.validate_release_payload(release)
    plan_hash = validate_plan_payload(release, plan)
    _decision_shape(payload)
    require(payload["deployment_payload_hash"] == plan_hash, "deployment decision: plan binding mismatch")
    require(payload["release_payload_hash"] == release_hash, "deployment decision: release binding mismatch")
    supplied_hashes = payload["health_payload_hashes"]
    target = payload["target_release_payload_hash"]
    if target is not None:
        hex64(target, "deployment decision.target_release_payload_hash")

    wave = next((wave for wave in plan["waves"] if wave["id"] == payload["wave_id"]), None)
    require(wave is not None, "deployment decision.wave_id: not present in plan")
    wave_index = next(index for index, candidate in enumerate(plan["waves"]) if candidate["id"] == wave["id"])
    previous_hash = payload["previous_decision_payload_hash"]
    if previous_decision is None:
        require(wave_index == 0, "deployment decision: non-first wave requires predecessor decision")
        require(previous_hash is None, "deployment decision: first wave predecessor must be null")
        prior_health_heads = {}
        wave_authorized_at = utc(plan["created_utc"], "deployment.created_utc")
    else:
        _decision_shape(previous_decision)
        require(
            previous_decision["deployment_payload_hash"] == plan_hash
            and previous_decision["release_payload_hash"] == release_hash,
            "deployment decision: predecessor binding mismatch",
        )
        require(
            previous_hash == particle_hash(previous_decision),
            "deployment decision: predecessor hash mismatch",
        )
        previous_wave_index = next(
            (
                index
                for index, candidate in enumerate(plan["waves"])
                if candidate["id"] == previous_decision["wave_id"]
            ),
            None,
        )
        require(previous_wave_index is not None, "deployment decision: predecessor wave is not in plan")
        if previous_wave_index == wave_index - 1:
            require(
                previous_decision["action"] == "advance",
                "deployment decision: previous wave did not advance",
            )
            prior_wave = plan["waves"][previous_wave_index]
        elif previous_wave_index == wave_index:
            allowed_same_wave_predecessors = {"hold", "quarantine"}
            if wave_index == len(plan["waves"]) - 1:
                allowed_same_wave_predecessors.add("complete")
            require(
                previous_decision["action"] in allowed_same_wave_predecessors,
                "deployment decision: same-wave predecessor cannot continue",
            )
            prior_wave = wave
        else:
            raise ValueError("deployment decision: skipped or forked decision chain")
        prior_cells = set(prior_wave["cell_ids"])
        prior_health_heads = dict(previous_decision["health_heads"])
        require(
            set(prior_health_heads) <= set(wave["cell_ids"]),
            "deployment decision: predecessor health head is outside current wave",
        )
        if previous_wave_index == wave_index - 1:
            require(
                prior_cells <= set(prior_health_heads),
                "deployment decision: predecessor wave lacks a health head for an exposed cell",
            )
        wave_authorized_at = utc(previous_decision["decided_utc"], "previous decision.decided_utc")

    decided = utc(payload["decided_utc"], "deployment decision.decided_utc")
    require(decided <= verification_time, "deployment decision: future decision")
    if previous_decision is not None:
        require(
            utc(previous_decision["decided_utc"], "previous decision.decided_utc") <= decided,
            "deployment decision: decision time moved backward",
        )
    actual_hashes = [
        validate_health(release, plan, health, verification_time=decided)
        for health in health_records
    ]
    require(sorted(supplied_hashes) == sorted(actual_hashes), "deployment decision: health evidence set mismatch")
    require(health_records, "deployment decision: health evidence required")
    require(all(health["wave_id"] == wave["id"] for health in health_records), "deployment decision: mixed waves")
    last_heads = dict(prior_health_heads)
    seen_current_cells = set()
    for health in health_records:
        if health["cell_id"] not in seen_current_cells:
            require(
                utc(health["window_start_utc"], "health.window_start_utc") >= wave_authorized_at,
                "deployment decision: health predates wave authorization",
            )
            seen_current_cells.add(health["cell_id"])
        prior_head = last_heads.get(health["cell_id"])
        expected_previous = prior_head["payload_hash"] if prior_head is not None else None
        require(
            health["previous_health_payload_hash"] == expected_previous,
            "deployment decision: broken health predecessor chain",
        )
        if prior_head is not None:
            require(
                utc(health["window_start_utc"], "health.window_start_utc")
                > utc(prior_head["window_end_utc"], "prior health.window_end_utc"),
                "deployment decision: overlapping or reordered health windows",
            )
        last_heads[health["cell_id"]] = {
            "payload_hash": particle_hash(health),
            "window_end_utc": health["window_end_utc"],
        }
    require(
        payload["health_heads"] == last_heads,
        "deployment decision: resulting health heads mismatch",
    )

    healthy_counts = Counter(
        health["cell_id"] for health in health_records if health["verdict"] == "healthy"
    )
    ready = all(
        healthy_counts[cell_id] >= wave["minimum_healthy_windows"]
        for cell_id in wave["cell_ids"]
    )
    if payload["action"] in ("advance", "complete"):
        require(
            all(health["verdict"] == "healthy" for health in health_records),
            "deployment decision: unhealthy evidence cannot advance",
        )
        require(ready, "deployment decision: insufficient healthy windows")
        is_last = wave["id"] == plan["waves"][-1]["id"]
        require(
            payload["action"] == ("complete" if is_last else "advance"),
            "deployment decision: action does not match wave position",
        )
        require(target is None, "deployment decision: advance/complete target must be null")
    elif payload["action"] == "rollback":
        require(target == plan["rollback_release_payload_hash"], "deployment decision: wrong rollback target")
    else:
        require(target is None, "deployment decision: hold/quarantine target must be null")
    return particle_hash(payload)


def _decision_shape(payload: dict) -> dict:
    canonical_object(payload, "deployment decision")
    exact_keys(payload, DECISION_KEYS, "deployment decision")
    require(payload["schema"] == DECISION_SCHEMA, "deployment decision.schema: wrong protocol")
    hex64(payload["deployment_payload_hash"], "deployment decision.deployment_payload_hash")
    hex64(payload["release_payload_hash"], "deployment decision.release_payload_hash")
    label(payload["wave_id"], "deployment decision.wave_id")
    require(
        payload["action"] in ("advance", "complete", "hold", "rollback", "quarantine"),
        "deployment decision.action: unsupported",
    )
    supplied_hashes = unique_strings(
        payload["health_payload_hashes"],
        "deployment decision.health_payload_hashes",
    )
    for index, digest in enumerate(supplied_hashes):
        hex64(digest, f"deployment decision.health_payload_hashes[{index}]")
    target = payload["target_release_payload_hash"]
    if target is not None:
        hex64(target, "deployment decision.target_release_payload_hash")
    previous = payload["previous_decision_payload_hash"]
    if previous is not None:
        hex64(previous, "deployment decision.previous_decision_payload_hash")
    health_heads = payload["health_heads"]
    require(isinstance(health_heads, dict), "deployment decision.health_heads: expected object")
    for cell_id, head in health_heads.items():
        label(cell_id, "deployment decision.health_heads cell")
        head = exact_keys(
            head,
            {"payload_hash", "window_end_utc"},
            f"deployment decision.health_heads.{cell_id}",
        )
        hex64(head["payload_hash"], f"deployment decision.health_heads.{cell_id}.payload_hash")
        utc(head["window_end_utc"], f"deployment decision.health_heads.{cell_id}.window_end_utc")
    utc(payload["decided_utc"], "deployment decision.decided_utc")
    return payload


def authorize_plan_frame(
    *,
    release: dict,
    grail_binding: dict,
    policy: dict,
    evidence_chain: list[dict],
    promotion: dict,
    rollback_release: dict,
    rollback_grail_binding: dict,
    frame: dict,
    head: dict | None,
    stream_id: str,
    registered_kinds: set[str],
    signature_verifier,
    authorization_verifier,
    verification_time: datetime,
    promotion_authorization_verifier,
    evidence_authorization_verifier,
    rollback_authorization_verifier,
    grail_binding_verifier,
    rollback_grail_binding_verifier,
) -> str:
    plan = authoritative_frame_payload(
        frame,
        expected_schema=PLAN_SCHEMA,
        purpose="rapp-deploy-plan",
        head=head,
        stream_id=stream_id,
        registered_kinds=registered_kinds,
        signature_verifier=signature_verifier,
        authorization_verifier=authorization_verifier,
    )
    return authorize_plan(
        release=release,
        grail_binding=grail_binding,
        policy=policy,
        evidence_chain=evidence_chain,
        promotion=promotion,
        rollback_release=rollback_release,
        rollback_grail_binding=rollback_grail_binding,
        plan=plan,
        verification_time=verification_time,
        promotion_authorization_verifier=promotion_authorization_verifier,
        evidence_authorization_verifier=evidence_authorization_verifier,
        rollback_authorization_verifier=rollback_authorization_verifier,
        grail_binding_verifier=grail_binding_verifier,
        rollback_grail_binding_verifier=rollback_grail_binding_verifier,
    )


def authorize_decision_frame(
    *,
    release: dict,
    plan: dict,
    health_records: list[dict],
    frame: dict,
    head: dict | None,
    stream_id: str,
    registered_kinds: set[str],
    signature_verifier,
    authorization_verifier,
    plan_authorization_verifier,
    health_authorization_verifier,
    previous_decision_authorization_verifier,
    verification_time: datetime,
    previous_decision: dict | None = None,
) -> str:
    require(
        plan_authorization_verifier is not None and bool(plan_authorization_verifier(plan)),
        "rapp-deploy-decision: deployment plan is not authorized",
    )
    require(
        health_authorization_verifier is not None
        and all(bool(health_authorization_verifier(health)) for health in health_records),
        "rapp-deploy-decision: health evidence is not authorized",
    )
    if previous_decision is not None:
        require(
            previous_decision_authorization_verifier is not None
            and bool(previous_decision_authorization_verifier(previous_decision)),
            "rapp-deploy-decision: predecessor decision is not authorized",
        )
    decision = authoritative_frame_payload(
        frame,
        expected_schema=DECISION_SCHEMA,
        purpose="rapp-deploy-decision",
        head=head,
        stream_id=stream_id,
        registered_kinds=registered_kinds,
        signature_verifier=signature_verifier,
        authorization_verifier=authorization_verifier,
    )
    require(head is not None, "rapp-deploy-decision: frame predecessor is required")
    expected_head_payload_hash = particle_hash(
        previous_decision if previous_decision is not None else plan
    )
    require(
        head["payload_hash"] == expected_head_payload_hash,
        "rapp-deploy-decision: frame head does not match decision predecessor",
    )
    return validate_decision(
        release,
        plan,
        health_records,
        decision,
        verification_time=verification_time,
        previous_decision=previous_decision,
    )


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("plan", "health", "decision"))
    parser.add_argument("document")
    parser.add_argument("--release", required=True)
    parser.add_argument("--plan")
    parser.add_argument("--health", action="append", default=[])
    parser.add_argument("--previous-decision")
    parser.add_argument("--verification-utc")
    args = parser.parse_args()
    release = load_json(args.release)
    document = load_json(args.document)
    if args.kind == "plan":
        digest = validate_plan_payload(release, document)
    elif args.kind == "health":
        require(args.plan and args.verification_utc, "health requires --plan and --verification-utc")
        digest = validate_health(
            release,
            load_json(args.plan),
            document,
            verification_time=utc(args.verification_utc, "verification_utc"),
        )
    else:
        require(
            args.plan and args.health and args.verification_utc,
            "decision requires --plan, --verification-utc, and at least one --health",
        )
        digest = validate_decision(
            release,
            load_json(args.plan),
            [load_json(path) for path in args.health],
            document,
            verification_time=utc(args.verification_utc, "verification_utc"),
            previous_decision=load_json(args.previous_decision) if args.previous_decision else None,
        )
    print(json.dumps({"status": "payload-conformant", "payload_hash": digest}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "refused", "detail": str(error)}))
        sys.exit(1)
