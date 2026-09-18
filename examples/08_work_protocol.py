#!/usr/bin/env python3
"""Build and verify the seven-frame rapp-work/1 example lifecycle."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import rapp as R
import rapp_work as W

EXAMPLES = ROOT / "protocols" / "examples"
bundle = json.loads((EXAMPLES / "work-lifecycle.json").read_text(encoding="utf-8"))
release = json.loads((EXAMPLES / "release.json").read_text(encoding="utf-8"))
rollback_release = json.loads((EXAMPLES / "rollback-release.json").read_text(encoding="utf-8"))
deployment = json.loads((EXAMPLES / "deployment.json").read_text(encoding="utf-8"))
organization = bundle["organization"]
qualification_verifier = lambda candidate, policy_sha256: (
    candidate["release_scope"] == organization["release_scope"]
    and policy_sha256 == organization["policy_sha256"]
)
source_head_verifier = lambda source: source == bundle["migration"]["source"]

W.validate_organization(organization)
W.validate_catalog(bundle["catalog"], organization)
W.validate_vector(bundle["vector"], organization)
W.validate_rollback(
    bundle["rollback"],
    organization,
    rollback_release,
    deployment=deployment,
    candidate_release=release,
    qualification_verifier=qualification_verifier,
)
W.validate_migration(
    bundle["migration"],
    organization,
    bundle["catalog"],
    bundle["vector"],
    release,
    bundle["rollback"],
    source_head_verifier=source_head_verifier,
    qualification_verifier=qualification_verifier,
)
W.validate_migration_receipt(
    bundle["receipt"],
    bundle["migration"],
    organization,
    custody_verifier=lambda _custody: True,
)
W.validate_observation(
    bundle["observation"],
    organization,
    release,
    deployment,
    bundle["vector"],
    health_verifier=lambda _observation: True,
    qualification_verifier=qualification_verifier,
)

payloads = [
    ("work.organization", bundle["organization"]),
    ("work.catalog", bundle["catalog"]),
    ("work.vector", bundle["vector"]),
    ("work.rollback", bundle["rollback"]),
    ("work.migration", bundle["migration"]),
    ("work.receipt", bundle["receipt"]),
    ("work.observation", bundle["observation"]),
]
head = None
for sequence, (kind, payload) in enumerate(payloads):
    frame = R.build_frame(
        kind,
        organization["organization_rappid"],
        sequence,
        payload.get("created_utc")
        or payload.get("observed_utc")
        or payload.get("issued_utc"),
        payload,
        None if head is None else head["payload_hash"],
        sig="example-signature",
    )
    W.authorize_frame(
        frame,
        expected_kind=kind,
        head=head,
        stream_id=organization["organization_rappid"],
        registered_kinds=set(W.WORK_KINDS),
        signature_verifier=lambda _unsigned, signature: (
            signature == "example-signature",
            "bad example signature",
        ),
        authorization_verifier=lambda _frame, _purpose: True,
        organization=organization,
    )
    assert set(frame) == R.FRAME_KEYS
    print(f"{sequence}: {kind} payload={frame['payload_hash']} wave={frame['frame_hash']}")
    head = frame

print("rapp-work/1 example: seven signed frames, exact eleven-key wire, PASS")
