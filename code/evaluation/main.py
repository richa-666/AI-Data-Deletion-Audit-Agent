from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from audit_agent.engine import audit_case, policy_actions, _load_activity_facts
from audit_agent.evidence import EvidenceCorpus
from audit_agent.identity import IdentityResolver, read_csv
from audit_agent.models import EvidenceFact


@dataclass
class StubIdentity:
    identifiers: dict[str, set[str]]

    def resolve(self, email: str, cutoff: str | None = None) -> StubIdentity:
        return self

    def identifiers_as_of(self, identity: StubIdentity, cutoff: str) -> dict[str, set[str]]:
        return self.identifiers


@dataclass
class StubCorpus:
    facts: list[EvidenceFact]

    @property
    def file_ids(self) -> set[str]:
        return {fact.evidence_id for fact in self.facts}

    def for_subject(self, identifiers: dict[str, set[str]], cutoff: str) -> list[EvidenceFact]:
        return self.facts


def _fact(
    evidence_id: str,
    resource_id: str,
    category: str,
    system_id: str,
    attributes: dict[str, Any],
) -> EvidenceFact:
    return EvidenceFact(
        evidence_id,
        "2026-09-01T00:00:00Z",
        "2026-09-01T00:00:00Z",
        system_id,
        resource_id,
        category,
        attributes,
        "synthetic evaluation case",
    )


def run_custom_cases() -> list[tuple[str, bool]]:
    identity = StubIdentity(
        {
            "user_id": {"user_eval"},
            "name": {"example user"},
            "email": {"example@example.test"},
            "phone": set(),
            "email_hash": set(),
        }
    )
    base_request = {
        "case_id": "custom",
        "email": "example@example.test",
        "audit_at": "2026-09-02T00:00:00Z",
    }
    empty_corpus = StubCorpus([])
    rules = {
        "USER_PROFILE": ("DELETE", "Always"),
        "SECURITY_AUDIT_LOG": ("RETAIN", "Within retention"),
    }

    non_deletion = audit_case(
        {
            **base_request,
            "request_text": "Please send me a copy of the personal data you hold.",
        },
        identity,
        empty_corpus,
        rules,
        [],
    )
    non_deletion_ok = (
        non_deletion["deletion_status"] == "NOT_APPLICABLE"
        and non_deletion["steps"] == []
    )

    remaining_and_flow = StubCorpus(
        [
            _fact(
                "evidence_custom_profile",
                "account_eval",
                "USER_PROFILE",
                "account_service",
                {
                    "user_id": "user_eval",
                    "email": "example@example.test",
                    "account_status": "ACTIVE",
                },
            ),
            _fact(
                "evidence_custom_flow",
                "data_flow_eval",
                "DATA_FLOW",
                "integration_service",
                {"user_id": "user_eval", "enabled": True},
            ),
        ]
    )
    incomplete = audit_case(
        {
            **base_request,
            "request_text": "Please permanently delete my account and stop sync.",
        },
        identity,
        remaining_and_flow,
        rules,
        [],
    )
    incomplete_ok = (
        incomplete["deletion_status"] == "INCOMPLETE"
        and [step["operation"] for step in incomplete["steps"]]
        == [
            "REPORT_REMAINING_RECORD",
            "REPORT_ACTIVE_DATA_FLOW",
            "DISABLE_DATA_FLOW",
            "DELETE_RECORD",
            "VERIFY_RECORD_ABSENT",
            "VERIFY_DATA_FLOW_DISABLED",
        ]
        and all(
            not step["evidence_id"]
            for step in incomplete["steps"]
            if step["phase"] != "FINDING"
        )
    )

    retained_corpus = StubCorpus(
        [
            _fact(
                "evidence_custom_profile_absent",
                "account_eval",
                "USER_PROFILE",
                "account_service",
                {
                    "user_id": "user_eval",
                    "email": "example@example.test",
                    "result": "not_found",
                },
            ),
            _fact(
                "evidence_custom_retained",
                "audit_eval",
                "SECURITY_AUDIT_LOG",
                "security_service",
                {"subject_reference": "user_eval", "result": "retained"},
            )
        ]
    )
    complete = audit_case(
        {
            **base_request,
            "request_text": "Delete my account and remove my personal data.",
        },
        identity,
        retained_corpus,
        rules,
        [],
    )
    complete_ok = (
        complete["deletion_status"] == "COMPLETE"
        and [step["operation"] for step in complete["steps"]]
        == ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT"]
        and complete["steps"][1]["evidence_id"] == "evidence_custom_retained"
    )
    return [
        ("non-deletion request is not applicable", non_deletion_ok),
        ("remaining profile and active flow need ordered remediation", incomplete_ok),
        ("policy-required security record is retained", complete_ok),
    ]


def run_sample_evaluation() -> dict[str, Any]:
    dataset = ROOT / "dataset"
    identities = IdentityResolver(dataset)
    corpus = EvidenceCorpus(dataset)
    rules = policy_actions(dataset)
    activity = _load_activity_facts(dataset)
    requests = read_csv(dataset / "sample_deletion_requests.csv")
    expected = read_csv(dataset / "sample_output.csv")
    predictions = {
        request["case_id"]: audit_case(request, identities, corpus, rules, activity)
        for request in requests
    }
    status_matches = sequence_matches = exact_step_matches = field_matches = 0
    step_slots = field_slots = 0
    expected_step_count = predicted_step_count = 0
    mismatch_counts: Counter[str] = Counter()
    representative_mismatches: list[dict[str, Any]] = []
    unresolved_cases: list[str] = []
    for row in expected:
        prediction = predictions[row["case_id"]]
        if prediction["evidence_gaps"]:
            unresolved_cases.append(row["case_id"])
        expected_steps = json.loads(row["steps_json"])
        predicted_steps = prediction["steps"]
        expected_step_count += len(expected_steps)
        predicted_step_count += len(predicted_steps)
        status_matches += prediction["deletion_status"] == row["deletion_status"]
        sequence_matches += (
            prediction["deletion_status"] == row["deletion_status"]
            and predicted_steps == expected_steps
        )
        for index in range(max(len(expected_steps), len(predicted_steps))):
            step_slots += 1
            field_slots += 7
            if index >= len(expected_steps):
                mismatch_counts["extra_predicted_steps"] += 1
                mismatch = {
                    "case_id": row["case_id"],
                    "step_no": index + 1,
                    "expected": None,
                    "predicted": predicted_steps[index],
                }
            elif index >= len(predicted_steps):
                mismatch_counts["missing_predicted_steps"] += 1
                mismatch_counts["missing_step.phase"] += 1
                mismatch_counts["missing_step.operation"] += 1
                mismatch_counts["missing_step.state"] += 1
                mismatch_counts["missing_step.system_id"] += 1
                mismatch_counts["missing_step.resource_id"] += 1
                mismatch_counts["missing_step.evidence_id"] += 1
                mismatch = {
                    "case_id": row["case_id"],
                    "step_no": index + 1,
                    "expected": expected_steps[index],
                    "predicted": None,
                }
            else:
                actual = predicted_steps[index]
                target = expected_steps[index]
                exact_step_matches += actual == target
                field_matches += sum(actual.get(key) == target.get(key) for key in target)
                for field in (
                    "phase",
                    "operation",
                    "state",
                    "system_id",
                    "resource_id",
                    "evidence_id",
                ):
                    if actual.get(field) != target.get(field):
                        mismatch_counts[f"field.{field}"] += 1
                mismatch = (
                    {
                        "case_id": row["case_id"],
                        "step_no": index + 1,
                        "expected": target,
                        "predicted": actual,
                    }
                    if actual != target
                    else None
                )
            if mismatch and len(representative_mismatches) < 12:
                representative_mismatches.append(mismatch)
    return {
        "case_count": len(expected),
        "status_matches": status_matches,
        "status_accuracy": status_matches / len(expected),
        "exact_step_matches": exact_step_matches,
        "step_slots": step_slots,
        "step_accuracy": exact_step_matches / step_slots if step_slots else 1.0,
        "field_matches": field_matches,
        "field_slots": field_slots,
        "field_accuracy": field_matches / field_slots if field_slots else 1.0,
        "sequence_matches": sequence_matches,
        "sequence_accuracy": sequence_matches / len(expected),
        "expected_steps": expected_step_count,
        "predicted_steps": predicted_step_count,
        "mismatch_counts": dict(sorted(mismatch_counts.items())),
        "representative_mismatches": representative_mismatches,
        "unresolved_cases": unresolved_cases,
    }


def main() -> int:
    metrics = run_sample_evaluation()
    print("Public sample evaluation")
    for key, value in metrics.items():
        if key in {"mismatch_counts", "representative_mismatches", "unresolved_cases"}:
            print(f"{key}: {json.dumps(value, ensure_ascii=False, sort_keys=True)}")
        else:
            print(f"{key}: {value:.4f}" if isinstance(value, float) else f"{key}: {value}")
    custom = run_custom_cases()
    print("\nIndependent custom cases")
    for label, passed in custom:
        print(f"{'PASS' if passed else 'FAIL'}: {label}")
    if not all(passed for _, passed in custom):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
