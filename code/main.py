import csv
import json
import sys
from collections import Counter
from pathlib import Path

from audit_agent.engine import AuditEvidenceGapError, run_audit, write_output


def write_unresolved_report(gaps_by_case: dict[str, list[str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case_id", "evidence_gaps_json"])
        writer.writeheader()
        for case_id, gaps in sorted(gaps_by_case.items()):
            writer.writerow(
                {
                    "case_id": case_id,
                    "evidence_gaps_json": json.dumps(
                        sorted(set(gaps)), ensure_ascii=False, separators=(",", ":")
                    ),
                }
            )


def _gap_category(reason: str) -> str:
    if "identity" in reason:
        return "identity resolution"
    if "category " in reason and "policy action" in reason:
        return "conditional policy lacks required fields"
    if "does not establish a state" in reason:
        return "resource state unknown"
    if "no subject-linked" in reason:
        return "no subject-linked evidence"
    if "completion lacks" in reason:
        return "completion proof missing"
    if "future verification" in reason:
        return "future verification cannot be planned"
    return "other evidence gap"


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    report_path = root / "code" / "evaluation" / "unresolved_cases.csv"
    try:
        rows = run_audit(root)
    except AuditEvidenceGapError as error:
        write_unresolved_report(error.gaps_by_case, report_path)
        categories = Counter(
            _gap_category(reason)
            for reasons in error.gaps_by_case.values()
            for reason in reasons
        )
        print(str(error), file=sys.stderr)
        print(
            f"Unresolved case IDs: {', '.join(sorted(error.gaps_by_case))}",
            file=sys.stderr,
        )
        print(f"Evidence-gap categories: {dict(sorted(categories.items()))}", file=sys.stderr)
        print(f"Detailed report: {report_path}", file=sys.stderr)
        print("The existing output.csv, if any, was left unchanged.", file=sys.stderr)
        raise SystemExit(2) from error
    output_path = root / "output.csv"
    write_output(rows, output_path)
    write_unresolved_report({}, report_path)
    print(f"Wrote {len(rows)} audit rows to {output_path}")


if __name__ == "__main__":
    main()