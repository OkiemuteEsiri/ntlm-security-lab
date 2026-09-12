from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ClosureResult:
    finding_id: str
    status: str
    reasons: tuple[str, ...]


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_record(raw: dict[str, Any]) -> ClosureResult:
    required = {
        "finding_id", "owner", "change_reference", "implemented_control",
        "retest_completed", "retest_protocol", "validation_passed", "validator",
    }
    if set(raw) != required:
        raise ValueError("remediation evidence schema mismatch")
    finding_id = raw["finding_id"]
    if not _nonempty(finding_id):
        raise ValueError("finding_id must be non-empty")
    for field in ("retest_completed", "validation_passed"):
        if type(raw[field]) is not bool:
            raise ValueError(f"{field} must be a boolean")

    missing = [field for field in ("owner", "change_reference", "implemented_control", "validator") if not _nonempty(raw[field])]
    reasons: list[str] = []
    if missing:
        reasons.append("missing evidence: " + ", ".join(sorted(missing)))
    if not raw["retest_completed"]:
        reasons.append("post-change retest has not been completed")
    if not _nonempty(raw["retest_protocol"]):
        reasons.append("retest protocol evidence is missing")
    if raw["retest_completed"] and raw["retest_protocol"] == "NTLMv1":
        reasons.append("retest still shows NTLMv1")
    if not raw["validation_passed"]:
        reasons.append("validation result is not passing")

    if not reasons:
        status = "validated"
    elif raw["retest_completed"] and not raw["validation_passed"]:
        status = "invalid_closure"
    else:
        status = "needs_evidence"
    return ClosureResult(str(finding_id), status, tuple(reasons))


def load_and_validate(path: str | Path) -> list[ClosureResult]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("top-level remediation JSON must be a list")
    results = [validate_record(record) for record in data]
    ids = [result.finding_id for result in results]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate remediation finding_id detected")
    return results
