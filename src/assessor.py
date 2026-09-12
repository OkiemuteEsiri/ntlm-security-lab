from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VALID_PROTOCOLS = {"NTLMv1", "NTLMv2", "Kerberos"}
VALID_CRITICALITY = {"low", "medium", "high", "critical"}

ATTACK = {
    "relay_context": "T1557.001",
    "smb_remote_service": "T1021.002",
    "valid_accounts": "T1078",
}


@dataclass(frozen=True)
class AuthEvent:
    event_id: str
    timestamp: str
    source_host: str
    destination_host: str
    identity: str
    protocol: str
    service: str
    success: bool
    privileged_identity: bool
    source_managed: bool
    destination_criticality: str
    smb_signing_required: bool
    detective_control: bool
    observation_count: int


@dataclass(frozen=True)
class Finding:
    finding_id: str
    event_id: str
    score: int
    severity: str
    title: str
    rationale: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    remediation: tuple[str, ...]


def _require_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field} must be a boolean")
    return value


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _parse_event(raw: dict[str, Any]) -> AuthEvent:
    required = {
        "event_id", "timestamp", "source_host", "destination_host", "identity",
        "protocol", "service", "success", "privileged_identity", "source_managed",
        "destination_criticality", "smb_signing_required", "detective_control",
        "observation_count",
    }
    if set(raw) != required:
        raise ValueError(f"event schema mismatch: expected {sorted(required)}")
    protocol = _require_text(raw["protocol"], "protocol")
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol}")
    criticality = _require_text(raw["destination_criticality"], "destination_criticality").lower()
    if criticality not in VALID_CRITICALITY:
        raise ValueError(f"invalid destination_criticality: {criticality}")
    count = raw["observation_count"]
    if type(count) is not int or count < 1:
        raise ValueError("observation_count must be a positive integer")
    return AuthEvent(
        event_id=_require_text(raw["event_id"], "event_id"),
        timestamp=_require_text(raw["timestamp"], "timestamp"),
        source_host=_require_text(raw["source_host"], "source_host"),
        destination_host=_require_text(raw["destination_host"], "destination_host"),
        identity=_require_text(raw["identity"], "identity"),
        protocol=protocol,
        service=_require_text(raw["service"], "service").upper(),
        success=_require_bool(raw["success"], "success"),
        privileged_identity=_require_bool(raw["privileged_identity"], "privileged_identity"),
        source_managed=_require_bool(raw["source_managed"], "source_managed"),
        destination_criticality=criticality,
        smb_signing_required=_require_bool(raw["smb_signing_required"], "smb_signing_required"),
        detective_control=_require_bool(raw["detective_control"], "detective_control"),
        observation_count=count,
    )


def load_events(path: str | Path) -> list[AuthEvent]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("top-level JSON must be a list")
    events = [_parse_event(item) for item in data]
    ids = [event.event_id for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event_id detected")
    return events


def severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def assess_event(event: AuthEvent) -> Finding | None:
    if event.protocol == "Kerberos":
        return None

    score = 0
    rationale: list[str] = []
    techniques = {ATTACK["valid_accounts"]}

    if event.protocol == "NTLMv1":
        score += 30
        rationale.append("NTLMv1 is legacy authentication and materially increases downgrade/credential exposure risk")
    if event.privileged_identity:
        score += 20
        rationale.append("privileged identity observed on the NTLM path")
    if event.destination_criticality in {"high", "critical"}:
        score += 15
        rationale.append(f"destination asset criticality is {event.destination_criticality}")
    if not event.source_managed:
        score += 10
        rationale.append("authentication originated from an unmanaged source")
    if event.service == "SMB" and not event.smb_signing_required:
        score += 10
        rationale.append("SMB signing is not required on the observed path")
        techniques.update({ATTACK["relay_context"], ATTACK["smb_remote_service"]})
    if event.success:
        score += 10
        rationale.append("authentication succeeded")
    if not event.detective_control:
        score += 5
        rationale.append("no compensating detective control is recorded")
    if event.observation_count >= 10:
        score += 5
        rationale.append("repeated observations indicate persistent migration debt")

    score = min(score, 100)
    fid_source = f"{event.event_id}|{event.identity}|{event.source_host}|{event.destination_host}|{event.protocol}"
    finding_id = "NTLM-" + hashlib.sha256(fid_source.encode()).hexdigest()[:12].upper()
    remediation = (
        "Confirm the application or service dependency and accountable owner.",
        "Migrate the authentication path to Kerberos or another approved modern mechanism where feasible.",
        "Disable NTLMv1 and require SMB signing where operationally compatible.",
        "Restrict privileged identities from legacy-authentication paths.",
        "Retest after change and retain protocol/control evidence before closure.",
    )
    return Finding(
        finding_id=finding_id,
        event_id=event.event_id,
        score=score,
        severity=severity(score),
        title=f"{event.protocol} exposure: {event.identity} -> {event.destination_host}",
        rationale=tuple(rationale),
        attack_techniques=tuple(sorted(techniques)),
        remediation=remediation,
    )


def assess(events: list[AuthEvent]) -> list[Finding]:
    findings = [finding for event in events if (finding := assess_event(event)) is not None]
    return sorted(findings, key=lambda f: (-f.score, f.finding_id))


def metrics(findings: list[Finding]) -> dict[str, int]:
    result = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        result[finding.severity] += 1
    return result


def render_markdown(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = [
        "# NTLM Security Assessment",
        "",
        "> Synthetic defensive assessment. No live authentication or production targeting was performed.",
        "",
        "## Executive summary",
        "",
        f"- Total findings: **{m['total']}**",
        f"- Critical: **{m['critical']}** | High: **{m['high']}** | Medium: **{m['medium']}** | Low: **{m['low']}**",
        "",
        "## Prioritized findings",
        "",
    ]
    for finding in findings:
        lines += [
            f"### {finding.finding_id} — {finding.title}",
            "",
            f"**Risk:** {finding.score}/100 ({finding.severity.upper()})",
            f"**MITRE ATT&CK:** {', '.join(finding.attack_techniques)}",
            "",
            "**Rationale**",
        ]
        lines += [f"- {item}" for item in finding.rationale]
        lines += ["", "**Remediation / validation**"]
        lines += [f"- {item}" for item in finding.remediation]
        lines.append("")
    return "\n".join(lines)
