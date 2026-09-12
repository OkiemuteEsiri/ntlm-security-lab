import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from src.assessor import AuthEvent, assess, assess_event, load_events, metrics, render_markdown
from src.remediation import validate_record


BASE = AuthEvent(
    event_id="E1",
    timestamp="2026-09-10T00:00:00Z",
    source_host="SRC-01",
    destination_host="DST-01",
    identity="user1",
    protocol="NTLMv2",
    service="SMB",
    success=True,
    privileged_identity=False,
    source_managed=True,
    destination_criticality="medium",
    smb_signing_required=True,
    detective_control=True,
    observation_count=1,
)


class AssessorTests(unittest.TestCase):
    def test_kerberos_is_not_reported(self):
        self.assertIsNone(assess_event(replace(BASE, protocol="Kerberos")))

    def test_ntlmv1_increases_risk(self):
        v1 = assess_event(replace(BASE, protocol="NTLMv1"))
        v2 = assess_event(BASE)
        self.assertGreater(v1.score, v2.score)

    def test_privileged_identity_increases_risk(self):
        normal = assess_event(BASE)
        privileged = assess_event(replace(BASE, privileged_identity=True))
        self.assertEqual(privileged.score - normal.score, 20)

    def test_smb_unsigned_adds_attack_context(self):
        finding = assess_event(replace(BASE, smb_signing_required=False))
        self.assertIn("T1557.001", finding.attack_techniques)
        self.assertIn("T1021.002", finding.attack_techniques)

    def test_score_is_bounded(self):
        finding = assess_event(replace(
            BASE,
            protocol="NTLMv1",
            privileged_identity=True,
            source_managed=False,
            destination_criticality="critical",
            smb_signing_required=False,
            detective_control=False,
            observation_count=99,
        ))
        self.assertEqual(finding.score, 100)
        self.assertEqual(finding.severity, "critical")

    def test_deterministic_finding_id(self):
        self.assertEqual(assess_event(BASE).finding_id, assess_event(BASE).finding_id)

    def test_priority_ordering(self):
        low = BASE
        high = replace(BASE, event_id="E2", protocol="NTLMv1", privileged_identity=True)
        findings = assess([low, high])
        self.assertGreaterEqual(findings[0].score, findings[1].score)

    def test_metrics(self):
        findings = assess([BASE, replace(BASE, event_id="E2", protocol="NTLMv1", privileged_identity=True)])
        result = metrics(findings)
        self.assertEqual(result["total"], 2)
        self.assertEqual(sum(result[k] for k in ("critical", "high", "medium", "low")), 2)

    def test_report_contains_attack_mapping(self):
        report = render_markdown(assess([replace(BASE, smb_signing_required=False)]))
        self.assertIn("T1557.001", report)
        self.assertIn("MITRE ATT&CK", report)

    def test_duplicate_events_rejected(self):
        record = {
            "event_id":"DUP","timestamp":"2026-01-01T00:00:00Z","source_host":"A","destination_host":"B",
            "identity":"u","protocol":"NTLMv2","service":"SMB","success":True,"privileged_identity":False,
            "source_managed":True,"destination_criticality":"medium","smb_signing_required":True,
            "detective_control":True,"observation_count":1
        }
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.json"
            path.write_text(json.dumps([record, record]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_events(path)

    def test_malformed_boolean_rejected(self):
        record = {
            "event_id":"E","timestamp":"2026-01-01T00:00:00Z","source_host":"A","destination_host":"B",
            "identity":"u","protocol":"NTLMv2","service":"SMB","success":"true","privileged_identity":False,
            "source_managed":True,"destination_criticality":"medium","smb_signing_required":True,
            "detective_control":True,"observation_count":1
        }
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.json"
            path.write_text(json.dumps([record]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_events(path)

    def test_validated_closure(self):
        result = validate_record({
            "finding_id":"F1","owner":"Identity","change_reference":"CHG-1","implemented_control":"Kerberos migration",
            "retest_completed":True,"retest_protocol":"Kerberos","validation_passed":True,"validator":"Assurance"
        })
        self.assertEqual(result.status, "validated")

    def test_failed_retest_is_invalid_closure(self):
        result = validate_record({
            "finding_id":"F1","owner":"Identity","change_reference":"CHG-1","implemented_control":"Config change",
            "retest_completed":True,"retest_protocol":"NTLMv1","validation_passed":False,"validator":"Assurance"
        })
        self.assertEqual(result.status, "invalid_closure")

    def test_incomplete_evidence_needs_evidence(self):
        result = validate_record({
            "finding_id":"F1","owner":"Identity","change_reference":"","implemented_control":"Planned",
            "retest_completed":False,"retest_protocol":"","validation_passed":False,"validator":""
        })
        self.assertEqual(result.status, "needs_evidence")


if __name__ == "__main__":
    unittest.main()
