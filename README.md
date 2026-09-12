# NTLM Security Assessment Lab

A defensive identity-security engineering project for assessing synthetic Windows authentication telemetry and identifying NTLM exposure that increases credential-relay, downgrade, lateral-movement, and legacy-authentication risk.

> Safety: this repository does **not** capture hashes, relay authentication, coerce hosts, crack passwords, query live domains, or target production systems. All evidence is fictional and intentionally synthetic.

## Problem statement

NTLM remains operationally relevant in many Windows estates because legacy applications, appliances, service accounts, and fallback paths can preserve it long after Kerberos-first authentication is expected. The engineering challenge is not simply to count NTLM events; it is to identify which observations represent the greatest identity and lateral-movement exposure, route them to an accountable owner, and verify remediation with evidence.

## Architecture

```text
Synthetic authentication telemetry
        |
        v
 strict schema validation
        |
        v
 NTLM exposure assessment -----> MITRE ATT&CK context
        |                         T1557.001 / T1021.002 / T1078
        v
 contextual 0-100 risk score
        |
        +----> prioritized findings + metrics
        +----> Markdown analyst report
        +----> remediation evidence validator
```

## What it evaluates

- NTLMv1 authentication.
- NTLM use by privileged identities.
- NTLM access to high/critical assets.
- Authentication originating from unmanaged sources.
- SMB authentication where signing is not required.
- Successful NTLM authentication without compensating detective controls.
- Repeated legacy-authentication observations indicating migration debt.

## Risk model

Each finding receives a bounded **0-100** contextual risk score.

| Signal | Risk contribution |
|---|---:|
| NTLMv1 | +30 |
| Privileged identity | +20 |
| Critical/high-value destination | +15 |
| Unmanaged source | +10 |
| SMB signing not required | +10 |
| Successful authentication | +10 |
| No detective control | +5 |

Severity thresholds: Critical >= 80, High >= 60, Medium >= 35, Low < 35.

## MITRE ATT&CK context

Mappings are defensive threat-model references, not claims that compromise occurred:

- **T1557.001 – Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**
- **T1021.002 – Remote Services: SMB/Windows Admin Shares**
- **T1078 – Valid Accounts**

## Repository structure

```text
.github/workflows/security-quality.yml
 data/auth_events.json
 data/remediation_evidence.json
 docs/methodology.md
 reports/example-assessment.md
 src/__init__.py
 src/assessor.py
 src/cli.py
 src/remediation.py
 tests/test_assessor.py
```

## Usage

```bash
python -m src.cli data/auth_events.json --output reports/generated-assessment.md
python -m unittest discover -s tests -v
```

No third-party Python package is required.

## Remediation workflow

1. Establish the application/service dependency for each legacy authentication path.
2. Prefer Kerberos-capable service configuration and SPN hygiene where applicable.
3. Disable NTLMv1 and validate policy inheritance.
4. Require SMB signing where operationally compatible and validate exceptions explicitly.
5. Restrict privileged identities from legacy-authentication paths.
6. Retest using approved telemetry and document the resulting authentication protocol.
7. Close only when accountable ownership, change evidence, retest evidence, and validation result are present.

The remediation validator intentionally separates *implemented change* from *validated closure*.

## Design decisions

- **Fail closed:** malformed booleans, unsupported protocol versions, duplicate event IDs, and invalid criticality values are rejected.
- **Deterministic IDs:** SHA-256-derived finding IDs remain stable for the same evidence record.
- **Technical risk != governance acceptance:** an exception does not erase exposure.
- **Offline by default:** no LDAP, SMB, domain-controller, EDR, or SIEM connection is performed.
- **Synthetic evidence only:** hostnames, identities, timestamps, and change references are fictional.

## Skills demonstrated

Identity security engineering, Windows authentication risk analysis, security telemetry normalization, contextual risk scoring, MITRE ATT&CK mapping, remediation governance, evidence-based validation, Python engineering, unit testing, and CI/CD quality controls.

## Limitations

This lab does not prove relay feasibility, inspect network packets, validate SPNs, query domain policy, enumerate SMB dialects, or determine whether an individual event is malicious. In production, findings should be correlated with directory posture, endpoint telemetry, network controls, application ownership, and approved change windows.

## Roadmap

- Kerberos-vs-NTLM migration trend reporting.
- Application dependency grouping and owner mapping.
- NTLM exception ageing and expiry governance.
- SMB signing posture import from a controlled configuration inventory.
- Sigma/SIEM export for defensive monitoring.
- Historical baseline and regression detection.
