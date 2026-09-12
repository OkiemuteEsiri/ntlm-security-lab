# NTLM Security Assessment — Example Output

> Synthetic defensive assessment. No live authentication or production targeting was performed.

## Executive summary

The sample evidence demonstrates how NTLM risk changes when legacy protocol version, privilege, destination criticality, source management, SMB signing, authentication success, monitoring coverage, and recurrence are considered together.

Highest-priority scenario: a privileged identity successfully authenticating with NTLMv1 from an unmanaged workstation to a critical file server where SMB signing is not required and no detective control is recorded. This combination reaches the model ceiling and is treated as Critical exposure requiring urgent engineering ownership and validation.

## Prioritized observations

| Event | Protocol | Identity context | Destination | Key exposure | Expected priority |
|---|---|---|---|---|---|
| AUTH-001 | NTLMv1 | Privileged | Critical | unmanaged source, unsigned SMB, no detective control, repeated success | Critical |
| AUTH-006 | NTLMv1 | Standard | Low | unsigned SMB, successful legacy authentication | High |
| AUTH-002 | NTLMv2 | Service | High | unsigned SMB, persistent successful use | Medium |
| AUTH-005 | NTLMv2 | Privileged | Critical | privileged legacy-auth attempt, but failed and monitored | Medium |
| AUTH-004 | NTLMv2 | Service | Medium | unmanaged source, repeated success, no detective control | Medium |
| AUTH-003 | Kerberos | Standard | Medium | modern protocol baseline | Not reported |

## ATT&CK context

- **T1557.001** — defensive relay-risk context for SMB paths where signing is not required.
- **T1021.002** — SMB/Windows Admin Shares remote-service context.
- **T1078** — valid-account context for authenticated identity use.

These mappings support threat modeling and control design; they are not evidence that any ATT&CK technique actually occurred.

## Remediation validation examples

The synthetic remediation register demonstrates three states:

- `validated`: accountable change evidence exists and retest confirms a passing post-change state.
- `invalid_closure`: a retest was completed but the result still shows NTLMv1 and validation failed.
- `needs_evidence`: ownership or change/retest evidence is incomplete.

## Recommended program actions

1. Remove NTLMv1 dependencies first.
2. Identify business owners for recurring NTLMv2 dependencies and develop migration plans.
3. Require SMB signing where compatible.
4. Prevent privileged identities from using legacy authentication paths.
5. Track migration trend by application and owner rather than closing individual events in isolation.
6. Retain post-change evidence before accepting closure.
