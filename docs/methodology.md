# Methodology and Trust Boundaries

## Objective

This lab demonstrates a defensive workflow for identifying and prioritizing NTLM exposure from already-collected authentication telemetry. It is intentionally designed as an offline assessment engine rather than a scanner or exploitation framework.

## Trust boundaries

The assessment treats input telemetry as untrusted. Before scoring, every event must satisfy an exact schema, approved protocol enumeration, boolean typing, controlled asset criticality, positive observation count, and unique event identifier. Unexpected fields are rejected so that silent schema drift does not alter risk decisions.

The engine does not trust an exception, remediation ticket, or implementation statement as proof that exposure has been removed. Closure is a separate evidence-validation decision.

## Processing stages

1. **Ingest** synthetic JSON evidence.
2. **Validate** schema, enumerations, types, and uniqueness.
3. **Filter** Kerberos observations from NTLM exposure findings.
4. **Score** NTLM evidence using identity, protocol, asset, source, SMB-signing, success, monitoring, and recurrence context.
5. **Map** relevant ATT&CK techniques for defensive threat modeling.
6. **Prioritize** findings by score with stable deterministic IDs.
7. **Report** rationale and recommended remediation/validation actions.
8. **Validate closure** independently using accountable change and retest evidence.

## Risk interpretation

The model is deliberately transparent rather than statistically predictive. A high score means the combination of legacy authentication and contextual controls deserves earlier engineering attention; it does not mean an adversary is present.

### Primary drivers

- NTLMv1 materially increases legacy-protocol concern.
- Privileged identity use increases potential blast radius.
- Critical destinations increase business and control impact.
- Unmanaged sources weaken endpoint assurance.
- SMB without required signing increases relay-related exposure context.
- Successful authentication confirms the path is usable.
- Missing detective controls reduce visibility.
- High recurrence suggests persistent migration debt.

## ATT&CK mapping

- **T1557.001** is added when SMB authentication is observed without required signing, as relay-related defensive context.
- **T1021.002** is added to the same SMB context because Windows Admin Shares/SMB can support remote service activity.
- **T1078** applies broadly to authenticated account use.

These mappings do not assert exploitation or compromise.

## Remediation validation

A closure record is considered `validated` only when it includes:

- an accountable owner;
- a change/reference identifier;
- a stated implemented control;
- a completed retest;
- observed post-change authentication protocol;
- an explicit passing validation result;
- a named validating function.

A completed retest that still shows NTLMv1 and fails validation becomes `invalid_closure`. Incomplete evidence remains `needs_evidence`.

## Production considerations

A production implementation should additionally correlate:

- domain-controller authentication telemetry;
- Group Policy and NTLM restriction posture;
- SPN/service-account inventory;
- SMB signing configuration inventory;
- application ownership and service dependency records;
- endpoint management state;
- approved exceptions with expiry dates;
- historical protocol migration trends.

## Safety constraints

The lab performs no credential capture, SMB relay, responder-style poisoning, password cracking, coercion, live authentication, directory enumeration, or packet interception. All fixtures are fictional.
