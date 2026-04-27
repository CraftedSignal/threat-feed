---
title: Meridian Library Multiple Defense-in-Depth Gaps
slug: 2026-04-17-meridian-defense-gaps
description: Multiple defense-in-depth gaps exist in Meridian versions prior to 2.1.1, including high severity issues related to bypassing safety caps on collection mapping that can lead to resource exhaustion, along with medium and low severity issues affecting constructor selection, telemetry, retry mechanisms, and exception handling.
date: "2026-04-17T12:00:00Z"
severities:
  - high
tags:
  - defense-in-depth
  - resource-exhaustion
  - information-disclosure
  - dotnet
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Software Vulnerability
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-f5v8-v6q3-q4h6
  - https://github.com/UmutKorkmaz/meridian/blob/main/CHANGELOG.md#211---2026-04-16
  - https://github.com/UmutKorkmaz/meridian/blob/main/docs/security-model.md
  - https://github.com/UmutKorkmaz/meridian/blob/main/SECURITY.md
rules:
  - title: Detect Excessive Collection Mapping Attempts (Simulated)
    description: Detects a high number of mapping operations within a short timeframe, potentially indicating exploitation of the collection size cap vulnerability. This is a placeholder rule as direct mapping events may not be logged.
    platform: sigma
    severity: low
    tactics:
      - impact
      - resource_development
    data_sources:
      - application
      - windows
  - title: Detect OpenTelemetry Stack Trace Emission (Simulated)
    description: Detects when OpenTelemetry is configured to record exception stack traces which may expose sensitive information. This is a placeholder rule, as direct telemetry settings might not be visible.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
      - information_disclosure
    data_sources:
      - application
      - windows
  - title: Detect Retry Policy Configuration (Simulated)
    description: Detects application configurations that define a broad and aggressive retry policy that could amplify an attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    data_sources:
      - application
      - windows
rules_count: 3
---

Meridian versions before 2.1.1 contain multiple vulnerabilities stemming from defense-in-depth gaps within the `Meridian.Mapping` and `Meridian.Mediator` components. Two high-severity issues involve bypassing the advertised `DefaultMaxCollectionItems` and `DefaultMaxDepth` safety caps, particularly when using the `IMapper.Map(source, destination)` overload or `.UseDestinationValue()` on collection-typed properties. These flaws can lead to resource exhaustion. Additional medium-severity issues…
