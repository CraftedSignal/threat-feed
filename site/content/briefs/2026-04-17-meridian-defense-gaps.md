---
title: Meridian Library Multiple Defense-in-Depth Gaps
slug: 2026-04-17-meridian-defense-gaps
description: Multiple defense-in-depth gaps exist in Meridian versions prior to 2.1.1, including high severity issues related to bypassing safety caps on collection mapping that can lead to resource exhaustion, along with medium and low severity issues affecting constructor selection, telemetry, retry mechanisms, and exception handling.
date: "2026-04-17T12:00:00Z"
type: coverage
types:
  - coverage
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

Meridian versions before 2.1.1 contain multiple vulnerabilities stemming from defense-in-depth gaps within the `Meridian.Mapping` and `Meridian.Mediator` components. Two high-severity issues involve bypassing the advertised `DefaultMaxCollectionItems` and `DefaultMaxDepth` safety caps, particularly when using the `IMapper.Map(source, destination)` overload or `.UseDestinationValue()` on collection-typed properties. These flaws can lead to resource exhaustion. Additional medium-severity issues include constructor invariant bypass, OpenTelemetry stack-trace information disclosure, retry amplification, and notification fan-out amplification. The vulnerabilities were patched in version 2.1.1, released on April 16, 2026. The issues affect applications using the Meridian library for object-object mapping and mediation. Successful exploitation could lead to denial-of-service conditions, information disclosure, and unexpected application behavior.

## Attack Chain

1. An attacker sends a crafted request to an application using Meridian, including a large or self-referential collection in the request payload.
2. The application's mapping logic utilizes `IMapper.Map(source, destination)` or `.UseDestinationValue()` on a collection property, triggering the vulnerable code path.
3. The `MappingEngine.TryMapCollectionOntoExisting` method processes the collection without enforcing `DefaultMaxCollectionItems`, leading to excessive memory consumption.
4. Collection-item recursion fails to increment `ResolutionContext.Depth`, allowing self-referential graphs to bypass `DefaultMaxDepth` and cause a stack overflow.
5. The unbounded collection processing consumes excessive CPU and memory resources, potentially blocking the worker thread.
6. Alternatively, an attacker exploits the `ObjectCreator.CreateWithConstructorMapping` vulnerability by providing input that bypasses constructor invariants due to the widest constructor being selected.
7. The application experiences a denial-of-service condition due to resource exhaustion or exhibits unintended behavior due to bypassed constructor invariants.

## Impact

Successful exploitation of these vulnerabilities can lead to significant consequences. An attacker can cause denial-of-service by exhausting server resources, potentially impacting all users of the affected application. Information disclosure is possible through OpenTelemetry stack traces, and bypassing constructor invariants can lead to unexpected application behavior and potential data corruption. The high-severity vulnerabilities related to collection mapping are particularly concerning due to the potential for easy exploitation through a single crafted request. The impact is mitigated by upgrading to version 2.1.1 of the `Meridian.Mapping` and `Meridian.Mediator` libraries.

## Recommendation

*   Immediately upgrade to Meridian version 2.1.1 to patch the identified vulnerabilities, as documented in the [v2.1.1 CHANGELOG](https://github.com/UmutKorkmaz/meridian/blob/main/CHANGELOG.md#211---2026-04-16).
*   For applications that cannot be immediately upgraded, avoid using `mapper.Map(src, dst)` and `.UseDestinationValue()` on collection-typed destination members as a temporary workaround.
*   Implement explicit size limits on input collection deserialization before passing the payload to Meridian, as described in the [Workarounds section](#workarounds) of this brief.
*   Consider disabling OpenTelemetry `exception.stacktrace` tag emission if your trace sink is not fully trusted, mitigating potential information disclosure.
