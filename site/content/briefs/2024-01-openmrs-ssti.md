---
title: OpenMRS Stored Velocity SSTI to RCE via ConceptReferenceRange
slug: 2024-01-openmrs-ssti
description: OpenMRS is vulnerable to a Stored Velocity SSTI to RCE via ConceptReferenceRange, where the `ConceptReferenceRangeUtility.evaluateCriteria()` method evaluates database-stored criteria strings as Apache Velocity templates without a sandbox, allowing unrestricted Java reflection through template expressions, leading to persistent remote code execution and privilege escalation when a user with the `Manage Concepts` privilege stores a malicious Velocity template expression in a concept's reference range criteria field.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssti
  - rce
  - velocity
  - openmrs
vendors:
  - OpenMRS
products:
  - openmrs-api (>= 2.7.0, < 2.7.9)
  - openmrs-api (>= 2.8.0, < 2.8.6)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1205
    technique_name: Traffic Signaling
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xj4f-8jjg-vx4q
  - https://github.com/openmrs/openmrs-core/commit/8d1c193
  - https://www.machinespirits.com/advisory/1e8430/
rules:
  - title: Detect OpenMRS Velocity Template Injection Attempt
    description: Detects potential attempts to inject malicious Velocity templates into OpenMRS, specifically targeting the concept management functionality.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenMRS Velocity Template Injection via concept dictionary
    description: Detects potential attempts to inject malicious Velocity templates into OpenMRS, specifically targeting the concept management functionality.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenMRS is vulnerable to a critical security flaw stemming from the unsafe use of Apache Velocity templates. Specifically, the `ConceptReferenceRangeUtility.evaluateCriteria()` method processes database-stored criteria strings as Velocity templates without any sandbox restrictions. This allows for unrestricted Java reflection through template expressions. A user possessing the `Manage Concepts` privilege can inject a malicious Velocity template expression into a concept's reference range criteria field. This payload will then execute automatically whenever a user or an API call validates an observation against the compromised concept. This issue impacts OpenMRS versions 2.7.0 through 2.7.8, and 2.8.0 through 2.8.5. Successful exploitation allows an attacker to escalate privileges from content management to arbitrary code execution as the Tomcat application server process, with the potential for exfiltration of protected health information (PHI). The vulnerability is identified as CVE-2026-41258.

## Attack Chain

1. An attacker gains access to an OpenMRS account with the `Manage Concepts` privilege.
2. The attacker navigates to the concept dictionary management interface.
3. The attacker locates a commonly used concept, such as one for a standard clinical measurement.
4. The attacker modifies the concept and injects a malicious Velocity template expression into the concept's reference range criteria field. The expression leverages Java reflection to execute arbitrary code.
5. The malicious template is saved and stored in the `concept_reference_range` database table.
6. A user or API call validates an observation against the affected concept, triggering the execution of the stored Velocity template.
7. The attacker achieves arbitrary code execution within the context of the Tomcat application server process.
8. The attacker can then perform actions such as installing a web shell for persistent access or exfiltrating patient data.

## Impact

Successful exploitation of this vulnerability allows for persistent remote code execution on the OpenMRS server. The injected payload persists within the `concept_reference_range` database table (VARCHAR 65535). A single compromised concept, especially one used for common clinical measurements, can lead to the execution of the malicious payload on every subsequent observation validation across all users, API clients, and integrations. This affects all facilities using the compromised OpenMRS instance. The attacker can escalate privileges from content dictionary management to arbitrary code execution and potentially exfiltrate PHI data.

## Recommendation

*   Upgrade OpenMRS to version 2.8.6 or 2.7.9 or later to patch CVE-2026-41258.
*   Restrict the `Manage Concepts` privilege to only authorized users, as mentioned in the advisory's workarounds.
*   Deploy the provided Sigma rule detecting Velocity template injection attempts to your SIEM and tune for your environment.
*   Implement database monitoring to detect unauthorized modifications to the `concept_reference_range` table to identify potential exploitation attempts.
