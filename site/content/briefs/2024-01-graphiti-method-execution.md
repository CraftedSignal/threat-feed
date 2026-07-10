---
title: Graphiti JSONAPI Arbitrary Method Execution Vulnerability (CVE-2026-33286)
slug: 2024-01-graphiti-method-execution
description: Graphiti versions prior to 1.10.2 are vulnerable to arbitrary method execution via maliciously crafted JSONAPI payloads, allowing attackers to invoke public methods on model instances, classes, or associations.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - graphiti
  - jsonapi
  - method-execution
  - vulnerability
vendors:
  - Graphiti
products:
  - Graphiti
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Services
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33286
rules:
  - title: Detect Graphiti JSONAPI Method Execution Attempt via POST Request
    description: Detects suspicious POST requests to Graphiti endpoints with unusual relationship names, indicating a potential method execution attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Graphiti JSONAPI Method Execution Attempt via URI
    description: Detects suspicious URIs with unusual relationship names, indicating a potential method execution attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Graphiti, a framework for exposing models via a JSON:API-compliant interface, contains an arbitrary method execution vulnerability (CVE-2026-33286) in versions prior to 1.10.2. This flaw resides within Graphiti's JSONAPI write functionality, specifically affecting how relationship names are handled. By crafting a malicious JSONAPI payload with arbitrary relationship names, an attacker can invoke any public method on the underlying model instance, its class, or its associations. Any application exposing Graphiti write endpoints (create/update/delete) to untrusted users is susceptible to this attack. The vulnerability stems from the `Graphiti::Util::ValidationResponse#all_valid?` method's recursive calls to `model.send(name)` without proper validation of user-supplied relationship names. This allows attackers to potentially execute arbitrary public methods, including destructive operations. Upgrade to Graphiti v1.10.2 to patch the vulnerability.

## Attack Chain

1.  The attacker identifies a Graphiti endpoint (create/update/delete) accessible to untrusted users.
2.  The attacker crafts a malicious JSONAPI payload containing arbitrary relationship names.
3.  The malicious payload is submitted to the Graphiti endpoint.
4.  `Graphiti::Util::ValidationResponse#all_valid?` processes the payload and recursively calls `model.send(name)` using the attacker-controlled relationship names.
5.  The attacker leverages the ability to call arbitrary public methods on the model instance, class, or associated instances/classes.
6.  The attacker executes a destructive or malicious method, such as deleting data, modifying configurations, or executing arbitrary code.
7.  The application state is altered based on the executed method, potentially leading to data loss, privilege escalation, or complete system compromise.

## Impact

Successful exploitation of this vulnerability (CVE-2026-33286) can lead to arbitrary method execution on the server, potentially resulting in complete system compromise. Attackers could delete data, modify configurations, escalate privileges, or even execute arbitrary code on the affected system. The vulnerability affects any application exposing Graphiti write endpoints to untrusted users. The severity is high due to the potential for remote code execution and data corruption.

## Recommendation

*   Upgrade to Graphiti v1.10.2 to patch the vulnerability (CVE-2026-33286).
*   Implement strong authentication and authorization checks before processing any write operation on Graphiti endpoints.
*   Apply strong parameter filtering (e.g., Rails strong parameters) to ensure only valid parameters are processed, mitigating the risk of arbitrary method calls.
*   Monitor web server logs for suspicious POST requests containing unusual or unexpected relationship names in JSONAPI payloads. Deploy the Sigma rules provided to detect this activity.
