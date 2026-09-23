---
title: Code Injection Vulnerability in @orval/core Form-Data Serializer
slug: 2026-09-orval-code-injection
description: The @orval/core library is vulnerable to code injection via improper sanitization of multipart property names, allowing attackers to execute arbitrary code within the consumer process.
date: "2026-09-23T18:43:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:orval:orval:*:*:*:*:*:node.js:*:*
tags:
  - supply-chain
  - code-injection
products:
  - '@orval/core (< 8.28.0)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject ${...} expressions into OpenAPI schema property names that execute as live interpolation when the generated client builds FormData bodies.
    confidence_band: high
cves:
  - id: CVE-2026-96758
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96758
action_plan:
  priority: immediate_escalation
  owners:
    - Development Teams
    - DevSecOps
  immediate_actions:
    - action: Upgrade @orval/core to 8.28.0
      owner: Development Teams
      due: 24h
      evidence: CVE-2026-96758 vendor patch requirement.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @orval/core to 8.28.0
      owner: Development Teams
      addresses: CVE-2026-96758
      evidence: NVD vulnerability disclosure.
---

The orval library, specifically the @orval/core package prior to version 8.28.0, is affected by a critical code injection vulnerability within its form-data serializer. The flaw arises because the serializer fails to properly escape multipart property names when generating template literals for FormData construction. 

By supplying an OpenAPI schema containing malicious property names formatted with template literal syntax (e.g., ${...}), an attacker can force the generated client code to interpret and execute these strings during runtime. Because the generated code runs with the same privileges as the application consuming the orval-generated client, successful exploitation can lead to arbitrary code execution within the environment hosting the client application. This vulnerability is particularly concerning for automated CI/CD pipelines or backend services that process untrusted OpenAPI definitions.

## Impact

Successful exploitation allows for remote code execution within the context of the application consuming the orval-generated client. This poses a severe risk to any environment that processes external or user-provided OpenAPI schemas using vulnerable versions of @orval/core, potentially leading to unauthorized data access, system compromise, or lateral movement within the host network.

## Recommendation

* Upgrade the @orval/core package to version 8.28.0 or later immediately to patch the form-data serializer logic.
* Audit build-time workflows and internal tools that ingest external OpenAPI specifications to identify potential use of vulnerable @orval/core versions.
* Implement strict input validation for all OpenAPI schema files processed by automation pipelines to ensure property names do not contain unexpected shell or template characters.
