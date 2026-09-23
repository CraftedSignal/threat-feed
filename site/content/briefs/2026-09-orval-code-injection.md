---
title: Code Injection Vulnerability in @orval/hono Generator
slug: 2026-09-orval-code-injection
description: orval versions before 8.29.0 contain a code injection vulnerability in the @orval/hono generator due to improper escaping of OpenAPI path values, allowing arbitrary JavaScript execution upon import.
date: "2026-09-23T18:43:26Z"
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
  - vulnerability
products:
  - '@orval/hono (< 8.29.0)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft an OpenAPI document with an apostrophe in a static path segment to inject arbitrary JavaScript code that executes when the generated TypeScript module is imported.
    confidence_band: high
cves:
  - id: CVE-2026-96754
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96754
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - Security Operations
  immediate_actions:
    - action: Upgrade @orval/hono to version 8.29.0 or later
      owner: Development Teams
      due: 48h
      evidence: CVE-2026-96754 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Upgrade orval to 8.29.0
      owner: Development Teams
      addresses: CVE-2026-96754
      evidence: Source NVD advisory
---

orval versions prior to 8.29.0 are affected by a code injection vulnerability (CVE-2026-96754) residing within the @orval/hono generator. The flaw exists because the generator fails to properly escape OpenAPI path values when embedding them into single-quoted route literals within generated TypeScript code. 

An attacker who can influence an OpenAPI document used as input for the orval generator can inject malicious characters, specifically an apostrophe, into a static path segment. This results in the generation of a TypeScript module containing unsanitized input that breaks out of the intended string literal. Consequently, arbitrary JavaScript code is executed when the downstream application or development environment imports the generated TypeScript module. This vulnerability poses a significant supply chain risk for projects utilizing automated API client generation with orval and the @orval/hono plugin.

## Impact

Successful exploitation leads to arbitrary code execution within the context of the build or application process where the generated code is imported. This can result in unauthorized access to development environments, theft of source code, credential exfiltration, or further compromise of CI/CD pipelines.

## Recommendation

- Upgrade the orval package to version 8.29.0 or later to ensure the @orval/hono generator correctly handles path escaping.
- Audit all OpenAPI documents currently processed by the orval generator to ensure that path definitions do not contain unexpected special characters or suspicious apostrophes.
- Implement validation checks on any OpenAPI schemas ingested from untrusted or external third-party sources prior to running code generation tools.
