---
title: Code Injection Vulnerability in Orval @orval/effect Generator
slug: 2026-09-orval-code-injection
description: Versions 8.14.0 through 8.28.1 of Orval contain a code injection vulnerability allowing arbitrary JavaScript execution via malicious OpenAPI schema defaults.
date: "2026-09-23T18:43:33Z"
lastmod: "2026-09-23T18:44:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:orval:orval:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - code-injection
  - vulnerability
vendors:
  - Orval
products:
  - orval (8.14.0 - 8.28.1)
  - orval (< 8.29.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject arbitrary JavaScript expressions via schema defaults containing ${...} syntax, which are executed at module scope when the generated code is built or imported.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Attackers can inject arbitrary JavaScript code through a crafted operationId in an OpenAPI specification that executes when generated hooks are called.
    confidence_band: high
cves:
  - id: CVE-2026-96755
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96755
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96759
action_plan:
  priority: elevated
  owners:
    - Development Teams
  immediate_actions:
    - action: Upgrade Orval to version 8.28.2 or later to address CVE-2026-96755
      owner: Development Teams
      due: 24h
      evidence: CVE-2026-96755 metadata
  mitigation_plan:
    - priority: immediate
      action: Review and sanitize OpenAPI schema default values in project repositories
      owner: Development Teams
      addresses: CVE-2026-96755
      evidence: Vulnerability analysis of @orval/effect
updates:
  - at: "2026-09-23T18:44:05Z"
    level: L2
    summary: added coverage for orval (< 8.29.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-96759
---

Orval versions 8.14.0 through 8.28.1 are affected by a code injection vulnerability located within the @orval/effect generator component. The vulnerability exists because the generator improperly processes OpenAPI schema default values, directly converting them into template literals within the generated output files. An attacker capable of influencing the OpenAPI definition - such as through a compromised API specification source or a malicious pull request - can embed arbitrary JavaScript expressions using the ${...} syntax. These expressions are subsequently evaluated at module scope when the generated code is built by a bundler or imported into a Node.js or browser environment. This vulnerability enables remote code execution during the build process or runtime, posing a critical risk to CI/CD pipelines and downstream applications consuming the generated client libraries.

## Impact

Successful exploitation allows for arbitrary code execution within the environment where the Orval-generated code is processed. This can lead to the compromise of CI/CD build environments, exfiltration of environment variables and secrets, or the injection of malicious code into the final application build. This vulnerability affects developers and organizations using Orval to generate client code from untrusted or externally sourced OpenAPI specifications.

## Recommendation

* Upgrade the Orval package to a version beyond 8.28.1 immediately to resolve CVE-2026-96755.
* Audit all OpenAPI specification files currently being processed by Orval for any instances of ${...} syntax appearing within default values.
* Implement strict validation and sanitization for OpenAPI files sourced from untrusted external contributors or third-party repositories before processing them with Orval.
