---
title: Kiota Java and PHP Code Injection via OpenAPI Sanitization Bypass
slug: 2026-10-kiota-code-injection
description: The Kiota Java and PHP generators are vulnerable to a code injection attack where malicious OpenAPI descriptions can lead to the generation of attacker-controlled source code due to improper sanitization of block-comment delimiters.
date: "2026-10-06T18:48:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:kiota:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - code-injection
  - vulnerability
vendors:
  - Microsoft
products:
  - Microsoft.OpenApi.Kiota (< 1.35.0)
  - Microsoft.OpenApi.Kiota.Builder (< 1.35.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: An attacker who controls or tampers with an OpenAPI description can cause Kiota to emit attacker-controlled Java or PHP source.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Code executes in the consuming application's or build environment's security context.
    confidence_band: high
cves:
  - id: CVE-2026-105796
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-rm89-rhwj-9j92
  - https://github.com/microsoft/kiota/pull/8017
  - https://github.com/microsoft/kiota/releases/tag/v1.35.0
action_plan:
  priority: elevated
  owners:
    - Development
    - DevOps
  immediate_actions:
    - action: Upgrade Microsoft.OpenApi.Kiota and Microsoft.OpenApi.Kiota.Builder to 1.35.0 or later.
      owner: Development
      due: 24h
      evidence: 'Fixed release: https://github.com/microsoft/kiota/releases/tag/v1.35.0'
    - action: Regenerate all Java and PHP clients generated with previous versions.
      owner: Development
      due: 48h
      evidence: Upgrade to Kiota 1.35.0 or later and regenerate affected clients.
  mitigation_plan:
    - priority: immediate
      action: Restrict Kiota usage to only trusted, integrity-protected OpenAPI descriptions.
      owner: DevOps
      addresses: CVE-2026-105796
      evidence: Until upgrading, generate clients only from trusted, integrity-protected OpenAPI descriptions.
---

Microsoft Kiota versions prior to 1.35.0 contain a vulnerability (CVE-2026-105796) in the Java and PHP generators that allows for code injection during the client generation process. The sanitization logic within the generators incorrectly attempts to remove block-comment delimiters (such as '*/') rather than neutralizing them. This approach allows an attacker who controls an OpenAPI description to craft input that causes these delimiters to reform after the sanitization step, either through overlapping characters or normalization processes. In the Java generator, the removal of non-ASCII characters after the initial sanitization can also trigger the creation of new comment terminators.

When a developer or an automated build pipeline uses Kiota to generate a client from a malicious OpenAPI definition, the resulting Java or PHP source code contains injected payloads outside of the intended documentation comments. If this generated code is subsequently compiled, loaded, or executed, the attacker's code runs within the security context of the build environment or the consuming application.

## Impact

Successful exploitation can lead to arbitrary code execution within the developer's build environment or the application consuming the generated client. This impacts any project relying on Kiota to generate Java or PHP clients from untrusted or tampered OpenAPI specifications. The vulnerability specifically affects the `Microsoft.OpenApi.Kiota` and `Microsoft.OpenApi.Kiota.Builder` NuGet packages. Organizations using automated CI/CD pipelines to generate SDKs from external OpenAPI sources are at the highest risk, as the injection occurs at the generation phase.

## Recommendation

- Upgrade to Kiota version 1.35.0 or later to apply the fix, which properly neutralizes comment delimiters and updates the sanitization order for Java.
- After upgrading, regenerate all clients previously created with vulnerable versions of Kiota.
- Implement a policy to only generate clients from trusted, integrity-protected OpenAPI descriptions in build environments.
- Review generated Java and PHP source code for unauthorized modifications before committing to version control or deploying to production environments.
- Restrict access to build environments and minimize the privileges/secrets available to generation and CI/CD pipelines.
