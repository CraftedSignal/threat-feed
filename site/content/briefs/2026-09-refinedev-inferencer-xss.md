---
title: Cross-Site Scripting via @refinedev/inferencer
slug: 2026-09-refinedev-inferencer-xss
description: The @refinedev/inferencer package versions through 7.0.0 are vulnerable to an injection attack where malicious JSON property names are improperly escaped during JSX code generation, leading to arbitrary JavaScript execution in the developer's browser.
date: "2026-09-16T21:56:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:refine:inferencer:*:*:*:*:*:*:*:*
vendors:
  - Refine
products:
  - inferencer (<= 7.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers controlling the data provider can inject malicious JavaScript through crafted JSON property names that execute in the developer's browser when the Inferencer page renders.
    confidence_band: high
cves:
  - id: CVE-2026-92784
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92784
action_plan:
  priority: elevated
  owners:
    - Security Team
    - Development Team
  mitigation_plan:
    - priority: immediate
      action: Upgrade @refinedev/inferencer to a patched version beyond 7.0.0
      owner: Development Team
      addresses: CVE-2026-92784
      evidence: NVD vulnerability record for CVE-2026-92784
---

The @refinedev/inferencer package, used for automating the generation of views and forms based on API data structures, contains a critical security flaw (CVE-2026-92784) in versions through 7.0.0. The vulnerability stems from improper neutralization of input data when the package interpolates API field names into generated JSX source code.

An attacker capable of influencing the data returned by the application's data provider can inject malicious JavaScript payloads within JSON property names. When a developer utilizes the Inferencer feature to render a page based on this data, the payload is injected directly into the component source code. This results in Cross-Site Scripting (XSS) executing in the context of the developer's browser environment. This vulnerability is significant for development environments where Inferencer is used to parse untrusted or externally sourced API responses, potentially leading to unauthorized data access or session hijacking within the development environment.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript within the developer's browser when they interact with the Inferencer-generated interface. This can lead to the compromise of local development session tokens, exfiltration of local sensitive data, or unauthorized actions performed on behalf of the developer. As the tool is often used to parse API schemas during development, this impacts software supply chain security and the integrity of the local development environment.

## Recommendation

Prioritize the update of the @refinedev/inferencer package to a version that addresses CVE-2026-92784. If an immediate update is not feasible, restrict the use of the Inferencer component to data providers that are trusted and verified, ensuring that JSON property names in API responses do not contain arbitrary or user-controllable input.
