---
title: Remote Code Execution in Orval via Malicious Zod Schema Generation
slug: 2026-09-orval-rce
description: Orval versions prior to 8.21.0 are vulnerable to remote code execution during module import due to improper sanitization of OpenAPI query parameter default values in generated Zod schemas.
date: "2026-09-02T18:03:05Z"
lastmod: "2026-09-04T00:04:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:orval:orval:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - rce
  - nodejs
  - typescript
vendors:
  - Orval
products:
  - Orval (< 8.21.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker providing a malicious OpenAPI specification containing a crafted default value (using `${...}` syntax) can trigger arbitrary JavaScript execution when the generated module is imported by an application.
    confidence_band: high
cves:
  - id: CVE-2026-72716
    epss: 0.00523
  - id: CVE-2026-71871
    epss: 0.00478
  - id: CVE-2026-71868
    epss: 0.00478
  - id: CVE-2026-71865
    epss: 0.00478
references:
  - https://github.com/advisories/GHSA-p4cg-3328-rvfg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72716
  - https://github.com/advisories/GHSA-6mr6-jvcr-2f25
  - https://github.com/user-attachments/files/29426038/maintainer-report.txt
  - https://github.com/user-attachments/files/29426039/make_spec.py
  - https://github.com/user-attachments/files/29426040/reproduce.sh
  - https://github.com/advisories/GHSA-2h9g-j24r-h63g
  - https://github.com/advisories/GHSA-8j6p-r8jg-mxqh
  - https://github.com/advisories/GHSA-3575-w9fc-c2j6
  - https://github.com/advisories/GHSA-653q-5476-x79g
action_plan:
  priority: immediate_escalation
  owners:
    - Security Engineering
    - Development
  immediate_actions:
    - action: Upgrade Orval to version 8.21.0 or later
      owner: Development
      due: 24h
      evidence: CVE-2026-72716 mitigation via patch in version 8.21.0
  mitigation_plan:
    - priority: immediate
      action: Validate OpenAPI specifications for malicious template literal syntax
      owner: Security Engineering
      addresses: CVE-2026-72716
      evidence: Source advisory recommends escaping default values or ensuring no interpolation is possible
updates:
  - at: "2026-09-02T18:03:14Z"
    level: L2
    summary: added coverage for orval (< 8.21.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6mr6-jvcr-2f25
  - at: "2026-09-04T00:03:59Z"
    level: L2
    summary: added CVE-2026-71871
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-8j6p-r8jg-mxqh
  - at: "2026-09-04T00:04:04Z"
    level: L2
    summary: added CVE-2026-71865, CVE-2026-71868
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-3575-w9fc-c2j6
      - https://github.com/advisories/GHSA-653q-5476-x79g
---

Orval, a popular tool for generating TypeScript clients and Zod schemas from OpenAPI specifications, contains a critical vulnerability (CVE-2026-72716) that allows for remote code execution. The issue stems from the way the tool emits query parameter default values within the generated Zod schema modules. Specifically, these values are written as module-level template literals (e.g., `export const …Default = `&lt;default>`;`) without adequate escaping of backticks or the `${` character sequence.

An attacker who can provide or influence an OpenAPI specification can include a crafted default value containing a JavaScript expression, such as `v${<attacker-controlled-JS>}w`. When an application imports the generated Zod schema module, the JavaScript engine evaluates the interpolated expression, leading to arbitrary code execution within the context of the importing process. This vulnerability is present in Orval version 8.19.0 and affects all versions prior to 8.21.0. The exploit requires no additional API interaction once the malicious schema is generated and integrated into the victim's codebase.

## Impact

Successful exploitation results in arbitrary code execution during the build or runtime import phase of any application relying on Orval-generated schemas. This poses a significant risk to CI/CD pipelines, build servers, and runtime environments that process untrusted OpenAPI descriptions. The scope includes any application that integrates Orval to generate schemas from attacker-influenced input sources, such as public repositories or user-submitted API documentation.

## Recommendation

Prioritized, concrete actions for development and security teams:
- Upgrade Orval to version 8.21.0 or later immediately to resolve CVE-2026-72716.
- Audit existing OpenAPI specifications used in build processes to ensure `default` values do not contain suspicious syntax like `${` or backticks.
- If immediate patching is not possible, implement strict validation of OpenAPI specification files before feeding them into the Orval generator.
- Review build pipeline logs for unexpected execution of JavaScript modules generated by Orval.
