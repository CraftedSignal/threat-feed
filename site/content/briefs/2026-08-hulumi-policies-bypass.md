---
title: Evidence Validation Bypass in @hulumi/policies
slug: 2026-08-hulumi-policies-bypass
description: An evidence validation flaw in @hulumi/policies versions prior to 1.3.2 allows attackers to suppress security violations by submitting valid, but unrelated, evidence from other resources.
date: "2026-08-31T11:16:33Z"
lastmod: "2026-08-31T11:17:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:hulumi:policies:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - cve-2026-82860
  - iam
vendors:
  - Hulumi
products:
  - '@hulumi/policies (< 1.3.2)'
cves:
  - id: CVE-2026-82855
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82855
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82860
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @hulumi/policies to version 1.3.2 or later in all build environments and policy engines.
      owner: IT Operations
      due: 48h
      evidence: Source states versions before 1.3.2 contain the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @hulumi/policies to version 1.3.2.
      owner: IT Operations
      addresses: CVE-2026-82855
      evidence: NVD vulnerability entry.
updates:
  - at: "2026-08-31T11:17:13Z"
    level: L2
    summary: added coverage for @hulumi/policies (< 1.3.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82860
---

The @hulumi/policies package contains a critical evidence validation bypass vulnerability affecting its Cloudflare and deployment-governance validators. In versions prior to 1.3.2, the logic responsible for verifying security compliance fails to strictly enforce the association between the submitted evidence and the specific resource being evaluated. Consequently, an attacker can submit compliant evidence obtained from a legitimate, different resource - such as a separate Cloudflare zone, hostname, origin, or repository - to satisfy the validation checks for a target resource that would otherwise trigger a violation. This vulnerability effectively allows for the bypassing of security guardrails within a shared stack, potentially permitting the deployment or configuration of non-compliant resources. The flaw stems from a lack of scoping in the validation mechanism, making the guardrails susceptible to input manipulation where legitimate data is repurposed to bypass compliance controls.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.8, indicating the potential for high-impact security misconfigurations. Successful exploitation allows an attacker to bypass critical security guardrails, facilitating the deployment of unauthorized or non-compliant infrastructure and services. This impacts organizations relying on automated governance and policy enforcement within their Cloudflare and deployment pipelines, as the integrity of these validation checks is compromised.

## Recommendation

Prioritize the upgrade of the @hulumi/policies package to version 1.3.2 or later across all deployment pipelines and governance engines. If an immediate upgrade is not feasible, implement manual auditing of security policy violations for sensitive stacks, as automated alerts may be suppressed by malicious evidence submission. Monitor CI/CD logs for submissions involving cross-resource evidence references, as these are indicators of potential exploitation attempts.
