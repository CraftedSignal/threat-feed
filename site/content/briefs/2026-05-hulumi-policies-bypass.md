---
title: '@hulumi/policies Evidence Bypass Vulnerability'
slug: 2026-05-hulumi-policies-bypass
description: '@hulumi/policies versions before 1.3.2 allowed unrelated compliant-looking evidence to suppress violations for different zones, hostnames, origins, or repositories in the same stack, bypassing Cloudflare and deployment-governance guardrails.'
date: "2026-05-21T20:50:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dependency-confusion
  - security-bypass
  - cloud
vendors:
  - Cloudflare
  - Hulumi
products:
  - '@hulumi/policies (< 1.3.2)'
references:
  - https://github.com/advisories/GHSA-59f3-7227-wmh4
rules:
  - title: Detect @hulumi/policies Package Installation with Vulnerable Version
    description: Detects installation of the @hulumi/policies npm package with a version prior to 1.3.2, which is known to be vulnerable to an evidence bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - linux
  - title: Detect @hulumi/policies Update to Vulnerable Version via npm
    description: Detects attempts to downgrade or update @hulumi/policies to a vulnerable version (less than 1.3.2) using npm install.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

@hulumi/policies, a package used for deployment governance and security policy enforcement, contained a vulnerability in versions prior to 1.3.2. The vulnerability stemmed from the use of stack-wide evidence shortcuts within Cloudflare and deployment-governance validators. This meant that arbitrary, compliant-looking evidence could be used to suppress violations across different Cloudflare zones, hostnames, origins, or repositories within the same stack. This vulnerability effectively bypassed intended security and governance controls, potentially allowing unauthorized or non-compliant deployments to proceed undetected. Hulumi released version 1.3.2 to address this issue, implementing stricter evidence correlation and including regression tests to prevent future bypasses.

## Attack Chain

1.  An attacker identifies a resource within a stack protected by @hulumi/policies.
2.  The attacker determines the criteria for a compliant evidence object.
3.  The attacker creates a compliant evidence object, unrelated to the target resource, within the same stack.
4.  The attacker triggers a deployment or configuration change on the protected resource.
5.  @hulumi/policies incorrectly uses the unrelated compliant evidence to satisfy the policy requirements of the targeted resource.
6.  The policy check incorrectly passes, allowing the deployment or configuration change to proceed.
7.  The attacker successfully bypasses the intended security and governance controls.
8.  The attacker achieves unauthorized changes to the target resource.

## Impact

The vulnerability in @hulumi/policies allowed attackers to bypass intended security and governance controls. This could lead to unauthorized deployments, misconfigurations, and potentially compromise the security posture of systems protected by these policies. While the specific number of affected organizations is unknown, any environment relying on @hulumi/policies prior to version 1.3.2 for Cloudflare or deployment governance was susceptible to this bypass. Successful exploitation could lead to data breaches, service disruptions, or other security incidents depending on the specific resources being protected.

## Recommendation

*   Upgrade @hulumi/policies to version 1.3.2 or later to remediate the vulnerability (reference: Remediation section).
*   Review existing deployment pipelines and security policies to ensure they are aligned with the updated version of @hulumi/policies.
*   Enable logging for deployment events to detect any potential unauthorized changes (reference: attack chain).
