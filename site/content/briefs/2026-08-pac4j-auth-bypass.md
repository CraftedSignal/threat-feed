---
title: Authentication Bypass Vulnerability in pac4j-core
slug: 2026-08-pac4j-auth-bypass
description: An authentication bypass vulnerability in pac4j-core versions prior to 6.5.6 caused by flawed validation logic in CheckProfileTypeAuthorizer allows unauthorized access to restricted resources.
date: "2026-08-29T17:40:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pac4j:pac4j-core:*:*:*:*:*:*:*:*
vendors:
  - pac4j
products:
  - pac4j-core (< 6.5.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can authenticate through a weaker client and access resources requiring a stronger profile type by satisfying generic profile checks.
    confidence_band: high
cves:
  - id: CVE-2026-82463
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82463
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade pac4j-core dependency to 6.5.6
      owner: Development
      due: 48h
      evidence: pac4j-core before 6.5.6 contains an authentication bypass vulnerability
  mitigation_plan:
    - priority: immediate
      action: Patch pac4j-core to 6.5.6
      owner: Development
      addresses: CVE-2026-82463
      evidence: pac4j-core before 6.5.6 contains an authentication bypass vulnerability
---

The pac4j-core library, commonly used for security and authentication in Java-based web applications, contains a critical authentication bypass vulnerability identified as CVE-2026-82463. The vulnerability exists within the CheckProfileTypeAuthorizer component. Due to a logical error in the validation logic, the profile type check is effectively reversed. This flaw allows an attacker to authenticate using a lower-privileged or weaker client and successfully bypass authorization checks intended for higher-privileged profiles. 

By exploiting this flaw, unauthenticated or low-privilege actors can gain access to sensitive application resources that should be restricted to specific, stronger profile types. This vulnerability affects all pac4j-core versions prior to 6.5.6. Given the library's integration into web frameworks, this poses a significant risk to application authorization policies. Defenders should identify applications utilizing vulnerable versions of the library and prioritize the upgrade to version 6.5.6 or later.

## Impact

Successful exploitation of CVE-2026-82463 permits unauthorized access to resources and data restricted by the pac4j-core authorization framework. This bypass undermines the integrity of access control mechanisms within affected web applications, potentially leading to unauthorized data exposure, privilege escalation, or administrative action performance by unauthorized users. The extent of the damage depends on the specific resources protected by the affected authorizer within the target application.

## Recommendation

- Upgrade the pac4j-core dependency to version 6.5.6 or later in all Java-based applications.
- Review application authorization policies that utilize CheckProfileTypeAuthorizer to confirm they are not relying on default behavior if currently running a vulnerable version.
- Audit web application logs for unexpected access patterns where users with low-privilege sessions are accessing endpoints protected by CheckProfileTypeAuthorizer.
