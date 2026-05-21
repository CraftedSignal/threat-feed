---
title: '@hulumi/policies: CIS 1.16 Admin Policy Bypass Vulnerability'
slug: 2026-05-hulumi-policy-bypass
description: '@hulumi/policies versions before 1.3.2 improperly inspect inline and attached IAM policies, potentially allowing admin-equivalent policy paths to bypass the administrator-policy guardrail, resulting in a CIS 1.16 admin policy bypass.'
date: "2026-05-21T20:45:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - iam
  - policy bypass
  - privilege escalation
vendors:
  - GitHub
products:
  - '@hulumi/policies'
  - github.com
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-4xrh-5m3m-328w
rules:
  - title: Detect @hulumi/policies Usage with Vulnerable Versions
    description: Detects usage of @hulumi/policies library with versions prior to 1.3.2, indicating potential vulnerability to admin policy bypass.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Installation of Vulnerable @hulumi/policies Package
    description: Detects installation commands referencing vulnerable versions (<1.3.2) of the @hulumi/policies package.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Versions of @hulumi/policies before 1.3.2 are vulnerable to a security flaw that allows for a bypass of the CIS 1.16 administrator-policy guardrail. This vulnerability arises because the software does not fully inspect inline and attached IAM policy evidence. As a result, some policy paths that should be considered admin-equivalent are not properly evaluated, potentially granting unauthorized administrative privileges. The issue was identified and patched in version 1.3.2, which includes enhanced validation of affected policy shapes and regression tests to prevent future occurrences.

## Attack Chain

This vulnerability does not involve a traditional attack chain in the sense of external exploitation. However, the following steps outline how an attacker could leverage the vulnerability:

1.  An attacker identifies an existing IAM policy or attempts to create a new policy.
2.  The attacker crafts the IAM policy with specific permissions that, while not explicitly granting admin privileges, provide equivalent access.
3.  The attacker uses the crafted policy in an environment where @hulumi/policies version is < 1.3.2.
4.  @hulumi/policies fails to properly evaluate the policy due to incomplete inspection of inline and attached IAM policies.
5.  The crafted policy is applied, granting the attacker unintended administrative access.
6.  The attacker leverages the elevated privileges to perform unauthorized actions within the system.

## Impact

The vulnerability allows for a potential bypass of administrative policy controls, leading to the unintended granting of administrative privileges. Successful exploitation of this vulnerability could lead to unauthorized access to sensitive data, modification of critical system settings, or disruption of services. This could impact any systems or applications relying on @hulumi/policies for IAM policy enforcement. The impact is limited to systems running versions of @hulumi/policies prior to 1.3.2.

## Recommendation

*   Upgrade @hulumi/policies to version 1.3.2 or later to remediate the vulnerability as described in the advisory ([https://github.com/advisories/GHSA-4xrh-5m3m-328w](https://github.com/advisories/GHSA-4xrh-5m3m-328w)).
*   Implement code review processes to validate IAM policies and ensure they adhere to security best practices, even after the upgrade.
*   Continuously monitor systems relying on @hulumi/policies for any unexpected behavior that may indicate successful exploitation of the vulnerability.
