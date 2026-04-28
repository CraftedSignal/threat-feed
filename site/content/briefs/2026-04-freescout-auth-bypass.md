---
title: FreeScout Authorization Bypass Vulnerability (CVE-2026-39384)
slug: 2026-04-freescout-auth-bypass
description: FreeScout before version 1.8.212 is vulnerable to an authorization bypass (CVE-2026-39384) due to improper validation of the `limit_user_customer_visibility` parameter during customer merging, potentially leading to unauthorized data modification and access.
date: "2026-04-07T17:16:37Z"
severities:
  - high
tags:
  - authorization-bypass
  - cve-2026-39384
  - freescout
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-39384
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39384
  - https://github.com/freescout-help-desk/freescout/commit/b395a1179117af5e2df704c6bad71feeb301b4ce
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-j6v9-22vq-53vh
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Customer Merges
    description: Detects potential authorization bypass attempts during customer merges in FreeScout by monitoring for requests that manipulate the `limit_user_customer_visibility` parameter.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect FreeScout web requests
    description: Detects FreeScout web requests
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a PHP-based help desk and shared inbox application built on the Laravel framework, contains an authorization bypass vulnerability (CVE-2026-39384) affecting versions prior to 1.8.212. The vulnerability stems from the application's failure to properly validate the `limit_user_customer_visibility` parameter when merging customer accounts. This oversight allows an attacker with low privileges to potentially bypass intended authorization controls, leading to unauthorized modification of customer data and access to information beyond their designated scope. The vulnerability was reported and patched in version 1.8.212. This issue poses a risk to organizations using FreeScout for customer support, as it could allow unauthorized users to gain access to sensitive customer information and perform actions they are not authorized to undertake.

## Attack Chain

1. Attacker authenticates to FreeScout with low-privileged user credentials.
2. Attacker identifies the customer merge functionality within FreeScout.
3. Attacker crafts a malicious request to the customer merge endpoint.
4. The crafted request manipulates the `limit_user_customer_visibility` parameter.
5. Due to missing validation, the manipulated parameter bypasses authorization checks.
6. The system merges customer accounts without properly enforcing visibility restrictions.
7. The attacker gains unauthorized access to customer data beyond their intended scope.
8. The attacker modifies customer data or performs actions that would otherwise be prohibited.

## Impact

Successful exploitation of CVE-2026-39384 can lead to unauthorized access and modification of customer data within FreeScout installations. This could expose sensitive customer information, such as contact details, support conversations, and other private data. The number of affected organizations depends on the adoption rate of FreeScout and the prevalence of vulnerable versions. The impact includes potential data breaches, compliance violations, and reputational damage.

## Recommendation

*   Upgrade FreeScout to version 1.8.212 or later to patch CVE-2026-39384.
*   Deploy the Sigma rule "Detect Suspicious Customer Merges" to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests to the customer merge functionality with unusual parameters.
*   Implement strict input validation and sanitization for all user-supplied parameters, especially those related to authorization and access control.
