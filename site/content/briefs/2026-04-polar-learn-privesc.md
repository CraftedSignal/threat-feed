---
title: PolarLearn Privilege Escalation Vulnerability (CVE-2026-35610)
slug: 2026-04-polar-learn-privesc
description: PolarLearn version 0-PRERELEASE-14 and earlier contains a privilege escalation vulnerability (CVE-2026-35610) in the account-management module, allowing authenticated non-admin users to execute administrative functions due to an inverted admin check.
date: "2026-04-07T17:16:35Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-35610
  - privilege-escalation
  - polarnl
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35610
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35610
  - https://github.com/polarnl/PolarLearn/security/advisories/GHSA-8hww-w7cc-77rj
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect PolarLearn Privilege Escalation
    description: Detects attempts to exploit the PolarLearn privilege escalation vulnerability (CVE-2026-35610) by monitoring for requests to the setCustomPassword function from non-admin users.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect PolarLearn User Deletion Attempt by Non-Admin
    description: Detects attempts to exploit the PolarLearn vulnerability where non-admin users can delete accounts.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PolarLearn, a free and open-source learning program, is vulnerable to a privilege escalation flaw (CVE-2026-35610) in versions 0-PRERELEASE-14 and earlier. The vulnerability lies within the account-management module, specifically affecting the `setCustomPassword(userId, password)` and `deleteUser(userId)` functions. An inverted admin check allows authenticated non-admin users to perform these actions, while simultaneously denying legitimate administrators the same privileges. This oversight allows malicious users to gain unauthorized control over user accounts and system configurations, leading to potential data breaches or service disruption.

## Attack Chain

1.  Attacker authenticates to the PolarLearn application using valid, non-admin credentials.
2.  Attacker identifies the vulnerable `setCustomPassword` function within the account-management module.
3.  Attacker crafts a malicious request to the `setCustomPassword` function, targeting the `userId` of an administrator account.
4.  Due to the inverted admin check, the application incorrectly validates the attacker's non-admin privileges as sufficient for the action.
5.  The application executes the `setCustomPassword` function, modifying the administrator's password using the attacker's provided value.
6.  The attacker authenticates to the PolarLearn application using the compromised administrator credentials.
7.  The attacker leverages the escalated administrator privileges to access sensitive data or modify critical system settings.
8.  Alternatively, the attacker could exploit the `deleteUser` function, deleting administrator or other user accounts.

## Impact

Successful exploitation of CVE-2026-35610 allows unauthorized privilege escalation within PolarLearn. Non-admin users can modify administrator passwords or delete user accounts, leading to potential data breaches, service disruption, and unauthorized access to sensitive information. The vulnerability affects versions 0-PRERELEASE-14 and earlier, potentially impacting all deployments of the software within educational institutions and other organizations using PolarLearn.

## Recommendation

*   Upgrade PolarLearn to a patched version beyond 0-PRERELEASE-14 to remediate the vulnerability described in CVE-2026-35610.
*   Implement the Sigma rule `DetectPolarLearnPrivilegeEscalation` to detect exploitation attempts by monitoring calls to the `setCustomPassword` function made by non-admin users.
*   Review and audit user permissions within PolarLearn to identify and remove any unauthorized administrator accounts created through exploitation of CVE-2026-35610.
