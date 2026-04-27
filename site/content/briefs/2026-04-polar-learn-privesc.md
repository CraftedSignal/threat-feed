---
title: PolarLearn Privilege Escalation Vulnerability (CVE-2026-35610)
slug: 2026-04-polar-learn-privesc
description: PolarLearn version 0-PRERELEASE-14 and earlier contains a privilege escalation vulnerability (CVE-2026-35610) in the account-management module, allowing authenticated non-admin users to execute administrative functions due to an inverted admin check.
date: "2026-04-07T17:16:35Z"
severities:
  - high
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

PolarLearn, a free and open-source learning program, is vulnerable to a privilege escalation flaw (CVE-2026-35610) in versions 0-PRERELEASE-14 and earlier. The vulnerability lies within the account-management module, specifically affecting the `setCustomPassword(userId, password)` and `deleteUser(userId)` functions. An inverted admin check allows authenticated non-admin users to perform these actions, while simultaneously denying legitimate administrators the same privileges. This oversight…
