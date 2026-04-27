---
title: WordPress Custom Role Manager Plugin Privilege Escalation via CVE-2026-7106
slug: 2024-01-wordpress-privesc
description: Highland Software's Custom Role Manager plugin for WordPress, versions 1.0.0 and earlier, contains a privilege escalation vulnerability (CVE-2026-7106) that allows authenticated users with subscriber-level access to modify user roles due to insufficient authorization checks in the hscrm_save_user_roles() function.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - wordpress
  - cve
vendors:
  - Highland Software
products:
  - Custom Role Manager plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7106
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7106
rules:
  - title: Detect Suspicious WordPress Role Updates
    description: Detects attempts to modify user roles by low-privileged accounts in WordPress, potentially indicating privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect direct access of hscrm_save_user_roles() function
    description: Detects unauthorized access to the hscrm_save_user_roles() function, which is indicative of a privilege escalation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Highland Software Custom Role Manager plugin, versions up to and including 1.0.0, is vulnerable to privilege escalation. The vulnerability, identified as CVE-2026-7106, stems from a lack of sufficient authorization checks within the `hscrm_save_user_roles()` function. This function is accessible to any authenticated user via the `personal_options_update` action. This allows an attacker with minimal privileges (subscriber level or higher) to potentially elevate their own privileges or those…
