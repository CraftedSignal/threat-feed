---
title: RUGGEDCOM CROSSBOW SAM-P Privilege Escalation Vulnerability (CVE-2026-27668)
slug: 2026-04-ruggdcom-privilege-escalation
description: CVE-2026-27668 allows authenticated User Administrators in RUGGEDCOM CROSSBOW Secure Access Manager Primary (SAM-P) to escalate their privileges and access any device group, due to an incorrect privilege assignment in versions prior to V5.8.
date: "2026-04-14T09:18:18Z"
severities:
  - high
tags:
  - ruggedcom
  - privilege-escalation
  - cve-2026-27668
  - sam-p
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27668
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27668
  - https://cert-portal.siemens.com/productcert/html/ssa-741509.html
rules:
  - title: Detect RUGGEDCOM SAM-P Group Membership Modification
    description: Detects modifications to user group memberships within RUGGEDCOM SAM-P, which could indicate privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect RUGGEDCOM SAM-P Admin Login Activity
    description: Detects successful login events to the RUGGEDCOM SAM-P admin interface, which can be used to monitor for suspicious admin activity
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-27668, affects RUGGEDCOM CROSSBOW Secure Access Manager Primary (SAM-P) versions prior to V5.8. The vulnerability stems from User Administrators being granted the ability to administer groups they belong to. An attacker with User Administrator privileges can exploit this flaw to escalate their own privileges, granting themselves unauthorized access to any device group at any access level. This vulnerability poses a significant risk to organizations relying on…
