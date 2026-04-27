---
title: Brave CMS Missing Authorization Leads to Privilege Escalation
slug: 2026-04-brave-cms-privesc
description: Brave CMS versions prior to 2.0.6 are vulnerable to privilege escalation due to a missing authorization check in the update role endpoint, allowing any authenticated user to gain Super Admin privileges.
date: "2026-04-06T20:16:26Z"
severities:
  - critical
tags:
  - cve-2026-35182
  - privilege-escalation
  - web-application
  - brave-cms
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35182
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35182
  - https://github.com/Ajax30/BraveCMS-2.0/security/advisories/GHSA-g58h-mvjw-f4hv
ioc_counts:
  email: 1
rules:
  - title: Detect Brave CMS Unauthorized Role Update
    description: Detects POST requests to the /rights/update-role endpoint without proper authorization, indicating potential privilege escalation attempts in Brave CMS.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Brave CMS Super Admin Creation
    description: Detects requests which result in creation of super admin users.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Brave CMS, an open-source content management system, is susceptible to a critical vulnerability (CVE-2026-35182) affecting versions prior to 2.0.6. The vulnerability stems from a missing authorization check in the `/rights/update-role/{id}` endpoint, specifically within the `routes/web.php` file. The absence of the `checkUserPermissions:assign-user-roles` middleware on the POST route allows any authenticated user, regardless of their current role, to modify account roles. This enables malicious…
