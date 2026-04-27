---
title: CouchCMS Privilege Escalation via f_k_levels_list Parameter Manipulation (CVE-2026-29002)
slug: 2026-04-couchcms-privesc
description: CouchCMS is vulnerable to privilege escalation, allowing authenticated Admin-level users to create SuperAdmin accounts by manipulating the 'f_k_levels_list' parameter during user creation, granting them full application control.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - cve
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-29002
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29002
  - https://gist.github.com/thepiyushkumarshukla/477e2d2bbbe8cc3ec0d640c50f0cf9e1
  - https://www.couchcms.com/
  - https://www.vulncheck.com/advisories/couchcms-privilege-escalation-via-f-k-levels-list-parameter
rules:
  - title: Detect CouchCMS SuperAdmin Creation via Parameter Tampering
    description: Detects attempts to create SuperAdmin accounts in CouchCMS by tampering with the f_k_levels_list parameter.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect CouchCMS Admin Panel Access
    description: Detects access to the CouchCMS administration panel login page.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-29002 identifies a privilege escalation vulnerability in CouchCMS. This flaw allows authenticated users with Admin-level privileges to elevate their access to SuperAdmin by tampering with the `f_k_levels_list` parameter during the user creation process. By modifying the value of this parameter from "4" to "10" in the HTTP request body, an attacker can bypass authorization checks, effectively circumventing restrictions on SuperAdmin account creation and privilege assignment. This…
