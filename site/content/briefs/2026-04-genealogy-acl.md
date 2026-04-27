---
title: Genealogy PHP Application Broken Access Control Vulnerability (CVE-2026-39355)
slug: 2026-04-genealogy-acl
description: A critical broken access control vulnerability (CVE-2026-39355) in Genealogy PHP application versions prior to 5.9.1 allows authenticated users to transfer ownership of arbitrary teams, leading to complete takeover of team workspaces and unrestricted data access.
date: "2026-04-07T19:16:46Z"
severities:
  - critical
tags:
  - broken-access-control
  - php
  - genealogy
  - CVE-2026-39355
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encryption for Impact
cves:
  - id: CVE-2026-39355
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39355
  - https://github.com/MGeurts/genealogy/security/advisories/GHSA-2rq7-jqm7-w8x4
rules:
  - title: Detect Suspicious Genealogy Team Ownership Transfer
    description: Detects potential exploitation of CVE-2026-39355 by monitoring for suspicious POST requests to team management endpoints associated with ownership transfers in Genealogy PHP application.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-39355
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Genealogy Application Version Prior to 5.9.1
    description: Detects web requests from Genealogy application version prior to 5.9.1, which are vulnerable to CVE-2026-39355.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-39355
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Genealogy is a family tree PHP application that, prior to version 5.9.1, contained a critical broken access control vulnerability identified as CVE-2026-39355. This flaw allows any authenticated user to transfer ownership of non-personal teams to themselves without proper authorization checks. This unauthorized ownership transfer leads to complete takeover of other users’ team workspaces, granting the attacker unrestricted access to all genealogy data associated with the compromised team…
