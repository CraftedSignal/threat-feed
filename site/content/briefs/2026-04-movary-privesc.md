---
title: Movary Privilege Escalation Vulnerability (CVE-2026-40349)
slug: 2026-04-movary-privesc
description: Movary versions prior to 0.71.1 allow authenticated users to escalate privileges to administrator by manipulating the `isAdmin` field via a PUT request to the `/settings/users/{userId}` endpoint, due to missing authorization checks.
date: "2026-04-18T00:16:38Z"
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - cve-2026-40349
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40349
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40349
  - https://github.com/leepeuker/movary/security/advisories/GHSA-mcfq-8rx7-w25v
ioc_counts:
  email: 1
rules:
  - title: Detect Movary Admin Privilege Escalation Attempt
    description: Detects attempts to escalate privileges in Movary by sending a PUT request to the /settings/users endpoint with isAdmin=true.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Movary User Settings Modification
    description: Detects PUT requests to the Movary /settings/users endpoint, which could indicate suspicious user profile modifications.
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

Movary is a self-hosted web application designed for users to track and rate movies they have watched. Prior to version 0.71.1, the application contains a privilege escalation vulnerability (CVE-2026-40349). An authenticated user could modify their account to gain administrative privileges without proper authorization. This is achieved by sending a PUT request to the `/settings/users/{userId}` endpoint with the `isAdmin` field set to `true`. This vulnerability exists because the application…
