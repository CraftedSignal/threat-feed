---
title: Webkul Krayin CRM BOLA Vulnerability (CVE-2026-38529)
slug: 2026-04-krayin-bola
description: CVE-2026-38529 is a Broken Object-Level Authorization (BOLA) vulnerability in Webkul Krayin CRM v2.2.x that allows authenticated attackers to reset user passwords and take over accounts.
date: "2026-04-14T16:16:43Z"
severities:
  - critical
tags:
  - bola
  - cve-2026-38529
  - krayin-crm
  - account-takeover
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-38529
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-38529
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2026-38529
  - https://github.com/krayin/laravel-crm
rules:
  - title: Detect Krayin CRM Password Reset via UserController
    description: Detects password reset attempts on the /Settings/UserController.php endpoint in Krayin CRM, indicative of CVE-2026-38529 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1555
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect Krayin CRM UserController Access
    description: Detects access to the /Settings/UserController.php endpoint in Krayin CRM. Requires further analysis to determine if it is malicious activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-38529 describes a Broken Object-Level Authorization (BOLA) vulnerability affecting Webkul Krayin CRM version 2.2.x. The vulnerability resides in the `/Settings/UserController.php` endpoint. An authenticated attacker can exploit this flaw by sending a crafted HTTP request. Successful exploitation allows the attacker to arbitrarily reset the passwords of other users, leading to complete account takeover. Given the potential for widespread compromise and data breaches, this vulnerability…
