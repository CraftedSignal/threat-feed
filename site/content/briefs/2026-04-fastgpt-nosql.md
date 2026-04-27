---
title: FastGPT NoSQL Injection Vulnerability in Password Change Endpoint
slug: 2026-04-fastgpt-nosql
description: FastGPT versions prior to 4.14.9.5 are vulnerable to NoSQL injection in the password change endpoint, allowing authenticated attackers to bypass password verification and perform account takeover.
date: "2026-04-17T22:16:32Z"
severities:
  - high
tags:
  - nosql-injection
  - account-takeover
  - cve
  - fastgpt
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-40352
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40352
rules:
  - title: Detect FastGPT Password Reset Bypass
    description: Detects potential NoSQL injection attempts to bypass the password verification during password reset in FastGPT.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect FastGPT Password Reset Endpoint Access
    description: Detects access to the FastGPT password reset endpoint, which could be indicative of account takeover attempts.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FastGPT, an AI Agent building platform, is susceptible to a critical NoSQL injection vulnerability affecting versions before 4.14.9.5. The flaw resides within the password change endpoint, enabling an authenticated attacker to circumvent the necessary "old password" verification process. By injecting MongoDB query operators, an attacker with an existing, low-privileged session can manipulate password changes for their own account, or potentially other accounts if combined with ID manipulation…
