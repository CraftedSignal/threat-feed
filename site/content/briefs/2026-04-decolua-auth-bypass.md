---
title: Decolua 9router Authorization Bypass Vulnerability (CVE-2026-5842)
slug: 2026-04-decolua-auth-bypass
description: CVE-2026-5842 is an authorization bypass vulnerability in decolua 9router versions up to 0.3.47, allowing remote attackers to gain unauthorized access via manipulation of the /api endpoint.
date: "2026-04-09T05:16:06Z"
severities:
  - high
tags:
  - cve
  - authorization-bypass
  - router
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5842
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5842
  - https://github.com/decolua/9router/
  - https://github.com/decolua/9router/releases/tag/v0.3.75
rules:
  - title: Detect Access to Decolua 9router API Endpoint
    description: Detects access to the Decolua 9router administrative API endpoint, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Upgrade of Decolua 9router
    description: Detects access to the Decolua 9router upgrade endpoint, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-5842, affects decolua 9router versions up to 0.3.47. The vulnerability resides within an unknown function of the `/api` endpoint, specifically the Administrative API. Successful exploitation of this flaw allows a remote attacker to bypass authorization controls, potentially gaining administrative privileges. A public exploit for this vulnerability has been disclosed, increasing the risk of exploitation. Organizations using vulnerable versions of…
