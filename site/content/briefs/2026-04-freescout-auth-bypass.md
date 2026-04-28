---
title: FreeScout Incorrect Authorization Vulnerability via Save Draft
slug: 2026-04-freescout-auth-bypass
description: FreeScout before 1.8.215 has an incorrect authorization vulnerability where a direct POST request to the `save_draft` AJAX path can create a draft inside a hidden conversation when `APP_SHOW_ONLY_ASSIGNED_CONVERSATIONS` is enabled, potentially allowing unauthorized access or modification of data.
date: "2026-04-22T12:00:00Z"
severities:
  - medium
tags:
  - cve
  - authorization
  - web application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41190
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41190
  - https://github.com/freescout-help-desk/freescout/commit/414878eb79be7cb01a3ae124df6efcd23729275f
  - https://github.com/freescout-help-desk/freescout/releases/tag/1.8.215
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-vj2p-2789-3747
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect FreeScout Save Draft Abuse
    description: Detects POST requests to the save_draft endpoint in FreeScout, potentially indicating an attempt to exploit CVE-2026-41190
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: FreeScout Unauthorized Draft Creation Attempt
    description: Detects suspicious POST requests to the FreeScout save_draft endpoint with a high data volume, potentially indicating an attempt to create a large or malicious draft.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout is a self-hosted help desk and shared mailbox platform. Prior to version 1.8.215, a vulnerability exists related to authorization controls when the `APP_SHOW_ONLY_ASSIGNED_CONVERSATIONS` setting is enabled. Specifically, the `save_draft` AJAX endpoint lacks proper authorization checks. This allows an attacker to potentially bypass intended access restrictions and create drafts within conversations that they should not be able to access, leading to unauthorized modification or viewing…
