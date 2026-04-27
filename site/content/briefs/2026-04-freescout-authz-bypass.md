---
title: FreeScout Incorrect Authorization Vulnerability (CVE-2026-41189)
slug: 2026-04-freescout-authz-bypass
description: FreeScout versions before 1.8.215 are vulnerable to an incorrect authorization issue where users without conversation access can edit customer threads due to a flaw in the `ThreadPolicy::edit()` function.
date: "2026-04-22T12:00:00Z"
severities:
  - medium
tags:
  - freescout
  - authorization
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41189
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41189
  - https://github.com/freescout-help-desk/freescout/commit/cdadaf621bb1e1d017315df20d743671f7eae7a9
  - https://github.com/freescout-help-desk/freescout/releases/tag/1.8.215
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-4h5p-7f5c-q7gj
ioc_counts:
  email: 1
  url: 3
rules:
  - title: FreeScout Unauthorized Thread Edit Attempt
    description: Detects attempts to edit customer threads in FreeScout by users without proper authorization based on HTTP POST requests to specific endpoints.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: FreeScout Thread Policy Edit Function Access
    description: Detects access to the ThreadPolicy edit function, potentially indicating an attempt to exploit CVE-2026-41189. Requires application-level logging.
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

FreeScout, a self-hosted help desk and shared mailbox platform, is affected by an authorization bypass vulnerability. Specifically, versions prior to 1.8.215 fail to properly restrict access to customer threads within conversations. The vulnerability resides in the `ThreadPolicy::edit()` function, which checks mailbox access but neglects to enforce the `ConversationPolicy`'s assigned-only restriction.  This allows a user who should not have access to a conversation to still load and modify…
