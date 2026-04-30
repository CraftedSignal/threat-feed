---
title: WWBN AVideo Channel Password Bypass Vulnerability (CVE-2026-33297)
slug: 2024-01-avideo-password-bypass
description: WWBN AVideo versions prior to 26.0 are vulnerable to a credential access vulnerability where passwords containing non-numeric characters are incorrectly processed, effectively setting the password to '0' and allowing trivial channel access bypass.
date: "2026-03-23T14:16:33Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-33297
  - credential-access
  - web-application
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1213
    technique_name: Data from Information Repository
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33297
rules:
  - title: AVideo Password Reset Request
    description: Detects requests to the setPassword.json.php endpoint, which may indicate attempted exploitation of CVE-2026-33297.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
  - title: AVideo Failed Login Attempt with '0' Password
    description: Detects failed login attempts with the password '0', which is the effective password after exploiting CVE-2026-33297.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo is an open-source video platform. A critical vulnerability exists in versions prior to 26.0 within the CustomizeUser plugin. Specifically, the `setPassword.json.php` endpoint is susceptible to a logic error affecting channel password assignments. When an administrator attempts to set a channel password containing non-numeric characters for any user, the system incorrectly coerces the password to the integer zero before storing it. This effectively sets the channel password to '0'…
