---
title: Vikunja Account Reactivation Vulnerability (CVE-2026-33316)
slug: 2024-01-vikunja-account-reactivation
description: A critical vulnerability in Vikunja versions prior to 2.2.0 allows disabled users to bypass administrator controls and reactivate their accounts by exploiting a flaw in the password reset logic.
date: "2026-03-24T15:16:35Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - vikunja
  - account-reactivation
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33316
rules:
  - title: Detect Password Reset Request from Disabled User
    description: Detects requests to the password reset token endpoint from potentially disabled user accounts by correlating web server logs with a list of disabled users. Requires a method to correlate IP addresses or user identifiers from the Vikunja application with web server logs. The rule triggers when a request to `/api/v1/user/password/token` or `/api/v1/user/password/reset` is seen and the source IP address or user identifier matches a disabled user.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Password Reset Request
    description: Detects requests to the password reset token endpoint `/api/v1/user/password/token`.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Password Reset Completion
    description: Detects requests to the password reset completion endpoint `/api/v1/user/password/reset`.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Vikunja, an open-source self-hosted task management platform, is vulnerable to unauthorized account reactivation. Prior to version 2.2.0, the platform's password reset mechanism fails to validate the account status before enabling password reset, allowing disabled users to regain access. Specifically, the `ResetPassword()` function sets the user’s status to `StatusActive` after a successful password reset without verifying if the account was deliberately disabled by an administrator. This…
