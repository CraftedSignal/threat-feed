---
title: Signal K Server Privilege Escalation via Unprotected /enableSecurity Endpoint
slug: 2026-04-signalk-privesc
description: The Signal K server is vulnerable to privilege escalation due to the /skServer/enableSecurity endpoint remaining active after initial setup, allowing unauthenticated users to inject a new admin account and gain full server control; this affects versions prior to 2.24.0-beta.4.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
tags:
  - privilege-escalation
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-33950
    cvss: 9.4
    epss: 0.00049
references:
  - https://github.com/advisories/GHSA-x8hc-fqv3-7gwf
rules:
  - title: Detect SignalK Admin Role Injection
    description: Detects attempts to inject an admin user via the /skServer/enableSecurity endpoint in SignalK, indicating a privilege escalation attempt.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect SignalK Login Attempt with Default Admin User
    description: Detects login attempts using the potentially created 'admin' user via /signalk/v1/auth/login, indicating a potential takeover.
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

The Signal K server, a popular open-source project for marine navigation data, contains a critical vulnerability that allows unauthenticated privilege escalation. The vulnerability resides in the `/skServer/enableSecurity` endpoint, which is intended for initial administrator setup when security is disabled. However, this endpoint is not disabled after the initial setup, leaving it perpetually exposed. Consequently, any unauthenticated user can call this endpoint to inject a new, fully…
