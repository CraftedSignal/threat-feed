---
title: Actual Privilege Escalation via change-password Endpoint on OpenID-Migrated Servers
slug: 2024-01-03-actual-privesc
description: Any authenticated user can escalate to ADMIN on Actual servers migrated from password authentication to OpenID Connect by exploiting a lack of authorization checks, orphaned password rows, and client-controlled login methods, leading to full administrative privileges.
date: "2024-01-03T12:00:00Z"
severities:
  - critical
tags:
  - privilege-escalation
  - web-application
vendors:
  - Actual
products:
  - '@actual-app/sync-server'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-prp4-2f49-fcgp
rules:
  - title: Detect Password Change Attempts on OpenID-Only Servers
    description: Detects attempts to change the password on servers that should only be using OpenID Connect by monitoring requests to the /account/change-password endpoint when the server is configured for OpenID only.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Login Attempts with Client-Specified Password Method
    description: Detects login attempts where the client specifies the 'password' login method, potentially bypassing server-side authentication configurations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1550
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Actual is vulnerable to a privilege escalation attack affecting servers migrated from password authentication to OpenID Connect. This vulnerability, identified as CVE-2026-33318, allows any authenticated user, regardless of their initial role (including the BASIC role), to gain full ADMIN access. The vulnerability stems from three weaknesses: a missing authorization check on the `/account/change-password` endpoint, the persistence of the inactive password `auth` row after migration, and the…
