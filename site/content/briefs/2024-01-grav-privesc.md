---
title: Grav Login Plugin Privilege Escalation Vulnerability
slug: 2024-01-grav-privesc
description: Unauthenticated users can escalate privileges to admin in Grav CMS by manipulating registration data due to missing server-side validation in the Login plugin.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - grav
  - privilege-escalation
  - web
vendors:
  - Grav
products:
  - Login Plugin
  - Grav Core
  - grav-plugin-login
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/advisories/GHSA-pxm6-mhxr-q4mj
iocs:
  - type: email
    value: attacker@evil.com
ioc_counts:
  email: 1
rules:
  - title: Detect Malicious Grav User Registration
    description: Detects Grav user registration attempts injecting admin privileges
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Grav Registration Attempt with Group/Access Parameters
    description: Detects Grav user registration attempts with groups or access parameters.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical privilege escalation vulnerability exists in the Grav CMS Login plugin, version 3.8.0, affecting Grav Core versions prior to 2.0.0-beta.2. The vulnerability stems from the `Login::register()` method not validating the `groups` and `access` fields during user registration. If registration is enabled and these fields are included in the allowed registration fields, an unauthenticated user can craft a malicious registration request to assign themselves admin privileges. This can lead to complete compromise of the Grav CMS instance, allowing attackers to modify content, install malicious plugins, and potentially execute arbitrary code. The vulnerability is tracked as CVE-2026-42613. The fix was applied on 2026-04-24 and released in grav-plugin-login 3.8.2.

## Attack Chain

1.  The attacker identifies a Grav CMS instance with user registration enabled and the `groups` or `access` fields included in the allowed registration fields.
2.  The attacker crafts a malicious HTTP POST request to the `/user_register` endpoint, including `username`, `password`, `email`, and `fullname` fields.
3.  The attacker injects `groups` and `access` fields into the POST request with values designed to grant admin privileges (e.g., `groups[]=admins`, `access[admin][super]=true`).
4.  The `Login::register()` method processes the registration data without proper validation of the injected `groups` and `access` fields.
5.  The attacker-controlled `groups` and `access` values are assigned directly to the newly created user object.
6.  The user object is saved, creating a new user account with admin privileges in the `user/accounts/` directory.
7.  The attacker logs in to the Grav admin panel using the newly created account.
8.  The attacker leverages their admin access to install malicious plugins or execute arbitrary code on the server, achieving complete system compromise.

## Impact

Successful exploitation of this vulnerability grants unauthenticated attackers full administrative access to the Grav CMS instance. This can lead to complete website defacement, data exfiltration, or remote code execution. Since no victim count or specific sector targeting is mentioned in the advisory, we can assume any Grav instance with the vulnerable configuration is at risk, potentially impacting numerous websites and organizations relying on Grav CMS.

## Recommendation

*   Upgrade to grav-plugin-login version 3.8.2 or later to patch CVE-2026-42613.
*   If upgrading is not immediately feasible, remove `groups` and `access` from the allowed registration fields in the Login plugin configuration.
*   Deploy the Sigma rule `Detect Malicious Grav User Registration` to identify registration attempts with injected admin privileges based on user-registration requests.
*   Monitor web server logs for POST requests to the `/user_register` endpoint containing `groups` or `access` parameters using the `Grav Registration Attempt with Group/Access Parameters` Sigma rule.
