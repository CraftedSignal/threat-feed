---
title: Signal K Server Privilege Escalation via Unprotected /enableSecurity Endpoint
slug: 2026-04-signalk-privesc
description: The Signal K server is vulnerable to privilege escalation due to the /skServer/enableSecurity endpoint remaining active after initial setup, allowing unauthenticated users to inject a new admin account and gain full server control; this affects versions prior to 2.24.0-beta.4.
date: "2026-04-04T12:00:00Z"
type: coverage
types:
  - coverage
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

The Signal K server, a popular open-source project for marine navigation data, contains a critical vulnerability that allows unauthenticated privilege escalation. The vulnerability resides in the `/skServer/enableSecurity` endpoint, which is intended for initial administrator setup when security is disabled. However, this endpoint is not disabled after the initial setup, leaving it perpetually exposed. Consequently, any unauthenticated user can call this endpoint to inject a new, fully privileged "admin" account by crafting a malicious POST request. This vulnerability affects Signal K server versions prior to 2.24.0-beta.4 and poses a significant risk to maritime systems relying on this software. Successful exploitation grants attackers full control over the Signal K server and access to sensitive vessel data, potentially leading to manipulation of routing, alteration of server configurations, and access to restricted API endpoints.

## Attack Chain

1.  The attacker identifies a vulnerable Signal K server running a version prior to 2.24.0-beta.4.
2.  The attacker sends an unauthenticated POST request to the `/skServer/enableSecurity` endpoint.
3.  The POST request contains a JSON payload with the attacker's desired username, password, and the critical `"type": "admin"` parameter.
4.  The Signal K server's `addUser` function in `src/tokensecurity.ts` blindly trusts the injected "type" field without validation.
5.  A new user account is created with administrator privileges, bypassing any existing authentication mechanisms.
6.  The attacker uses the newly created account's username and password to obtain a valid JWT token via the `/signalk/v1/auth/login` endpoint.
7.  The attacker uses the JWT token to authenticate to restricted API endpoints, demonstrating successful privilege escalation.
8.  The attacker can now modify vessel routing data, alter server configurations, and access sensitive information.

## Impact

Successful exploitation of this vulnerability grants an unauthenticated attacker full Administrator access to the Signal K server. This allows them to modify sensitive vessel routing data, which can have serious safety implications. The attacker can also alter server configurations, potentially disrupting services or injecting malicious code. Furthermore, the attacker gains access to restricted endpoints, exposing sensitive information and enabling further malicious activities. This vulnerability affects Signal K server versions prior to 2.24.0-beta.4, potentially impacting numerous vessels and maritime systems relying on the vulnerable software.

## Recommendation

*   Upgrade Signal K server to version 2.24.0-beta.4 or later to patch CVE-2026-33950.
*   Deploy the Sigma rule `Detect SignalK Admin Role Injection` to detect attempts to exploit this vulnerability by monitoring for POST requests to the `/skServer/enableSecurity` endpoint.
*   Enable web server logging and specifically monitor POST requests to the `/skServer/enableSecurity` endpoint to investigate any suspicious activity.
