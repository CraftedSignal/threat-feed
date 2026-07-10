---
title: Movary Privilege Escalation via User Management Endpoint Access (CVE-2026-40350)
slug: 2024-01-26-movary-privesc
description: Movary versions prior to 0.71.1 are vulnerable to a privilege escalation, allowing authenticated non-admin users to access user management endpoints and create new administrator accounts due to missing middleware and flawed authorization checks.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-40350
  - privilege-escalation
  - web-application
vendors:
  - Movary
products:
  - Movary
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40350
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40350
rules:
  - title: Movary User Management Endpoint Access
    description: Detects unauthorized access attempts to the /settings/users endpoint in Movary, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Movary Admin Account Creation Attempt
    description: Detects attempts to create a new administrator account in Movary by monitoring POST requests to user management endpoints with administrator role assignments.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Movary, a self-hosted web application for tracking and rating movies, contains a privilege escalation vulnerability, identified as CVE-2026-40350, in versions prior to 0.71.1. This flaw allows any authenticated user, regardless of their assigned role, to access sensitive user management endpoints typically reserved for administrators. Specifically, an attacker can leverage the `/settings/users` endpoint to enumerate all existing users and create new administrator accounts. The root cause lies in the absence of proper admin-only middleware enforcement in the route definitions and a broken boolean condition within the controller-level authorization check. Successful exploitation grants the attacker complete administrative control over the Movary instance. The vulnerability was patched in version 0.71.1.

## Attack Chain

1.  The attacker gains initial access to the Movary application by creating a standard user account or compromising an existing non-admin account using valid credentials.
2.  The attacker authenticates to the Movary web application, establishing a valid web session.
3.  The attacker crafts a malicious HTTP GET or POST request targeting the `/settings/users` endpoint, typically intended for administrator access.
4.  Due to the missing admin-only middleware, the request is not blocked, and the application proceeds to process it.
5.  The application's controller-level authorization check contains a flawed boolean condition that fails to properly restrict access based on user roles.
6.  The application enumerates all existing users, exposing their usernames and potentially other details to the attacker.
7.  The attacker crafts a new HTTP POST request to create a new user account, specifying administrator privileges.
8.  The flawed authorization check allows the creation of the new administrator account, granting the attacker full control over the Movary instance.

## Impact

Successful exploitation of CVE-2026-40350 allows an attacker to gain complete administrative control over a vulnerable Movary instance. This can lead to unauthorized data access, modification, or deletion, as well as the potential for further malicious activities, such as deploying backdoors or compromising the underlying server. The number of affected Movary installations is currently unknown. Organizations and individuals using Movary are urged to upgrade to version 0.71.1 immediately.

## Recommendation

*   Upgrade Movary installations to version 0.71.1 to remediate CVE-2026-40350.
*   Implement the provided Sigma rule "Movary User Management Endpoint Access" to detect unauthorized access attempts to `/settings/users` in web server logs.
*   Review web server access logs for suspicious activity targeting the `/settings/users` endpoint, especially requests from non-administrator users.
*   Enable stricter role-based access control mechanisms for web applications to prevent similar privilege escalation vulnerabilities.
