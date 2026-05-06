---
title: Movary Privilege Escalation Vulnerability (CVE-2026-40349)
slug: 2026-04-movary-privesc
description: Movary versions prior to 0.71.1 allow authenticated users to escalate privileges to administrator by manipulating the `isAdmin` field via a PUT request to the `/settings/users/{userId}` endpoint, due to missing authorization checks.
date: "2026-04-18T00:16:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - cve-2026-40349
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40349
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40349
  - https://github.com/leepeuker/movary/security/advisories/GHSA-mcfq-8rx7-w25v
rules:
  - title: Detect Movary Admin Privilege Escalation Attempt
    description: Detects attempts to escalate privileges in Movary by sending a PUT request to the /settings/users endpoint with isAdmin=true.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Movary User Settings Modification
    description: Detects PUT requests to the Movary /settings/users endpoint, which could indicate suspicious user profile modifications.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Movary is a self-hosted web application designed for users to track and rate movies they have watched. Prior to version 0.71.1, the application contains a privilege escalation vulnerability (CVE-2026-40349). An authenticated user could modify their account to gain administrative privileges without proper authorization. This is achieved by sending a PUT request to the `/settings/users/{userId}` endpoint with the `isAdmin` field set to `true`. This vulnerability exists because the application fails to implement sufficient authorization checks before updating the sensitive `isAdmin` field. Version 0.71.1 addresses this issue, mitigating the risk of unauthorized privilege escalation. The vulnerable versions expose self-hosted Movary instances to potential compromise.

## Attack Chain

1. An attacker gains initial access to a Movary instance with a valid, non-administrative user account.
2. The attacker identifies the vulnerable `/settings/users/{userId}` endpoint that manages user profile settings.
3. The attacker crafts a PUT request to `/settings/users/{userId}`, substituting `{userId}` with their own user ID.
4. The PUT request includes the parameter `isAdmin=true` within the request body, attempting to modify the user's privilege level.
5. The Movary server processes the PUT request without performing adequate authorization checks to verify the user's authority to modify the `isAdmin` field.
6. The server updates the user's account, setting the `isAdmin` flag to `true`, effectively granting the attacker administrative privileges.
7. The attacker logs out and back into the Movary instance.
8. Upon re-authentication, the attacker now possesses administrative privileges and can access and modify sensitive data, configurations, and potentially compromise the entire Movary instance.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain full administrative control over a Movary instance. This could lead to unauthorized access to user data, modification or deletion of movies and ratings, and potentially complete compromise of the server hosting the application. The number of affected instances is unknown but depends on the number of deployments running vulnerable versions of Movary. The severity is high, as it allows a low-privilege user to gain complete control over the application.

## Recommendation

*   Upgrade Movary instances to version 0.71.1 or later to remediate the vulnerability (references: Overview section).
*   Deploy the provided Sigma rule to detect suspicious PUT requests to `/settings/users/{userId}` attempting to modify the `isAdmin` parameter (references: Sigma rule below).
*   Implement input validation and authorization checks on the server-side to prevent unauthorized modification of sensitive user attributes (references: CVE-2026-40349 description).
