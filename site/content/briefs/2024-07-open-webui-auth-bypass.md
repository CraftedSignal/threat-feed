---
title: Open WebUI Improper Authorization Control Vulnerability
slug: 2024-07-open-webui-auth-bypass
description: Open WebUI version 0.1.105 is vulnerable to an improper authorization control issue, where user accounts with a `pending` status can bypass authorization checks and make authenticated API calls as a `user` context due to the application failing to properly validate the user's role beyond JWT validation.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization
  - web-application
  - vulnerability
vendors:
  - Open WebUI
products:
  - Open WebUI (Formerly Ollama WebUI) 0.1.105
affected_os:
  - Debian GNU/Linux 12 (bookworm)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-4vg5-rp28-gvjf
iocs:
  - type: email
    value: bad_guy@korelogic.com
ioc_counts:
  email: 1
rules:
  - title: Detect Open WebUI API Access by Pending User
    description: Detects API requests to /ollama/api/tags with a Bearer token and a 200 OK status, indicating potential access by a pending user.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Open WebUI User Registration
    description: Detects new user registration requests to the /api/v1/auths/signup endpoint.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI, formerly Ollama WebUI, version 0.1.105, suffers from an improper authorization control vulnerability. This flaw allows users with a 'pending' status to bypass intended restrictions and make authenticated API calls as if they were authorized 'user' roles. The vulnerability arises because the application's API endpoints do not adequately validate the user's role, relying solely on the presence of a valid JWT for authentication, while neglecting to verify the user's assigned role. The vulnerability was discovered by Taylor Pennington of KoreLogic, Inc. This issue allows unapproved users to access sensitive data and functionality.

## Attack Chain

1.  Attacker registers a new user account on the Open WebUI platform with `new sign-ups` enabled. The new account is automatically assigned a `pending` status.
2.  The application generates a JWT for the new user, despite their `pending` status, and returns it to the attacker.
3.  The attacker crafts an HTTP GET request to the `/ollama/api/tags` endpoint, including the JWT in the `Authorization` header.
4.  The Open WebUI server receives the request and validates the JWT using the `get_current_user` function.
5.  The `get_current_user` function only checks the validity of the JWT but does not verify the user's role, thus allowing the request to proceed.
6.  The server retrieves a list of available models without properly validating the user's authorization.
7.  The server returns the list of available models in the HTTP response to the attacker.
8.  The attacker can now access other regular user accessible endpoints.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to access sensitive information such as available models and potentially other resources intended only for authorized users. This could lead to information disclosure, unauthorized use of resources, and further compromise of the system. This issue affects Open WebUI installations that have enabled new user sign-ups without properly verifying user roles, potentially impacting all users on the platform.

## Recommendation

*   Deploy the Sigma rule "Detect Open WebUI API Access by Pending User" to your SIEM to identify unauthorized API access attempts from users with a `pending` role based on HTTP request headers and response codes.
*   Apply the patch recommended by Open WebUI to utilize the `get_verified_user()` function instead of `get_current_user()` in all authenticated endpoints to enforce proper authorization checks as described in the Mitigation Recommendation section.
*   Monitor user registration requests to `/api/v1/auths/signup` using the "Detect Open WebUI User Registration" Sigma rule to track account creation attempts and potential abuse.
*   Investigate and revoke any JWTs associated with `pending` user accounts to prevent unauthorized access using the email IOC.
