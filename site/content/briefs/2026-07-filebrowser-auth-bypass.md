---
title: FileBrowser Authentication Bypass via Forged Proxy Authentication Header
slug: 2026-07-filebrowser-auth-bypass
description: An unauthenticated attacker can impersonate any user, including administrators, or automatically create new user accounts in FileBrowser by forging the `X-Remote-User` HTTP header when the server is configured for proxy authentication and is directly reachable, leading to full administrative control and unauthorized access to data.
date: "2026-07-10T19:37:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - web-vulnerability
  - privilege-escalation
  - file-browser
  - account-creation
vendors:
  - FileBrowser
products:
  - FileBrowser (all versions supporting proxy authentication)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated attacker who can reach the server directly can impersonate any user - including admin - by sending a single forged HTTP header. No credentials are required.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Additionally, specifying a non-existent username causes the server to automatically create a new user account, providing an account creation primitive with no authorization.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: any unauthenticated attacker who can reach the server directly can impersonate any user - including admin - by sending a single forged HTTP header.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xqp3-jq6g-x3qm
rules:
  - title: Detect FileBrowser Authentication Bypass Attempt via X-Remote-User Header Forgery
    description: Detects attempts to exploit an authentication bypass vulnerability in FileBrowser where an unauthenticated attacker forges the X-Remote-User HTTP header during a login attempt to gain unauthorized access, including administrative control or account creation. This rule assumes web server logs are configured to capture custom HTTP headers like X-Remote-User.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078.001
      - T1136
      - T1550
    data_sources:
      - webserver
rules_count: 1
---

A critical authentication bypass vulnerability affects FileBrowser instances configured to use proxy authentication (`auth.method=proxy`) where the application server is directly exposed to untrusted networks. This allows any unauthenticated attacker to impersonate any existing user, including the administrator, by simply sending a forged `X-Remote-User` HTTP header during a POST request to the `/api/login` endpoint. Additionally, specifying a non-existent username in the forged header causes FileBrowser to automatically create a new user account with default permissions, providing an account creation primitive without authorization. This vulnerability stems from FileBrowser unconditionally trusting the `X-Remote-User` header without any origin validation or password verification, a behavior present across all versions that support this authentication method. This is a common misconfiguration for organizations using reverse proxies for SSO/LDAP/OAuth. Successful exploitation grants full administrative control over the FileBrowser instance and access to all hosted files.

## Attack Chain

1. An unauthenticated attacker identifies a FileBrowser instance configured with `auth.method=proxy` that is directly reachable (i.e., not exclusively behind a trusted reverse proxy).
2. The attacker crafts an HTTP POST request to the `/api/login` endpoint, including a forged HTTP header, typically `X-Remote-User`, set to a target username such as `admin`.
3. FileBrowser's `ProxyAuth.Auth()` function receives the request and extracts the username from the `X-Remote-User` header, implicitly trusting its value without any origin validation (e.g., checking trusted IP addresses) or cryptographic verification.
4. If the specified username exists, FileBrowser retrieves the corresponding user object from its internal user store. If the username does not exist, the `createUser()` function is automatically invoked, creating a new user account with default permissions and a locked, random password.
5. The `loginHandler` proceeds to mint a valid JSON Web Token (JWT) for the impersonated or newly created user. This JWT contains the full permissions of the target user, including administrator privileges if `admin` was specified.
6. The attacker receives this valid JWT and uses it in subsequent HTTP requests by including it in the `X-Auth` header to interact with privileged endpoints (e.g., `/api/settings`, `/api/users`) or access specific user resources (e.g., `/api/resources/`).
7. The attacker achieves full administrative control over the FileBrowser instance, allowing modification of server settings, enumeration of all user accounts, and unauthorized access to all files and data within the application's scope.

## Impact

Successful exploitation of this vulnerability leads to complete compromise of the FileBrowser instance. Attackers gain full administrative control, allowing them to modify server configurations, create, delete, or modify files, and access sensitive data stored within the FileBrowser environment. This also enables the creation of arbitrary user accounts without authorization, potentially leading to further persistence or resource exhaustion. Organizations deploying FileBrowser behind reverse proxies, especially those exposing the application's port directly to an untrusted network (e.g., due to Docker container defaults or misconfigured cloud security groups), are at high risk of data breach and system compromise.

## Recommendation

* **Restrict direct access:** Configure network firewalls or security groups to ensure the FileBrowser application is only accessible by trusted reverse proxies, preventing direct access from untrusted networks.
* **Review logging**: Deploy the provided Sigma rule to detect POST requests to `/api/login` containing the `X-Remote-User` header. Ensure web server logs capture the `X-Remote-User` HTTP header for effective detection.
* **Update configuration:** If direct exposure is unavoidable, consider switching `auth.method` from `proxy` to `json` and implementing alternative, more secure authentication mechanisms at the application layer or within a properly secured reverse proxy setup.
* **Implement trusted proxy validation:** If using `auth.method=proxy` is essential, implement stringent trusted proxy validation at the network layer or enhance FileBrowser with origin validation checks (e.g., by contributing a patch to verify `r.RemoteAddr` against a list of trusted IPs).
