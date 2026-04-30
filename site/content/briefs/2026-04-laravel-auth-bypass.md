---
title: Laravel Passport Authentication Bypass Vulnerability (CVE-2026-39976)
slug: 2026-04-laravel-auth-bypass
description: Laravel Passport versions 13.0.0 before 13.7.1 contain an authentication bypass vulnerability (CVE-2026-39976) where machine-to-machine tokens can authenticate as a real user due to improper validation of the JWT sub claim.
date: "2026-04-09T17:16:31Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-39976
  - laravel
  - oauth2
  - authentication bypass
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Accounts
cves:
  - id: CVE-2026-39976
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39976
rules:
  - title: Detect Laravel Passport Authentication Bypass Attempt
    description: Detects requests where a machine-to-machine token authenticates as a regular user, indicative of CVE-2026-39976 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1586
      - T1586.002
    data_sources:
      - webserver
      - linux
  - title: Detect Errors Authenticating with Machine Credentials
    description: Detects 401 errors authenticating with client credentials, possibly an attempted authentication bypass
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586
      - T1586.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Laravel Passport, an OAuth2 server implementation for Laravel, is vulnerable to an authentication bypass (CVE-2026-39976) in versions 13.0.0 up to, but not including, 13.7.1. The vulnerability stems from the `league/oauth2-server` library, where the JWT `sub` claim is set to the client identifier for `client_credentials` tokens, as there is no associated user. Subsequently, the token guard uses this client identifier to retrieve user information via `retrieveById()` without proper validation, potentially resolving and authenticating an unrelated, real user. This means any machine-to-machine token can inadvertently authenticate as an actual user within the Laravel application. The vulnerability is resolved in Laravel Passport version 13.7.1. This allows attackers to perform actions with the privileges of the authenticated user.

## Attack Chain

1.  Attacker obtains a valid `client_credentials` token issued by Laravel Passport (versions 13.0.0 - 13.7.0). This could be a token intended for machine-to-machine communication.
2.  The attacker sends a request to a protected endpoint of the Laravel application, including the `client_credentials` token in the `Authorization` header.
3.  The Laravel Passport token guard extracts the JWT `sub` claim from the token. In vulnerable versions, this `sub` claim contains the client identifier.
4.  The token guard calls `retrieveById()` using the client identifier from the `sub` claim as the user ID.
5.  Due to the lack of validation, `retrieveById()` queries the user database, potentially finding a user whose ID matches the client identifier.
6.  If a user with the matching ID is found, the application authenticates the request as that user, granting the attacker their privileges.
7.  The attacker can then access resources and perform actions as the authenticated user.
8.  The attacker exploits the user's privileges to compromise data or perform unauthorized actions within the application.

## Impact

Successful exploitation of CVE-2026-39976 allows attackers to bypass authentication and gain unauthorized access to user accounts in Laravel applications using affected versions of Laravel Passport. This can lead to data breaches, privilege escalation, and other malicious activities, depending on the privileges of the compromised user accounts. The severity of the impact depends on the application's functionality and the sensitivity of the data it handles. Potentially all applications using Laravel Passport for authentication are vulnerable.

## Recommendation

*   Upgrade Laravel Passport to version 13.7.1 or later to patch CVE-2026-39976.
*   Implement additional validation within the application's authentication logic to verify that the user ID extracted from the JWT `sub` claim corresponds to a valid user, especially when using `client_credentials` tokens.
*   Monitor application logs for unexpected authentication events or API requests originating from machine-to-machine tokens that are being authenticated as users. The `webserver` log source can be used for this monitoring.
*   Deploy the Sigma rule provided to detect requests to protected endpoints with `client_credentials` tokens that are incorrectly authenticated as users.
