---
title: Laravel Passport Authentication Bypass via Client Credentials Tokens
slug: 2024-01-laravel-passport-auth-bypass
description: Laravel Passport before v13.7.1 allows an authentication bypass via client credentials tokens, where a client's identifier can be used to impersonate a user if `Passport::$clientUuids` is set to false or the EnsureClientIsResourceOwner middleware is in use.
date: "2024-01-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - laravel
  - passport
  - oauth2
  - authentication-bypass
vendors:
  - Laravel
products:
  - Laravel Passport
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials From Password Stores
references:
  - https://github.com/advisories/GHSA-349c-2h2f-mxf6
  - https://github.com/laravel/passport/issues/1900
  - https://github.com/laravel/passport/pull/1901
  - https://github.com/laravel/passport/pull/1902
  - https://github.com/thephpleague/oauth2-server/issues/1456#issuecomment-2734989996
rules:
  - title: Detect Laravel Passport Authentication Bypass Attempt
    description: Detects attempts to exploit the Laravel Passport authentication bypass vulnerability by monitoring for calls to the /oauth/token endpoint with client_credentials grant type.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Laravel Passport Malicious Client Registration
    description: Detects potential reconnaissance activity by monitoring for unusual POST requests to the /oauth/clients endpoint which could indicate a malicious actor attempting to create a client for exploit attempts
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Laravel Passport, a popular OAuth2 server package for Laravel applications, is vulnerable to an authentication bypass. Specifically, in versions prior to 13.7.1, when using `client_credentials` grant type tokens, the library sets the JWT `sub` claim to the client identifier. The `TokenGuard` then uses this client identifier without validating that it is actually a user ID, leading to a scenario where an attacker-controlled client ID may resolve to an existing user. The risk is amplified when `Passport::$clientUuids` is set to `false` or the `EnsureClientIsResourceOwner` middleware is in use, potentially resulting in machine-to-machine tokens inadvertently authenticating as actual users. This vulnerability allows unauthorized access to resources intended for specific users.

## Attack Chain

1. An attacker identifies a Laravel application using a vulnerable version of Laravel Passport (<13.7.1) that uses `client_credentials` grants.
2. The attacker registers a new OAuth2 client within the vulnerable application.
3. The attacker obtains the client ID of the registered client.
4. The attacker crafts a `client_credentials` token request to the `/oauth/token` endpoint, using the client's ID and secret.
5. The OAuth2 server generates a JWT access token. The `sub` claim in this token is set to the client ID.
6. The attacker makes a request to an API endpoint that is protected by Passport's `auth:api` guard using the crafted JWT access token.
7. The `TokenGuard` extracts the client ID from the `sub` claim of the JWT.
8. The `TokenGuard` calls `retrieveById()` using the client ID. If a user exists with an ID that matches the client ID, the `retrieveById()` method will return that user. The application incorrectly authenticates the request as that unrelated user, granting unauthorized access.

## Impact

Successful exploitation of this vulnerability can lead to significant data breaches and unauthorized access to user accounts. An attacker could gain access to sensitive information, perform actions on behalf of legitimate users, or escalate privileges within the application. The impact depends on the scope of data and actions accessible to a successfully impersonated user. This vulnerability affects all applications using Laravel Passport versions prior to 13.7.1 that have either disabled UUIDs for clients or are using the `EnsureClientIsResourceOwner` middleware in a vulnerable configuration.

## Recommendation

*   Upgrade to Laravel Passport version 13.7.1 or later to patch the vulnerability.
*   As a workaround, disallow the use of `client_credentials` grant type to prevent the vulnerability.
*   Review the configuration of `Passport::$clientUuids` and ensure it is set to `true` to mitigate the risk (see documentation in Overview).
*   Deploy the Sigma rule "Detect Laravel Passport Authentication Bypass Attempt" to detect potential exploitation attempts.
