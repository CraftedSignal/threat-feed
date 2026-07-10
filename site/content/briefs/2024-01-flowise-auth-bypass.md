---
title: Flowise resetPassword Authentication Bypass Vulnerability
slug: 2024-01-flowise-auth-bypass
description: Flowise version 3.0.12 is vulnerable to an authentication bypass vulnerability due to improper implementation of the password reset mechanism, allowing an attacker to reset a user's password and gain unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - flowise
  - authentication-bypass
  - credential-access
vendors:
  - Flowise
products:
  - Flowise
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-f6hc-c5jr-878p
rules:
  - title: Detect Flowise Password Reset Attempt with Empty Token
    description: Detects attempts to reset passwords in Flowise by sending a POST request to the /api/v1/account/reset-password endpoint with a null or empty token.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Flowise Password Reset Attempt with Empty String Token
    description: Detects attempts to reset passwords in Flowise by sending a POST request to the /api/v1/account/reset-password endpoint with an empty string token.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Flowise is an open-source low-code tool that enables developers to build custom large language model (LLM) applications and AI agents. Version 3.0.12 of Flowise contains an authentication bypass vulnerability within the resetPassword method of the AccountService class. This vulnerability arises from a flaw in the password reset token validation process. Specifically, the system fails to verify whether a reset token has been generated for a user account before allowing a password reset. This allows an attacker with knowledge of a target user's email address to submit a password reset request to the `/api/v1/account/reset-password` endpoint with a null or empty reset token. The vulnerable version, 3.0.12, was tested and confirmed vulnerable. This vulnerability allows for complete account takeover.

## Attack Chain

1. The attacker obtains the email address of a valid Flowise user.
2. The attacker sends a POST request to the `/api/v1/account/forgot-password` endpoint with the target user's email address. (This step is technically not required but could be performed by the attacker.)
3. The attacker crafts a malicious POST request to the `/api/v1/account/reset-password` endpoint, including the target user's email address, a new password chosen by the attacker, and a null or empty string as the reset token.
4. The `resetPassword()` method in the AccountService class retrieves the user's account information based on the provided email address.
5. The method checks if the provided reset token matches the token stored in the user's account. Since the default value of `tempToken` is null, or an empty string after password reset, the check passes.
6. The method validates the token expiry. An attacker with knowledge of a recently created user account's email can bypass this check. By default, the expiry time stored in the account of a user that has never generated a reset token before is equal to the time of their accounts creation plus 15 minutes (or the value of the PASSWORD_RESET_TOKEN_EXPIRY_IN_MINUTES environment variable).
7. The user's password is changed to the attacker's chosen password. The `tempToken` is also set to an empty string.
8. The attacker uses the new password to log into the user's account, gaining unauthorized access to the Flowise application.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control over a user's Flowise account. The attacker can access sensitive data, modify existing configurations, create new AI agents, and potentially pivot to other systems or data sources integrated with the compromised Flowise instance. The number of potential victims is directly related to the number of Flowise deployments and active user accounts. This could result in significant data breaches, financial losses, and reputational damage for affected organizations.

## Recommendation

*   Upgrade Flowise to a patched version (>= 3.0.14) that addresses the authentication bypass vulnerability as this issue has been fixed in subsequent releases.
*   Deploy the following Sigma rule to detect suspicious requests to the `/api/v1/account/reset-password` endpoint with empty tokens.
*   Monitor web server logs for POST requests to `/api/v1/account/reset-password` with a body containing a null or empty `tempToken` value.
*   Implement rate limiting on the `/api/v1/account/reset-password` endpoint to prevent attackers from rapidly attempting password resets for multiple accounts.
