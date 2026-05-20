---
title: phpMyFAQ Unauthenticated Password Reset Vulnerability
slug: 2026-05-phpmyfaq-password-reset
description: phpMyFAQ versions prior to 4.1.3 are vulnerable to an unauthenticated password reset vulnerability that allows attackers to enumerate valid accounts and forcibly change user passwords by exploiting the password reset API without token validation.
date: "2026-05-20T15:47:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - phpMyFAQ
  - password-reset
  - account-enumeration
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ < 4.1.3
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://github.com/advisories/GHSA-9qv9-8xv6-5p35
rules:
  - title: Detect phpMyFAQ Password Reset Attempt
    description: Detects attempts to exploit the phpMyFAQ unauthenticated password reset vulnerability by monitoring for PUT requests to the password update endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect phpMyFAQ Failed Password Reset Attempt
    description: Detects failed attempts to exploit the phpMyFAQ unauthenticated password reset vulnerability by monitoring for 409 Conflict responses after a PUT request to the password update endpoint.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ versions prior to 4.1.3 are vulnerable to an unauthenticated password reset vulnerability. The vulnerability resides in the password reset API, which lacks proper authentication and authorization checks. An attacker can exploit this by sending a crafted request to the `/api/index.php/user/password/update` endpoint with a valid username and email combination. Upon receiving this request, the application immediately generates a new password, updates the user's account, and sends the new password to the user's email address. This bypasses the intended password reset flow, allowing attackers to forcibly change passwords without any out-of-band confirmation or token validation. This issue was confirmed in a local Docker deployment.

## Attack Chain

1.  The attacker identifies a potential target username and email address.
2.  The attacker crafts a PUT request to `/api/index.php/user/password/update` with the target's username and email in the JSON body.
3.  The phpMyFAQ application receives the request at `phpmyfaq/src/phpMyFAQ/Controller/Frontend/Api/UnauthorizedUserController.php`.
4.  The application checks if the provided username and email combination exists.
5.  If the username and email are valid, the application generates a new password.
6.  The application updates the user's password in the database with the newly generated password.
7.  The application sends the new password to the user's email address.
8.  The attacker has now forced a password reset, effectively locking the user out of their account using the original password.

## Impact

The unauthenticated password reset vulnerability in phpMyFAQ allows attackers to enumerate valid usernames and email addresses. More critically, it enables attackers to forcibly reset user passwords, leading to account disruption and potential denial of service. An attacker knowing a valid username/email pair can trigger an immediate password change without any confirmation, invalidating the old password. While the attacker might not gain immediate access to the account if they lack access to the email, the forced password reset disrupts the victim's access and could lead to further exploitation if the attacker can intercept the new password.

## Recommendation

*   Apply the provided patch or upgrade to phpMyFAQ version 4.1.3 or later to remediate the vulnerability.
*   Deploy the Sigma rule `Detect phpMyFAQ Password Reset Attempt` to monitor for suspicious PUT requests to the password update endpoint.
*   Implement rate limiting on the `/api/index.php/user/password/update` endpoint to mitigate brute-force attempts to enumerate valid username/email pairs.
*   Change the password recovery flow to a token-based design as outlined in the source document, generating reset tokens and validating those tokens before resetting the password.
