---
title: phpMyFAQ Authentication Bypass Allows Account Takeover
slug: 2026-05-phpmyfaq-account-takeover
description: An authentication bypass vulnerability in phpMyFAQ allows an unauthenticated attacker to reset the password of any user account, including SuperAdmin accounts, by sending a PUT request with a valid username and associated email address to /api/user/password/update, resulting in complete account takeover.
date: "2026-05-20T15:50:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - account-takeover
  - phpmyfaq
  - web-application
vendors:
  - phpmyfaq
products:
  - phpmyfaq < 4.1.3
references:
  - https://github.com/advisories/GHSA-w9xh-5f39-vq89
rules:
  - title: Detect phpMyFAQ Password Reset Exploit
    description: Detects exploitation of the phpMyFAQ password reset vulnerability by monitoring for PUT requests to /api/user/password/update. Excludes known good status codes.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
  - title: Detect phpMyFAQ Username Enumeration Attempts
    description: Detects possible phpMyFAQ username enumeration attempts using the password reset endpoint by monitoring for multiple requests with invalid email addresses.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 2
---

A critical authentication bypass vulnerability exists in phpMyFAQ versions prior to 4.1.3. This flaw allows an unauthenticated attacker to reset the password of any user account, including those with SuperAdmin privileges. The vulnerability stems from the lack of proper password reset token verification, rate limiting, and email confirmation in the `/api/user/password/update` endpoint. By crafting a simple PUT request containing a valid username and associated email address, an attacker can trigger the system to generate a new plaintext password and transmit it to the user's email address, effectively granting them complete control over the targeted account. This poses a significant risk to organizations using phpMyFAQ for knowledge management and support purposes.

## Attack Chain

1.  The attacker identifies a target phpMyFAQ instance.
2.  The attacker sends a PUT request to `/phpmyfaq/api/user/password/update` with a valid username and incorrect email address to determine if the username exists (username enumeration).
3.  If the response indicates the username exists, the attacker sends another PUT request to `/phpmyfaq/api/user/password/update` with the valid username and associated email address in the JSON body.
4.  The phpMyFAQ application, lacking proper authentication, processes the request without requiring any token verification, rate limiting, or email confirmation.
5.  The application generates a new plaintext password for the specified user account.
6.  The application sends the new plaintext password to the user's email address.
7.  The attacker intercepts the email containing the new password.
8.  The attacker uses the new password to log in to the phpMyFAQ application and take complete control of the account.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain full administrative access to a phpMyFAQ installation. This includes the ability to access and modify sensitive information, such as user data and FAQ content. An attacker can also lock out legitimate users, disrupt service availability, and potentially use the compromised system as a platform for further malicious activities. All phpMyFAQ administrators and end-users are potentially impacted, especially those using default installations. The attack has very low complexity, requiring no special knowledge beyond identifying a valid username and associated email address.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.3 or later to patch the vulnerability as detailed in [GHSA-w9xh-5f39-vq89](https://github.com/advisories/GHSA-w9xh-5f39-vq89).
*   Deploy the Sigma rule `Detect phpMyFAQ Password Reset Exploit` to identify potential exploitation attempts in web server logs.
*   Implement rate limiting on the `/api/user/password/update` endpoint to prevent username/email enumeration attacks.
