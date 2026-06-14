---
title: phpMyFAQ Authentication Bypass Vulnerability (CVE-2026-35675)
slug: 2026-05-phpmyfaq-auth-bypass
description: phpMyFAQ before version 4.1.3 is vulnerable to an authentication bypass in the password reset endpoint, allowing unauthenticated attackers to reset any user account password without token verification or email confirmation, potentially leading to complete account takeover, including administrative access.
date: "2026-05-28T16:18:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication bypass
  - cve-2026-35675
  - phpMyFAQ
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ < 4.1.3
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Password Reset
cves:
  - id: CVE-2026-35675
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35675
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-w9xh-5f39-vq89
  - https://www.vulncheck.com/advisories/phpmyfaq-authentication-bypass-via-missing-password-reset-token-in-api-user-password-update
rules:
  - title: Detect PhpMyFAQ Password Reset Request Without Authentication
    description: Detects CVE-2026-35675 exploitation - HTTP POST requests to the password reset endpoint in phpMyFAQ without proper authentication, indicating a potential password reset attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect PhpMyFAQ User Enumeration via Password Reset Endpoint
    description: Detects potential user enumeration attempts by monitoring access to the password reset endpoint with invalid or non-existent usernames.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before 4.1.3 is susceptible to an authentication bypass vulnerability (CVE-2026-35675) within its password reset functionality. This flaw allows unauthenticated attackers to reset the passwords of arbitrary user accounts without requiring any token verification or email confirmation. Successful exploitation grants attackers complete control over compromised accounts, including those with administrative privileges. The vulnerability stems from a lack of proper authorization checks in the password reset endpoint. This can lead to attackers enumerating valid usernames, resetting their passwords, and obtaining plaintext passwords through the password reset email functionality.

## Attack Chain

1.  The attacker identifies a vulnerable phpMyFAQ instance running a version prior to 4.1.3.
2.  The attacker accesses the password reset endpoint without authentication.
3.  The attacker enumerates valid usernames, potentially by leveraging public information or other vulnerabilities.
4.  The attacker submits a password reset request for a targeted user account.
5.  Due to the missing token verification, the password reset is processed without proper authorization.
6.  The system sends a password reset email containing the new plaintext password to the targeted user's email address.
7.  The attacker intercepts or gains access to the password reset email.
8.  The attacker uses the plaintext password to log into the compromised account and perform unauthorized actions, including gaining administrative access.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to reset any user account password, leading to complete account takeover. This can result in unauthorized access to sensitive information, data breaches, and potential disruption of services. If an attacker gains access to an administrative account, they can modify the application, inject malicious code, or further compromise the server.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.3 or later to patch CVE-2026-35675.
*   Implement multi-factor authentication (MFA) to mitigate the impact of password compromise.
*   Deploy the Sigma rule `Detect PhpMyFAQ Password Reset Request Without Authentication` to identify potential exploitation attempts.
*   Monitor web server logs for suspicious activity related to the password reset endpoint as per the `logsource` defined in the Sigma rules.
