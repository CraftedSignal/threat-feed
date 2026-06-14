---
title: phpMyFAQ Unauthenticated Password Reset Vulnerability (CVE-2026-35676)
slug: 2026-05-phpmyfaq-password-reset
description: phpMyFAQ before 4.1.3 is vulnerable to an unauthenticated password reset, allowing attackers to change account passwords without token validation by sending crafted PUT requests to the /api/index.php/user/password/update endpoint.
date: "2026-05-28T16:18:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - vulnerability
  - password reset
  - unauthenticated
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-35676
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35676
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-9qv9-8xv6-5p35
  - https://www.vulncheck.com/advisories/phpmyfaq-unauthenticated-password-reset-via-user-password-update-endpoint
rules:
  - title: Detect phpMyFAQ Password Reset Attempt
    description: Detects CVE-2026-35676 exploitation - an unauthenticated password reset attempt in phpMyFAQ via PUT requests to /api/index.php/user/password/update.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect phpMyFAQ Password Reset from Uncommon Source IP
    description: Detects CVE-2026-35676 exploitation - an unauthenticated password reset attempt in phpMyFAQ via PUT requests to /api/index.php/user/password/update from uncommon source IPs
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before version 4.1.3 is susceptible to an unauthenticated password reset vulnerability (CVE-2026-35676). This flaw resides in the user password update API endpoint, specifically within the `/api/index.php/user/password/update` path. Attackers can exploit this vulnerability by sending crafted PUT requests to the vulnerable endpoint, bypassing token validation. Successful exploitation allows threat actors to change the passwords of existing accounts, leading to account disruption, denial of service, and potential unauthorized access. This vulnerability can be exploited without authentication, making it critical for defenders to address.

## Attack Chain

1.  Attacker identifies a phpMyFAQ instance running a version prior to 4.1.3.
2.  Attacker enumerates valid usernames and associated email addresses.
3.  Attacker crafts a PUT request targeting the `/api/index.php/user/password/update` endpoint. The request body contains the target username, email address, and the attacker's desired new password.
4.  Attacker sends the crafted PUT request to the vulnerable endpoint.
5.  The phpMyFAQ application, lacking proper token validation, updates the user's password to the attacker-specified value.
6.  The legitimate user's password is now changed without their consent or knowledge.
7.  Attacker uses the new password to log into the compromised account.
8.  Attacker gains unauthorized access to the user's account and any associated sensitive data.

## Impact

Successful exploitation of this vulnerability allows attackers to take complete control of user accounts in affected phpMyFAQ installations. This can lead to data breaches, denial of service, or further malicious activities within the application. Given the ease of exploitation and lack of authentication required, this vulnerability poses a significant risk to organizations utilizing vulnerable phpMyFAQ versions. There is no specified victim count for this CVE.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.3 or later to patch CVE-2026-35676.
*   Deploy the Sigma rule `Detect phpMyFAQ Password Reset Attempt` to your SIEM to identify exploitation attempts targeting the `/api/index.php/user/password/update` endpoint.
*   Monitor web server logs for unusual PUT requests to the `/api/index.php/user/password/update` endpoint, as this is the primary attack vector.
*   Implement rate limiting on the password reset endpoint to mitigate brute-force enumeration attempts.
