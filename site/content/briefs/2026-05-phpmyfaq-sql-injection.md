---
title: phpMyFAQ SQL Injection Vulnerability in CurrentUser::setTokenData (CVE-2026-46359)
slug: 2026-05-phpmyfaq-sql-injection
description: phpMyFAQ before version 4.1.2 contains a SQL injection vulnerability in CurrentUser::setTokenData, allowing authenticated attackers with crafted Azure AD accounts to execute arbitrary SQL queries by injecting malicious OAuth token claims.
date: "2026-05-15T19:20:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - phpMyFAQ
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-46359
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46359
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-pm8c-3qq3-72w7
  - https://www.vulncheck.com/advisories/phpmyfaq-sql-injection-in-currentuser-settokendata-via-unescaped-oauth-token-fields
rules:
  - title: Detects CVE-2026-46359 Exploitation — phpMyFAQ SQL Injection via OAuth Token
    description: Detects CVE-2026-46359 exploitation — Attempts to inject SQL commands into OAuth token claims processed by phpMyFAQ's CurrentUser::setTokenData function
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-46359 Exploitation — phpMyFAQ SQL Injection via Azure AD Display Name
    description: Detects CVE-2026-46359 exploitation — Azure AD display names with SQL metacharacters being processed by phpMyFAQ
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before version 4.1.2 is vulnerable to SQL injection in the `CurrentUser::setTokenData` function. This vulnerability, identified as CVE-2026-46359, allows authenticated attackers to execute arbitrary SQL queries. The attack vector involves injecting malicious OAuth token claims. Specifically, attackers with Azure AD accounts containing SQL metacharacters in their display names or JWT claims can exploit this vulnerability. Successful exploitation can lead to unauthorized data access, modification, or complete compromise of the database. This poses a significant risk to organizations using affected versions of phpMyFAQ, particularly those integrated with Azure AD for authentication.

## Attack Chain

1. An attacker authenticates to the phpMyFAQ application using an Azure AD account.
2. The Azure AD account contains SQL metacharacters in its display name or JWT claims.
3. phpMyFAQ's `CurrentUser::setTokenData` function processes the OAuth token claims without proper sanitization.
4. Malicious SQL metacharacters are injected into the SQL query executed by the function.
5. The injected SQL commands modify the intended query, allowing arbitrary SQL execution.
6. The attacker can then read, modify, or delete data within the phpMyFAQ database.
7. The attacker may gain administrative privileges or access sensitive information.
8. Finally, the attacker achieves full database compromise, potentially exfiltrating sensitive data.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-46359) can lead to complete compromise of the phpMyFAQ database. This can result in unauthorized access to sensitive information, data modification, or data deletion. The impact can range from information disclosure to full system takeover, depending on the privileges of the database user used by phpMyFAQ. Organizations using vulnerable versions are at risk of data breaches, financial loss, and reputational damage.

## Recommendation

*   Upgrade to phpMyFAQ version 4.1.2 or later to patch the SQL injection vulnerability (CVE-2026-46359).
*   Deploy the Sigma rules provided below to your SIEM to detect potential exploitation attempts.
*   Review Azure AD account creation policies to restrict the use of special characters in display names.
*   Implement proper input validation and sanitization techniques in the `CurrentUser::setTokenData` function if patching is not immediately feasible.
