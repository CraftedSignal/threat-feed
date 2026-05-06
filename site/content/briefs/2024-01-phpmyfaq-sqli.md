---
title: phpMyFAQ SQL Injection via Unescaped OAuth Token
slug: 2024-01-phpmyfaq-sqli
description: phpMyFAQ is vulnerable to SQL injection due to the `setTokenData` function failing to sanitize OAuth token fields from Azure AD JWT claims, potentially allowing attackers to execute arbitrary SQL commands via crafted Azure AD display names or custom claims.
date: "2026-05-06T20:44:39Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - oauth
  - phpmyfaq
vendors:
  - phpMyFAQ
  - Microsoft
products:
  - phpMyFAQ <= 4.1.1
  - Azure AD
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-pm8c-3qq3-72w7
rules:
  - title: phpMyFAQ SQL Injection Attempt
    description: Detects potential SQL injection attempts in phpMyFAQ by monitoring for specific SQL syntax within JWT claims.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: phpMyFAQ OAuth Login with Crafted Claim
    description: Detects a phpMyFAQ OAuth login attempt where an Azure AD claim contains a single quote that might cause SQL injection
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

phpMyFAQ version 4.1.1 and earlier contains a SQL injection vulnerability within the `CurrentUser::setTokenData()` function. This function, responsible for updating user data with OAuth token information, fails to properly sanitize specific fields (`refresh_token`, `access_token`, `code_verifier`, and `jwt`) extracted from the Azure AD `id_token`. An attacker with a Microsoft Azure AD account whose display name or custom claim contains SQL metacharacters (e.g., a single quote) can inject arbitrary SQL queries into the phpMyFAQ database. The vulnerability exists because `setTokenData()` utilizes `sprintf` for constructing the SQL query without proper escaping, unlike other functions within the same file. Successful exploitation allows an attacker to read, modify, or delete sensitive FAQ data, extract user credentials, and potentially compromise the entire phpMyFAQ installation.

## Attack Chain

1. Attacker registers an Azure AD account and crafts a malicious display name or claim containing SQL injection payloads (e.g., `O'Brien` or `x',(SELECT SLEEP(5)))-- -`).
2. The attacker initiates the OAuth login flow on a phpMyFAQ instance with Azure AD authentication enabled.
3. The Azure AD authorization endpoint redirects back to the phpMyFAQ instance.
4. The phpMyFAQ instance requests an access token from Azure AD, receiving a JWT in response.
5. The JWT contains the attacker's crafted display name or claim.
6. phpMyFAQ's `setTokenData()` function receives the JWT and extracts the malicious claim without sanitization.
7. The unsanitized claim is injected into an SQL UPDATE statement, leading to arbitrary SQL execution.
8. The attacker can then read sensitive data, modify content, or extract password hashes.

## Impact

Successful exploitation of this SQL injection vulnerability grants the attacker the ability to execute arbitrary SQL commands on the phpMyFAQ database. This can lead to a full compromise of the application, including unauthorized access to all FAQ data (including restricted entries), modification or deletion of content, and extraction of password hashes and session tokens of all users, including administrators. This can result in significant data breaches and reputational damage.

## Recommendation

*   Deploy the Sigma rule `phpMyFAQ SQL Injection Attempt` to detect potential exploitation attempts by monitoring for suspicious SQL syntax within JWT claims (logsource: `webserver`, category: `webserver`).
*   Apply the recommended fix provided in the GHSA advisory, which involves escaping all interpolated values using `$this->configuration->getDb()->escape()` in the `setTokenData()` function to mitigate the SQL injection vulnerability (reference: GHSA-pm8c-3qq3-72w7).
*   Upgrade to a patched version of phpMyFAQ that addresses this vulnerability to prevent further exploitation (affected_products: `phpMyFAQ <= 4.1.1`).
